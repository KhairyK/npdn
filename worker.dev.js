/**
 * 2025 © OpenDN Foundation & My Academy Labs
 * NPDN Worker v2.3 — modified: remove-gzip, scoped-package-fix
 * Powered by Cloudflare Workers
 */

const POPULAR_PACKAGES = [
  ["react", "latest", "index.js"],
  ["react", "latest", "jsx-runtime.js"],
  ["vue", "latest", "dist/vue.esm.js"],
  ["axios", "latest", "dist/axios.min.js"],
  ["lodash", "latest", "lodash.js"],
];

export default {
  async fetch(request, env) {
    const trace = [];
    try {
      const url = new URL(request.url);

      if (!url.pathname.startsWith("/npm/")) {
        trace.push("bad-route");
        return respondText("Use: /npm/<pkg>@<ver>/<file>", 400, trace);
      }

      // normalize and strip leading /npm/
      const clean = url.pathname.replace("/npm/", "").replace(/^\/+|\/+$/g, "");
      const [pkgWithVer, ...rest] = clean.split("/");
      const atIndex = pkgWithVer.lastIndexOf("@");
      if (atIndex <= 0) {
        trace.push("invalid-pkg@ver");
        return respondText("Invalid package@version format", 400, trace);
      }

      let pkgName = pkgWithVer.slice(0, atIndex);
      let pkgVer = pkgWithVer.slice(atIndex + 1);
      let rawFilePath = rest.join("/"); // may be empty for manifest/meta

      const wantIntegrityParam = url.searchParams.get("integrity"); // can be 'all' or presence
      const wantIntegrityJson = url.searchParams.has("integrity") && wantIntegrityParam !== "all";
      const wantIntegrityAll = url.searchParams.has("integrity") && wantIntegrityParam === "all";
      const wantMeta = url.searchParams.has("meta");

      // decode and sanitize filePath (if present)
      let filePath = "";
      if (rawFilePath) {
        try {
          filePath = decodeURIComponent(rawFilePath)
            .replace(/^\.\/+/, "")
            .replace(/\\/g, "/");
        } catch (e) {
          trace.push("bad-percent-encoding");
          return respondText("Bad request (invalid percent-encoding)", 400, trace);
        }
        if (filePath.includes("..")) {
          trace.push("path-traversal");
          return respondText("Forbidden path", 403, trace);
        }
      }

      const isMapRequest = filePath.endsWith(".map");

      // --------------------------------------------------
      // Resolve version (handle 'latest' or dist-tag)
      // --------------------------------------------------
      const encodedPkg = encodeURIComponent(pkgName);
      const registryUrl = `https://registry.npmjs.org/${encodedPkg}`;
      let metadata;
      try {
        const metaRes = await fetch(registryUrl);
        if (!metaRes.ok) {
          trace.push("registry-404");
          return respondText("Package not found on registry", 404, trace);
        }
        metadata = await metaRes.json();
        trace.push("registry-fetch");
      } catch (err) {
        trace.push("registry-fetch-failed");
        return respondText("Failed to fetch registry metadata", 502, trace);
      }

      const distTags = metadata["dist-tags"] || {};
      let resolvedVersion = distTags[pkgVer] || pkgVer;

      // fallback to latest if missing
      if (!metadata.versions || !metadata.versions[resolvedVersion]) {
        if (distTags.latest) resolvedVersion = distTags.latest;
        if (!metadata.versions || !metadata.versions[resolvedVersion]) {
          trace.push("version-not-found");
          return respondText("Version not found", 404, trace);
        }
      }

      // Canonical redirect: if user used tag (like 'latest') -> redirect to concrete version
      if (pkgVer !== resolvedVersion && !wantIntegrityAll && !wantMeta && !filePath) {
        // encode pkgName in path so scoped packages don't create extra path segments
        const canonicalPkg = encodeURIComponent(pkgName);
        const canonicalPath = `/npm/${canonicalPkg}@${resolvedVersion}/${filePath}`;
        const headers = new Headers();
        headers.set("Location", canonicalPath);
        headers.set("Link", `<${canonicalPath}>; rel="canonical"`);
        headers.set("X-CDN-Trace", trace.concat(["canonical-redirect"]).join(";"));
        return new Response(null, { status: 302, headers });
      }

      const versionMeta = metadata.versions[resolvedVersion];
      const tarballUrl =
        (versionMeta && versionMeta.dist && versionMeta.dist.tarball) ||
        `https://registry.npmjs.org/${encodedPkg}/-/${encodeURIComponent(getPkgBase(pkgName))}-${resolvedVersion}.tgz`;

      if (!tarballUrl) {
        trace.push("no-tarball");
        return respondText("Tarball URL not found", 502, trace);
      }

      // KV keys - use encoded package name so scoped names don't inject extra slashes
      const KV_FILE_KEY = `${encodeURIComponent(pkgName)}@${resolvedVersion}/${filePath}`;
      const KV_MANIFEST_KEY = `${encodeURIComponent(pkgName)}@${resolvedVersion}::integrity-manifest`;

      // HEAD handling (reply headers only)
      if (request.method === "HEAD") {
        if (wantIntegrityAll) {
          const manifestText = await env.NPM_CACHE.get(KV_MANIFEST_KEY);
          const headers = new Headers();
          headers.set("Content-Type", "application/json");
          headers.set("Access-Control-Allow-Origin", "*");
          headers.set("X-Manifest-Cached", manifestText ? "true" : "false");
          headers.set("X-CDN-Trace", trace.concat(["head"]).join(";"));
          return new Response(null, { status: 200, headers });
        }

        const cached = filePath ? await env.NPM_CACHE.get(KV_FILE_KEY, "arrayBuffer") : null;
        const headers = new Headers();
        headers.set("Access-Control-Allow-Origin", "*");
        headers.set("Content-Type", filePath ? mimeTypeForPath(filePath) : "application/json");
        headers.set("Cache-Control", "public, max-age=31536000, immutable");
        headers.set("Accept-Ranges", "bytes");
        if (cached) {
          trace.push("kv-hit");
          headers.set("X-Cache", "HIT");
          const etag = await computeETag(cached);
          headers.set("ETag", etag);
        } else {
          trace.push("kv-miss");
          headers.set("X-Cache", "MISS");
        }
        headers.set("X-CDN-Trace", trace.join(";"));
        return new Response(null, { status: 200, headers });
      }

      // --------------------------------------------------
      // ?meta endpoint
      // --------------------------------------------------
      if (wantMeta && !filePath) {
        const filesCount = (versionMeta && versionMeta.files) ? Object.keys(versionMeta.files).length : null;
        const metaObj = {
          name: metadata.name,
          version: resolvedVersion,
          filesCount,
          hasTypes: !!versionMeta.types || !!versionMeta.typings,
          entry: {
            main: versionMeta && versionMeta.main ? versionMeta.main : null,
            module: versionMeta && versionMeta.module ? versionMeta.module : null,
            browser: versionMeta && versionMeta.browser ? versionMeta.browser : null,
          },
          license: versionMeta && versionMeta.license ? versionMeta.license : null,
        };
        trace.push("meta");
        return jsonResponse(metaObj, { "X-CDN-Trace": trace.join(";") });
      }

      // --------------------------------------------------
      // If integrity=all requested for package root -> return/generate manifest
      // --------------------------------------------------
      if (wantIntegrityAll && !filePath) {
        const cachedManifest = await env.NPM_CACHE.get(KV_MANIFEST_KEY);
        if (cachedManifest) {
          trace.push("manifest-kv-hit");
          return jsonResponse(JSON.parse(cachedManifest), { "X-Manifest-Cached": "true", "X-CDN-Trace": trace.join(";") });
        }

        // fetch tarball, build manifest
        let tarRes;
        try {
          tarRes = await fetch(tarballUrl);
          if (!tarRes.ok) {
            trace.push("tarball-404");
            return respondText("Tarball not found on npm", 404, trace);
          }
          trace.push("tarball-fetch");
        } catch (err) {
          trace.push("tarball-fetch-failed");
          return respondText("Failed fetching tarball", 502, trace);
        }

        let tarBytes;
        try {
          const tarStream = tarRes.body.pipeThrough(new DecompressionStream("gzip"));
          tarBytes = await streamToUint8Array(tarStream);
        } catch (err) {
          try {
            const ab = await tarRes.arrayBuffer();
            tarBytes = new Uint8Array(ab);
          } catch (e) {
            trace.push("tarball-read-fail");
            return respondText("Failed to read tarball bytes", 502, trace);
          }
        }

        const files = untar(tarBytes);
        const manifest = {};
        for (const f of files) {
          const name = normalizeName(f.name);
          if (!name) continue;
          const bodyUint8 = f.data instanceof Uint8Array ? f.data : new Uint8Array(f.data);
          if (bodyUint8.length === 0) continue;
          const integrity = await computeSRI(bodyUint8.buffer);
          manifest[name] = {
            integrity,
            size: bodyUint8.byteLength,
            mime: mimeTypeForPath(name),
          };
        }

        try {
          await env.NPM_CACHE.put(KV_MANIFEST_KEY, JSON.stringify(manifest), {
            expirationTtl: 60 * 60 * 24 * 30,
          });
          trace.push("manifest-kv-put");
        } catch (e) {
          trace.push("manifest-kv-put-failed");
          console.warn("KV manifest put failed:", e);
        }

        trace.push("manifest-generated");
        return jsonResponse(manifest, { "X-Manifest-Cached": "false", "X-CDN-Trace": trace.join(";") });
      }

      // --------------------------------------------------
      // Smart Default Resolver (if no filePath)
      // --------------------------------------------------
      if (!filePath && !wantIntegrityAll && !wantMeta) {
        const candidates = [
          versionMeta && versionMeta.module,
          versionMeta && versionMeta.browser,
          versionMeta && versionMeta.main,
          "dist/index.esm.js",
          "dist/index.js",
          "index.js",
        ].filter(Boolean);

        if (!candidates.length) {
          trace.push("no-entry-candidates");
          return respondText("No entry file found", 404, trace);
        }

        filePath = candidates[0];
        trace.push("smart-resolve:" + filePath);
      }

      // --------------------------------------------------
      // Check KV (skip for .map)
      // --------------------------------------------------
      if (!isMapRequest) {
        const cachedArrayBuffer = await env.NPM_CACHE.get(KV_FILE_KEY, "arrayBuffer");
        if (cachedArrayBuffer) {
          trace.push("kv-hit");
          const cachedUint8 = new Uint8Array(cachedArrayBuffer);
          const incomingIfNone = request.headers.get("If-None-Match");
          const cachedETag = await computeETag(cachedArrayBuffer);
          if (incomingIfNone && compareEtags(incomingIfNone, cachedETag)) {
            trace.push("etag-match");
            const headers304 = new Headers();
            headers304.set("ETag", cachedETag);
            headers304.set("Access-Control-Allow-Origin", "*");
            headers304.set("X-Cache", "HIT");
            headers304.set("X-CDN-Trace", trace.join(";"));
            return new Response(null, { status: 304, headers: headers304 });
          }

          // Range
          const rangeHeader = request.headers.get("Range");
          if (rangeHeader) {
            trace.push("range-request");
            const rangeResp = handleRangeRequest(cachedUint8, rangeHeader, cachedETag, filePath, trace);
            if (rangeResp) return rangeResp;
          }

          if (wantIntegrityJson) {
            const integrity = await computeSRI(cachedUint8.buffer);
            const mime = mimeTypeForPath(filePath);
            trace.push("integrity-json-kv");
            return jsonResponse({
              url: request.url,
              integrity,
              size: cachedUint8.byteLength,
              mime,
              cached: true,
            }, { "X-CDN-Trace": trace.join(";") });
          }

          // Serve cached file (uncompressed)
          const headersExtra = { ETag: cachedETag, "Accept-Ranges": "bytes" };
          return await makeFileResponse(request, cachedUint8, filePath, true, headersExtra, trace);
        } else {
          trace.push("kv-miss");
        }
      }

      // --------------------------------------------------
      // Fetch tarball & extract
      // --------------------------------------------------
      let tarRes;
      try {
        tarRes = await fetch(tarballUrl);
        if (!tarRes.ok) {
          trace.push("tarball-404");
          return respondText("Tarball not found on npm", 404, trace);
        }
        trace.push("tarball-fetch");
      } catch (err) {
        trace.push("tarball-fetch-failed");
        return respondText("Failed fetching tarball", 502, trace);
      }

      // decompress
      let tarBytes;
      try {
        const tarStream = tarRes.body.pipeThrough(new DecompressionStream("gzip"));
        tarBytes = await streamToUint8Array(tarStream);
      } catch (err) {
        try {
          const ab = await tarRes.arrayBuffer();
          tarBytes = new Uint8Array(ab);
        } catch (e) {
          trace.push("tarball-read-fail");
          return respondText("Failed to read tarball bytes", 502, trace);
        }
      }

      const files = untar(tarBytes);

      // helper normalize
      function normalizeName(name) {
        return name.replace(/^package\//, "");
      }

      // .map direct serve (no KV put)
      if (isMapRequest) {
        const targetMap = files.find((f) => normalizeName(f.name) === filePath);
        if (!targetMap) {
          trace.push("map-not-found");
          return respondText(`.map file not found: ${filePath}`, 404, trace);
        }
        const bodyUint8 = targetMap.data instanceof Uint8Array ? targetMap.data : new Uint8Array(targetMap.data);
        if (wantIntegrityJson) {
          const integrity = await computeSRI(bodyUint8.buffer);
          const mime = mimeTypeForPath(filePath);
          trace.push("map-integrity");
          return jsonResponse({
            url: request.url,
            integrity,
            size: bodyUint8.byteLength,
            mime,
            cached: false,
          }, { "X-CDN-Trace": trace.join(";") });
        }
        trace.push("map-serve");
        return await makeFileResponse(request, bodyUint8, filePath, false, {}, trace);
      }

      // find target file inside tar
      const target = files.find((f) => normalizeName(f.name) === filePath);
      if (!target) {
        // if map exists, hint
        const possibleMap = files.find((f) => normalizeName(f.name) === filePath + ".map");
        if (possibleMap) {
          trace.push("file-not-found-but-map-exists");
          return jsonResponse({
            error: "Requested file not found, but a sourcemap exists",
            sourcemap: `/npm/${encodeURIComponent(pkgName)}@${resolvedVersion}/${filePath}.map`,
          }, { "X-CDN-Trace": trace.join(";") });
        }
        trace.push("file-not-found");
        return respondText(`File not found in tarball: ${filePath}`, 404, trace);
      }

      // Save file to KV
      const bodyUint8 = target.data instanceof Uint8Array ? target.data : new Uint8Array(target.data);
      try {
        await env.NPM_CACHE.put(KV_FILE_KEY, bodyUint8, { expirationTtl: 60 * 60 * 24 * 365 });
        trace.push("kv-put");
      } catch (err) {
        trace.push("kv-put-failed");
        console.warn("KV put failed:", err);
      }

      // X-Sourcemap header if present
      const mapCandidate = files.find((f) => normalizeName(f.name) === filePath + ".map");
      const headersExtra = {};
      if (mapCandidate) {
        headersExtra["X-Sourcemap-URL"] = `/npm/${encodeURIComponent(pkgName)}@${resolvedVersion}/${filePath}.map`;
      }

      const newETag = await computeETag(bodyUint8.buffer);

      if (wantIntegrityJson) {
        const integrity = await computeSRI(bodyUint8.buffer);
        const mime = mimeTypeForPath(filePath);
        trace.push("integrity-json-generated");
        return jsonResponse({
          url: request.url,
          integrity,
          size: bodyUint8.byteLength,
          mime,
          cached: false,
        }, { "X-CDN-Trace": trace.join(";") });
      }

      const incomingIfNoneMatch = request.headers.get("If-None-Match");
      if (incomingIfNoneMatch && compareEtags(incomingIfNoneMatch, newETag)) {
        trace.push("etag-match-after-put");
        const headers304 = new Headers();
        headers304.set("ETag", newETag);
        headers304.set("Access-Control-Allow-Origin", "*");
        headers304.set("X-CDN-Trace", trace.join(";"));
        return new Response(null, { status: 304, headers: headers304 });
      }

      const rangeHeader = request.headers.get("Range");
      if (rangeHeader) {
        trace.push("range-request");
        const rangeResp = handleRangeRequest(bodyUint8, rangeHeader, newETag, filePath, trace);
        if (rangeResp) return rangeResp;
      }

      // Serve the file (fresh, uncompressed)
      return await makeFileResponse(request, bodyUint8, false, Object.assign({}, headersExtra, { ETag: newETag, "Accept-Ranges": "bytes" }), trace);

    } catch (err) {
      console.error("Unhandled error:", err);
      trace.push("internal-error");
      return respondText("Internal Server Error", 500, trace);
    }
  },

  // Cron pre-warm
  async scheduled(event, env, ctx) {
    // fire-and-forget prefetches
    for (const [pkg, ver, file] of POPULAR_PACKAGES) {
      // encode package name for scoped packages
      const uPkg = encodeURIComponent(pkg);
      const url = `https://npdn.kyrt.my.id/npm/${uPkg}@${ver}/${file}`;
      ctx.waitUntil(fetch(url)); // warm the cache
    }
  }
};

/* -------------------------
   Helpers: package base
--------------------------*/
function getPkgBase(pkgName) {
  if (pkgName.startsWith("@")) {
    const parts = pkgName.split("/");
    return parts[1] || pkgName.replace("@", "");
  }
  return pkgName;
}

/* ------------------------------------------------------
   TAR PARSER (simple)
------------------------------------------------------ */
function untar(bytes) {
  const files = [];
  let offset = 0;

  while (offset + 512 <= bytes.length) {
    const name = readStr(bytes, offset, 100).replace(/\0.*$/, "");
    if (!name) break;

    const sizeOct = readStr(bytes, offset + 124, 12).replace(/\0.*$/, "");
    const size = parseInt(sizeOct.trim() || "0", 8);

    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    if (dataEnd > bytes.length) break;

    const data = bytes.slice(dataStart, dataEnd);
    files.push({ name, data });

    offset = dataStart + Math.ceil(size / 512) * 512;
  }

  return files;
}

function readStr(bytes, start, len) {
  return new TextDecoder().decode(bytes.slice(start, start + len));
}

/* ------------------------------------------------------
   STREAM → Uint8Array
------------------------------------------------------ */
async function streamToUint8Array(stream) {
  const reader = stream.getReader();
  const chunks = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.length;
  }

  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

/* ------------------------------------------------------
   MIME detection
------------------------------------------------------ */
function mimeTypeForPath(path) {
  const ext = (path || "").split(".").pop().toLowerCase();
  const map = {
    js: "application/javascript",
    mjs: "application/javascript",
    cjs: "application/javascript",
    map: "application/json",
    json: "application/json",
    css: "text/css",
    html: "text/html",
    htm: "text/html",
    svg: "image/svg+xml",
    png: "image/png",
    jpg: "image/jpeg",
    jpeg: "image/jpeg",
    gif: "image/gif",
    webp: "image/webp",
    avif: "image/avif",
    ico: "image/x-icon",
    txt: "text/plain",
    xml: "application/xml",
    wasm: "application/wasm",
    csv: "text/csv",
    ttf: "font/ttf",
    otf: "font/otf",
    woff: "font/woff",
    woff2: "font/woff2",
    eot: "application/vnd.ms-fontobject",
    mp3: "audio/mpeg",
    mp4: "video/mp4",
    ts: "text/typescript",
    zs: "text/zoroonscript",
  };
  return map[ext] || "application/octet-stream";
}

/* ------------------------------------------------------
   SRI (sha512) helper -> returns 'sha512-<base64>'
------------------------------------------------------ */
async function computeSRI(arrayBuffer) {
  const hashBuffer = await crypto.subtle.digest("SHA-512", arrayBuffer);
  const b64 = arrayBufferToBase64(hashBuffer);
  return `sha512-${b64}`;
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

/* ------------------------------------------------------
   ETag (sha256 hex)
------------------------------------------------------ */
async function computeETag(arrayBufferOrView) {
  let buffer;
  if (arrayBufferOrView instanceof ArrayBuffer) buffer = arrayBufferOrView;
  else if (arrayBufferOrView.buffer) buffer = arrayBufferOrView.buffer;
  else buffer = arrayBufferOrView;
  const hash = await crypto.subtle.digest("SHA-256", buffer);
  const hex = bufferToHex(hash);
  return `"${hex}"`;
}

function bufferToHex(buf) {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    s += (bytes[i] + 0x100).toString(16).substr(1);
  }
  return s;
}

/* ------------------------------------------------------
   Compare ETags (support multiple ETags)
------------------------------------------------------ */
function compareEtags(ifNoneHeader, actualEtag) {
  const list = ifNoneHeader.split(",").map(s => s.trim());
  return list.some(item => item === actualEtag || item.replace(/^W\//, "") === actualEtag);
}

/* ------------------------------------------------------
   Range request handling (single-range)
------------------------------------------------------ */
function handleRangeRequest(uint8arr, rangeHeader, etag, path, trace = []) {
  const m = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader);
  if (!m) return null;
  const total = uint8arr.byteLength;
  let start = m[1] === "" ? null : parseInt(m[1], 10);
  let end = m[2] === "" ? null : parseInt(m[2], 10);

  if (start === null && end === null) return null;

  if (start === null) {
    const suffixLen = end;
    if (suffixLen <= 0) return null;
    start = Math.max(0, total - suffixLen);
    end = total - 1;
  } else if (end === null) {
    end = total - 1;
  }

  if (isNaN(start) || isNaN(end) || start > end || start < 0 || end >= total) {
    const headers = new Headers();
    headers.set("Content-Range", `bytes */${total}`);
    headers.set("Accept-Ranges", "bytes");
    headers.set("Access-Control-Allow-Origin", "*");
    headers.set("X-CDN-Trace", trace.concat(["range-416"]).join(";"));
    return new Response(null, { status: 416, headers });
  }

  const chunk = uint8arr.slice(start, end + 1);
  const headers = new Headers();
  headers.set("Content-Type", mimeTypeForPath(path));
  headers.set("Content-Length", String(chunk.byteLength));
  headers.set("Content-Range", `bytes ${start}-${end}/${total}`);
  headers.set("Accept-Ranges", "bytes");
  headers.set("Cache-Control", "public, max-age=31536000, immutable");
  headers.set("ETag", etag);
  headers.set("X-Partial-Content", "true");
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("X-CDN-Trace", trace.concat(["range-206"]).join(";"));

  return new Response(chunk, { status: 206, headers });
}

/* ------------------------------------------------------
   MIME + HEADERS -> RESPONSE (NO gzip)
   Always serve uncompressed with Content-Length.
------------------------------------------------------ */
async function makeFileResponse(request, dataOrUint8, cached = false, extraHeaders = {}, trace = []) {
  const h = new Headers();
  h.set("Access-Control-Allow-Origin", "*");

  // If caller passed data as (request, data, path, ...) previously, we updated signature above.
  // For safety accept Uint8Array or ArrayBufferView or plain ArrayBuffer.
  const bodyUint8 = dataOrUint8 instanceof Uint8Array ? dataOrUint8 : new Uint8Array(dataOrUint8);

  // set Content-Type if provided in extraHeaders or try to deduce from ETag path not available here.
  if (extraHeaders["Content-Type"]) {
    h.set("Content-Type", extraHeaders["Content-Type"]);
    delete extraHeaders["Content-Type"];
  } else {
    // If a request had a path, most call-sites set Content-Type earlier. Fallback to octet-stream.
    h.set("Content-Type", "application/octet-stream");
  }

  h.set("Cache-Control", "public, max-age=31536000, immutable");
  h.set("X-Cache", cached ? "HIT" : "MISS");
  h.set("Accept-Ranges", "bytes");

  for (const k in extraHeaders) h.set(k, extraHeaders[k]);

  h.set("Content-Length", String(bodyUint8.byteLength));
  h.set("X-CDN-Trace", trace.join(";"));

  return new Response(bodyUint8, { status: 200, headers: h });
}

/* ------------------------------------------------------
   JSON / TEXT helpers
------------------------------------------------------ */
function jsonResponse(obj, extraHeaders = {}) {
  const h = new Headers();
  h.set("Content-Type", "application/json");
  h.set("Access-Control-Allow-Origin", "*");
  for (const k in extraHeaders) h.set(k, extraHeaders[k]);
  return new Response(JSON.stringify(obj), { status: 200, headers: h });
}

function respondText(text, status = 200, trace = []) {
  const h = new Headers();
  h.set("Content-Type", "text/plain; charset=utf-8");
  h.set("Access-Control-Allow-Origin", "*");
  h.set("X-CDN-Trace", trace.join(";"));
  return new Response(text, { status, headers: h });
}
