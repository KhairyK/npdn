/**
 * NPDN Worker v2.2 — Ultra-Fast (with ULTRA_FAST, no-redirect, tarball-KV, lazy-untar)
 *
 * Requirements:
 *  - KV Namespace binding name: NPM_CACHE
 *
 * New behaviors:
 *  - ULTRA_FAST flag (set ULTRA_FAST_GLOBAL = true to force)
 *  - ?fast=true to bypass canonical 302 redirect and serve directly
 *  - Small tarball cache into KV (TAR_KV_MAX_BYTES)
 *  - Cache-Control tuned with s-maxage & stale-while-revalidate
 *  - Source maps skipped by default; serve only with ?sourcemap=1
 *  - Lazy untar: extract file until target found (no full untar unless manifest requested)
 */

const ULTRA_FAST_GLOBAL = true;
const TAR_KV_MAX_BYTES = 8 * 1024 * 1024; // 8 MB threshold for caching full tarball in KV
const PREWARM_PACKAGES = [
  "react@latest/index.js",
  "react@latest/jsx-runtime.js",
  "vue@latest/dist/vue.esm-browser.js",
  "lodash@latest/lodash.min.js",
  "axios@latest/dist/axios.min.js",
  "bootstrap@latest/dist/css/bootstrap.min.css",
  "bootstrap@latest/dist/js/bootstrap.bundle.min.js",
];

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // quick guard
    if (!url.pathname.startsWith("/npm/")) {
      return new Response("Use: /npm/<pkg>@<ver>/<file>", { status: 400 });
    }

    const clean = url.pathname.replace("/npm/", "").replace(/^\/+|\/+$/g, "");
    const [pkgWithVer, ...rest] = clean.split("/");
    const atIndex = pkgWithVer.lastIndexOf("@");
    if (atIndex <= 0) return new Response("Invalid package@version format", { status: 400 });

    const pkgName = pkgWithVer.slice(0, atIndex);
    let pkgVer = pkgWithVer.slice(atIndex + 1);
    let rawFilePath = rest.join("/"); // may be empty (manifest or root)
    const qsFast = url.searchParams.get("fast");
    const fastMode = ULTRA_FAST_GLOBAL || qsFast === "true"; // no-redirect if true
    const wantIntegrityParam = url.searchParams.get("integrity"); // can be 'all' or presence
    const wantIntegrityJson = url.searchParams.has("integrity") && wantIntegrityParam !== "all";
    const wantIntegrityAll = url.searchParams.has("integrity") && wantIntegrityParam === "all";
    const wantSourcemap = url.searchParams.get("sourcemap") === "1"; // serve maps only if ?sourcemap=1

    if (!pkgName || !pkgVer || (!rawFilePath && !wantIntegrityAll)) {
      return new Response(
        "Invalid format. Example: /npm/vue@3.3.4/dist/vue.esm.js or /npm/vue@3.3.4/?integrity=all",
        { status: 400 }
      );
    }

    // sanitize file path
    let filePath = "";
    if (rawFilePath) {
      try {
        filePath = decodeURIComponent(rawFilePath).replace(/^\.\/+/, "").replace(/\\/g, "/");
      } catch (e) {
        return new Response("Bad request (invalid percent-encoding)", { status: 400 });
      }
      if (filePath.includes("..")) return new Response("Forbidden path", { status: 403 });
    }

    // skip sourcemap by default
    if (filePath.endsWith(".map") && !wantSourcemap) {
      return new Response("Source maps are disabled by default. Add ?sourcemap=1 to request.", {
        status: 404,
        headers: { "X-Sourcemap-Skipped": "true", "Access-Control-Allow-Origin": "*" },
      });
    }

    const isMapRequest = filePath.endsWith(".map");

    // KV keys
    const KV_FILE_KEY = `${pkgName}@${pkgVer}/${filePath}`;
    const KV_MANIFEST_KEY = `${pkgName}@${pkgVer}::integrity-manifest`;
    const KV_META_KEY = `${pkgName}::meta`;
    const KV_CANONICAL_KEY = `${pkgName}@${pkgVer}::resolved`;
    const KV_TARBALL_KEY = `${pkgName}@${pkgVer}::tarball`;
    const KV_FILE_META_KEY = `${KV_FILE_KEY}::meta`;

    // HEAD short-circuit (KV-only, lightweight)
    if (request.method === "HEAD") {
      if (wantIntegrityAll && !filePath) {
        const manifestText = await env.NPM_CACHE.get(KV_MANIFEST_KEY);
        const headers = new Headers();
        headers.set("Content-Type", "application/json");
        setCors(headers);
        headers.set("X-Manifest-Cached", manifestText ? "true" : "false");
        return new Response(null, { status: 200, headers });
      }

      if (filePath) {
        const cached = await env.NPM_CACHE.get(KV_FILE_KEY, "arrayBuffer");
        const headers = new Headers();
        setCors(headers);
        headers.set("Content-Type", mimeTypeForPath(filePath));
        setCacheControl(headers, /*cached=*/ !!cached);
        headers.set("Accept-Ranges", "bytes");

        if (cached) {
          headers.set("X-Cache", "HIT");
          const etag = await computeETag(cached);
          headers.set("ETag", etag);
        } else {
          headers.set("X-Cache", "MISS");
        }
        return new Response(null, { status: 200, headers });
      }

      // root HEAD
      return new Response(null, { status: 200, headers: { "Access-Control-Allow-Origin": "*" } });
    }

    // Try canonical cache (avoid registry hits for tags)
    let resolvedVersion = null;
    let needRegistryResolve = true;

    const cachedResolved = await env.NPM_CACHE.get(KV_CANONICAL_KEY);
    if (cachedResolved) {
      resolvedVersion = cachedResolved;
      needRegistryResolve = false;
    }

    // Resolve registry metadata if needed
    let versionMeta = null;
    if (needRegistryResolve) {
      const encodedPkg = encodeURIComponent(pkgName);
      const registryUrl = `https://registry.npmjs.org/${encodedPkg}`;

      let metadata = null;
      try {
        const metaText = await env.NPM_CACHE.get(KV_META_KEY);
        if (metaText) {
          metadata = JSON.parse(metaText);
        } else {
          const metaRes = await fetch(registryUrl);
          if (!metaRes.ok) return new Response("Package not found on registry", { status: 404 });
          metadata = await metaRes.json();
          try {
            await env.NPM_CACHE.put(KV_META_KEY, JSON.stringify(metadata), {
              expirationTtl: 60 * 60 * 6,
            });
          } catch (e) {
            console.warn("KV meta put failed:", e);
          }
        }
      } catch (err) {
        return new Response("Failed to fetch registry metadata", { status: 502 });
      }

      const distTags = metadata["dist-tags"] || {};
      resolvedVersion = distTags[pkgVer] || pkgVer;

      if (!metadata.versions || !metadata.versions[resolvedVersion]) {
        if (distTags.latest) resolvedVersion = distTags.latest;
        if (!metadata.versions || !metadata.versions[resolvedVersion]) {
          return new Response("Version not found", { status: 404 });
        }
      }

      // store canonical
      try {
        await env.NPM_CACHE.put(KV_CANONICAL_KEY, resolvedVersion, { expirationTtl: 60 * 60 * 24 });
      } catch (e) {
        console.warn("KV canonical put failed:", e);
      }

      versionMeta = metadata.versions[resolvedVersion];
    } else {
      // canonical resolved present -> fetch metadata from KV or registry fallback
      let metadataText = await env.NPM_CACHE.get(KV_META_KEY);
      let metadata = metadataText ? JSON.parse(metadataText) : null;
      if (!metadata || !metadata.versions || !metadata.versions[resolvedVersion]) {
        try {
          const metaRes = await fetch(`https://registry.npmjs.org/${encodeURIComponent(pkgName)}`);
          if (!metaRes.ok) return new Response("Package not found on registry", { status: 404 });
          metadata = await metaRes.json();
          try {
            await env.NPM_CACHE.put(KV_META_KEY, JSON.stringify(metadata), { expirationTtl: 60 * 60 * 6 });
          } catch (e) {}
        } catch (e) {
          return new Response("Failed to fetch registry metadata", { status: 502 });
        }
      }
      versionMeta = metadata.versions && metadata.versions[resolvedVersion];
      if (!versionMeta) return new Response("Version not found", { status: 404 });
    }

    // If tag used and not fast-mode and not integrity=all -> redirect to canonical
    if (pkgVer !== resolvedVersion && !wantIntegrityAll && !fastMode) {
      const canonical = `/npm/${pkgName}@${resolvedVersion}/${filePath}`;
      return Response.redirect(canonical, 302);
    }

    // If in fastMode, we skip redirect but set header
    const canonicalHeader = { "X-Resolved-Version": resolvedVersion };

    // tarball URL (from versionMeta or fallback)
    const encodedPkg = encodeURIComponent(pkgName);
    const tarballUrl =
      (versionMeta && versionMeta.dist && versionMeta.dist.tarball) ||
      `https://registry.npmjs.org/${encodedPkg}/-/${encodeURIComponent(getPkgBase(pkgName))}-${resolvedVersion}.tgz`;
    if (!tarballUrl) return new Response("Tarball URL not found", { status: 502 });

    // Integrity manifest handling (needs full untar)
    if (wantIntegrityAll && !filePath) {
      const cachedManifest = await env.NPM_CACHE.get(KV_MANIFEST_KEY);
      if (cachedManifest) {
        return jsonResponse(JSON.parse(cachedManifest), Object.assign({}, canonicalHeader, { "X-Manifest-Cached": "true" }));
      }

      // fetch tarball (try KV tarball first)
      let tarBytes;
      const kvTar = await env.NPM_CACHE.get(KV_TARBALL_KEY, "arrayBuffer");
      if (kvTar) {
        tarBytes = new Uint8Array(kvTar);
      } else {
        let tarRes;
        try {
          tarRes = await fetch(tarballUrl);
          if (!tarRes.ok) return new Response("Tarball not found on npm", { status: 404 });
        } catch (err) {
          return new Response("Failed fetching tarball", { status: 502 });
        }

        try {
          const tarStream = tarRes.body.pipeThrough(new DecompressionStream("gzip"));
          tarBytes = await streamToUint8Array(tarStream);
        } catch (err) {
          try {
            const ab = await tarRes.arrayBuffer();
            tarBytes = new Uint8Array(ab);
          } catch (e) {
            return new Response("Failed to read tarball bytes", { status: 502 });
          }
        }

        // opportunistic tarball cache if small
        try {
          if (tarBytes.length <= TAR_KV_MAX_BYTES) {
            await env.NPM_CACHE.put(KV_TARBALL_KEY, tarBytes, { expirationTtl: 60 * 60 * 24 }); // 1 day
          }
        } catch (e) {
          console.warn("KV put tarball failed:", e);
        }
      }

      // full untar to build manifest
      const files = untar(tarBytes);
      const manifest = {};
      for (const f of files) {
        const name = normalizeName(f.name);
        if (!name) continue;
        const bodyUint8 = f.data instanceof Uint8Array ? f.data : new Uint8Array(f.data);
        if (bodyUint8.length === 0) continue;
        const integrity = await computeSRI(bodyUint8.buffer);
        manifest[name] = { integrity, size: bodyUint8.byteLength, mime: mimeTypeForPath(name) };
      }

      try {
        await env.NPM_CACHE.put(KV_MANIFEST_KEY, JSON.stringify(manifest), { expirationTtl: 60 * 60 * 24 * 30 });
      } catch (e) {
        console.warn("KV manifest put failed:", e);
      }

      return jsonResponse(manifest, Object.assign({}, canonicalHeader, { "X-Manifest-Cached": "false" }));
    }

    // file GET: check KV cached file (skip for maps if map is disabled by default)
    if (!isMapRequest) {
      const cachedArrayBuffer = await env.NPM_CACHE.get(KV_FILE_KEY, "arrayBuffer");
      if (cachedArrayBuffer) {
        const cachedUint8 = new Uint8Array(cachedArrayBuffer);

        // quick metadata check
        const metaText = await env.NPM_CACHE.get(KV_FILE_META_KEY);
        let cachedETag = null;
        if (metaText) {
          try {
            const metaObj = JSON.parse(metaText);
            cachedETag = metaObj.etag;
          } catch (e) {}
        } else {
          cachedETag = await computeETag(cachedUint8.buffer);
          // store meta best-effort
          try {
            await env.NPM_CACHE.put(KV_FILE_META_KEY, JSON.stringify({ etag: cachedETag }), { expirationTtl: 60 * 60 * 24 * 365 });
          } catch (e) {}
        }

        // If-None-Match
        const incomingIfNone = request.headers.get("If-None-Match");
        if (incomingIfNone && cachedETag && compareEtags(incomingIfNone, cachedETag)) {
          const headers304 = new Headers();
          headers304.set("ETag", cachedETag);
          setCors(headers304);
          return new Response(null, { status: 304, headers: headers304 });
        }

        // Range support
        const rangeHeader = request.headers.get("Range");
        if (rangeHeader) {
          const rangeResp = handleRangeRequest(cachedUint8, rangeHeader, cachedETag, filePath);
          if (rangeResp) return rangeResp;
        }

        if (wantIntegrityJson) {
          // compute or fetch integrity from meta
          let integrity = null;
          try {
            const metaText2 = await env.NPM_CACHE.get(KV_FILE_META_KEY);
            if (metaText2) {
              const m = JSON.parse(metaText2);
              if (m.integrity) integrity = m.integrity;
            }
            if (!integrity) {
              integrity = await computeSRI(cachedUint8.buffer);
              await env.NPM_CACHE.put(KV_FILE_META_KEY, JSON.stringify({ etag: cachedETag, integrity }), { expirationTtl: 60 * 60 * 24 * 365 });
            }
          } catch (e) {}
          const mime = mimeTypeForPath(filePath);
          return jsonResponse({ url: request.url, integrity, size: cachedUint8.byteLength, mime, cached: true }, canonicalHeader);
        }

        return makeFileResponse(cachedUint8, filePath, true, Object.assign({}, canonicalHeader, { ETag: cachedETag }));
      }
    }

    // Cache MISS: fetch tarball (prefer KV tarball if present)
    let tarBytes = null;
    const kvTarBytes = await env.NPM_CACHE.get(KV_TARBALL_KEY, "arrayBuffer");
    if (kvTarBytes) {
      tarBytes = new Uint8Array(kvTarBytes);
    } else {
      let tarRes;
      try {
        tarRes = await fetch(tarballUrl);
        if (!tarRes.ok) return new Response("Tarball not found on npm", { status: 404 });
      } catch (err) {
        return new Response("Failed fetching tarball", { status: 502 });
      }

      try {
        const tarStream = tarRes.body.pipeThrough(new DecompressionStream("gzip"));
        tarBytes = await streamToUint8Array(tarStream);
      } catch (err) {
        try {
          const ab = await tarRes.arrayBuffer();
          tarBytes = new Uint8Array(ab);
        } catch (e) {
          return new Response("Failed to read tarball bytes", { status: 502 });
        }
      }

      // opportunistic cache small tarballs
      try {
        if (tarBytes.length <= TAR_KV_MAX_BYTES) {
          await env.NPM_CACHE.put(KV_TARBALL_KEY, tarBytes, { expirationTtl: 60 * 60 * 24 });
        }
      } catch (e) {
        console.warn("KV put tarball failed:", e);
      }
    }

    // If this is a map request and maps allowed (we already gated maps earlier), handle directly (no caching)
    if (isMapRequest) {
      const mapData = extractFileFromTar(tarBytes, `package/${filePath}`);
      if (!mapData) return new Response(`.map file not found: ${filePath}`, { status: 404 });
      const bodyUint8 = mapData;
      if (wantIntegrityJson) {
        const integrity = await computeSRI(bodyUint8.buffer);
        const mime = mimeTypeForPath(filePath);
        return jsonResponse({ url: request.url, integrity, size: bodyUint8.byteLength, mime, cached: false }, canonicalHeader);
      }
      return makeFileResponse(bodyUint8, filePath, false, canonicalHeader);
    }

    // Lazy untar: look for target file and stop when found
    const targetData = extractFileFromTar(tarBytes, `package/${filePath}`);
    if (!targetData) {
      const possibleMap = extractFileFromTar(tarBytes, `package/${filePath}.map`);
      if (possibleMap) {
        return jsonResponse({
          error: "Requested file not found, but a sourcemap exists",
          sourcemap: `/npm/${pkgName}@${resolvedVersion}/${filePath}.map?sourcemap=1`,
        }, canonicalHeader);
      }
      return new Response(`File not found in tarball: ${filePath}`, { status: 404 });
    }

    // Save file to KV (best-effort) and save metadata (etag/integrity) for future zero-CPU hits
    const bodyUint8 = targetData instanceof Uint8Array ? targetData : new Uint8Array(targetData);
    const newETag = await computeETag(bodyUint8.buffer);
    try {
      await env.NPM_CACHE.put(KV_FILE_KEY, bodyUint8, { expirationTtl: 60 * 60 * 24 * 365 });
      // compute integrity but store separately to avoid blocking future hits; best-effort
      const integrity = await computeSRI(bodyUint8.buffer);
      await env.NPM_CACHE.put(KV_FILE_META_KEY, JSON.stringify({ etag: newETag, integrity, size: bodyUint8.byteLength, mime: mimeTypeForPath(filePath) }), { expirationTtl: 60 * 60 * 24 * 365 });
    } catch (err) {
      console.warn("KV put failed:", err);
    }

    // If client asked integrity JSON
    if (wantIntegrityJson) {
      const integrity = await computeSRI(bodyUint8.buffer);
      const mime = mimeTypeForPath(filePath);
      return jsonResponse({ url: request.url, integrity, size: bodyUint8.byteLength, mime, cached: false }, canonicalHeader);
    }

    // If-None-Match immediate support
    const incomingIfNoneMatch = request.headers.get("If-None-Match");
    if (incomingIfNoneMatch && compareEtags(incomingIfNoneMatch, newETag)) {
      const headers304 = new Headers();
      headers304.set("ETag", newETag);
      setCors(headers304);
      return new Response(null, { status: 304, headers: headers304 });
    }

    // Range handling
    const rangeHeader = request.headers.get("Range");
    if (rangeHeader) {
      const rangeResp = handleRangeRequest(bodyUint8, rangeHeader, newETag, filePath);
      if (rangeResp) return rangeResp;
    }

    // Final response (no redirect mode: include resolved header)
    return makeFileResponse(bodyUint8, filePath, false, Object.assign({}, canonicalHeader, { ETag: newETag }));
  },

  // Scheduled pre-warm (cron)
  async scheduled(controller, env, ctx) {
    const base = env.BASE_ORIGIN || "https://npdn.kyrt.my.id";
    const fetches = PREWARM_PACKAGES.map((p) => {
      const url = `${base}/npm/${p}?fast=1`; // use fast HEAD
      return fetch(url, { method: "HEAD" }).catch((e) => {
        console.warn("Prewarm failed:", url, e);
        return null;
      });
    });
    await Promise.all(fetches);
  },
};

/* -------------------------
   Helper utilities
   - lazy untar: extractFileFromTar
   - full untar (used for manifest)
--------------------------*/

function getPkgBase(pkgName) {
  if (pkgName.startsWith("@")) {
    const parts = pkgName.split("/");
    return parts[1] || pkgName.replace("@", "");
  }
  return pkgName;
}

function normalizeName(name) {
  return name.replace(/^package\//, "");
}

// full untar: returns array of {name, data}
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

// lazy extractor: scan tar headers until the target file is found; returns Uint8Array or null
function extractFileFromTar(bytes, targetEntryName) {
  let offset = 0;
  while (offset + 512 <= bytes.length) {
    const name = readStr(bytes, offset, 100).replace(/\0.*$/, "");
    if (!name) break;
    const sizeOct = readStr(bytes, offset + 124, 12).replace(/\0.*$/, "");
    const size = parseInt(sizeOct.trim() || "0", 8);
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    if (dataEnd > bytes.length) break;
    if (name === targetEntryName) {
      return bytes.slice(dataStart, dataEnd);
    }
    offset = dataStart + Math.ceil(size / 512) * 512;
  }
  return null;
}

function readStr(bytes, start, len) {
  return new TextDecoder().decode(bytes.slice(start, start + len));
}

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

/* MIME detection (same map) */
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

/* SRI (sha512) -> 'sha512-<base64>' */
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

/* ETag sha256 hex */
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

function compareEtags(ifNoneHeader, actualEtag) {
  const list = ifNoneHeader.split(",").map((s) => s.trim());
  return list.some((item) => item === actualEtag || item.replace(/^W\//, "") === actualEtag);
}

/* Range handler (single range) */
function handleRangeRequest(uint8arr, rangeHeader, etag, path) {
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
    setCors(headers);
    return new Response(null, { status: 416, headers });
  }
  const chunk = uint8arr.slice(start, end + 1);
  const headers = new Headers();
  headers.set("Content-Type", mimeTypeForPath(path));
  headers.set("Content-Length", String(chunk.byteLength));
  headers.set("Content-Range", `bytes ${start}-${end}/${total}`);
  headers.set("Accept-Ranges", "bytes");
  setCacheControl(headers, /*cached=*/ true);
  headers.set("ETag", etag);
  headers.set("X-Partial-Content", "true");
  setCors(headers);
  return new Response(chunk, { status: 206, headers });
}

/* Response builders */
function makeFileResponse(data, path, cached = false, extraHeaders = {}) {
  const h = new Headers();
  setCors(h);
  h.set("Content-Type", mimeTypeForPath(path));
  setCacheControl(h, cached);
  h.set("X-Cache", cached ? "HIT" : "MISS");
  h.set("Accept-Ranges", "bytes");
  for (const k in extraHeaders) h.set(k, extraHeaders[k]);
  const body = data instanceof Uint8Array ? data : new Uint8Array(data);
  return new Response(body, { status: 200, headers: h });
}
function jsonResponse(obj, extraHeaders = {}) {
  const h = new Headers();
  setCors(h);
  h.set("Content-Type", "application/json");
  for (const k in extraHeaders) h.set(k, extraHeaders[k]);
  return new Response(JSON.stringify(obj), { status: 200, headers: h });
}

/* Small helpers for headers */
function setCors(headers) {
  headers.set("Access-Control-Allow-Origin", "*");
}
function setCacheControl(headers, cached) {
  // tuned: long client TTL, and s-maxage (edge) + stale-while-revalidate to allow fast edge behavior
  if (cached) {
    headers.set("Cache-Control", "public, max-age=31536000, immutable, s-maxage=31536000, stale-while-revalidate=86400");
  } else {
    headers.set("Cache-Control", "public, max-age=60, s-maxage=86400, stale-while-revalidate=86400");
  }
}
