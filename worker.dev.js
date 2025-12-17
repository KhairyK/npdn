/**  
 * NPDN Worker v2.2 — Weak ETag + Smart Redirect + ?meta=1 + Edge Cache + Trace Headers  
 * Bindings required: NPM_CACHE (KV Namespace), BASE_ORIGIN optional
 */  

const PREWARM_PACKAGES = [
  "react@latest/index.js",
  "react@latest/jsx-runtime.js",
  "vue@latest/dist/vue.esm-browser.js",
  "lodash@latest/lodash.min.js",
  "axios@latest/dist/axios.min.js",
  "bootstrap@latest/dist/css/bootstrap.min.css",
  "bootstrap@latest/dist/js/bootstrap.bundle.min.js"
];

const WEAK_ETAG_THRESHOLD = 2 * 1024 * 1024; // 2MB -> use weak ETag for >= this

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const wantTrace = url.searchParams.has("trace") || request.headers.get("X-NPDN-Trace") === "1";
    const wantMeta = url.searchParams.has("meta");
    const wantIntegrityParam = url.searchParams.get("integrity"); // 'all' or presence
    const wantIntegrityJson = url.searchParams.has("integrity") && wantIntegrityParam !== "all";
    const wantIntegrityAll = url.searchParams.has("integrity") && wantIntegrityParam === "all";

    // Basic route guard
    if (!url.pathname.startsWith("/npm/")) {
      return new Response("Use: /npm/<pkg>@<ver>/<file>", { status: 400 });
    }

    // normalize incoming path after /npm/
    const clean = url.pathname.replace("/npm/", "").replace(/^\/+|\/+$/g, "");
    // Smart-root shortcut: if user hit /npm/<pkg> (no @) treat as pkg + tag latest
    let pkgWithVer = null;
    let rawFilePath = "";
    if (!clean.includes("@") && clean !== "") {
      // e.g. "react" -> we'll auto-resolve to latest and redirect to entry
      pkgWithVer = `${clean}@latest`;
    } else {
      pkgWithVer = clean.split("/")[0] || "";
      rawFilePath = clean.split("/").slice(1).join("/");
    }

    // if there are extra path segments when user passed pkg@ver/..., override rawFilePath
    if (clean.includes("@") && clean.split("/").length > 1) {
      rawFilePath = clean.split("/").slice(1).join("/");
    }

    // allow user to call /npm/react (no filePath) — handled by redirect later
    const atIndex = pkgWithVer.lastIndexOf("@");
    if (atIndex <= 0) {
      return new Response("Invalid package@version format", { status: 400 });
    }

    let pkgName = pkgWithVer.slice(0, atIndex);
    let pkgVer = pkgWithVer.slice(atIndex + 1);
    let filePath = rawFilePath; // may be empty for manifest/root

    // sanitize
    if (filePath) {
      try {
        filePath = decodeURIComponent(filePath).replace(/^\.\/+/, "").replace(/\\/g, "/");
      } catch (e) {
        return new Response("Bad request (invalid percent-encoding)", { status: 400 });
      }
      if (filePath.includes("..")) return new Response("Forbidden path", { status: 403 });
    }

    const isMapRequest = filePath.endsWith(".map");

    // KV key helpers
    const KV_FILE_KEY_BASE = `${pkgName}@${pkgVer}`;
    const KV_FILE_KEY = `${KV_FILE_KEY_BASE}/${filePath}`;
    const KV_MANIFEST_KEY = `${KV_FILE_KEY_BASE}::integrity-manifest`;
    const KV_META_KEY = `${pkgName}::meta`;
    const KV_CANONICAL_KEY = `${pkgName}@${pkgVer}::resolved`;

    // trace state
    let trace = {
      edge: "MISS",
      kv: "MISS",
      registry: "MISS",
      resolvedVersion: null,
      resolvedEntry: null,
      manifestCached: false
    };

    // ---------- HEAD short-circuit (with edge + KV check) ----------
    if (request.method === "HEAD") {
      // if manifest HEAD (integrity=all)
      if (wantIntegrityAll && !filePath) {
        const manifestText = await env.NPM_CACHE.get(KV_MANIFEST_KEY);
        const headers = new Headers();
        headers.set("Content-Type", "application/json");
        headers.set("Access-Control-Allow-Origin", "*");
        headers.set("X-Manifest-Cached", manifestText ? "true" : "false");
        if (wantTrace) {
          headers.set("X-NPDN-Edge", "HEAD");
          headers.set("X-NPDN-KV", manifestText ? "HIT" : "MISS");
        }
        return new Response(null, { status: 200, headers });
      }

      // file HEAD -> check edge cache first
      if (filePath) {
        // edge
        const cacheKey = new Request(request.url);
        const edgeResp = await caches.default.match(cacheKey);
        const headers = new Headers();
        headers.set("Access-Control-Allow-Origin", "*");
        headers.set("Content-Type", mimeTypeForPath(filePath));
        headers.set("Cache-Control", "public, max-age=31536000, immutable");
        headers.set("Accept-Ranges", "bytes");

        if (edgeResp) {
          trace.edge = "HIT";
          // If cached, attempt to read ETag from cached headers (if present)
          const cachedETag = edgeResp.headers.get("ETag");
          if (cachedETag) headers.set("ETag", cachedETag);
          headers.set("X-Cache", "HIT");
          if (wantTrace) {
            headers.set("X-NPDN-Edge", "HIT");
            headers.set("X-NPDN-KV", "N/A");
          }
          return new Response(null, { status: 200, headers });
        }

        // fallback to KV-only check (no registry fetch)
        try {
          const cached = await env.NPM_CACHE.get(KV_FILE_KEY, "arrayBuffer");
          if (cached) {
            trace.kv = "HIT";
            const etag = await computeETag(cached);
            headers.set("ETag", etag);
            headers.set("X-Cache", "HIT");
            if (wantTrace) {
              headers.set("X-NPDN-Edge", "MISS");
              headers.set("X-NPDN-KV", "HIT");
            }
          } else {
            headers.set("X-Cache", "MISS");
            if (wantTrace) {
              headers.set("X-NPDN-Edge", "MISS");
              headers.set("X-NPDN-KV", "MISS");
            }
          }
        } catch (e) {
          headers.set("X-Cache", "MISS");
        }
        return new Response(null, { status: 200, headers });
      }

      // HEAD to package root (no file)
      return new Response(null, { status: 200, headers: { "Access-Control-Allow-Origin": "*" } });
    }

    // ---------- Attempt to pick canonical resolved from KV (avoid registry) ----------
    let resolvedVersion = null;
    let needRegistryResolve = true;
    try {
      const cachedResolved = await env.NPM_CACHE.get(KV_CANONICAL_KEY);
      if (cachedResolved) {
        resolvedVersion = cachedResolved;
        needRegistryResolve = false;
        trace.kv = "HIT";
      }
    } catch (e) {
      // ignore
    }

    // ---------- Registry metadata (with KV caching) ----------
    let versionMeta = null;
    let metadata = null;
    const encodedPkg = encodeURIComponent(pkgName);
    const registryUrl = `https://registry.npmjs.org/${encodedPkg}`;

    if (needRegistryResolve) {
      // Try meta KV first
      try {
        const metaText = await env.NPM_CACHE.get(KV_META_KEY);
        if (metaText) {
          metadata = JSON.parse(metaText);
          trace.kv = trace.kv === "HIT" ? "HIT" : "HIT";
        } else {
          const metaRes = await fetch(registryUrl);
          if (!metaRes.ok) return new Response("Package not found on registry", { status: 404 });
          metadata = await metaRes.json();
          try {
            await env.NPM_CACHE.put(KV_META_KEY, JSON.stringify(metadata), { expirationTtl: 60 * 60 * 6 }); // 6h
          } catch (e) { /* ignore */ }
          trace.registry = "HIT";
        }
      } catch (err) {
        return new Response("Failed to fetch registry metadata", { status: 502 });
      }

      const distTags = metadata["dist-tags"] || {};
      resolvedVersion = distTags[pkgVer] || pkgVer;

      // fallback to latest if missing
      if (!metadata.versions || !metadata.versions[resolvedVersion]) {
        if (distTags.latest) resolvedVersion = distTags.latest;
        if (!metadata.versions || !metadata.versions[resolvedVersion]) {
          return new Response("Version not found", { status: 404 });
        }
      }

      // store resolved mapping
      try {
        await env.NPM_CACHE.put(KV_CANONICAL_KEY, resolvedVersion, { expirationTtl: 60 * 60 * 24 }); // 24h
      } catch (e) { /* ignore */ }

      versionMeta = metadata.versions[resolvedVersion];
      trace.resolvedVersion = resolvedVersion;
    } else {
      // canonical was present -> try to use meta if present, otherwise fetch registry (rare)
      let metadataText = await env.NPM_CACHE.get(KV_META_KEY);
      metadata = metadataText ? JSON.parse(metadataText) : null;
      if (!metadata || !metadata.versions || !metadata.versions[resolvedVersion]) {
        try {
          const metaRes = await fetch(registryUrl);
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
      trace.resolvedVersion = resolvedVersion;
      trace.registry = "MISS"; // we avoided registry fetch by using cached canonical/meta
    }

    // ---------- ?meta=1 endpoint (lightweight) ----------
    if (wantMeta && !filePath) {
      // prefer cached metadata
      const metaOut = {
        name: metadata.name,
        requested: pkgVer,
        resolved: resolvedVersion,
        dist: (versionMeta && versionMeta.dist) || null,
        exportsEntry: versionMeta && (versionMeta.exports || versionMeta.module || versionMeta.main || null)
      };
      const headers = new Headers();
      headers.set("Content-Type", "application/json");
      headers.set("Access-Control-Allow-Origin", "*");
      headers.set("X-NPDN-Resolved-Version", resolvedVersion || "");
      if (wantTrace) {
        headers.set("X-NPDN-Registry", trace.registry || "HIT");
        headers.set("X-NPDN-KV", trace.kv || "HIT");
      }
      return new Response(JSON.stringify(metaOut), { status: 200, headers });
    }

    // ---------- Smart entry auto-redirect (when user hit /npm/<pkg> or /npm/<pkg>@<ver> with no file) ----------
    if (!filePath && !wantIntegrityAll) {
      let entry =
        (versionMeta && versionMeta.exports && versionMeta.exports["."]) ||
        (versionMeta && versionMeta.module) ||
        (versionMeta && versionMeta.browser) ||
        (versionMeta && versionMeta.main) ||
        "index.js";

      // exports can be object
      if (typeof entry === "object") {
        // prefer import or browser or default
        entry = entry.import || entry.browser || entry.default || Object.values(entry)[0];
      }
      if (typeof entry !== "string") entry = "index.js";
      entry = entry.replace(/^\.?\//, "");

      trace.resolvedEntry = entry;
      const target = `/npm/${pkgName}@${resolvedVersion}/${entry}`;
      const headers = new Headers();
      headers.set("Cache-Control", "public, max-age=3600"); // short control for redirects
      if (wantTrace) {
        headers.set("X-NPDN-Resolved-Version", resolvedVersion);
        headers.set("X-NPDN-Entry", entry);
        headers.set("X-NPDN-Registry", trace.registry || "HIT");
        headers.set("X-NPDN-KV", trace.kv || "HIT");
      }
      return Response.redirect(target, 302);
    }

    // ---------- build tarball URL ----------
    const tarballUrl =
      (versionMeta && versionMeta.dist && versionMeta.dist.tarball) ||
      `https://registry.npmjs.org/${encodedPkg}/-/${encodeURIComponent(getPkgBase(pkgName))}-${resolvedVersion}.tgz`;
    if (!tarballUrl) return new Response("Tarball URL not found", { status: 502 });

    // ---------- integrity=all manifest (heavy path) ----------
    if (wantIntegrityAll && !filePath) {
      // Try cached manifest first
      const cachedManifest = await env.NPM_CACHE.get(KV_MANIFEST_KEY);
      if (cachedManifest) {
        trace.manifestCached = true;
        const headers = new Headers();
        headers.set("Content-Type", "application/json");
        headers.set("Access-Control-Allow-Origin", "*");
        headers.set("X-Manifest-Cached", "true");
        if (wantTrace) {
          headers.set("X-NPDN-Resolved-Version", resolvedVersion);
          headers.set("X-NPDN-KV", "HIT");
        }
        return new Response(cachedManifest, { status: 200, headers });
      }

      // fetch tarball & build manifest (this is heavy)
      let tarRes;
      try {
        tarRes = await fetch(tarballUrl);
        if (!tarRes.ok) return new Response("Tarball not found on npm", { status: 404 });
      } catch (err) {
        return new Response("Failed fetching tarball", { status: 502 });
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
          return new Response("Failed to read tarball bytes", { status: 502 });
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
        await env.NPM_CACHE.put(KV_MANIFEST_KEY, JSON.stringify(manifest), { expirationTtl: 60 * 60 * 24 * 30 }); // 30 days
      } catch (e) {
        console.warn("KV manifest put failed:", e);
      }

      const headers = new Headers();
      headers.set("Content-Type", "application/json");
      headers.set("Access-Control-Allow-Origin", "*");
      headers.set("X-Manifest-Cached", "false");
      if (wantTrace) {
        headers.set("X-NPDN-Resolved-Version", resolvedVersion);
        headers.set("X-NPDN-Registry", "HIT");
      }
      return new Response(JSON.stringify(manifest), { status: 200, headers });
    }

    // ---------- GET flows: Check Edge cache first (not for .map maybe) ----------
    const cacheKey = new Request(request.url);
    if (request.method === "GET" && !isMapRequest) {
      const edgeResp = await caches.default.match(cacheKey);
      if (edgeResp) {
        trace.edge = "HIT";
        // clone and add trace headers if requested
        const cloned = edgeResp.clone();
        const mergedHeaders = new Headers(cloned.headers);
        mergedHeaders.set("X-Cache", "HIT");
        mergedHeaders.set("Access-Control-Allow-Origin", "*");
        if (wantTrace) {
          mergedHeaders.set("X-NPDN-Edge", "HIT");
          mergedHeaders.set("X-NPDN-KV", trace.kv || "MISS");
          mergedHeaders.set("X-NPDN-Registry", trace.registry || "MISS");
          mergedHeaders.set("X-NPDN-Resolved-Version", resolvedVersion || "");
          if (trace.resolvedEntry) mergedHeaders.set("X-NPDN-Entry", trace.resolvedEntry);
        }
        const body = await cloned.arrayBuffer();
        return new Response(body, { status: cloned.status, headers: mergedHeaders });
      }
    }

    // ---------- Check KV cache for the requested file (skip for .map) ----------
    if (!isMapRequest) {
      try {
        const cachedArrayBuffer = await env.NPM_CACHE.get(KV_FILE_KEY, "arrayBuffer");
        if (cachedArrayBuffer) {
          trace.kv = "HIT";
          const cachedUint8 = new Uint8Array(cachedArrayBuffer);

          // compute ETag (smart - weak for large)
          const cachedETag = await smartETag(cachedUint8.buffer, resolvedVersion, filePath);

          // handle If-None-Match
          const incomingIfNone = request.headers.get("If-None-Match");
          if (incomingIfNone && compareEtags(incomingIfNone, cachedETag)) {
            const headers304 = new Headers();
            headers304.set("ETag", cachedETag);
            headers304.set("Access-Control-Allow-Origin", "*");
            if (wantTrace) {
              headers304.set("X-NPDN-KV", "HIT");
              headers304.set("X-NPDN-Edge", "MISS");
            }
            return new Response(null, { status: 304, headers: headers304 });
          }

          // Range header
          const rangeHeader = request.headers.get("Range");
          if (rangeHeader) {
            const rangeResp = handleRangeRequest(cachedUint8, rangeHeader, cachedETag, filePath);
            if (rangeResp) {
              if (wantTrace) rangeResp.headers.set("X-NPDN-KV", "HIT");
              return rangeResp;
            }
          }

          if (wantIntegrityJson) {
            const integrity = await computeSRI(cachedUint8.buffer);
            const mime = mimeTypeForPath(filePath);
            return jsonResponse({
              url: request.url,
              integrity,
              size: cachedUint8.byteLength,
              mime,
              cached: true,
            }, wantTrace ? { "X-NPDN-KV": "HIT", "X-NPDN-Resolved-Version": resolvedVersion } : {});
          }

          // final response (from KV) - but also put into edge cache for faster subsequent hits
          const res = makeFileResponse(cachedUint8, filePath, true, { ETag: cachedETag, "Accept-Ranges": "bytes" });
          // store in edge cache asynchronously
          ctx.waitUntil((async () => {
            try {
              await caches.default.put(cacheKey, res.clone());
            } catch (e) {}
          })());
          if (wantTrace) {
            res.headers.set("X-NPDN-KV", "HIT");
            res.headers.set("X-NPDN-Edge", "MISS");
            res.headers.set("X-NPDN-Resolved-Version", resolvedVersion || "");
          }
          return res;
        }
      } catch (e) {
        // KV read error -> continue to tarball fetch
      }
    }

    // ---------- Cache MISS -> fetch tarball and extract target ----------
    let tarRes;
    try {
      tarRes = await fetch(tarballUrl);
      if (!tarRes.ok) return new Response("Tarball not found on npm", { status: 404 });
      trace.registry = "HIT";
    } catch (err) {
      return new Response("Failed fetching tarball", { status: 502 });
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
        return new Response("Failed to read tarball bytes", { status: 502 });
      }
    }

    const files = untar(tarBytes);

    function normalizeName(name) {
      return name.replace(/^package\//, "");
    }

    // .map handling: serve directly (not cached)
    if (isMapRequest) {
      const targetMap = files.find((f) => normalizeName(f.name) === filePath);
      if (!targetMap) return new Response(`.map file not found: ${filePath}`, { status: 404 });
      const bodyUint8 = targetMap.data instanceof Uint8Array ? targetMap.data : new Uint8Array(targetMap.data);
      if (wantIntegrityJson) {
        const integrity = await computeSRI(bodyUint8.buffer);
        const mime = mimeTypeForPath(filePath);
        return jsonResponse({
          url: request.url,
          integrity,
          size: bodyUint8.byteLength,
          mime,
          cached: false,
        }, wantTrace ? { "X-NPDN-Registry": "HIT", "X-NPDN-Resolved-Version": resolvedVersion } : {});
      }
      // return but do not put into KV
      const res = makeFileResponse(bodyUint8, filePath, false);
      if (wantTrace) {
        res.headers.set("X-NPDN-Registry", "HIT");
        res.headers.set("X-NPDN-Resolved-Version", resolvedVersion || "");
      }
      // cache to edge for quicker subsequent GETs
      ctx.waitUntil((async () => {
        try { await caches.default.put(cacheKey, res.clone()); } catch (e) {}
      })());
      return res;
    }

    const target = files.find((f) => normalizeName(f.name) === filePath);
    if (!target) {
      const possibleMap = files.find((f) => normalizeName(f.name) === filePath + ".map");
      if (possibleMap) {
        return jsonResponse({
          error: "Requested file not found, but a sourcemap exists",
          sourcemap: `/npm/${pkgName}@${resolvedVersion}/${filePath}.map`,
        }, wantTrace ? { "X-NPDN-Registry": "HIT" } : {});
      }
      return new Response(`File not found in tarball: ${filePath}`, { status: 404 });
    }

    // Save file to KV (best-effort but skip if too big)
    const bodyUint8 = target.data instanceof Uint8Array ? target.data : new Uint8Array(target.data);
    try {
      if (bodyUint8.byteLength <= 25 * 1024 * 1024) { // KV limit guard
        await env.NPM_CACHE.put(KV_FILE_KEY, bodyUint8, { expirationTtl: 60 * 60 * 24 * 365 }); // 1 year
        trace.kv = "PUT";
      } else {
        trace.kv = "SKIP-LARGE";
      }
    } catch (err) {
      console.warn("KV put failed:", err);
    }

    // expose sourcemap route if present in tarball
    const mapCandidate = files.find((f) => normalizeName(f.name) === filePath + ".map");
    const headersExtra = {};
    if (mapCandidate) {
      headersExtra["X-Sourcemap-URL"] = `/npm/${pkgName}@${resolvedVersion}/${filePath}.map`;
    }

    // compute smart ETag
    const newETag = await smartETag(bodyUint8.buffer, resolvedVersion, filePath);

    // integrity JSON support
    if (wantIntegrityJson) {
      const integrity = await computeSRI(bodyUint8.buffer);
      const mime = mimeTypeForPath(filePath);
      return jsonResponse({
        url: request.url,
        integrity,
        size: bodyUint8.byteLength,
        mime,
        cached: false,
      }, wantTrace ? { "X-NPDN-Registry": "HIT", "X-NPDN-Resolved-Version": resolvedVersion } : {});
    }

    // If-None-Match immediate support
    const incomingIfNoneMatch = request.headers.get("If-None-Match");
    if (incomingIfNoneMatch && compareEtags(incomingIfNoneMatch, newETag)) {
      const headers304 = new Headers();
      headers304.set("ETag", newETag);
      headers304.set("Access-Control-Allow-Origin", "*");
      if (wantTrace) {
        headers304.set("X-NPDN-Registry", "HIT");
        headers304.set("X-NPDN-KV", trace.kv || "MISS");
        headers304.set("X-NPDN-Edge", "MISS");
        headers304.set("X-NPDN-Resolved-Version", resolvedVersion || "");
      }
      return new Response(null, { status: 304, headers: headers304 });
    }

    // handle Range header
    const rangeHeader = request.headers.get("Range");
    if (rangeHeader) {
      const rangeResp = handleRangeRequest(bodyUint8, rangeHeader, newETag, filePath);
      if (rangeResp) {
        if (wantTrace) rangeResp.headers.set("X-NPDN-Registry", "HIT");
        return rangeResp;
      }
    }

    // final response
    const finalRes = makeFileResponse(bodyUint8, filePath, false, Object.assign({}, headersExtra, { ETag: newETag, "Accept-Ranges": "bytes" }));
    if (wantTrace) {
      finalRes.headers.set("X-NPDN-Registry", "HIT");
      finalRes.headers.set("X-NPDN-KV", trace.kv || "MISS");
      finalRes.headers.set("X-NPDN-Edge", "MISS");
      finalRes.headers.set("X-NPDN-Resolved-Version", resolvedVersion || "");
      if (trace.resolvedEntry) finalRes.headers.set("X-NPDN-Entry", trace.resolvedEntry);
    }

    // store to edge cache for fast next hits
    ctx.waitUntil((async () => {
      try {
        await caches.default.put(cacheKey, finalRes.clone());
      } catch (e) {}
    })());

    return finalRes;
  },

  // Scheduled pre-warm (cron)
  async scheduled(controller, env, ctx) {
    const base = env.BASE_ORIGIN || "https://npdn.kyrt.my.id";
    const fetches = PREWARM_PACKAGES.map((p) => {
      const url = `${base}/npm/${p}`;
      return fetch(url, { method: "HEAD" }).catch((e) => { console.warn("Prewarm failed:", url, e); return null; });
    });
    await Promise.all(fetches);
  },
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
   TAR PARSER (simple, works for typical npm tgz outputs)
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
   ETag (sha256 hex) + smart weak ETag
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

// simple non-crypto hash for weak etag generation (fast)
function simpleHash(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = (h << 5) - h + str.charCodeAt(i);
    h |= 0;
  }
  return Math.abs(h).toString(16);
}
function makeWeakETag(size, version, path) {
  const base = `${size}:${version || "?"}:${path || "?"}`;
  return `W/"${simpleHash(base)}"`;
}

// smartETag: choose strong or weak based on threshold
async function smartETag(buffer, version, path) {
  const size = buffer.byteLength || buffer.length || 0;
  if (size >= WEAK_ETAG_THRESHOLD) {
    return makeWeakETag(size, version, path);
  }
  return computeETag(buffer);
}

/* ------------------------------------------------------
   Compare ETags (support multiple ETags in If-None-Match)
------------------------------------------------------ */
function compareEtags(ifNoneHeader, actualEtag) {
  if (!ifNoneHeader || !actualEtag) return false;
  const list = ifNoneHeader.split(",").map((s) => s.trim());
  return list.some((item) => item === actualEtag || item.replace(/^W\//, "") === actualEtag);
}

/* ------------------------------------------------------
   Range request handling (single-range)
------------------------------------------------------ */
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
    headers.set("Access-Control-Allow-Origin", "*");
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
  return new Response(chunk, { status: 206, headers });
}

/* ------------------------------------------------------
   MIME + HEADERS -> RESPONSE
------------------------------------------------------ */
function makeFileResponse(data, path, cached = false, extraHeaders = {}) {
  const h = new Headers();
  h.set("Access-Control-Allow-Origin", "*");
  h.set("Content-Type", mimeTypeForPath(path));
  h.set("Cache-Control", "public, max-age=31536000, immutable");
  h.set("X-Cache", cached ? "HIT" : "MISS");
  h.set("Accept-Ranges", "bytes");
  h.set("Vary", "Accept-Encoding");
  for (const k in extraHeaders) h.set(k, extraHeaders[k]);
  const body = data instanceof Uint8Array ? data : new Uint8Array(data);
  return new Response(body, { status: 200, headers: h });
}

function jsonResponse(obj, extraHeaders = {}) {
  const h = new Headers();
  h.set("Content-Type", "application/json");
  h.set("Access-Control-Allow-Origin", "*");
  for (const k in extraHeaders) h.set(k, extraHeaders[k]);
  return new Response(JSON.stringify(obj), { status: 200, headers: h });
}
