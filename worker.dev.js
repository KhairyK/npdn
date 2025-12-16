/**  
  * 2025 © OpenDN Foundation & My Academy Labs  
  * Powered By Cloudflare Worker's 'https://workers.cloudflare.com/'  
  * BASE URL: https://npdn.kyrt.my.id/npm/<pkg>@<ver>/<file>  
  * Now v2.0-BETA
  *  
  * Added:  
  *  - ETag support (SHA-256 hex)  
  *  - If-None-Match -> 304 handling  
  *  - Range requests (single range) -> 206 Partial Content  
  *  - Auto-generate integrity manifest: GET /npm/pkg@ver/?integrity=all  
  *  - .map handling: served directly (not cached)  
*/  
export default {  
  async fetch(request, env) {  
    const url = new URL(request.url);  
  
    // Route harus /npm/<pkg>@<ver>/<file> (file optional if doing integrity=all)  
    if (!url.pathname.startsWith("/npm/")) {  
      return new Response("Use: /npm/<pkg>@<ver>/<file>", { status: 400 });  
    }  
  
    // normalize and strip leading /npm/  
    const clean = url.pathname.replace("/npm/", "").replace(/^\/+|\/+$/g, "");  
    const [pkgWithVer, ...rest] = clean.split("/");  
    const atIndex = pkgWithVer.lastIndexOf("@");  
    if (atIndex <= 0) {  
      return new Response("Invalid package@version format", { status: 400 });  
    }  
  
    let pkgName = pkgWithVer.slice(0, atIndex);  
    let pkgVer = pkgWithVer.slice(atIndex + 1);  
    let rawFilePath = rest.join("/"); // may be empty for manifest  
  
    const wantIntegrityParam = url.searchParams.get("integrity"); // can be 'all' or just presence  
    const wantIntegrityJson = url.searchParams.has("integrity") && wantIntegrityParam !== "all";  
    const wantIntegrityAll = url.searchParams.has("integrity") && wantIntegrityParam === "all";  
  
    // Basic validations  
    if (!pkgName || !pkgVer || (!rawFilePath && !wantIntegrityAll)) {  
      return new Response(  
        "Invalid format. Example: /npm/vue@3.3.4/dist/vue.esm.js or /npm/vue@3.3.4/?integrity=all",  
        { status: 400 }  
      );  
    }  
  
    // decode and sanitize filePath (if present)  
    let filePath = "";  
    if (rawFilePath) {  
      try {  
        filePath = decodeURIComponent(rawFilePath)  
          .replace(/^\.\/+/, "") // remove leading ./  
          .replace(/\\/g, "/"); // normalize backslashes  
      } catch (e) {  
        return new Response("Bad request (invalid percent-encoding)", { status: 400 });  
      }  
      // block directory traversal  
      if (filePath.includes("..")) {  
        return new Response("Forbidden path", { status: 403 });  
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
        return new Response("Package not found on registry", { status: 404 });  
      }  
      metadata = await metaRes.json();  
    } catch (err) {  
      return new Response("Failed to fetch registry metadata", { status: 502 });  
    }  
  
    const distTags = metadata["dist-tags"] || {};  
    let resolvedVersion = distTags[pkgVer] || pkgVer;  
  
    // fallback to latest if missing  
    if (!metadata.versions || !metadata.versions[resolvedVersion]) {  
      if (distTags.latest) resolvedVersion = distTags.latest;  
      if (!metadata.versions || !metadata.versions[resolvedVersion]) {  
        return new Response("Version not found", { status: 404 });  
      }  
    }  
  
    // canonical redirect: if user used tag (like 'latest') -> redirect to concrete version  
    if (pkgVer !== resolvedVersion && !wantIntegrityAll) {  
      const canonical = `/npm/${pkgName}@${resolvedVersion}/${filePath}`;  
      return Response.redirect(canonical, 302);  
    }  
  
    // use tarball from metadata if available  
    const versionMeta = metadata.versions[resolvedVersion];  
    const tarballUrl =  
      (versionMeta && versionMeta.dist && versionMeta.dist.tarball) ||  
      `https://registry.npmjs.org/${encodedPkg}/-/${encodeURIComponent(getPkgBase(pkgName))}-${resolvedVersion}.tgz`;  
  
    if (!tarballUrl) {  
      return new Response("Tarball URL not found", { status: 502 });  
    }  
  
    // KV keys  
    const KV_FILE_KEY = `${pkgName}@${resolvedVersion}/${filePath}`;  
    const KV_MANIFEST_KEY = `${pkgName}@${resolvedVersion}::integrity-manifest`;  
  
    // support HEAD early return (we'll respond with headers only)  
    // but need to know if cached exists to set headers  
    if (request.method === "HEAD") {  
      // if manifest requested via HEAD -> check KV manifest  
      if (wantIntegrityAll) {  
        const manifestText = await env.NPM_CACHE.get(KV_MANIFEST_KEY);  
        const headers = new Headers();  
        headers.set("Content-Type", "application/json");  
        headers.set("Access-Control-Allow-Origin", "*");  
        headers.set("X-Manifest-Cached", manifestText ? "true" : "false");  
        return new Response(null, { status: 200, headers });  
      }  
  
      const cached = filePath ? await env.NPM_CACHE.get(KV_FILE_KEY, "arrayBuffer") : null;  
      const headers = new Headers();  
      headers.set("Access-Control-Allow-Origin", "*");  
      headers.set("Content-Type", filePath ? mimeTypeForPath(filePath) : "application/json");  
      headers.set("Cache-Control", "public, max-age=31536000, immutable");  
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
  
    // --------------------------------------------------  
    // If integrity=all requested for package root -> return/generate manifest  
    // --------------------------------------------------  
    if (wantIntegrityAll && !filePath) {  
      // Try cached manifest first  
      const cachedManifest = await env.NPM_CACHE.get(KV_MANIFEST_KEY);  
      if (cachedManifest) {  
        return jsonResponse(JSON.parse(cachedManifest), { "X-Manifest-Cached": "true" });  
      }  
  
      // Otherwise fetch tarball, build manifest  
      let tarRes;  
      try {  
        tarRes = await fetch(tarballUrl);  
        if (!tarRes.ok) {  
          return new Response("Tarball not found on npm", { status: 404 });  
        }  
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
      // compute SRI for each file and add mime+size (skip directories / empty names)  
      for (const f of files) {  
        const name = normalizeName(f.name);  
        if (!name) continue;  
        const bodyUint8 = f.data instanceof Uint8Array ? f.data : new Uint8Array(f.data);  
        // Only include real files (skip entries like package/ or directories)  
        if (bodyUint8.length === 0) continue;  
        const integrity = await computeSRI(bodyUint8.buffer);  
        manifest[name] = {  
          integrity,  
          size: bodyUint8.byteLength,  
          mime: mimeTypeForPath(name),  
        };  
      }  
  
      // store manifest to KV for faster subsequent requests (stringify)  
      try {  
        await env.NPM_CACHE.put(KV_MANIFEST_KEY, JSON.stringify(manifest), {  
          expirationTtl: 60 * 60 * 24 * 30, // cache manifest 30 days  
        });  
      } catch (e) {  
        // KV put fail -> ignore (we still return manifest)  
        console.warn("KV manifest put failed:", e);  
      }  
  
      return jsonResponse(manifest, { "X-Manifest-Cached": "false" });  
    }  
  
    // --------------------------------------------------  
    // Check KV cache (skip for .map requests by design)  
    // --------------------------------------------------  
    if (!isMapRequest) {  
      const cachedArrayBuffer = await env.NPM_CACHE.get(KV_FILE_KEY, "arrayBuffer");  
      if (cachedArrayBuffer) {  
        const cachedUint8 = new Uint8Array(cachedArrayBuffer);  
  
        // compute ETag and check If-None-Match  
        const incomingIfNone = request.headers.get("If-None-Match");  
        const cachedETag = await computeETag(cachedArrayBuffer);  
        if (incomingIfNone && compareEtags(incomingIfNone, cachedETag)) {  
          // client has fresh copy  
          const headers304 = new Headers();  
          headers304.set("ETag", cachedETag);  
          headers304.set("Access-Control-Allow-Origin", "*");  
          return new Response(null, { status: 304, headers: headers304 });  
        }  
  
        // handle Range header (single range)  
        const rangeHeader = request.headers.get("Range");  
        if (rangeHeader) {  
          const rangeResp = handleRangeRequest(cachedUint8, rangeHeader, cachedETag, filePath);  
          if (rangeResp) return rangeResp;  
          // if invalid range -> fallthrough to serve full file with correct headers  
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
          });  
        }  
  
        return makeFileResponse(cachedUint8, filePath, true, { ETag: cachedETag, "Accept-Ranges": "bytes" });  
      }  
    }  
  
    // --------------------------------------------------  
    // Fetch tarball from registry  
    // --------------------------------------------------  
    let tarRes;  
    try {  
      tarRes = await fetch(tarballUrl);  
      if (!tarRes.ok) {  
        return new Response("Tarball not found on npm", { status: 404 });  
      }  
    } catch (err) {  
      return new Response("Failed fetching tarball", { status: 502 });  
    }  
  
    // Decompress gzip (Cloudflare supports DecompressionStream)  
    let tarBytes;  
    try {  
      const tarStream = tarRes.body.pipeThrough(new DecompressionStream("gzip"));  
      tarBytes = await streamToUint8Array(tarStream);  
    } catch (err) {  
      // fallback: maybe tarball was not gzipped or DecompressionStream failed  
      try {  
        const ab = await tarRes.arrayBuffer();  
        tarBytes = new Uint8Array(ab);  
      } catch (e) {  
        return new Response("Failed to read tarball bytes", { status: 502 });  
      }  
    }  
  
    // Extract files from tar  
    const files = untar(tarBytes);  
  
    // helper to normalize filenames  
    function normalizeName(name) {  
      return name.replace(/^package\//, "");  
    }  
  
    // If this is a request for .map: find and return map directly (no KV put)  
    if (isMapRequest) {  
      const targetMap = files.find((f) => normalizeName(f.name) === filePath);  
      if (!targetMap) {  
        return new Response(`.map file not found: ${filePath}`, { status: 404 });  
      }  
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
        });  
      }  
      // Serve .map directly (not cached in KV by design)  
      return makeFileResponse(bodyUint8, filePath, false);  
    }  
  
    // find target file  
    const target = files.find((f) => normalizeName(f.name) === filePath);  
    if (!target) {  
      // If user requested JS and there's a map present, show location  
      const possibleMap = files.find((f) => normalizeName(f.name) === filePath + ".map");  
      if (possibleMap) {  
        return jsonResponse({  
          error: "Requested file not found, but a sourcemap exists",  
          sourcemap: `/npm/${pkgName}@${resolvedVersion}/${filePath}.map`,  
        });  
      }  
      return new Response(`File not found in tarball: ${filePath}`, { status: 404 });  
    }  
  
    // --------------------------------------------------  
    // Save file to KV (except .map files which we handled above)  
    // --------------------------------------------------  
    const bodyUint8 = target.data instanceof Uint8Array ? target.data : new Uint8Array(target.data);  
    try {  
      await env.NPM_CACHE.put(KV_FILE_KEY, bodyUint8, {  
        expirationTtl: 60 * 60 * 24 * 365, // 1 year  
      });  
    } catch (err) {  
      console.warn("KV put failed:", err);  
    }  
  
    // If there is a matching .map in the tarball, expose its route in header  
    const mapCandidate = files.find((f) => normalizeName(f.name) === filePath + ".map");  
    const headersExtra = {};  
    if (mapCandidate) {  
      headersExtra["X-Sourcemap-URL"] = `/npm/${pkgName}@${resolvedVersion}/${filePath}.map`;  
    }  
  
    // compute ETag for new file  
    const newETag = await computeETag(bodyUint8.buffer);  
  
    // If client requested integrity JSON, compute and return  
    if (wantIntegrityJson) {  
      const integrity = await computeSRI(bodyUint8.buffer);  
      const mime = mimeTypeForPath(filePath);  
      return jsonResponse({  
        url: request.url,  
        integrity,  
        size: bodyUint8.byteLength,  
        mime,  
        cached: false,  
      });  
    }  
  
    // Support If-None-Match immediately after storing  
    const incomingIfNoneMatch = request.headers.get("If-None-Match");  
    if (incomingIfNoneMatch && compareEtags(incomingIfNoneMatch, newETag)) {  
      const headers304 = new Headers();  
      headers304.set("ETag", newETag);  
      headers304.set("Access-Control-Allow-Origin", "*");  
      return new Response(null, { status: 304, headers: headers304 });  
    }  
  
    // handle Range header  
    const rangeHeader = request.headers.get("Range");  
    if (rangeHeader) {  
      const rangeResp = handleRangeRequest(bodyUint8, rangeHeader, newETag, filePath);  
      if (rangeResp) return rangeResp;  
      // invalid -> fallthrough to serve full file  
    }  
  
    // Serve the file  
    return makeFileResponse(bodyUint8, filePath, false, Object.assign({}, headersExtra, { ETag: newETag, "Accept-Ranges": "bytes" }));  
  },  
};  
  
/* -------------------------  
   Helpers: package base  
--------------------------*/  
function getPkgBase(pkgName) {  
  // '@scope/pkg' -> 'pkg', 'foo' -> 'foo'  
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
  
    // advance to next header (aligned to 512)  
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
  // accepts ArrayBuffer or Uint8Array  
  let buffer;  
  if (arrayBufferOrView instanceof ArrayBuffer) buffer = arrayBufferOrView;  
  else if (arrayBufferOrView.buffer) buffer = arrayBufferOrView.buffer;  
  else buffer = arrayBufferOrView;  
  const hash = await crypto.subtle.digest("SHA-256", buffer);  
  const hex = bufferToHex(hash);  
  return `"${hex}"`; // quoted ETag  
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
   Compare ETags (support multiple ETags in If-None-Match)  
------------------------------------------------------ */  
function compareEtags(ifNoneHeader, actualEtag) {  
  // ifNoneHeader may be like: W/"...", "etag1", "etag2"  
  const list = ifNoneHeader.split(",").map(s => s.trim());  
  return list.some(item => item === actualEtag || item.replace(/^W\//, "") === actualEtag);  
}  
  
/* ------------------------------------------------------  
   Range request handling (single-range)  
   - returns Response or null if invalid (fallthrough to full serve)  
------------------------------------------------------ */  
function handleRangeRequest(uint8arr, rangeHeader, etag, path) {  
  // Accept only "bytes=start-end"  
  const m = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader);  
  if (!m) return null;  
  const total = uint8arr.byteLength;  
  let start = m[1] === "" ? null : parseInt(m[1], 10);  
  let end = m[2] === "" ? null : parseInt(m[2], 10);  
  
  if (start === null && end === null) return null;  
  
  if (start === null) {  
    // suffix-byte-range-spec e.g. bytes=-500 (last 500 bytes)  
    const suffixLen = end;  
    if (suffixLen <= 0) return null;  
    start = Math.max(0, total - suffixLen);  
    end = total - 1;  
  } else if (end === null) {  
    end = total - 1;  
  }  
  
  if (isNaN(start) || isNaN(end) || start > end || start < 0 || end >= total) {  
    // invalid range -> respond 416 Range Not Satisfiable  
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
   optional extraHeaders object to add custom headers  
------------------------------------------------------ */  
function makeFileResponse(data, path, cached = false, extraHeaders = {}) {  
  const h = new Headers();  
  h.set("Access-Control-Allow-Origin", "*");  
  h.set("Content-Type", mimeTypeForPath(path));  
  h.set("Cache-Control", "public, max-age=31536000, immutable");  
  h.set("X-Cache", cached ? "HIT" : "MISS");  
  h.set("Accept-Ranges", "bytes");  
  // attach extras  
  for (const k in extraHeaders) h.set(k, extraHeaders[k]);  
  
  // data can be Uint8Array or ArrayBuffer  
  const body = data instanceof Uint8Array ? data : new Uint8Array(data);  
  // if extraHeaders already provided ETag, it will be present  
  return new Response(body, { status: 200, headers: h });  
}  
  
function jsonResponse(obj, extraHeaders = {}) {  
  const h = new Headers();  
  h.set("Content-Type", "application/json");  
  h.set("Access-Control-Allow-Origin", "*");  
  for (const k in extraHeaders) h.set(k, extraHeaders[k]);  
  return new Response(JSON.stringify(obj), { status: 200, headers: h });  
}
