export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Route harus /npm/<pkg>@<ver>/<file>
    if (!url.pathname.startsWith("/npm/")) {
      return new Response("Use: /npm/<pkg>@<ver>/<file>", { status: 400 });
    }

    const clean = url.pathname.replace("/npm/", "").replace(/^\/+|\/+$/g, "");
    // pkgWithVer bisa berupa: "vue@3.3.4" atau "@scope/pkg@1.2.3"
    const [pkgWithVer, ...rest] = clean.split("/");
    const atIndex = pkgWithVer.lastIndexOf("@");
    if (atIndex <= 0) {
      return new Response("Invalid package@version format", { status: 400 });
    }
    let pkgName = pkgWithVer.slice(0, atIndex);
    let pkgVer = pkgWithVer.slice(atIndex + 1);
    const filePath = rest.join("/"); // bisa kosong jika hanya ingin listing (tidak kita tangani sekarang)

    if (!pkgName || !pkgVer || !filePath) {
      return new Response(
        "Invalid format. Example: /npm/vue@3.3.4/dist/vue.esm.js",
        { status: 400 }
      );
    }

    // apakah client minta integrity JSON? (mis: /npm/vue@3.3.4/dist/vue.esm.js?integrity)
    const wantIntegrityJson = url.searchParams.has("integrity");

    // --------------------------------------------------
    // 1) Resolve version (handle 'latest' atau dist-tag)
    // --------------------------------------------------
    // ambil metadata dari registry untuk memastikan versi & tarball url
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

    // jika pkgVer adalah dist-tag (mis: latest, next) -> resolve ke version sebenarnya
    const distTags = metadata["dist-tags"] || {};
    let resolvedVersion = distTags[pkgVer] || pkgVer;

    // safety: jika resolvedVersion tidak ada di metadata.versions, coba fallback: jika tag diberikan, ambil latest
    if (!metadata.versions || !metadata.versions[resolvedVersion]) {
      if (distTags.latest) resolvedVersion = distTags.latest;
      if (!metadata.versions || !metadata.versions[resolvedVersion]) {
        return new Response("Version not found", { status: 404 });
      }
    }

    // gunakan tarball URL dari metadata (lebih andal, handle scoped packages)
    const versionMeta = metadata.versions[resolvedVersion];
    const tarballUrl = (versionMeta && versionMeta.dist && versionMeta.dist.tarball) ?
                       versionMeta.dist.tarball :
                       `https://registry.npmjs.org/${encodedPkg}/-/${encodeURIComponent(getPkgBase(pkgName))}-${resolvedVersion}.tgz`;

    const KV_KEY = `${pkgName}@${resolvedVersion}/${filePath}`;

    // --------------------------------------------------
    // 2) CEK CACHE DI KV
    // --------------------------------------------------
    let cachedArrayBuffer = await env.NPM_CACHE.get(KV_KEY, "arrayBuffer");
    if (cachedArrayBuffer) {
      const cachedUint8 = new Uint8Array(cachedArrayBuffer);
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
      return makeFileResponse(cachedUint8, filePath, true);
    }

    // --------------------------------------------------
    // 3) FETCH TARBALL DARI REGISTRY
    // --------------------------------------------------
    const tarRes = await fetch(tarballUrl);
    if (!tarRes.ok) {
      return new Response("Tarball not found on npm", { status: 404 });
    }

    // decompress .tgz → TAR bytes
    const tarStream = tarRes.body.pipeThrough(new DecompressionStream("gzip"));
    const tarBytes = await streamToUint8Array(tarStream);

    // Extract file
    const files = untar(tarBytes);
    const target = files.find(
      (f) => f.name.replace(/^package\//, "") === filePath
    );

    if (!target) {
      return new Response(`File not found in tarball: ${filePath}`, { status: 404 });
    }

    // --------------------------------------------------
    // 4) SIMPAN FILE KE KV
    // --------------------------------------------------
    // target.data adalah Uint8Array (dari untar)
    await env.NPM_CACHE.put(KV_KEY, target.data, {
      expirationTtl: 60 * 60 * 24 * 365, // 1 tahun
    });

    // --------------------------------------------------
    // 5) jika client minta integrity -> hitung & return JSON
    // --------------------------------------------------
    if (wantIntegrityJson) {
      const integrity = await computeSRI(target.data.buffer);
      const mime = mimeTypeForPath(filePath);
      return jsonResponse({
        url: request.url,
        integrity,
        size: target.data.byteLength,
        mime,
        cached: false,
      });
    }

    // --------------------------------------------------
    // 6) KIRIM FILE KE USER
    // --------------------------------------------------
    return makeFileResponse(target.data, filePath, false);
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
   TAR PARSER (sama seperti milikmu)
------------------------------------------------------ */
function untar(bytes) {
  const files = [];
  let offset = 0;

  while (offset < bytes.length) {
    const name = readStr(bytes, offset, 100).replace(/\0.*$/, "");
    if (!name) break;

    const sizeOct = readStr(bytes, offset + 124, 12).replace(/\0.*$/, "");
    const size = parseInt(sizeOct.trim() || "0", 8);

    const dataStart = offset + 512;
    const data = bytes.slice(dataStart, dataStart + size);

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
   MIME detection (lebih lengkap)
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
    svgz: "image/svg+xml",
    ttf: "font/ttf",
    otf: "font/otf",
    woff: "font/woff",
    woff2: "font/woff2",
    eot: "application/vnd.ms-fontobject",
    mp3: "audio/mpeg",
    mp4: "video/mp4",
    wasm: "application/wasm",
    // fallback handled below
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
  // browser-friendly base64 conversion
  const bytes = new Uint8Array(buffer);
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  // btoa is available in Workers
  return btoa(binary);
}

/* ------------------------------------------------------
   MIME + HEADERS -> RESPONSE
------------------------------------------------------ */
function makeFileResponse(data, path, cached) {
  const h = new Headers();
  h.set("Access-Control-Allow-Origin", "*");

  const mime = mimeTypeForPath(path);
  h.set("Content-Type", mime);

  h.set("Cache-Control", "public, max-age=31536000, immutable");
  h.set("X-Cache", cached ? "HIT" : "MISS");

  // data can be Uint8Array or ArrayBuffer
  const body = data instanceof Uint8Array ? data : new Uint8Array(data);
  return new Response(body, { status: 200, headers: h });
}

function jsonResponse(obj) {
  const h = new Headers();
  h.set("Content-Type", "application/json");
  h.set("Access-Control-Allow-Origin", "*");
  return new Response(JSON.stringify(obj), { status: 200, headers: h });
          }
