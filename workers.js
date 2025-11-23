export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Route harus /npm/<pkg>@<ver>/<file>
    if (!url.pathname.startsWith("/npm/")) {
      return new Response("Use: /npm/<pkg>@<ver>/<file>", { status: 400 });
    }

    const clean = url.pathname.replace("/npm/", "");
    const [pkgWithVer, ...rest] = clean.split("/");
    const [pkgName, pkgVer] = pkgWithVer.split("@");
    const filePath = rest.join("/");

    if (!pkgName || !pkgVer || !filePath) {
      return new Response("Invalid format. Example: /npm/vue@3.3.4/dist/vue.esm.js", {
        status: 400,
      });
    }

    const KV_KEY = `${pkgName}@${pkgVer}/${filePath}`;

    // --------------------------------------------------
    // 1) CEK CACHE DI KV
    // --------------------------------------------------
    const cached = await env.NPM_CACHE.get(KV_KEY, "arrayBuffer");
    if (cached) {
      return makeFileResponse(new Uint8Array(cached), filePath, true);
    }

    // --------------------------------------------------
    // 2) FETCH TARBALL DARI REGISTRY
    // --------------------------------------------------
    const tarURL = `https://registry.npmjs.org/${pkgName}/-/${pkgName}-${pkgVer}.tgz`;
    const tarRes = await fetch(tarURL);

    if (!tarRes.ok) {
      return new Response("Tarball not found on npm", { status: 404 });
    }

    // decompress .tgz → TAR bytes
    const tarStream = tarRes.body.pipeThrough(new DecompressionStream("gzip"));
    const tarBytes = await streamToUint8Array(tarStream);

    // Extract file
    const files = untar(tarBytes);
    const target = files.find(f => f.name.replace(/^package\//, "") === filePath);

    if (!target) {
      return new Response(`File not found in tarball: ${filePath}`, { status: 404 });
    }

    // --------------------------------------------------
    // 3) SIMPAN FILE KE KV
    // --------------------------------------------------
    await env.NPM_CACHE.put(KV_KEY, target.data, {
      expirationTtl: 60 * 60 * 24 * 365, // 1 tahun
    });

    // --------------------------------------------------
    // 4) KIRIM RESPONSE KE USER
    // --------------------------------------------------
    return makeFileResponse(target.data, filePath, false);
  },
};

/* ------------------------------------------------------
   TAR PARSER
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
   MIME + HEADERS
------------------------------------------------------ */
function makeFileResponse(data, path, cached) {
  const h = new Headers();
  h.set("Access-Control-Allow-Origin", "*");

  // MIME detection
  if (path.endsWith(".js") || path.endsWith(".mjs")) h.set("Content-Type", "application/javascript");
  else if (path.endsWith(".css")) h.set("Content-Type", "text/css");
  else if (path.endsWith(".json")) h.set("Content-Type", "application/json");
  else if (path.endsWith(".map")) h.set("Content-Type", "application/json");
  else h.set("Content-Type", "application/octet-stream");

  h.set("Cache-Control", "public, max-age=31536000, immutable");
  h.set("X-Cache", cached ? "HIT" : "MISS");

  return new Response(data, { status: 200, headers: h });
}
