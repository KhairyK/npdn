import { ungzip, strFromU8 } from './node_modules/fflate/esm/browser.js';
import Tar from './node_modules/tar-js/tar.js';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    let path = url.pathname.slice(1);
    const lastSlash = path.lastIndexOf('/');
    const file = path.slice(lastSlash + 1);
    const pkgAndVersion = path.slice(0, lastSlash);

    const atVersion = pkgAndVersion.lastIndexOf('@');
    let pkg, version;
    if (pkgAndVersion.startsWith('@')) {
      pkg = pkgAndVersion.slice(0, atVersion);
      version = pkgAndVersion.slice(atVersion + 1);
    } else {
      pkg = pkgAndVersion.slice(0, atVersion);
      version = pkgAndVersion.slice(atVersion + 1);
    }

    const cacheKey = `${pkg}@${version}`;

    try {
      // 1. Cek cache di KV
      let tarballArrayBuffer = await env.NPM_CACHE.get(cacheKey, { type: "arrayBuffer" });

      if (!tarballArrayBuffer) {
        // 2. Fetch tarball npm
        const metaRes = await fetch(`https://registry.npmjs.org/${pkg}/${version}`);
        if (!metaRes.ok) return new Response('Package not found', { status: 404 });
        const meta = await metaRes.json();
        const tarballUrl = meta.dist.tarball;

        const tarballRes = await fetch(tarballUrl);
        tarballArrayBuffer = await tarballRes.arrayBuffer();

        // 3. Simpan di KV
        await env.NPM_CACHE.put(cacheKey, tarballArrayBuffer);
      }

      // 4. Extract file dari tarball
      const files = await untar(tarballArrayBuffer);
      const targetFile = files.find(f => f.name.endsWith(file));
      if (!targetFile) return new Response('File not found', { status: 404 });

      return new Response(targetFile.buffer, {
        headers: {
          'Content-Type': 'application/javascript',
          'Cache-Control': 'public, max-age=31536000'
        }
      });

    } catch (e) {
      return new Response(e.toString(), { status: 500 });
    }
  }
};
