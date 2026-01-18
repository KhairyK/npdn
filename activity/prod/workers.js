
// CONFIG
const CONFIG = {
  // Operational
  ENTERPRISE_MODE: true, // when true: disallow @latest and require pinned versions unless allowlisted
  ALLOW_LATEST_FOR: ["internal-package@latest"], // example allowlist

  // Limits
  MAX_EXTRACTED_SIZE: 25 * 1024 * 1024, // 25 MiB
  MAX_FILE_COUNT: 2000,
  MAX_SINGLE_FILE_SIZE: 10 * 1024 * 1024, // 10 MiB
  TAR_DECOMPRESS_TIMEOUT_MS: 10_000,
  FETCH_TIMEOUT_MS: 10_000,
  INTEGRITY_HEAT_LIMIT_PER_MIN: 60, // throttle integrity=all usage

  // KV keys
  KV_PREFIX: "npdn:",

  // Security
  REQUIRE_DIST_INTEGRITY: true, // verify tarball/tarball integrity if registry supplies it

  // Telemetry
  METRICS_ENDPOINT: null // if set, POST structured metrics (consider auth)
};

// Helpers
function now() { return Date.now(); }

function safeJsonParse(s) {
  try { return JSON.parse(s); } catch (e) { return null; }
}

function makeResponse(body, status = 200, headers = {}) {
  const h = new Headers(headers);
  if (!h.has('Content-Type')) h.set('Content-Type', 'text/plain; charset=utf-8');
  h.set('Access-Control-Allow-Origin', '*');
  return new Response(body, { status, headers: h });
}

// Top-level wrapper to avoid uncaught exceptions
export default {
  async fetch(request, env, ctx) {
    const start = now();
    try {
      return await handleRequest(request, env, ctx);
    } catch (err) {
      // Structured error reporting (do NOT leak internal data to clients)
      try { console.error('PANIC', { msg: err?.message, stack: err?.stack }); } catch (e) {}
      // Optional telemetry
      if (CONFIG.METRICS_ENDPOINT && typeof fetch === 'function') {
        void sendMetric({ type: 'worker_panic', message: String(err?.message || 'panic'), ts: new Date().toISOString() }, CONFIG.METRICS_ENDPOINT);
      }
      // Generic 500 to client
      return makeResponse('Internal worker error', 500, { 'X-NPDN-Error': 'internal' });
    } finally {
      // You can emit lightweight telemetry here (p95, request path)
      // Keep it non-blocking
      const dur = now() - start;
      // console.info('req-dur', dur);
    }
  },

  // scheduled remains unchanged but should be robust in production
  async scheduled(controller, env, ctx) {
    // implement safe prewarm job with retries and small concurrency
    try {
      const pkgs = (env.PREWARM_PACKAGES || '').split(',').map(s => s.trim()).filter(Boolean);
      for (const p of pkgs) {
        // HEAD with short timeout
        try { await safeFetch(`${env.BASE_ORIGIN || 'https://npdn.kyrt.my.id'}/npm/${p}`, { method: 'HEAD' }, env); } catch (e) {}
      }
    } catch (err) {
      console.error('scheduled error', err?.message);
    }
  }
};

/* ---------------------- Core handler ---------------------- */
async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  // Basic dashboard and metrics route
  if (url.pathname === '/' || url.pathname === '/dashboard') return makeResponse('NPDN Dashboard (protected)', 200);

  // Validate path
  if (!url.pathname.startsWith('/npm/')) return makeResponse('Use: /npm/<pkg>@<ver>/<file>', 400);

  // parse clean path
  const clean = url.pathname.replace('/npm/', '').replace(/^\/+|\/+$/g, '');
  if (!clean) return makeResponse('Invalid package', 400);

  // Determine pkgWithVer and rawFilePath carefully
  let pkgWithVer = null; let rawFilePath = '';
  if (!clean.includes('@') || /@latest($|\/)/.test(clean)) {
    // either no version or latest used
    pkgWithVer = clean.includes('@') ? clean : clean + '@latest';
  } else {
    pkgWithVer = clean.split('/')[0] || '';
    rawFilePath = clean.split('/').slice(1).join('/');
  }
  if (clean.includes('@') && clean.split('/').length > 1) rawFilePath = clean.split('/').slice(1).join('/');

  const atIndex = pkgWithVer.lastIndexOf('@');
  if (atIndex <= 0) return makeResponse('Invalid package@version format', 400);

  let pkgName = pkgWithVer.slice(0, atIndex);
  let pkgVer = pkgWithVer.slice(atIndex + 1);
  let filePath = rawFilePath || '';

  // SANITIZE inputs
  try {
    filePath = filePath ? decodeURIComponent(filePath).replace(/^\.\/+/, '').replace(/\\/g, '/') : '';
  } catch (e) {
    return makeResponse('Bad request (invalid percent-encoding)', 400);
  }
  if (filePath.includes('..')) return makeResponse('Forbidden path', 403);

  // Enterprise mode restrictions
  if (CONFIG.ENTERPRISE_MODE && (pkgVer === 'latest' || pkgVer === '' ) && !isAllowlistedLatest(pkgName, env)) {
    return makeResponse('Latest tag disabled in enterprise mode. Please pin a version.', 403);
  }

  // handle integrity & meta flags safely
  const wantMeta = url.searchParams.has('meta');
  const wantIntegrityAll = url.searchParams.has('integrity') && url.searchParams.get('integrity') === 'all';
  const wantIntegrityJson = url.searchParams.has('integrity') && !wantIntegrityAll;

  // RATE LIMIT sensitive endpoints (integrity=all) - prefer Durable Object or Cloudflare Rate Limits
  if (wantIntegrityAll) {
    const allowed = await checkIntegrityRateLimit(env, request);
    if (!allowed) return makeResponse('Rate limit exceeded for integrity manifest', 429);
  }

  // Resolve registry metadata with KV caching and safe guards
  const resolved = await safeResolveVersion(pkgName, pkgVer, env);
  if (!resolved) return makeResponse('Version not found', 404);
  const { resolvedVersion, versionMeta, metadata } = resolved;

  // Smart auto-redirect for root requests - but avoid heavy work here
  if (!filePath && !wantIntegrityAll) {
    const entry = pickEntry(versionMeta);
    const target = `/npm/${pkgName}@${resolvedVersion}/${entry}`;
    const headers = { 'Cache-Control': 'public, max-age=3600' };
    return Response.redirect(target, 302);
  }

  // compute keys
  const KV_FILE_KEY_BASE = `${pkgName}@${resolvedVersion}`;
  const KV_FILE_KEY = `${KV_FILE_KEY_BASE}/${filePath}`;
  const isMap = filePath.endsWith('.map');

  // HEAD short-circuit (see earlier implementation) - implement safe HEAD handling
  if (request.method === 'HEAD') {
    return handleHead(request, env, { KV_FILE_KEY, KV_FILE_KEY_BASE, filePath, isMap });
  }

  // Edge cache check (caches.default) - if present return early
  if (request.method === 'GET' && !isMap) {
    const cached = await caches.default.match(request.url);
    if (cached) {
      const cloned = cached.clone();
      const merged = new Headers(cloned.headers);
      merged.set('X-Cache', 'HIT');
      merged.set('Access-Control-Allow-Origin', '*');
      return new Response(await cloned.arrayBuffer(), { status: cloned.status, headers: merged });
    }
  }

  // KV file check (skip maps if you choose)
  try {
    const kvBuf = await env.NPM_CACHE.get(KV_FILE_KEY, 'arrayBuffer');
    if (kvBuf) {
      // enforce size/counters, compute ETag quickly
      if (kvBuf.byteLength > CONFIG.MAX_EXTRACTED_SIZE) {
        // skip to tarball path
      } else {
        const etag = await computeETag(kvBuf);
        // handle If-None-Match
        const incoming = request.headers.get('If-None-Match');
        if (incoming && compareEtags(incoming, etag)) {
          const headers = { 'ETag': etag, 'Access-Control-Allow-Origin': '*' };
          return new Response(null, { status: 304, headers });
        }
        // Range support
        const range = request.headers.get('Range');
        if (range) {
          const uint8 = new Uint8Array(kvBuf);
          const rres = handleRangeRequest(uint8, range, etag, filePath);
          if (rres) return rres;
        }
        // return final
        const res = makeFileResponse(kvBuf, filePath, true, { ETag: etag, 'Accept-Ranges': 'bytes' });
        ctx.waitUntil((async () => { try { await caches.default.put(request.url, res.clone()); } catch (e) {} })());
        return res;
      }
    }
  } catch (e) {
    console.error('KV read failure', e?.message);
  }

  // Fetch tarball and safely extract target file with strict guards
  const tarballUrl = (versionMeta && versionMeta.dist && versionMeta.dist.tarball) || null;
  if (!tarballUrl) return makeResponse('Tarball URL not found', 502);

  // safe fetch with timeout and optional integrity check
  const tarRes = await safeFetch(tarballUrl, { method: 'GET' }, env, CONFIG.FETCH_TIMEOUT_MS);
  if (!tarRes || !tarRes.ok) return makeResponse('Failed fetching tarball', 502);

  if (CONFIG.REQUIRE_DIST_INTEGRITY && versionMeta && versionMeta.dist && versionMeta.dist.integrity) {
    // verify tarball integrity if registry provided it
    const ok = await verifyStreamIntegrity(tarRes.clone(), versionMeta.dist.integrity);
    if (!ok) {
      console.error('tarball integrity mismatch', { pkgName, resolvedVersion });
      return makeResponse('Tarball integrity mismatch', 502);
    }
  }

  // Now read and decompress with timeout and size limits
  let tarBytes;
  try {
    tarBytes = await streamToUint8ArrayWithLimit(tarRes.body, CONFIG.MAX_EXTRACTED_SIZE, CONFIG.TAR_DECOMPRESS_TIMEOUT_MS);
  } catch (err) {
    console.error('decompress/read tar failed', err?.message);
    return makeResponse('Failed to read tarball bytes', 502);
  }

  const files = safeUntar(tarBytes, CONFIG);
  if (!files) return makeResponse('Failed to parse tarball', 502);

  // find target file
  const normalized = (name) => name.replace(/^package\//, '');
  const target = files.find(f => normalized(f.name) === filePath);
  if (!target) {
    const possibleMap = files.find(f => normalized(f.name) === filePath + '.map');
    if (possibleMap) {
      return makeResponse(JSON.stringify({ error: 'Requested file not found, but a sourcemap exists', sourcemap: `/npm/${pkgName}@${resolvedVersion}/${filePath}.map` }), 404, { 'Content-Type': 'application/json' });
    }
    return makeResponse(`File not found in tarball: ${filePath}`, 404);
  }

  // guard file size
  const bodyUint8 = target.data instanceof Uint8Array ? target.data : new Uint8Array(target.data);
  if (bodyUint8.byteLength > CONFIG.MAX_SINGLE_FILE_SIZE) {
    return makeResponse('File too large', 413);
  }

  // compute ETag and SRI (async) and store to KV (best-effort)
  const newETag = await computeETag(bodyUint8);
  ctx.waitUntil((async () => {
    try {
      if (bodyUint8.byteLength <= CONFIG.MAX_EXTRACTED_SIZE) {
        await env.NPM_CACHE.put(KV_FILE_KEY, bodyUint8, { expirationTtl: 60 * 60 * 24 * 365 });
      }
    } catch (e) { console.warn('KV put failed', e?.message); }
  })());

  // integrity JSON support
  if (wantIntegrityJson) {
    const integrity = await computeSRI(bodyUint8.buffer);
    return makeResponse(JSON.stringify({ url: request.url, integrity, size: bodyUint8.byteLength, mime: mimeTypeForPath(filePath), cached: false }), 200, { 'Content-Type': 'application/json' });
  }

  // final response with safe headers
  const finalRes = makeFileResponse(bodyUint8, filePath, false, { ETag: newETag, 'Accept-Ranges': 'bytes' });
  if (env && ctx) ctx.waitUntil((async () => { try { await caches.default.put(request.url, finalRes.clone()); } catch (e) {} })());
  return finalRes;
}

/* ---------------------- Supporting safe helpers ---------------------- */

async function safeFetch(url, opts = {}, env = {}, timeout = 10_000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, { ...opts, signal: controller.signal });
    clearTimeout(id);
    return res;
  } catch (err) {
    clearTimeout(id);
    // optionally retry transient errors (1 retry)
    if (err.name === 'AbortError') throw err;
    try {
      const res2 = await fetch(url, { ...opts });
      return res2;
    } catch (e) { throw e; }
  }
}

async function verifyStreamIntegrity(response, expected) {
  // expected example: "sha512-<base64>" or use SHA-1/sha256 from dist.integrity
  if (!expected) return true;
  try {
    const ab = await response.arrayBuffer();
    const computed = await computeSRI(ab);
    // computeSRI uses sha512-base64; compare suffix only if scheme differs
    return computed === expected || computed.endsWith(expected) || expected.endsWith(computed);
  } catch (e) {
    console.warn('verifyStreamIntegrity failed', e?.message);
    return false;
  }
}

// read stream with max bytes & timeout
async function streamToUint8ArrayWithLimit(stream, maxBytes, timeout) {
  const reader = stream.getReader();
  const chunks = [];
  let total = 0;
  const deadline = Date.now() + timeout;
  while (true) {
    if (Date.now() > deadline) {
      reader.cancel();
      throw new Error('stream timeout');
    }
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > maxBytes) {
      reader.cancel();
      throw new Error('max bytes exceeded');
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) { out.set(c, offset); offset += c.length; }
  return out;
}

function safeUntar(bytes, cfg) {
  // simple untar but with guards on file count and aggregated size
  const files = [];
  let offset = 0;
  let seenFiles = 0;
  const maxTotal = cfg.MAX_EXTRACTED_SIZE;
  let totalUnpacked = 0;
  while (offset + 512 <= bytes.length) {
    const name = readStr(bytes, offset, 100).replace(/\0.*$/, '');
    if (!name) break;
    const sizeOct = readStr(bytes, offset + 124, 12).replace(/\0.*$/, '');
    const size = parseInt(sizeOct.trim() || '0', 8) || 0;
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    if (dataEnd > bytes.length) break;
    // guard single file size
    if (size > cfg.MAX_SINGLE_FILE_SIZE) {
      console.warn('file too large in tar', name, size);
      return null;
    }
    totalUnpacked += size;
    if (totalUnpacked > maxTotal) { console.warn('total unpacked exceeded'); return null; }
    seenFiles++;
    if (seenFiles > cfg.MAX_FILE_COUNT) { console.warn('file count exceeded'); return null; }
    const data = bytes.slice(dataStart, dataEnd);
    files.push({ name, data });
    offset = dataStart + Math.ceil(size / 512) * 512;
  }
  return files;
}

function readStr(bytes, start, len) { return new TextDecoder().decode(bytes.slice(start, start + len)); }

/* ---------------------- KV / Rate helpers ---------------------- */
async function checkIntegrityRateLimit(env, request) {
  // Placeholder: prefer Durable Object counter. Here we do a naive KV-based minute window.
  if (!env.INTEGRITY_RATE_KV) return true; // not configured
  try {
    const key = 'integrity-rate:' + new Date().toISOString().slice(0,16);
    const cur = await env.INTEGRITY_RATE_KV.get(key);
    const n = parseInt(cur || '0', 10);
    if (n >= CONFIG.INTEGRITY_HEAT_LIMIT_PER_MIN) return false;
    await env.INTEGRITY_RATE_KV.put(key, String(n+1), { expirationTtl: 60*2 });
    return true;
  } catch (e) { return true; }
}

function isAllowlistedLatest(pkg, env) {
  // Example: check a KV or in-memory allowlist
  try {
    if (!env.ALLOW_LATEST_KV) return CONFIG.ALLOW_LATEST_FOR.includes(pkg + '@latest');
    return env.ALLOW_LATEST_KV.get(`${pkg}:allow_latest`).then(v => !!v);
  } catch (e) { return false; }
}

/* ---------------------- Utilities (ETag, SRI, mime, range) ---------------------- */
async function computeSRI(arrayBuffer) {
  const hashBuffer = await crypto.subtle.digest('SHA-512', arrayBuffer);
  const b64 = arrayBufferToBase64(hashBuffer);
  return `sha512-${b64}`;
}
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

async function computeETag(bufOrAb) {
  let buffer = bufOrAb instanceof ArrayBuffer ? bufOrAb : (bufOrAb.buffer || bufOrAb);
  const h = await crypto.subtle.digest('SHA-256', buffer);
  return '"' + bufferToHex(h) + '"';
}
function bufferToHex(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i++) { s += (bytes[i] + 0x100).toString(16).substr(1); }
  return s;
}

function compareEtags(ifNoneHeader, actualEtag) {
  if (!ifNoneHeader || !actualEtag) return false;
  const list = ifNoneHeader.split(',').map(s => s.trim());
  return list.some(item => item === actualEtag || item.replace(/^W\//, '') === actualEtag);
}

function mimeTypeForPath(path) {
  const ext = (path || '').split('.').pop().toLowerCase();
  const map = { js:'application/javascript', mjs:'application/javascript', map:'application/json', css:'text/css', json:'application/json', html:'text/html', svg:'image/svg+xml', png:'image/png', jpg:'image/jpeg', jpeg:'image/jpeg', wasm:'application/wasm' };
  return map[ext] || 'application/octet-stream';
}

function handleRangeRequest(uint8arr, rangeHeader, etag, path) {
  // same safe single-range implementation
  const m = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader);
  if (!m) return null;
  const total = uint8arr.byteLength;
  let start = m[1] === '' ? null : parseInt(m[1], 10);
  let end = m[2] === '' ? null : parseInt(m[2], 10);
  if (start === null && end === null) return null;
  if (start === null) { const suffixLen = end; if (suffixLen <= 0) return null; start = Math.max(0, total - suffixLen); end = total - 1; } else if (end === null) { end = total - 1; }
  if (isNaN(start) || isNaN(end) || start > end || start < 0 || end >= total) {
    const headers = new Headers(); headers.set('Content-Range', `bytes */${total}`); headers.set('Accept-Ranges', 'bytes'); headers.set('Access-Control-Allow-Origin', '*'); return new Response(null, { status: 416, headers });
  }
  const chunk = uint8arr.slice(start, end + 1);
  const headers = new Headers(); headers.set('Content-Type', mimeTypeForPath(path)); headers.set('Content-Length', String(chunk.byteLength)); headers.set('Content-Range', `bytes ${start}-${end}/${total}`); headers.set('Accept-Ranges', 'bytes'); headers.set('Cache-Control', 'public, max-age=31536000, immutable'); headers.set('ETag', etag); headers.set('Access-Control-Allow-Origin', '*'); return new Response(chunk, { status: 206, headers });
}

function makeFileResponse(data, path, cached = false, extraHeaders = {}) {
  const h = new Headers(); h.set('Access-Control-Allow-Origin', '*'); h.set('Content-Type', mimeTypeForPath(path)); h.set('Cache-Control', 'public, max-age=31536000, immutable'); h.set('X-Cache', cached ? 'HIT' : 'MISS'); h.set('Accept-Ranges', 'bytes'); h.set('Vary', 'Accept-Encoding'); for (const k in extraHeaders) h.set(k, extraHeaders[k]); const body = data instanceof Uint8Array ? data : new Uint8Array(data); return new Response(body, { status: 200, headers: h });
}

function jsonResponse(obj, extraHeaders = {}) { const h = new Headers(); h.set('Content-Type', 'application/json'); h.set('Access-Control-Allow-Origin', '*'); for (const k in extraHeaders) h.set(k, extraHeaders[k]); return new Response(JSON.stringify(obj), { status: 200, headers: h }); }

/* ---------------------- Small helpers: pickEntry, resolve version (safe) ---------------------- */
function pickEntry(versionMeta) {
  let entry = (versionMeta && versionMeta.exports && versionMeta.exports['.']) || (versionMeta && versionMeta.module) || (versionMeta && versionMeta.browser) || (versionMeta && versionMeta.main) || 'index.js';
  if (typeof entry === 'object') entry = entry.import || entry.browser || entry.default || Object.values(entry)[0];
  if (typeof entry !== 'string') entry = 'index.js';
  return entry.replace(/^\.?\//, '');
}

async function safeResolveVersion(pkgName, pkgVer, env) {
  // Try KV canonical -> meta KV -> registry with strong guards
  const KV_META_KEY = `${CONFIG.KV_PREFIX}${pkgName}::meta`;
  const KV_CANON_KEY = `${CONFIG.KV_PREFIX}${pkgName}@${pkgVer}::resolved`;
  try {
    // Try canonical
    const cachedResolved = await env.NPM_CACHE.get(KV_CANON_KEY);
    if (cachedResolved) {
      const metadataText = await env.NPM_CACHE.get(KV_META_KEY);
      const metadata = metadataText ? safeJsonParse(metadataText) : null;
      const versionMeta = metadata && metadata.versions && metadata.versions[cachedResolved];
      if (versionMeta) return { resolvedVersion: cachedResolved, versionMeta, metadata };
    }
  } catch (e) { console.warn('safeResolveVersion KV read failed', e?.message); }

  // Fallback to registry fetch
  const registryUrl = `https://registry.npmjs.org/${encodeURIComponent(pkgName)}`;
  let meta;
  try {
    const r = await safeFetch(registryUrl, { method: 'GET' }, env, CONFIG.FETCH_TIMEOUT_MS);
    if (!r || !r.ok) return null;
    const j = await r.json();
    meta = j;
    // cache metadata (best-effort)
    try { await env.NPM_CACHE.put(KV_META_KEY, JSON.stringify(j), { expirationTtl: 60 * 60 * 6 }); } catch (e) {}
  } catch (err) { console.warn('registry fetch failed', err?.message); return null; }

  const distTags = meta['dist-tags'] || {};
  let resolvedVersion = distTags[pkgVer] || pkgVer;
  if (!meta.versions || !meta.versions[resolvedVersion]) {
    if (distTags.latest) resolvedVersion = distTags.latest;
    if (!meta.versions || !meta.versions[resolvedVersion]) return null;
  }
  // write canonical mapping
  try { await env.NPM_CACHE.put(KV_CANON_KEY, resolvedVersion, { expirationTtl: 60 * 60 * 24 }); } catch (e) {}
  const versionMeta = meta.versions[resolvedVersion];
  return { resolvedVersion, versionMeta, metadata: meta };
}

/* ---------------------- small telemetry sender ---------------------- */
async function sendMetric(obj, endpoint) {
  try { await fetch(endpoint, { method: 'POST', body: JSON.stringify(obj), headers: { 'Content-Type': 'application/json' } }); } catch (e) {}
}

/* ---------------------- HEAD handler (minimal) ---------------------- */
async function handleHead(request, env, ctx) {
  const headers = { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' };
  // cheap check: manifest presence
  try {
    const manifestText = await env.NPM_CACHE.get(`${ctx.KV_FILE_KEY_BASE}::integrity-manifest`);
    headers['X-Manifest-Cached'] = manifestText ? 'true' : 'false';
    return new Response(null, { status: 200, headers });
  } catch (e) { return new Response(null, { status: 200, headers }); }
}
