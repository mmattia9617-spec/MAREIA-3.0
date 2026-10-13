// Security patch proposal for MARÈIA 2.9.5. Not yet deployed.
// Offline cache is restricted to known, public, static assets only.
const CACHE = 'mareia-295-static-v2';
const STATIC_PATHS = new Set([
  '/icon-192.png',
  '/icon-512.png',
  '/apple-touch-icon.png',
  '/mareia-hologram.webp',
  '/qrcode.js',
]);

function safeToCache(response) {
  if (!response || !response.ok || response.type === 'opaque') return false;
  const control = response.headers.get('cache-control') || '';
  if (/\b(?:no-store|private)\b/i.test(control)) return false;
  if (response.headers.has('set-cookie')) return false;
  return true;
}

self.addEventListener('install', event => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE);
    for (const path of STATIC_PATHS) {
      try {
        const response = await fetch(new Request(path, { credentials: 'omit', cache: 'no-store' }));
        if (safeToCache(response)) await cache.put(path, response.clone());
      } catch (_) {
        // Installation remains possible without optional offline assets.
      }
    }
  })());
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys
      .filter(key => key.startsWith('mareia-') && key !== CACHE)
      .map(key => caches.delete(key)));
  })());
  self.clients.claim();
});

self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin || url.search || !STATIC_PATHS.has(url.pathname)) return;

  event.respondWith((async () => {
    try {
      // No cookies or credentials are sent for public assets.
      const response = await fetch(new Request(url.href, { credentials: 'omit', cache: 'no-store' }));
      if (safeToCache(response)) {
        const cache = await caches.open(CACHE);
        await cache.put(url.pathname, response.clone());
      }
      return response;
    } catch (error) {
      const cached = await caches.match(url.pathname);
      if (cached) return cached;
      throw error;
    }
  })());
});
