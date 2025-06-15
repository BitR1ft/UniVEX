/* UniVex Service Worker — Offline Support */

const CACHE_NAME = 'univex-v1';
const OFFLINE_PAGE = '/offline';

/** Routes to pre-cache on service worker install (includes offline fallback page). */
const PRECACHE_ROUTES = ['/', '/dashboard', '/projects', '/manifest.json', '/favicon.ico', OFFLINE_PAGE];

// ---------------------------------------------------------------------------
// Install: pre-cache shell routes and skip waiting to activate immediately.
// ---------------------------------------------------------------------------

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(PRECACHE_ROUTES))
  );
  self.skipWaiting();
});

// ---------------------------------------------------------------------------
// Activate: remove any old caches from previous versions, then claim clients.
// ---------------------------------------------------------------------------

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((key) => key !== CACHE_NAME)
          .map((key) => caches.delete(key))
      )
    )
  );
  self.clients.claim();
});

// ---------------------------------------------------------------------------
// Fetch: route requests through the appropriate caching strategy.
// ---------------------------------------------------------------------------

self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Only handle same-origin requests.
  if (url.origin !== self.location.origin) return;

  if (isStaticAsset(request)) {
    // Cache-first: serve from cache immediately; populate cache on miss.
    event.respondWith(cacheFirst(request));
  } else if (request.mode === 'navigate') {
    // Network-first for navigation: fresh content when online, cache fallback when not.
    event.respondWith(networkFirstNavigation(request));
  }
});

// ---------------------------------------------------------------------------
// Strategy: network-first with cache fallback for navigation requests.
// ---------------------------------------------------------------------------

async function networkFirstNavigation(request) {
  try {
    const networkResponse = await fetch(request);
    const cache = await caches.open(CACHE_NAME);
    cache.put(request, networkResponse.clone());
    return networkResponse;
  } catch {
    const cached = await caches.match(request);
    if (cached) return cached;
    // Last resort: return the cached offline page if available.
    const offlineFallback = await caches.match(OFFLINE_PAGE);
    return offlineFallback || new Response('Offline', { status: 503 });
  }
}

// ---------------------------------------------------------------------------
// Strategy: cache-first for static assets (images, fonts, CSS, JS).
// ---------------------------------------------------------------------------

async function cacheFirst(request) {
  const cached = await caches.match(request);
  if (cached) return cached;

  try {
    const networkResponse = await fetch(request);
    const cache = await caches.open(CACHE_NAME);
    cache.put(request, networkResponse.clone());
    return networkResponse;
  } catch {
    return new Response('Asset not available offline', { status: 503 });
  }
}

// ---------------------------------------------------------------------------
// Helper: detect static asset requests by URL extension.
// ---------------------------------------------------------------------------

function isStaticAsset(request) {
  const url = new URL(request.url);
  return /\.(png|jpg|jpeg|gif|svg|webp|ico|woff|woff2|ttf|otf|css|js)$/i.test(url.pathname);
}
