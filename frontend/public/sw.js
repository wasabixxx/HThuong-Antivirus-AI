// HThuong Antivirus AI — Service Worker (PWA Offline + Cache)
const CACHE_VERSION = 'hthuong-av-v2';
const STATIC_CACHE = `${CACHE_VERSION}-static`;
const API_CACHE = `${CACHE_VERSION}-api`;

// Các asset tĩnh cần cache ngay khi install
const PRECACHE_URLS = [
  '/',
  '/index.html',
  '/manifest.json',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
];

// ============================================================
// INSTALL — Cache static assets
// ============================================================
self.addEventListener('install', (event) => {
  console.log('[SW] Installing service worker...');
  event.waitUntil(
    caches.open(STATIC_CACHE).then((cache) => {
      return cache.addAll(PRECACHE_URLS);
    }).then(() => {
      // Kích hoạt ngay, không đợi tab cũ đóng
      return self.skipWaiting();
    })
  );
});

// ============================================================
// ACTIVATE — Xoá cache cũ
// ============================================================
self.addEventListener('activate', (event) => {
  console.log('[SW] Activating service worker...');
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames
          .filter((name) => name !== STATIC_CACHE && name !== API_CACHE)
          .map((name) => {
            console.log('[SW] Deleting old cache:', name);
            return caches.delete(name);
          })
      );
    }).then(() => {
      // Claim tất cả tab đang mở
      return self.clients.claim();
    })
  );
});

// ============================================================
// FETCH — Network-first cho API, Cache-first cho static
// ============================================================
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Bỏ qua non-GET requests
  if (event.request.method !== 'GET') return;

  // API calls → Network-first, fallback cache
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(networkFirstStrategy(event.request));
    return;
  }

  // Static assets (JS, CSS, images) → Cache-first
  if (url.pathname.match(/\.(js|css|png|jpg|jpeg|svg|ico|woff2?)$/)) {
    event.respondWith(cacheFirstStrategy(event.request));
    return;
  }

  // HTML pages → Network-first (để luôn lấy bản mới nhất)
  event.respondWith(networkFirstStrategy(event.request));
});

// ============================================================
// STRATEGIES
// ============================================================

/**
 * Network-first: thử mạng trước, nếu lỗi thì dùng cache
 */
async function networkFirstStrategy(request) {
  try {
    const response = await fetch(request);
    // Cache response thành công
    if (response.ok) {
      const cache = await caches.open(API_CACHE);
      cache.put(request, response.clone());
    }
    return response;
  } catch (error) {
    const cached = await caches.match(request);
    if (cached) return cached;

    // Nếu là navigation → trả về index.html (SPA)
    if (request.mode === 'navigate') {
      const fallback = await caches.match('/index.html');
      if (fallback) return fallback;
    }

    return new Response('Không có kết nối mạng', {
      status: 503,
      statusText: 'Service Unavailable',
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    });
  }
}

/**
 * Cache-first: dùng cache trước, nếu chưa có thì fetch từ mạng
 */
async function cacheFirstStrategy(request) {
  const cached = await caches.match(request);
  if (cached) return cached;

  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(STATIC_CACHE);
      cache.put(request, response.clone());
    }
    return response;
  } catch (error) {
    return new Response('', { status: 404 });
  }
}
