const CACHE = 'mercado-app-v2';

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) => cache.addAll(['./', './index.html']))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((nombres) => Promise.all(
      nombres.filter((n) => n !== CACHE).map((n) => caches.delete(n))
    ))
  );
  self.clients.claim();
});

// Primero red, caché solo como respaldo si no hay conexión. Antes era al
// revés (caché primero) y una vez guardado el index.html quedaba pegado
// para siempre: las actualizaciones nunca se veían aunque se publicara
// código nuevo, porque nunca se volvía a pedir por red.
self.addEventListener('fetch', (event) => {
  event.respondWith(
    fetch(event.request)
      .then((res) => {
        const copia = res.clone();
        caches.open(CACHE).then((cache) => cache.put(event.request, copia));
        return res;
      })
      .catch(() => caches.match(event.request))
  );
});
