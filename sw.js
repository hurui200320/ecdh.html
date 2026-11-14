// ecdh.html service worker — cache-first app shell.
// Bump CACHE version whenever any file below (or index.html) changes.
const CACHE_PREFIX = "ecdh-html-";
const CACHE = CACHE_PREFIX + "v1-20261115010000";
const ASSETS = ["./", "./index.html", "./crypto.js", "./manifest.json", "./icon.svg"];
const ASSET_URLS = new Set(ASSETS.map((u) => new URL(u, self.location).href));

self.addEventListener("install", (e) => {
  e.waitUntil(
    caches.open(CACHE)
      .then((c) => c.addAll(ASSETS.map((u) => new Request(u, { cache: "reload" }))))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys.filter((k) => k.startsWith(CACHE_PREFIX) && k !== CACHE).map((k) => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;
  let lookup;
  try {
    const url = new URL(req.url);
    if (url.origin !== self.location.origin) return;
    lookup = req.mode === "navigate" ? new URL(url.pathname, url.origin).href : url.href;
  } catch { return; }
  if (!ASSET_URLS.has(lookup)) return;

  e.respondWith(
    caches.open(CACHE).then((c) =>
      c.match(req, { ignoreSearch: req.mode === "navigate" }).then((hit) =>
        hit || fetch(req).catch(() => (req.mode === "navigate" ? c.match("./index.html") : Response.error()))
      )
    )
  );
});
