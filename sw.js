// SPDX-License-Identifier: AGPL-3.0-or-later
// ecdh.html service worker — cache-first app shell.
// Bump CACHE version whenever any file below (or index.html) changes.
const CACHE_PREFIX = "ecdh-html-";
const CACHE = CACHE_PREFIX + "v1-20261115030000";
const ASSETS = ["./", "./index.html", "./crypto.js", "./manifest.json", "./icon.svg"];
const ASSET_URLS = new Set(ASSETS.map((u) => new URL(u, self.location).href));

self.addEventListener("install", (e) => {
  e.waitUntil(
    caches.open(CACHE)
      .then((c) => Promise.all(ASSETS.map(async (u) => {
        const res = await fetch(new Request(u, { cache: "reload" }));
        if (!res.ok) throw new Error("Cache install failed for " + u + ": " + res.status);
        await c.put(u, res.redirected
          ? new Response(res.body, { status: res.status, statusText: res.statusText, headers: res.headers })
          : res);
      })))
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
        hit || fetch(req).catch(() =>
          (req.mode === "navigate" ? c.match("./").then((r) => r || c.match("./index.html")) : Response.error())
        )
      )
    )
  );
});
