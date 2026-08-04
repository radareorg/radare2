/* Cache the emulator, bios and disk-image chunks so repeat visits are free.
 * Asset urls carry a ?v=<version> query, so a new build naturally misses the
 * cache; the page's "Clear cache" button wipes everything and reloads. */
"use strict";
var CACHE = "r2ros-v1";
var NETWORK_FIRST = ["/", "/index.html", "/config.js", "/iso.js", "/sw.js"];

self.addEventListener("install", function () {
	self.skipWaiting();
});

self.addEventListener("activate", function (e) {
	e.waitUntil(self.clients.claim());
});

self.addEventListener("fetch", function (e) {
	var req = e.request;
	if (req.method !== "GET") {
		return;
	}
	var url = new URL(req.url);
	if (url.origin !== self.location.origin) {
		return;
	}
	// range requests (disk image chunks) go straight to the network and
	// rely on the regular http cache; caching partial responses is unreliable
	if (req.headers.get("range")) {
		return;
	}
	var leaf = url.pathname.replace(/.*\//, "/");
	if (NETWORK_FIRST.indexOf(leaf) !== -1) {
		e.respondWith(fetch(req).then(function (res) {
			if (res.ok) {
				var copy = res.clone();
				caches.open(CACHE).then(function (c) { c.put(req, copy); });
			}
			return res;
		}).catch(function () {
			return caches.match(req);
		}));
		return;
	}
	e.respondWith(caches.match(req).then(function (hit) {
		if (hit) {
			return hit;
		}
		return fetch(req).then(function (res) {
			if (res.ok) {
				var copy = res.clone();
				caches.open(CACHE).then(function (c) { c.put(req, copy); });
			}
			return res;
		});
	}));
});
