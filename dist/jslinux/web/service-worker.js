/* R2_CACHE_NAME and R2_OFFLINE_FILES are generated above this template. */
const R2_CACHE_PREFIX = "jslr2-offline-";

async function r2_broadcast(message) {
	try {
		const windows = await self.clients.matchAll({
			type: "window",
			includeUncontrolled: true
		});
		for (const window of windows) {
			window.postMessage(message);
		}
	} catch (e) {
	}
}

function r2_is_disk_block(file) {
	return /^root-r2\/blk[0-9]+\.bin$/.test(file);
}

async function r2_precache_shell() {
	const cache = await caches.open(R2_CACHE_NAME);
	const files = R2_OFFLINE_FILES.filter(function (file) {
		return !r2_is_disk_block(file);
	});
	try {
		for (const file of files) {
			const url = new URL(file, self.registration.scope);
			const request = new Request(url.href, {
				cache: "no-cache",
				credentials: "same-origin"
			});
			const cached = await cache.match(request);
			if (!cached) {
				const response = await fetch(request);
				if (!response.ok) {
					throw new Error(url.pathname + " returned HTTP " + response.status);
				}
				await cache.put(request, response);
			}
		}
	} catch (e) {
		await r2_broadcast({
			type: "r2-cache-error",
			message: e.message || String(e)
		});
		throw e;
	}
}

self.addEventListener("install", function (event) {
	event.waitUntil(r2_precache_shell().then(function () {
		return self.skipWaiting();
	}));
});

self.addEventListener("activate", function (event) {
	event.waitUntil((async function () {
		const names = await caches.keys();
		await Promise.all(names.map(function (name) {
			if (name.indexOf(R2_CACHE_PREFIX) === 0 && name !== R2_CACHE_NAME) {
				return caches.delete(name);
			}
			return Promise.resolve(false);
		}));
		await self.clients.claim();
	})());
});

self.addEventListener("fetch", function (event) {
	if (event.request.method !== "GET") {
		return;
	}
	/* The foreground downloader owns these sequential writes. Avoid a second
	 * cache.put() here and let the request use the normal network path. */
	if (event.request.headers.get("X-JSLinux-Precache") === "1") {
		return;
	}
	const url = new URL(event.request.url);
	const scope = new URL(self.registration.scope);
	if (url.origin !== scope.origin || url.pathname.indexOf(scope.pathname) !== 0) {
		return;
	}

	event.respondWith((async function () {
		const cache = await caches.open(R2_CACHE_NAME);
		const cached = await cache.match(event.request, { ignoreSearch: true });
		if (cached) {
			return cached;
		}
		try {
			const response = await fetch(event.request);
			if (response.ok) {
				const storing = cache.put(event.request, response.clone()).catch(function () {});
				try {
					event.waitUntil(storing);
				} catch (e) {
				}
			}
			return response;
		} catch (e) {
			if (event.request.mode === "navigate") {
				const shell = await cache.match(new URL("./", scope));
				if (shell) {
					return shell;
				}
			}
			throw e;
		}
	})());
});
