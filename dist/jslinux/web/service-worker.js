/* R2_CACHE_NAME and R2_OFFLINE_FILES are generated above this template. */
const R2_CACHE_PREFIX = "jslr2-offline-";
const R2_CACHE_WORKERS = 4;

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

async function r2_precache() {
	const cache = await caches.open(R2_CACHE_NAME);
	const total = R2_OFFLINE_FILES.length;
	let cursor = 0;
	let done = 0;
	let failure = null;

	await r2_broadcast({ type: "r2-cache-progress", done: 0, total: total });

	async function cache_next() {
		while (!failure) {
			const index = cursor++;
			if (index >= total) {
				return;
			}
			const url = new URL(R2_OFFLINE_FILES[index], self.registration.scope);
			const request = new Request(url.href, {
				cache: "reload",
				credentials: "same-origin"
			});
			try {
				const cached = await cache.match(request);
				if (!cached) {
					const response = await fetch(request);
					if (!response.ok) {
						throw new Error(url.pathname + " returned HTTP " + response.status);
					}
					await cache.put(request, response);
				}
				done++;
				if (!(done % R2_CACHE_WORKERS) || done === total) {
					await r2_broadcast({
						type: "r2-cache-progress",
						done: done,
						total: total
					});
				}
			} catch (e) {
				failure = e;
			}
		}
	}

	const workers = [];
	for (let i = 0; i < R2_CACHE_WORKERS; i++) {
		workers.push(cache_next());
	}
	await Promise.all(workers);
	if (failure) {
		await r2_broadcast({
			type: "r2-cache-error",
			message: failure.message || String(failure)
		});
		throw failure;
	}
	await r2_broadcast({ type: "r2-cache-ready" });
}

self.addEventListener("install", function (event) {
	event.waitUntil(r2_precache().then(function () {
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
				await cache.put(event.request, response.clone());
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
