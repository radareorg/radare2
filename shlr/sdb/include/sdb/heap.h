#ifndef SDB_HEAP_H
#define SDB_HEAP_H 1

typedef void *(*SdbHeapRealloc)(void *data, void *ptr, size_t size);
typedef void (*SdbHeapFini)(void *data);

// global heap apis
typedef struct sdb_global_heap_t {
	SdbHeapRealloc realloc;
	// SdbHeapInit init;
	SdbHeapFini fini;
	void *data;
} SdbGlobalHeap;

extern SdbGlobalHeap Gheap;
extern const SdbGlobalHeap sdb_gh_custom; // custom heap allocator
extern const SdbGlobalHeap sdb_gh_libc; // use libc's heap

static inline void sdb_gh_use(const SdbGlobalHeap *gh) {
	if (gh) {
		memcpy (&Gheap, gh, sizeof (SdbGlobalHeap));
	} else {
		memset (&Gheap, 0, sizeof (SdbGlobalHeap));
	}
}

static inline void sdb_gh_fini(void) {
	if (Gheap.fini) {
		Gheap.fini (Gheap.data);
	}
}

static inline void *sdb_gh_malloc(size_t size) {
	if (Gheap.realloc) {
		void *ptr = Gheap.realloc (Gheap.data, NULL, size);
//		eprintf ("malloc %p\n" , ptr);
		return ptr;
	}
	return malloc (size);
}

static inline void *sdb_gh_realloc(void *ptr, size_t size) {
	if (Gheap.realloc) {
		return Gheap.realloc (Gheap.data, ptr, size);
	}
	return realloc (ptr, size);
}

static inline void sdb_gh_free(void *ptr) {
	if (!ptr) {
		return;
	}
	if (Gheap.realloc) {
// 		eprintf ("free ptr %p\n" , ptr);
		Gheap.realloc (Gheap.data, ptr, 0);
	} else {
		free (ptr);
	}
}

static inline void *sdb_gh_calloc(size_t count, size_t size) {
	size_t total = count * size; // TODO: detect overflow
	void *res = sdb_gh_malloc (total);
	if (res) {
		memset (res, 0, total);
	}
	return res;
}

#endif
