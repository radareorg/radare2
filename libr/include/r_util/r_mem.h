#ifndef R_MEM_H
#define R_MEM_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_mmap_t {
	ut8 *buf;
	ut64 base;
	int len;
	int fd;
	int rw;
	char *filename;
#if __WINDOWS__
	HANDLE fh;
	HANDLE fm;
#endif
} RMmap;

typedef struct r_mem_pool_t {
	ut8 **nodes;
	int ncount;
	int npool;
	//
	int nodesize;
	int poolsize;
	int poolcount;
} RMemoryPool;

R_API ut64 r_mem_get_num(const ut8 *b, int size);

/* MEMORY POOL */
R_API RMemoryPool* r_mem_pool_deinit(RMemoryPool *pool);
R_API RMemoryPool *r_mem_pool_new(int nodesize, int poolsize, int poolcount);
R_API RMemoryPool *r_mem_pool_free(RMemoryPool *pool);
R_API void* r_mem_pool_alloc(RMemoryPool *pool);
R_API void *r_mem_dup(const void *s, int l);
R_API void *r_mem_alloc(int sz);
R_API void r_mem_free(void *);
R_API void r_mem_memzero(void *, size_t);
R_API void r_mem_reverse(ut8 *b, int l);
R_API int r_mem_protect(void *ptr, int size, const char *prot);
R_API int r_mem_set_num(ut8 *dest, int dest_size, ut64 num);
R_API int r_mem_eq(ut8 *a, ut8 *b, int len);
R_API void r_mem_copybits(ut8 *dst, const ut8 *src, int bits);
R_API void r_mem_copybits_delta(ut8 *dst, int doff, const ut8 *src, int soff, int bits);
R_API void r_mem_copyloop(ut8 *dest, const ut8 *orig, int dsize, int osize);
R_API void r_mem_swaporcopy(ut8 *dest, const ut8 *src, int len, bool big_endian);
R_API void r_mem_swapendian(ut8 *dest, const ut8 *orig, int size);
R_API int r_mem_cmp_mask(const ut8 *dest, const ut8 *orig, const ut8 *mask, int len);
R_API const ut8 *r_mem_mem(const ut8 *haystack, int hlen, const ut8 *needle, int nlen);
R_API const ut8 *r_mem_mem_aligned(const ut8 *haystack, int hlen, const ut8 *needle, int nlen, int align);
R_API int r_mem_count(const ut8 **addr);
R_API bool r_mem_is_printable (const ut8 *a, int la);
R_API bool r_mem_is_zero(const ut8 *b, int l);
R_API void *r_mem_mmap_resize(RMmap *m, ut64 newsize);

#ifdef __cplusplus
}
#endif
#endif //  R_MEM_H
