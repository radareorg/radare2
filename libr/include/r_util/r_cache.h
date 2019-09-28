#ifndef R_CACHE_H
#define R_CACHE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_cache_t {
	ut64 base;
	ut8 *buf;
	ut64 len;
} RCache;

typedef struct r_prof_t {
	struct timeval begin;
	double result;
} RProfile;

R_API RCache* r_cache_new(void);
R_API void r_cache_free(RCache *c);
R_API const ut8* r_cache_get(RCache *c, ut64 addr, int *len);
R_API int r_cache_set(RCache *c, ut64 addr, const ut8 *buf, int len);
R_API void r_cache_flush(RCache *c);
R_API void r_prof_start(RProfile *p);
R_API double r_prof_end(RProfile *p);

#ifdef __cplusplus
}
#endif
#endif //  R_CACHE_H
