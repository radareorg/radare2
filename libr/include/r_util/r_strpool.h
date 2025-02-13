#ifndef R_STRPOOL_H
#define R_STRPOOL_H

#define R_STRPOOL_INC 1024

#ifdef __cplusplus
extern "C" {
#endif

#if 1
// R2_600 -deprecate this api, just keep the new r_ustrpool

typedef struct {
	char *str; // single allocation with all the strings
	int len;   // sum(strlen(str*))
	int size;  // size of str allocation
} RStrpool;

R_API RStrpool* r_strpool_new(void);
R_API char *r_strpool_alloc(RStrpool *p, int l);
R_API int r_strpool_memcat(RStrpool *p, const char *s, int len);
R_API int r_strpool_ansi_trim(RStrpool *p, int n);
R_API int r_strpool_append(RStrpool *p, const char *s);
R_API void r_strpool_free(RStrpool *p);
R_API int r_strpool_fit(RStrpool *p);
R_API char *r_strpool_get(RStrpool *p, int index);
R_API char *r_strpool_get_i(RStrpool *p, int index);
R_API int r_strpool_get_index(RStrpool *p, const char *s);
R_API char *r_strpool_next(RStrpool *p, int index);
R_API char *r_strpool_slice(RStrpool *p, int index);

#endif

R_API char *r_strpool_empty(RStrpool *p);

typedef struct {
	char *str; // single allocation with all the strings
	int len;   // sum(strlen(str*))
	int size;  // size of str allocation
	/////////  // /////////////////////////
	int count; // amount of strings in pool
	int isize; // size of idxs allocation
	ut32 *idxs; // indexes
	ut32 *sidx; // sorted index -- not yet used
	RBloom *bloom;
} RUStrpool;

R_API RUStrpool* r_ustrpool_new(void);
R_API void r_ustrpool_free(RUStrpool *p);

R_API int r_ustrpool_add(RUStrpool *p, const char *s);
R_API int r_ustrpool_append(RUStrpool *p, const char *s);
R_API int r_ustrpool_get(RUStrpool *p, const char *s);
R_API char *r_ustrpool_get_at(RUStrpool *p, int index);
R_API char *r_ustrpool_get_nth(RUStrpool *p, int index);
#ifdef __cplusplus
}
#endif

#endif //  R_STRPOOL_H
