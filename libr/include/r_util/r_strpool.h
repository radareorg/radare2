#ifndef R_STRPOOL_H
#define R_STRPOOL_H

#define R_STRPOOL_INC 1024

#ifdef __cplusplus
extern "C" {
#endif


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
} RStrpool;

R_API RStrpool* r_strpool_new(void);
R_API void r_strpool_free(RStrpool *p);
R_API void r_strpool_empty(RStrpool *p);
R_API int r_strpool_add(RStrpool *p, const char *s);
R_API int r_strpool_append(RStrpool *p, const char *s);
R_API int r_strpool_get(RStrpool *p, const char *s);
R_API char *r_strpool_get_at(RStrpool *p, int index);
R_API char *r_strpool_get_nth(RStrpool *p, int index);
R_API void r_strpool_slice(RStrpool *p, int index);
#ifdef __cplusplus
}
#endif

#endif //  R_STRPOOL_H
