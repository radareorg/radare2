#ifndef R_STRPOOL_H
#define R_STRPOOL_H

#define R_STRPOOL_INC 1024

typedef struct {
	char *str;
	int len;
	int size;
} RStrpool;

R_API RStrpool* r_strpool_new(int sz);
R_API char *r_strpool_alloc(RStrpool *p, int l);
R_API int r_strpool_memcat(RStrpool *p, const char *s, int len);
R_API int r_strpool_ansi_chop(RStrpool *p, int n);
R_API int r_strpool_append(RStrpool *p, const char *s);
R_API void r_strpool_free(RStrpool *p);
R_API int r_strpool_fit(RStrpool *p);
R_API char *r_strpool_get(RStrpool *p, int index);
R_API char *r_strpool_get_i(RStrpool *p, int index);
R_API int r_strpool_get_index(RStrpool *p, const char *s);
R_API char *r_strpool_next(RStrpool *p, int index);
R_API char *r_strpool_slice(RStrpool *p, int index);
R_API char *r_strpool_empty(RStrpool *p);
#endif //  R_STRPOOL_H
