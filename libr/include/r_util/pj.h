#ifndef R_PJ_H
#define R_PJ_H 1
#define R_PRINT_JSON_DEPTH_LIMIT 128

#include <r_util/r_strbuf.h>

typedef struct pj_t {
	RStrBuf *sb;
	bool is_first;
	bool is_key;
	char braces[R_PRINT_JSON_DEPTH_LIMIT];
	int level;
} PJ;

/* lifecycle */
R_API PJ *pj_new(void);
R_API void pj_free(PJ *j);
R_API char *pj_drain(PJ *j);
R_API const char *pj_string(PJ *pj);
// R_API void pj_print(PJ *j, PrintfCallback cb);

/* nesting */
//R_API PJ *pj_begin(char type, PrintfCallback cb);
R_API PJ *pj_end(PJ *j);
R_API char *pj_fmt(PrintfCallback p, const char *fmt, ...);
/* object, array */
R_API PJ *pj_o(PJ *j);
R_API PJ *pj_a(PJ *j);
/* keys, values */
R_API PJ *pj_k(PJ *j, const char *k);
R_API PJ *pj_knull(PJ *j, const char *k);
R_API PJ *pj_kn(PJ *j, const char *k, ut64 n);
R_API PJ *pj_kN(PJ *j, const char *k, st64 n);
R_API PJ *pj_ks(PJ *j, const char *k, const char *v);
R_API PJ *pj_ki(PJ *j, const char *k, int d);
R_API PJ *pj_kd(PJ *j, const char *k, double d);
R_API PJ *pj_kf(PJ *j, const char *k, float d);
R_API PJ *pj_kb(PJ *j, const char *k, bool v);
R_API PJ *pj_null(PJ *j);
R_API PJ *pj_b(PJ *j, bool v);
R_API PJ *pj_s(PJ *j, const char *k);
R_API PJ *pj_n(PJ *j, ut64 n);
R_API PJ *pj_N(PJ *j, st64 n);
R_API PJ *pj_d(PJ *j, double d);
R_API PJ *pj_f(PJ *j, float d);
R_API PJ *pj_i(PJ *j, int d);
R_API PJ *pj_j(PJ *j, const char *k);
#endif

