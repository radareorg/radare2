#ifndef R_PJ_H
#define R_PJ_H 1
#define R_PRINT_JSON_DEPTH_LIMIT 128

#include <r_util/r_strbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

/* new encoding options of j commands */
typedef enum PJEncodingStr {
	PJ_ENCODING_STR_DEFAULT = 0,
	PJ_ENCODING_STR_BASE64,
	PJ_ENCODING_STR_HEX,
	PJ_ENCODING_STR_ARRAY,
	PJ_ENCODING_STR_STRIP
} PJEncodingStr;

typedef enum PJEncodingNum {
	PJ_ENCODING_NUM_DEFAULT = 0,
	PJ_ENCODING_NUM_STR,
	PJ_ENCODING_NUM_HEX
} PJEncodingNum;

typedef struct pj_t {
	RStrBuf sb;
	bool is_first;
	bool is_key;
	char braces[R_PRINT_JSON_DEPTH_LIMIT];
	int level;
	PJEncodingStr str_encoding;
	PJEncodingNum num_encoding;
} PJ;

/* lifecycle */
R_API PJ *pj_new(void);
R_API PJ *pj_new_with_encoding(PJEncodingStr str_encoding, PJEncodingNum num_encoding);
R_API void pj_free(PJ *j);
R_API void pj_reset(PJ *j); // clear the pj contents, but keep the buffer allocated to re-use it
R_API char *pj_drain(PJ *j);
/* encode the pj data as a string */
R_API const char *pj_string(PJ *pj);
// R_API void pj_print(PJ *j, PrintfCallback cb);

/* nesting */
//R_API PJ *pj_begin(char type, PrintfCallback cb);
/* close the current json list or array */
R_API PJ *pj_end(PJ *j);
R_API void pj_raw(PJ *j, const char *k);

/* object, array */
/* open new json list { */
R_API PJ *pj_o(PJ *j);
/* open new array [ */
R_API PJ *pj_a(PJ *j);

/* keys, values */
/* new key with no value "name": */
R_API PJ *pj_k(PJ *j, const char *k);
/* "name":"null" */
R_API PJ *pj_knull(PJ *j, const char *k);
/* unsigned "name":n */
R_API PJ *pj_kn(PJ *j, const char *k, ut64 n);
/* signed "name":n */
R_API PJ *pj_kN(PJ *j, const char *k, st64 n);
/* literal key "name":"key" */
R_API PJ *pj_ks(PJ *j, const char *k, const char *v);

/* begin named array entry: "name": [...] */
R_API PJ *pj_ka(PJ *j, const char *k);
/* begin named json entry: "name": {...} */
R_API PJ *pj_ko(PJ *j, const char *k);

/* named entry for primitive types */
R_API PJ *pj_ki(PJ *j, const char *k, int d);
R_API PJ *pj_kd(PJ *j, const char *k, double d);
R_API PJ *pj_kf(PJ *j, const char *k, float d);
R_API PJ *pj_kb(PJ *j, const char *k, bool v);

/* named "null" */
R_API PJ *pj_null(PJ *j);

/* append all uchars in v as signed ints (?) */
R_API PJ *pj_r(PJ *j, const unsigned char *v, size_t v_len);

/* named entry with pj_r */
R_API PJ *pj_kr(PJ *j, const char *k, const unsigned char *v, size_t v_len);

/* string, escaped for json */
R_API PJ *pj_s(PJ *j, const char *k);
/* string, raw */
R_API PJ *pj_j(PJ *j, const char *k);
/* string, encoded */
R_API PJ *pj_se(PJ *j, const char *k);
/* ut64, encoded */
R_API PJ *pj_ne(PJ *j, ut64 n);

/* formatted primitive types */
R_API PJ *pj_n(PJ *j, ut64 n);
R_API PJ *pj_N(PJ *j, st64 n);
R_API PJ *pj_i(PJ *j, int d);
R_API PJ *pj_d(PJ *j, double d);
R_API PJ *pj_f(PJ *j, float d);
R_API PJ *pj_b(PJ *j, bool v);

#ifdef __cplusplus
}
#endif

#endif

