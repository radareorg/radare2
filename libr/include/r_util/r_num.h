#ifndef R_NUM_H
#define R_NUM_H

#define R_NUMCALC_STRSZ 1024

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	double d;
	ut64 n;
} RNumCalcValue;

typedef union {
	ut16   u16;
	ut32   u32;
	ut64   u64;
	st16   s16;
	st32   s32;
	st64   s64;
	float  f32;
	double f64;
	/* long double f80; */
} RNumFloat;

typedef enum {
	RNCNAME, RNCNUMBER, RNCEND, RNCINC, RNCDEC,
	RNCLT, RNCGT, // comparison operators
    RNCBNOT, RNCBAND, RNCBOR, RNCBXOR, RNCBXNOR, RNCBEQ, RNCBNEQ,
	RNCPLUS='+', RNCMINUS='-', RNCMUL='*', RNCDIV='/', RNCMOD='%',
	RNCNEG='~', RNCAND='&', RNCOR='|', RNCXOR='^',
	RNCPRINT=';', RNCASSIGN='=', RNCLEFTP='(', RNCRIGHTP=')',
	RNCSHL='<', RNCSHR = '>', RNCROL = '#', RNCROR = '$',
} RNumCalcToken;

typedef struct r_num_calc_t {
	RNumCalcToken curr_tok;
	RNumCalcValue number_value;
	char string_value[R_NUMCALC_STRSZ];
	int errors;
	char oc;
	const char *calc_err; // rename to errstr
	int calc_i;
	const char *calc_buf;
	int calc_len;
	bool under_calc;
} RNumCalc;

typedef struct r_num_t {
	ut64 (*callback)(struct r_num_t *userptr, const char *str, bool *ok);
	const char *(*cb_from_value)(struct r_num_t *userptr, ut64 value, bool *ok);
//	RNumCallback callback;
	ut64 value;
	double fvalue;
	void *userptr;
	int dbz; /// division by zero happened
	RNumCalc nc;
// R2_590 R_REF_TYPE
} RNum;

typedef ut64 (*RNumCallback)(struct r_num_t *self, const char *str, bool *ok);
typedef const char *(*RNumCallback2)(struct r_num_t *self, ut64, bool *ok);

static inline ut64 r_num_bitmask(ut8 width) {
	if (width >= 64) {
		return UT64_MAX;
	}
	return ((ut64)1ULL << (ut64)width) - 1;
}

// R2_600 - make this an api instead of a define
#define r_num_failed(x) ((x)->nc.errors)
R_API RNum *r_num_new(RNumCallback cb, RNumCallback2 cb2, void *ptr);
R_API void r_num_free(RNum *num);
R_API char *r_num_units(char *buf, size_t len, ut64 number);
R_API int r_num_conditional(RNum *num, const char *str);
R_API ut64 r_num_chs(int cylinder, int head, int sector, int sectorsize);
R_API int r_num_is_valid_input(RNum *num, const char *input_value);
R_API ut64 r_num_get_input_value(RNum *num, const char *input_value);
R_API char *r_num_list_join(RList *str, const char *sep);
R_API const char *r_num_get_name(RNum *num, ut64 n);
R_API char* r_num_as_string(RNum *___, ut64 n, bool printable_only);
R_API ut64 r_num_tail(RNum *num, ut64 addr, const char *hex);
R_API ut64 r_num_tail_base(RNum *num, ut64 addr, ut64 off);
R_API bool r_num_segaddr(ut64 addr, ut64 sb, int sg, ut32 *a, ut32 *b);
R_API void r_num_minmax_swap(ut64 *a, ut64 *b);
R_API void r_num_minmax_swap_i(int *a, int *b); // XXX this can be a cpp macro :??

R_API ut64 r_num_get(RNum *num, const char *str);
R_API ut64 r_num_math(RNum *num, const char *str);
R_API ut64 r_num_math_err(RNum *num, const char *str, const char **err);
R_API const char *r_num_math_index(RNum *num, const char *p);

R_API int r_num_to_bits(char *out, ut64 num);
R_API int r_num_to_ternary(char *out, ut64 num);
R_API int r_num_rand(int max);
R_API ut64 r_num_genmask(int max);
R_API void r_num_irand(void);
R_API ut64 r_get_input_num_value(RNum *num, const char *input_value);
R_API bool r_is_valid_input_num_value(RNum *num, const char *input_value);
R_API int r_num_between(RNum *num, const char *input_value);
R_API bool r_num_is_op(const char c);
R_API int r_num_str_len(const char *str);
R_API int r_num_str_split(char *str);
R_API RList *r_num_str_split_list(char *str);
R_API void *r_num_dup(ut64 n);
R_API double r_num_cos(double a);
R_API double r_num_sin(double a);
R_API size_t r_num_bit_count(ut32 val);
R_API size_t r_num_bit_clz32(ut32 val);
R_API size_t r_num_bit_clz64(ut64 val);
R_API size_t r_num_bit_ctz32(ut32 val);
R_API size_t r_num_bit_ctz64(ut64 val);
R_API double r_num_get_double(RNum *num, const char *str);

static inline st64 r_num_abs(st64 num) {
	return num < 0 ? -num : num;
}

#ifdef __cplusplus
}
#endif

#endif //  R_NUM_H
