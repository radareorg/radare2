#ifndef R_TYPES_OVERFLOW_H
#define R_TYPES_OVERFLOW_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) || defined(__clang__)
#define R_HAVE_OVERFLOW_BUILTINS 1
#endif

#ifdef R_HAVE_OVERFLOW_BUILTINS

#define SZT_ADD_OVFCHK(x,y) ({ size_t _r; __builtin_add_overflow ((x), (y), &_r); })
#define SSZT_ADD_OVFCHK(a,x) ({ ssize_t _r; __builtin_add_overflow ((a), (x), &_r); })
#define UT64_ADD_OVFCHK(x,y) ({ ut64 _r; __builtin_add_overflow ((x), (y), &_r); })
#define ST64_ADD_OVFCHK(a,x) ({ st64 _r; __builtin_add_overflow ((a), (x), &_r); })
#define UT32_ADD_OVFCHK(x,y) ({ ut32 _r; __builtin_add_overflow ((x), (y), &_r); })
#define ST32_ADD_OVFCHK(a,x) ({ st32 _r; __builtin_add_overflow ((a), (x), &_r); })
#define UT16_ADD_OVFCHK(x,y) ({ ut16 _r; __builtin_add_overflow ((x), (y), &_r); })
#define ST16_ADD_OVFCHK(a,b) ({ st16 _r; __builtin_add_overflow ((a), (b), &_r); })
#define UT8_ADD_OVFCHK(x,y) ({ ut8 _r; __builtin_add_overflow ((x), (y), &_r); })
#define ST8_ADD_OVFCHK(a,x) ({ st8 _r; __builtin_add_overflow ((a), (x), &_r); })

#define SZT_SUB_OVFCHK(a,b) ({ size_t _r; __builtin_sub_overflow ((a), (b), &_r); })
#define SSZT_SUB_OVFCHK(a,b) ({ ssize_t _r; __builtin_sub_overflow ((a), (b), &_r); })
#define UT64_SUB_OVFCHK(a,b) ({ ut64 _r; __builtin_sub_overflow ((a), (b), &_r); })
#define ST64_SUB_OVFCHK(a,b) ({ st64 _r; __builtin_sub_overflow ((a), (b), &_r); })
#define UT32_SUB_OVFCHK(a,b) ({ ut32 _r; __builtin_sub_overflow ((a), (b), &_r); })
#define ST32_SUB_OVFCHK(a,b) ({ st32 _r; __builtin_sub_overflow ((a), (b), &_r); })
#define UT16_SUB_OVFCHK(a,b) ({ ut16 _r; __builtin_sub_overflow ((a), (b), &_r); })
#define ST16_SUB_OVFCHK(a,b) ({ st16 _r; __builtin_sub_overflow ((a), (b), &_r); })
#define UT8_SUB_OVFCHK(a,b) ({ ut8 _r; __builtin_sub_overflow ((a), (b), &_r); })
#define ST8_SUB_OVFCHK(a,b) ({ st8 _r; __builtin_sub_overflow ((a), (b), &_r); })

#define R_BUILTIN_MUL_OVFCHK(type, a, b) ({ type _r; __builtin_mul_overflow ((a), (b), &_r); })

static inline bool SZT_MUL_OVFCHK(size_t a, size_t b) { return R_BUILTIN_MUL_OVFCHK (size_t, a, b); }
static inline bool ST8_MUL_OVFCHK(st8 a, st8 b) { return R_BUILTIN_MUL_OVFCHK (st8, a, b); }
static inline bool ST16_MUL_OVFCHK(st16 a, st16 b) { return R_BUILTIN_MUL_OVFCHK (st16, a, b); }
static inline bool ST32_MUL_OVFCHK(st32 a, st32 b) { return R_BUILTIN_MUL_OVFCHK (st32, a, b); }
static inline bool ST64_MUL_OVFCHK(st64 a, st64 b) { return R_BUILTIN_MUL_OVFCHK (st64, a, b); }
static inline bool UT8_MUL_OVFCHK(ut8 a, ut8 b) { return R_BUILTIN_MUL_OVFCHK (ut8, a, b); }
static inline bool UT16_MUL_OVFCHK(ut16 a, ut16 b) { return R_BUILTIN_MUL_OVFCHK (ut16, a, b); }
static inline bool UT32_MUL_OVFCHK(ut32 a, ut32 b) { return R_BUILTIN_MUL_OVFCHK (ut32, a, b); }
static inline bool UT64_MUL_OVFCHK(ut64 a, ut64 b) { return R_BUILTIN_MUL_OVFCHK (ut64, a, b); }

static inline bool ST8_DIV_OVFCHK(ut8 a, ut8 b) { return (!b || (a == UT8_GT0 && b == UT8_MAX)); }
static inline bool ST16_DIV_OVFCHK(ut16 a, ut16 b) { return (!b || (a == UT16_GT0 && b == UT16_MAX)); }
static inline bool ST32_DIV_OVFCHK(ut32 a, ut32 b) { return (!b || (a == UT32_GT0 && b == UT32_MAX)); }
static inline bool ST64_DIV_OVFCHK(ut64 a, ut64 b) { return (!b || (a == UT64_GT0 && b == UT64_MAX)); }
static inline bool UT8_DIV_OVFCHK(ut8 a, ut8 b) { (void)(a); return !b; }
static inline bool UT16_DIV_OVFCHK(ut16 a, ut16 b) { (void)(a); return !b; }
static inline bool UT32_DIV_OVFCHK(ut32 a, ut32 b) { (void)(a); return !b; }
static inline bool UT64_DIV_OVFCHK(ut64 a, ut64 b) { (void)(a); return !b; }

#else

#define SZT_ADD_OVFCHK(x,y) ((SIZE_MAX - (x)) < (y))
#define SSZT_ADD_OVFCHK(a,x) ((((x) > 0) && ((a) > SSIZE_MAX - (x))) || (((x) < 0) && ((a) < SSIZE_MIN - (x))))
#define UT64_ADD_OVFCHK(x,y) ((UT64_MAX - (x)) < (y))
#define ST64_ADD_OVFCHK(a,x) ((((x) > 0) && ((a) > ST64_MAX - (x))) || (((x) < 0) && ((a) < ST64_MIN - (x))))
#define UT32_ADD_OVFCHK(x,y) ((UT32_MAX - (x)) < (y))
#define ST32_ADD_OVFCHK(a,x) ((((x) > 0) && ((a) > ST32_MAX - (x))) || (((x) < 0) && ((a) < ST32_MIN - (x))))
#define UT16_ADD_OVFCHK(x,y) (((y) > 0x8000) || ((UT16_MAX - (x)) < (y)))
#define ST16_ADD_OVFCHK(a,b) ((((b) > 0) && ((a) > ST16_MAX - (b))) || (((b) < 0) && ((a) < ST16_MIN - (b))))
#define UT8_ADD_OVFCHK(x,y) ((UT8_MAX - (x)) < (y))
#define ST8_ADD_OVFCHK(a,x) ((((x) > 0) && ((a) > ST8_MAX - (x))) || (((x) < 0) && ((a) < ST8_MIN - (x))))

#define SZT_SUB_OVFCHK(a,b) SZT_ADD_OVFCHK(a,-(b))
#define SSZT_SUB_OVFCHK(a,b) SSZT_ADD_OVFCHK(a,-(b))
#define UT64_SUB_OVFCHK(a,b) UT64_ADD_OVFCHK(a,(-(st64)(b)))
#define ST64_SUB_OVFCHK(a,b) ST64_ADD_OVFCHK(a,-(b))
#define UT32_SUB_OVFCHK(a,b) UT32_ADD_OVFCHK(a,(-(st32)(b)))
#define ST32_SUB_OVFCHK(a,b) ST32_ADD_OVFCHK(a,-(b))
#define UT16_SUB_OVFCHK(a,b) ((a) < (b))
#define ST16_SUB_OVFCHK(a,b) ST16_ADD_OVFCHK(a,-(b))
#define UT8_SUB_OVFCHK(a,b) UT8_ADD_OVFCHK(a,(-(st8)(b)))
#define ST8_SUB_OVFCHK(a,b) ST8_ADD_OVFCHK(a,-(b))

#define UNSIGNED_MUL_OVERFLOW_CHECK(overflow_name, type_base, type_min, type_max) \
static inline bool overflow_name(type_base a, type_base b) { \
	return (a > 0 && b > 0 && a > type_max / b); \
}

#define SIGNED_MUL_OVERFLOW_CHECK(overflow_name, type_base, type_min, type_max) \
static inline bool overflow_name(type_base a, type_base b) { \
	if (a > 0) { \
		if (b > 0) { return a > type_max / b; } \
		return b < type_min / a; \
	} \
	if (b > 0) { return a < type_min / b; } \
	return a && b < type_max / a; \
}

#define SIGNED_DIV_OVERFLOW_CHECK(overflow_name, type_base, type_mid, type_max) \
static inline bool overflow_name(type_base a, type_base b) { \
	return (!b || (a == type_mid && b == type_max)); \
}
#define UNSIGNED_DIV_OVERFLOW_CHECK(overflow_name, type_base, type_min, type_max) \
static inline bool overflow_name(type_base a, type_base b) { \
	(void)(a); \
	return !b; \
}

SIGNED_DIV_OVERFLOW_CHECK(ST8_DIV_OVFCHK,  ut8,  UT8_GT0,  UT8_MAX)
SIGNED_DIV_OVERFLOW_CHECK(ST16_DIV_OVFCHK, ut16, UT16_GT0, UT16_MAX)
SIGNED_DIV_OVERFLOW_CHECK(ST32_DIV_OVFCHK, ut32, UT32_GT0, UT32_MAX)
SIGNED_DIV_OVERFLOW_CHECK(ST64_DIV_OVFCHK, ut64, UT64_GT0, UT64_MAX)
UNSIGNED_DIV_OVERFLOW_CHECK(UT8_DIV_OVFCHK,  ut8,  UT8_MIN,  UT8_MAX)
UNSIGNED_DIV_OVERFLOW_CHECK(UT16_DIV_OVFCHK, ut16, UT16_MIN, UT16_MAX)
UNSIGNED_DIV_OVERFLOW_CHECK(UT32_DIV_OVFCHK, ut32, UT32_MIN, UT32_MAX)
UNSIGNED_DIV_OVERFLOW_CHECK(UT64_DIV_OVFCHK, ut64, UT64_MIN, UT64_MAX)
SIGNED_MUL_OVERFLOW_CHECK(ST8_MUL_OVFCHK, st8, ST8_MIN, ST8_MAX)
SIGNED_MUL_OVERFLOW_CHECK(ST16_MUL_OVFCHK, st16, ST16_MIN, ST16_MAX)
SIGNED_MUL_OVERFLOW_CHECK(ST32_MUL_OVFCHK, st32, ST32_MIN, ST32_MAX)
SIGNED_MUL_OVERFLOW_CHECK(ST64_MUL_OVFCHK, st64, ST64_MIN, ST64_MAX)
UNSIGNED_MUL_OVERFLOW_CHECK(SZT_MUL_OVFCHK, size_t, SZT_MIN, SZT_MAX)
UNSIGNED_MUL_OVERFLOW_CHECK(UT8_MUL_OVFCHK, ut8, UT8_MIN, UT8_MAX)
UNSIGNED_MUL_OVERFLOW_CHECK(UT16_MUL_OVFCHK, ut16, UT16_MIN, UT16_MAX)
UNSIGNED_MUL_OVERFLOW_CHECK(UT32_MUL_OVFCHK, ut32, UT32_MIN, UT32_MAX)
UNSIGNED_MUL_OVERFLOW_CHECK(UT64_MUL_OVFCHK, ut64, UT64_MIN, UT64_MAX)

#endif

#ifdef __cplusplus
}
#endif

#endif
