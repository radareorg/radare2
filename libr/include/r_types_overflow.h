#ifndef R_TYPES_OVERFLOW_H
#define R_TYPES_OVERFLOW_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__has_builtin)
#  if __has_builtin(__builtin_add_overflow) && \
      __has_builtin(__builtin_sub_overflow) && \
      __has_builtin(__builtin_mul_overflow)
#    define R_HAVE_BUILTIN_OVERFLOW 1
#  endif
#endif

#if defined(__GNUC__) && !defined(R_HAVE_BUILTIN_OVERFLOW)
#  define R_HAVE_BUILTIN_OVERFLOW 1
#endif

#define R_DEFINE_UNSIGNED_OVERFLOW(T, TMAX) \
static inline bool r_add_overflow_##T(T a, T b, T *res) { \
	*res = a + b; \
	return *res < a; \
} \
static inline bool r_sub_overflow_##T(T a, T b, T *res) { \
	*res = a - b; \
	return a < b; \
} \
static inline bool r_mul_overflow_##T(T a, T b, T *res) { \
	if (a == 0 || b == 0) { \
		*res = 0; \
		return false; \
	} \
	if (a > (TMAX) / b) { \
		return true; \
	} \
	*res = a * b; \
	return false; \
}

#define R_DEFINE_SIGNED_OVERFLOW(T, TMAX, TMIN) \
static inline bool r_add_overflow_##T(T a, T b, T *res) { \
	if ((b > 0 && a > (TMAX) - b) || \
	    (b < 0 && a < (TMIN) - b)) { \
		return true; \
	} \
	*res = a + b; \
	return false; \
} \
static inline bool r_sub_overflow_##T(T a, T b, T *res) { \
	if ((b < 0 && a > (TMAX) + b) || \
	    (b > 0 && a < (TMIN) + b)) { \
		return true; \
	} \
	*res = a - b; \
	return false; \
} \
static inline bool r_mul_overflow_##T(T a, T b, T *res) { \
	if (a == 0 || b == 0) { \
		*res = 0; \
		return false; \
	} \
	if (a == -1 && b == (TMIN)) { return true; } \
	if (b == -1 && a == (TMIN)) { return true; } \
	if (a > 0) { \
		if (b > 0) { \
			if (a > (TMAX) / b) { return true; } \
		} else { \
			if (b < (TMIN) / a) { return true; } \
		} \
	} else { \
		if (b > 0) { \
			if (a < (TMIN) / b) { return true; } \
		} else { \
			if (a != 0 && b < (TMAX) / a) { return true; } \
		} \
	} \
	*res = a * b; \
	return false; \
}

R_DEFINE_UNSIGNED_OVERFLOW(ut8,  UT8_MAX)
R_DEFINE_UNSIGNED_OVERFLOW(ut16, UT16_MAX)
R_DEFINE_UNSIGNED_OVERFLOW(ut32, UT32_MAX)
R_DEFINE_UNSIGNED_OVERFLOW(ut64, UT64_MAX)
R_DEFINE_UNSIGNED_OVERFLOW(size_t, SIZE_MAX)

R_DEFINE_SIGNED_OVERFLOW(st8,  ST8_MAX,  ST8_MIN)
R_DEFINE_SIGNED_OVERFLOW(st16, ST16_MAX, ST16_MIN)
R_DEFINE_SIGNED_OVERFLOW(st32, ST32_MAX, ST32_MIN)
R_DEFINE_SIGNED_OVERFLOW(st64, ST64_MAX, ST64_MIN)
R_DEFINE_SIGNED_OVERFLOW(ssize_t, SSZT_MAX, SSZT_MIN)

#if R_HAVE_BUILTIN_OVERFLOW

#define r_add_overflow(a,b,res) __builtin_add_overflow((a),(b),(res))
#define r_sub_overflow(a,b,res) __builtin_sub_overflow((a),(b),(res))
#define r_mul_overflow(a,b,res) __builtin_mul_overflow((a),(b),(res))

#elif defined(_MSC_VER) || !defined(__STDC_VERSION__) || __STDC_VERSION__ < 201112L

#define r_add_overflow(a,b,res) \
	(sizeof(*(res)) == 1 && sizeof(a) == 1 && sizeof(b) == 1 \
		? (*(res) = (a) + (b), *(res) < (a)) \
		: (sizeof(*(res)) == 2 ? r_add_overflow_ut16((ut16)(a), (ut16)(b), (ut16*)(res)) \
		: (sizeof(*(res)) == 4 ? r_add_overflow_ut32((ut32)(a), (ut32)(b), (ut32*)(res)) \
		: r_add_overflow_ut64((ut64)(a), (ut64)(b), (ut64*)(res)))))

#define r_sub_overflow(a,b,res) \
	(sizeof(*(res)) == 1 && sizeof(a) == 1 && sizeof(b) == 1 \
		? (*(res) = (a) - (b), (a) < (b)) \
		: (sizeof(*(res)) == 2 ? r_sub_overflow_ut16((ut16)(a), (ut16)(b), (ut16*)(res)) \
		: (sizeof(*(res)) == 4 ? r_sub_overflow_ut32((ut32)(a), (ut32)(b), (ut32*)(res)) \
		: r_sub_overflow_ut64((ut64)(a), (ut64)(b), (ut64*)(res)))))

#define r_mul_overflow(a,b,res) \
	(sizeof(*(res)) == 1 && sizeof(a) == 1 && sizeof(b) == 1 \
		? r_mul_overflow_ut8((ut8)(a), (ut8)(b), (ut8*)(res)) \
		: (sizeof(*(res)) == 2 ? r_mul_overflow_ut16((ut16)(a), (ut16)(b), (ut16*)(res)) \
		: (sizeof(*(res)) == 4 ? r_mul_overflow_ut32((ut32)(a), (ut32)(b), (ut32*)(res)) \
		: r_mul_overflow_ut64((ut64)(a), (ut64)(b), (ut64*)(res)))))

#else

#define r_add_overflow(a,b,res) _Generic(*(res), \
	ut8:    r_add_overflow_ut8,  \
	ut16:   r_add_overflow_ut16, \
	ut32:   r_add_overflow_ut32, \
	ut64:   r_add_overflow_ut64, \
	size_t: r_add_overflow_size_t, \
	st8:    r_add_overflow_st8,  \
	st16:   r_add_overflow_st16, \
	st32:   r_add_overflow_st32, \
	st64:   r_add_overflow_st64, \
	ssize_t: r_add_overflow_ssize_t \
)(a,b,res)

#define r_sub_overflow(a,b,res) _Generic(*(res), \
	ut8:    r_sub_overflow_ut8,  \
	ut16:   r_sub_overflow_ut16, \
	ut32:   r_sub_overflow_ut32, \
	ut64:   r_sub_overflow_ut64, \
	size_t: r_sub_overflow_size_t, \
	st8:    r_sub_overflow_st8,  \
	st16:   r_sub_overflow_st16, \
	st32:   r_sub_overflow_st32, \
	st64:   r_sub_overflow_st64, \
	ssize_t: r_sub_overflow_ssize_t \
)(a,b,res)

#define r_mul_overflow(a,b,res) _Generic(*(res), \
	ut8:    r_mul_overflow_ut8,  \
	ut16:   r_mul_overflow_ut16, \
	ut32:   r_mul_overflow_ut32, \
	ut64:   r_mul_overflow_ut64, \
	size_t: r_mul_overflow_size_t, \
	st8:    r_mul_overflow_st8,  \
	st16:   r_mul_overflow_st16, \
	st32:   r_mul_overflow_st32, \
	st64:   r_mul_overflow_st64, \
	ssize_t: r_mul_overflow_ssize_t \
)(a,b,res)

#endif

static inline bool r_div_overflow_st8(st8 a, st8 b) { return (!b || (a == ST8_MIN && b == -1)); }
static inline bool r_div_overflow_st16(st16 a, st16 b) { return (!b || (a == ST16_MIN && b == -1)); }
static inline bool r_div_overflow_st32(st32 a, st32 b) { return (!b || (a == ST32_MIN && b == -1)); }
static inline bool r_div_overflow_st64(st64 a, st64 b) { return (!b || (a == ST64_MIN && b == -1)); }
static inline bool r_div_overflow_ut8(ut8 a, ut8 b) { (void)(a); return !b; }
static inline bool r_div_overflow_ut16(ut16 a, ut16 b) { (void)(a); return !b; }
static inline bool r_div_overflow_ut32(ut32 a, ut32 b) { (void)(a); return !b; }
static inline bool r_div_overflow_ut64(ut64 a, ut64 b) { (void)(a); return !b; }

#define SZT_ADD_OVFCHK(a,b) ({ size_t _r; r_add_overflow ((a), (b), &_r); })
#define SSZT_ADD_OVFCHK(a,b) ({ ssize_t _r; r_add_overflow ((a), (b), &_r); })
#define UT64_ADD_OVFCHK(a,b) ({ ut64 _r; r_add_overflow ((a), (b), &_r); })
#define ST64_ADD_OVFCHK(a,b) ({ st64 _r; r_add_overflow ((a), (b), &_r); })
#define UT32_ADD_OVFCHK(a,b) ({ ut32 _r; r_add_overflow ((a), (b), &_r); })
#define ST32_ADD_OVFCHK(a,b) ({ st32 _r; r_add_overflow ((a), (b), &_r); })
#define UT16_ADD_OVFCHK(a,b) ({ ut16 _r; r_add_overflow ((a), (b), &_r); })
#define ST16_ADD_OVFCHK(a,b) ({ st16 _r; r_add_overflow ((a), (b), &_r); })
#define UT8_ADD_OVFCHK(a,b) ({ ut8 _r; r_add_overflow ((a), (b), &_r); })
#define ST8_ADD_OVFCHK(a,b) ({ st8 _r; r_add_overflow ((a), (b), &_r); })

#define SZT_SUB_OVFCHK(a,b) ({ size_t _r; r_sub_overflow ((a), (b), &_r); })
#define SSZT_SUB_OVFCHK(a,b) ({ ssize_t _r; r_sub_overflow ((a), (b), &_r); })
#define UT64_SUB_OVFCHK(a,b) ({ ut64 _r; r_sub_overflow ((a), (b), &_r); })
#define ST64_SUB_OVFCHK(a,b) ({ st64 _r; r_sub_overflow ((a), (b), &_r); })
#define UT32_SUB_OVFCHK(a,b) ({ ut32 _r; r_sub_overflow ((a), (b), &_r); })
#define ST32_SUB_OVFCHK(a,b) ({ st32 _r; r_sub_overflow ((a), (b), &_r); })
#define UT16_SUB_OVFCHK(a,b) ({ ut16 _r; r_sub_overflow ((a), (b), &_r); })
#define ST16_SUB_OVFCHK(a,b) ({ st16 _r; r_sub_overflow ((a), (b), &_r); })
#define UT8_SUB_OVFCHK(a,b) ({ ut8 _r; r_sub_overflow ((a), (b), &_r); })
#define ST8_SUB_OVFCHK(a,b) ({ st8 _r; r_sub_overflow ((a), (b), &_r); })

#define SZT_MUL_OVFCHK(a,b) ({ size_t _r; r_mul_overflow ((a), (b), &_r); })
#define UT64_MUL_OVFCHK(a,b) ({ ut64 _r; r_mul_overflow ((a), (b), &_r); })
#define ST64_MUL_OVFCHK(a,b) ({ st64 _r; r_mul_overflow ((a), (b), &_r); })
#define UT32_MUL_OVFCHK(a,b) ({ ut32 _r; r_mul_overflow ((a), (b), &_r); })
#define ST32_MUL_OVFCHK(a,b) ({ st32 _r; r_mul_overflow ((a), (b), &_r); })
#define UT16_MUL_OVFCHK(a,b) ({ ut16 _r; r_mul_overflow ((a), (b), &_r); })
#define ST16_MUL_OVFCHK(a,b) ({ st16 _r; r_mul_overflow ((a), (b), &_r); })
#define UT8_MUL_OVFCHK(a,b) ({ ut8 _r; r_mul_overflow ((a), (b), &_r); })
#define ST8_MUL_OVFCHK(a,b) ({ st8 _r; r_mul_overflow ((a), (b), &_r); })

#define ST64_DIV_OVFCHK(a,b) r_div_overflow_st64 ((a), (b))
#define ST32_DIV_OVFCHK(a,b) r_div_overflow_st32 ((a), (b))
#define ST16_DIV_OVFCHK(a,b) r_div_overflow_st16 ((a), (b))
#define ST8_DIV_OVFCHK(a,b) r_div_overflow_st8 ((a), (b))
#define UT64_DIV_OVFCHK(a,b) r_div_overflow_ut64 ((a), (b))
#define UT32_DIV_OVFCHK(a,b) r_div_overflow_ut32 ((a), (b))
#define UT16_DIV_OVFCHK(a,b) r_div_overflow_ut16 ((a), (b))
#define UT8_DIV_OVFCHK(a,b) r_div_overflow_ut8 ((a), (b))

#ifdef __cplusplus
}
#endif

#endif
