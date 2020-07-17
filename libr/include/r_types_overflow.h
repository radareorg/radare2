#ifndef R_TYPES_OVERFLOW_H
#define R_TYPES_OVERFLOW_H

// TODO: Use CLANG/GCC builtins if available: __builtin_mul_overflow

// ADD
// if ((x > 0) && (a > INT_MAX - x)) /* `a + x` would overflow */;
// if ((x < 0) && (a < INT_MIN - x)) /* `a + x` would underflow */;
#define SZT_ADD_OVFCHK(x,y) ((SIZE_MAX - (x)) < (y))
#define SSZT_ADD_OVFCHK(a,x) ((((x) > 0) && ((a) > SSIZE_MAX - (x))) || ((x) < 0 && (a) < - (x)))
#define UT64_ADD_OVFCHK(x,y) ((UT64_MAX - (x)) < (y))
#define ST64_ADD_OVFCHK(a,x) ((((x) > 0) && ((a) > ST64_MAX - (x))) || ((x) < 0 && (a) < - (x)))
#define UT32_ADD_OVFCHK(x,y) ((UT32_MAX - (x)) < (y))
#define ST32_ADD_OVFCHK(a,x) ((((x) > 0) && ((a) > ST32_MAX - (x))) || (((x) < 0) && (a) < - (x)))
#define UT16_ADD_OVFCHK(x,y) ((UT16_MAX - (x)) < (y))
#define ST16_ADD_OVFCHK(a,b) ( \
	   (((b) > 0) && ((a) > ST16_MAX - (b))) \
	|| (((b) < 0) && ((a) < -(b))) \
)
#define UT8_ADD_OVFCHK(x,y) ((UT8_MAX - (x)) < (y))
#define ST8_ADD_OVFCHK(a,x) ((((x) > 0) && ((a) > ST8_MAX - (x))) || ((x) < 0 && (a) < - (x)))

// SUB
// if ((x < 0) && (a > INT_MAX + x)) /* `a - x` would overflow */;
// if ((x > 0) && (a < INT_MIN + x)) /* `a - x` would underflow */;
#define SZT_SUB_OVFCHK(a,b) SZT_ADD_OVFCHK(a,-(b))
#define SSZT_SUB_OVFCHK(a,b) SSZT_ADD_OVFCHK(a,-(b))
#define UT64_SUB_OVFCHK(a,b) UT64_ADD_OVFCHK(a,-(b))
#define ST64_SUB_OVFCHK(a,b) ST64_ADD_OVFCHK(a,-(b))
#define UT32_SUB_OVFCHK(a,b) UT32_ADD_OVFCHK(a,-(b))
#define ST32_SUB_OVFCHK(a,b) ST32_ADD_OVFCHK(a,-(b))
#define UT16_SUB_OVFCHK(a,b) UT16_ADD_OVFCHK(a,-(b))
#define ST16_SUB_OVFCHK(a,b) ST16_ADD_OVFCHK(a,-(b))
#define UT8_SUB_OVFCHK(a,b) UT8_ADD_OVFCHK(a,-(b))
#define ST8_SUB_OVFCHK(a,b) ST8_ADD_OVFCHK(a,-(b))

// MUL
//if ((a == -1) && (x == INT_MIN)) /* `a * x` can overflow */
//if ((x == -1) && (a == INT_MIN)) /* `a * x` (or `a / x`) can overflow */
//if (a > INT_MAX / x) /* `a * x` would overflow */;
//if ((a < INT_MIN / x)) /* `a * x` would underflow */;
#define SZT_MUL_OVFCHK(x,y) ((y) && (x) > (SIZE_MAX / (y)))
#define SSZT_MUL_OVFCHK(x,y) ((y) && (x) > (SSIZE_MAX / (y)))
#define UT64_MUL_OVFCHK(x,y) ((y) && (x) > (UT64_MAX / (y)))
#define ST64_MUL_OVFCHK(x,y) ((y) && (x) > (ST64_MAX / (y)))
#define UT32_MUL_OVFCHK(x,y) ((y) && (x) > (UT32_MAX / (y)))
#define ST32_MUL_OVFCHK(x,y) ((y) && (x) > (ST32_MAX / (y)))
#define UT16_MUL_OVFCHK(x,y) ((y) && (x) > (UT16_MAX / (y)))
#define ST16_MUL_OVFCHK(x,y) ((y) && (x) > (ST16_MAX / (y)))
#define UT8_MUL_OVFCHK(x,y) ((y) && (x) > (UT8_MAX / (y)))
#define ST8_MUL_OVFCHK(x,y) ((y) && (x) > (ST8_MAX / (y)))

#endif
