#ifndef R_TYPES_OVERFLOW_H
#define R_TYPES_OVERFLOW_H

/* preventive math overflow checks */
#if !defined(SZT_ADD_OVFCHK)
#define SZT_ADD_OVFCHK(x,y) ((SIZE_MAX - (x)) < (y))
#endif

#if 0
// ADD
if ((x > 0) && (a > INT_MAX - x)) /* `a + x` would overflow */;
if ((x < 0) && (a < INT_MIN - x)) /* `a + x` would underflow */;
#endif
#define UT64_ADD_OVFCHK(x,y) ((UT64_MAX - (x)) < (y))
#define ST64_ADD_OVFCHK(a,x) ((((x) > 0) && ((a) > ST64_MAX - (x))) || ((x) <0 &&(a)< ST32_MIN - (x)))
#define UT32_ADD_OVFCHK(x,y) ((UT32_MAX - (x)) < (y))
#define ST32_ADD_OVFCHK(a,x) ((((x) > 0) && ((a) > ST32_MAX - (x))) || ((x) <0 &&(a)< ST32_MIN - (x)))
#define UT16_ADD_OVFCHK(x,y) ((UT16_MAX - (x)) < (y))
#define ST16_ADD_OVFCHK(a,x) ((((x) > 0) && ((a) > ST16_MAX - (x))) || (((x) <0) && ((a)< -(x))))
#define UT8_ADD_OVFCHK(x,y) ((UT8_MAX - (x)) < (y))
#define ST8_ADD_OVFCHK(a,x) ((((x) > 0) && ((a) > ST8_MAX - (x))) || ((x) <0 &&(a)< ST8_MIN - (x)))
// SUB
#define UT64_SUB_OVFCHK(a,b) UT64_ADD_OVFCHK(a,-b)
#define ST64_SUB_OVFCHK(a,b) ST64_ADD_OVFCHK(a,-b)
#define UT32_SUB_OVFCHK(a,b) UT32_ADD_OVFCHK(a,-b)
#define ST32_SUB_OVFCHK(a,b) ST32_ADD_OVFCHK(a,-b)
#define UT16_SUB_OVFCHK(a,b) UT16_ADD_OVFCHK(a,-b)
#define ST16_SUB_OVFCHK(a,b) ST16_ADD_OVFCHK(a,-b)
#define UT8_SUB_OVFCHK(a,b) UT8_ADD_OVFCHK(a,-b)
#define ST8_SUB_OVFCHK(a,b) ST8_ADD_OVFCHK(a,-b)

// MUL UT64
#define UT64_MUL_OVFCHK(x,y) ((x) > (UT64_MAX / (y)))
#define ST64_MUL_OVFCHK(x,y) ((x) > (ST64_MAX / (y)))
#define UT32_MUL_OVFCHK(x,y) ((x) > (UT32_MAX / (y)))
#define ST32_MUL_OVFCHK(x,y) ((x) > (ST32_MAX / (y)))
#define UT16_MUL_OVFCHK(x,y) ((x) > (UT16_MAX / (y)))
#define ST16_MUL_OVFCHK(x,y) ((x) > (ST16_MAX / (y)))
#define UT8_MUL_OVFCHK(x,y) ((x) > (UT8_MAX / (y)))
#define ST8_MUL_OVFCHK(x,y) ((x) > (ST8_MAX / (y)))
// #define ST8_MUL_OVFCHK(a,x) ((x>0) && (a)>(ST8_MIN / (x)))
#if 0
// SUB
if ((x < 0) && (a > INT_MAX + x)) /* `a - x` would overflow */;
if ((x > 0) && (a < INT_MIN + x)) /* `a - x` would underflow */;
// MUL
if ((a == -1) && (x == INT_MIN)) /* `a * x` can overflow */
if ((x == -1) && (a == INT_MIN)) /* `a * x` (or `a / x`) can overflow */
if (a > INT_MAX / x) /* `a * x` would overflow */;
if ((a < INT_MIN / x)) /* `a * x` would underflow */;
#endif

#endif
