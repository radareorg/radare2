/* radare2 uefi libc - LGPL - Copyright 2026 - pancake */

#ifndef _MATH_H
#define _MATH_H

#ifdef __cplusplus
extern "C" {
#endif

#define NAN __builtin_nanf ("")
#define INFINITY __builtin_inff ()
#define HUGE_VAL __builtin_huge_val ()
#define HUGE_VALF __builtin_huge_valf ()
#define HUGE_VALL __builtin_huge_vall ()

#define isnan(x) __builtin_isnan (x)
#define isinf(x) __builtin_isinf (x)
#define isfinite(x) __builtin_isfinite (x)
#define signbit(x) __builtin_signbit (x)
#define isnormal(x) __builtin_isnormal (x)

#define M_E 2.7182818284590452354
#define M_LN2 0.69314718055994530942
#define M_LN10 2.30258509299404568402
#define M_LOG2E 1.4426950408889634074
#define M_LOG10E 0.43429448190325182765
#define M_PI 3.14159265358979323846
#define M_PI_2 1.57079632679489661923
#define M_PI_4 0.78539816339744830962
#define M_SQRT2 1.41421356237309504880

#define FP_NAN 0
#define FP_INFINITE 1
#define FP_ZERO 2
#define FP_SUBNORMAL 3
#define FP_NORMAL 4

double floor(double x);
double ceil(double x);
double round(double x);
double trunc(double x);
double fabs(double x);
double fmod(double x, double y);
double sqrt(double x);
double cbrt(double x);
double pow(double x, double y);
double exp(double x);
double exp2(double x);
double log(double x);
double log2(double x);
double log10(double x);
double sin(double x);
double cos(double x);
double tan(double x);
double asin(double x);
double acos(double x);
double atan(double x);
double atan2(double y, double x);
double sinh(double x);
double cosh(double x);
double tanh(double x);
double hypot(double x, double y);
double ldexp(double x, int exp);
double frexp(double x, int *exp);
double modf(double x, double *iptr);
double copysign(double x, double y);
double nearbyint(double x);
double rint(double x);
long lround(double x);
long long llround(double x);
double fmin(double x, double y);
double fmax(double x, double y);

float floorf(float x);
float ceilf(float x);
float roundf(float x);
float truncf(float x);
float fabsf(float x);
float fmodf(float x, float y);
float sqrtf(float x);
float powf(float x, float y);
float expf(float x);
float logf(float x);
float log2f(float x);
float log10f(float x);
float sinf(float x);
float cosf(float x);
float tanf(float x);
float atan2f(float y, float x);
float ldexpf(float x, int exp);
float frexpf(float x, int *exp);
float modff(float x, float *iptr);
float copysignf(float x, float y);
float fminf(float x, float y);
float fmaxf(float x, float y);

long double floorl(long double x);
long double ceill(long double x);
long double fabsl(long double x);
long double fmodl(long double x, long double y);
long double sqrtl(long double x);
long double powl(long double x, long double y);
long double expl(long double x);
long double logl(long double x);
long double modfl(long double x, long double *iptr);
long double ldexpl(long double x, int exp);
long double frexpl(long double x, int *exp);
double scalbn(double x, int n);
long lrint(double x);
long long llrint(double x);
double asinh(double x);
double acosh(double x);
double atanh(double x);
double expm1(double x);
double log1p(double x);
float scalbnf(float x, int n);
long double fminl(long double x, long double y);
long double fmaxl(long double x, long double y);
long double roundl(long double x);
long double truncl(long double x);

#ifdef __cplusplus
}
#endif

#endif /* _MATH_H */
