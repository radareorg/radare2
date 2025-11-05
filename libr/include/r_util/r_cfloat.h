/* radare - LGPL - Copyright 2025 - pancake */

#include <r_types.h>

#ifndef R_UTIL_CFLOATH
#define R_UTIL_CFLOATH

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_cfloat_profile_t {
	int sign_bits;
	int exp_bits;
	int mant_bits;
	int bias;
	bool big_endian;
	bool explicit_leading_bit;
} RCFloatProfile;

#define R_CFLOAT_PROFILE_BINARY16 (RCFloatProfile){1, 5, 10, 15, false, false}
#define R_CFLOAT_PROFILE_BINARY32 (RCFloatProfile){1, 8, 23, 127, false, false}
#define R_CFLOAT_PROFILE_BINARY64 (RCFloatProfile){1, 11, 52, 1023, false, false}
#define R_CFLOAT_PROFILE_BINARY128 (RCFloatProfile){1, 15, 112, 16383, false, false}
#define R_CFLOAT_PROFILE_BFLOAT16 (RCFloatProfile){1, 8, 7, 127, false, false}
#define R_CFLOAT_PROFILE_X87_80 (RCFloatProfile){1, 15, 64, 16383, false, true}
#define R_CFLOAT_PROFILE_VAX_F (RCFloatProfile){1, 8, 23, 64, true, true}
#define R_CFLOAT_PROFILE_VAX_D (RCFloatProfile){1, 8, 55, 64, true, true}
#define R_CFLOAT_PROFILE_VAX_G (RCFloatProfile){1, 11, 52, 1024, true, true}
#define R_CFLOAT_PROFILE_IBM370_SHORT (RCFloatProfile){1, 7, 24, 64, true, true}
#define R_CFLOAT_PROFILE_IBM370_LONG (RCFloatProfile){1, 7, 56, 64, true, true}
#define R_CFLOAT_PROFILE_CRAY_48 (RCFloatProfile){1, 11, 36, 1024, true, false}
#define R_CFLOAT_PROFILE_CRAY_64 (RCFloatProfile){1, 15, 48, 16384, true, false}
#define R_CFLOAT_PROFILE_CRAY_128 (RCFloatProfile){1, 15, 112, 16384, true, false}
#define R_CFLOAT_PROFILE_BFLOAT8 (RCFloatProfile){1, 4, 3, 8, false, false}
#define R_CFLOAT_PROFILE_TF32 (RCFloatProfile){1, 8, 10, 127, false, false}
#define R_CFLOAT_PROFILE_BINARY96 (RCFloatProfile){1, 15, 80, 16383, false, true}
#define R_CFLOAT_PROFILE_BINARY128_IBM (RCFloatProfile){1, 15, 112, 16383, true, true}
#define R_CFLOAT_PROFILE_BINARY256 (RCFloatProfile){1, 19, 236, 262143, false, false}

R_API double r_cfloat_parse(const ut8 *buf, size_t buf_size, const RCFloatProfile *profile);
R_API double r_cfloat_parse_simple(const ut8 *buf, size_t buf_size, int exp_bits, int mant_bits);

R_API bool r_cfloat_write(double value, const RCFloatProfile *profile, ut8 *buf, size_t buf_size);
R_API bool r_cfloat_write_simple(double value, int exp_bits, int mant_bits, ut8 *buf, size_t buf_size);

#ifdef __cplusplus
}
#endif

#endif
