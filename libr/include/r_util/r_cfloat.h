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

// Predefined profiles
static inline const RCFloatProfile r_cfloat_profile_binary16 = {1, 5, 10, 15, false, false};
static inline const RCFloatProfile r_cfloat_profile_binary32 = {1, 8, 23, 127, false, false};
static inline const RCFloatProfile r_cfloat_profile_binary64 = {1, 11, 52, 1023, false, false};
static inline const RCFloatProfile r_cfloat_profile_binary128 = {1, 15, 112, 16383, false, false};
static inline const RCFloatProfile r_cfloat_profile_bfloat16 = {1, 8, 7, 127, false, false};
static inline const RCFloatProfile r_cfloat_profile_x87_80 = {1, 15, 64, 16383, false, true};

R_API double r_cfloat_parse(const ut8 *buf, size_t buf_size, const RCFloatProfile *profile);
R_API double r_cfloat_parse_simple(const ut8 *buf, size_t buf_size, int exp_bits, int mant_bits);

R_API bool r_cfloat_write(double value, const RCFloatProfile *profile, ut8 *buf, size_t buf_size);
R_API bool r_cfloat_write_simple(double value, int exp_bits, int mant_bits, ut8 *buf, size_t buf_size);

#ifdef __cplusplus
}
#endif

#endif
