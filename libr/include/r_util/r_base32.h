#ifndef R2_BASE32_H
#define R2_BASE32_H

#ifdef __cplusplus
extern "C" {
#endif

#if R2_USE_NEW_ABI

#include <r_util/r_base32.h>

R_API char *r_base32_encode(const ut8 *data, size_t input_length, size_t *output_length);
R_API ut8 *r_base32_decode(const char *data, size_t input_length, size_t *output_length);
R_API char *base32_encode_ut64(ut64 input);
R_API ut64 base32_decode_ut64(const char *input);
#endif

#ifdef __cplusplus
}
#endif

#endif
