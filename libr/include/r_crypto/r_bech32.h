#ifndef R_BECH32_H // is this file still useful ?
#define R_BECH32_H

#include <r_util.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// int bech32_encode (char *output, const char *hrp, const uint8_t *data, size_t data_len, bech32_encoding enc);
// bech32_encoding bech32_decode (char *hrp, uint8_t *data, size_t *data_len, const char *input);

#ifdef __cplusplus
}
#endif

#endif // R_BECH32_H
