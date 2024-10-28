#ifndef R_BECH32_H
#define R_BECH32_H

#include <r_util.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	BECH32_ENCODING_NONE,
	BECH32_ENCODING_BECH32,
	BECH32_ENCODING_BECH32M
} bech32_encoding;

// int bech32_encode (char *output, const char *hrp, const uint8_t *data, size_t data_len, bech32_encoding enc);
// bech32_encoding bech32_decode (char *hrp, uint8_t *data, size_t *data_len, const char *input);

#ifdef __cplusplus
}
#endif

#endif // R_BECH32_H
