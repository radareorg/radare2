#ifndef R2_BECH32_H
#define R2_BECH32_H

#ifdef __cplusplus
extern "C" {
#endif

#if R2_USE_NEW_ABI

R_API int bech32_encode(char *output, const char *hrp, const uint8_t *data, size_t data_len, bech32_encoding enc);
R_API bech32_encoding bech32_decode(char *hrp, uint8_t *data, size_t *data_len, const char *input);
#endif

#ifdef __cplusplus
}
#endif

#endif
