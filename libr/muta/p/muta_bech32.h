#ifndef R2_BECH32_H
#define R2_BECH32_H

#ifdef __cplusplus
extern "C" {
#endif

R_API int bech32_encode(char *output, const char *hrp, const uint8_t *data, size_t data_len, bech32_encoding enc);
R_API bech32_encoding bech32_decode(char *hrp, uint8_t *data, size_t *data_len, const char *input);

#ifdef __cplusplus
}
#endif

#endif
