#ifndef R_BASE64_H
#define R_BASE64_H

#ifdef __cplusplus
extern "C" {
#endif

R_API int r_base64_encode(char *bout, const ut8 *bin, int len);
R_API char *r_base64_encode_dyn(const ut8 *in, int len);
/* Decode standard and url-safe base64. When `strict` is set any invalid
 * character, misaligned length or misplaced padding fails with -1; otherwise
 * invalid bytes are skipped and as much data as possible is recovered.
 * Returns the amount of decoded bytes; `bout` must be able to hold at least
 * `((len / 4) + 1) * 3 + 1` bytes, where `len` is `strlen (bin)` when a
 * negative length is given. */
R_API int r_base64_decode(ut8 *bout, const char *bin, int len, bool strict);
R_API ut8 *r_base64_decode_dyn(const char *in, int len, int *olen, bool strict);

#ifdef __cplusplus
}
#endif

#endif //  R_BASE64_H
