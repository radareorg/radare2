#ifndef R_BASE91_H
#define R_BASE91_H

#ifdef __cplusplus
extern "C" {
#endif

/* Encode `len` bytes. `bout` must hold at least `((len * 16) / 13) + 3` bytes,
 * where `len` is `strlen (bin)` when a negative length is given. The output is
 * not NUL terminated; the amount of written chars is returned. */
R_API int r_base91_encode(char *bout, const ut8 *bin, int len);
/* Decode `len` chars. `bout` must hold at least `((len * 7) / 8) + 3` bytes.
 * Returns the amount of decoded bytes. */
R_API int r_base91_decode(ut8 *bout, const char *bin, int len);
/* Allocating variants that size the output buffer themselves. The encoded
 * string is NUL terminated; the decoded buffer is not, so it reports its
 * length through `olen` when that is not NULL. */
R_API char *r_base91_encode_dyn(const ut8 *bin, int len);
R_API ut8 *r_base91_decode_dyn(const char *bin, int len, int *olen);

#ifdef __cplusplus
}
#endif

#endif //  R_BASE91_H
