#ifndef R_BASE64_H
#define R_BASE64_H

#ifdef __cplusplus
extern "C" {
#endif

R_API int r_base64_encode(char *bout, const ut8 *bin, int len);
R_API int r_base64_decode(ut8 *bout, const char *bin, int len);
R_API ut8 *r_base64_decode_dyn(const char *in, int len, int *olen);
R_API char *r_base64_encode_dyn(const ut8 *in, int len);

#ifdef __cplusplus
}
#endif

#endif //  R_BASE64_H
