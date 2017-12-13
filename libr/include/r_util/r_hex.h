#ifndef R_HEX_H
#define R_HEX_H

#ifdef __cplusplus
extern "C" {
#endif

R_API int r_hex_pair2bin(const char *arg);
R_API int r_hex_str2binmask(const char *in, ut8 *out, ut8 *mask);
R_API int r_hex_str2bin(const char *in, ut8 *out);
R_API int r_hex_bin2str(const ut8 *in, int len, char *out);
R_API char *r_hex_bin2strdup(const ut8 *in, int len);
R_API int r_hex_to_byte(ut8 *val, ut8 c);
R_API int r_hex_str_is_valid(const char *s);
R_API st64 r_hex_bin_truncate(ut64 in, int n);
R_API char *r_hex_from_c(const char *code);
R_API char *r_hex_from_py(const char *code);
R_API char *r_hex_from_code(const char *code);
R_API char *r_hex_no_code(const char *code);
R_API char *r_hex_from_py_str(char *out, const char *code);
R_API char *r_hex_from_py_array(char *out, const char *code);
R_API char *r_hex_from_c_str(char *out, const char **code);
R_API char *r_hex_from_c_array(char *out, const char *code);
#ifdef __cplusplus
}
#endif

#endif //  R_HEX_H
