#ifndef R_UTF8_H
#define R_UTF8_H

typedef ut32 RRune;
R_API int r_utf8_encode(ut8 *ptr, const RRune ch);
R_API int r_utf8_decode(const ut8 *ptr, int ptrlen, RRune *ch);
R_API int r_utf8_encode_str(const RRune *str, ut8 *dst, const int dst_length);
R_API int r_utf8_size(const ut8 *ptr);
R_API int r_utf8_strlen(const ut8 *str);
R_API int r_isprint(const RRune c);
R_API char *r_utf16_to_utf8(const wchar_t *wc);
R_API wchar_t *r_utf8_to_utf16(const char *cstring);
#endif //  R_UTF8_H
