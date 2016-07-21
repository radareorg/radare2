#ifndef R_UTF8_H
#define R_UTF8_H

//typedef wchar_t RRune;
typedef int RRune;
R_API int r_utf8_encode(ut8 *ptr, const RRune ch);
R_API int r_utf8_decode(const ut8 *ptr, int ptrlen, RRune *ch);
R_API int r_utf8_encode_str(const RRune *str, ut8 *dst, const int dst_length);
R_API int r_utf8_size(const ut8 *ptr);
R_API int r_utf8_strlen(const ut8 *str);
R_API int r_isprint(const RRune c);
#endif //  R_UTF8_H
