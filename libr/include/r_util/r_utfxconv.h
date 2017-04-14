#ifndef R_UTFXCONV_H
#define R_UTFXCONV_H
R_API char *r_utf16_to_utf8(const wchar_t *wc);
R_API wchar_t *r_utf8_to_utf16(const char *cstring);
#endif
