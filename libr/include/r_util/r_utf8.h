#ifndef R_UTF8_H
#define R_UTF8_H

/* For RStrEnc definition */
#include "r_str.h"

typedef struct { ut32 from, to; const char *name; } RUtfBlock;
// extern const RUtfBlock r_utf_blocks[];

typedef ut32 RRune;
R_API int r_utf8_encode(ut8 *ptr, const RRune ch);
R_API int r_utf8_decode(const ut8 *ptr, int ptrlen, RRune *ch);
R_API int r_utf8_encode_str(const RRune *str, ut8 *dst, const int dst_length);
R_API int r_utf8_size(const ut8 *ptr);
R_API int r_utf8_strlen(const ut8 *str);
R_API int r_isprint(const RRune c);
R_API char *r_utf16_to_utf8_l(const wchar_t *wc, int len);
R_API const char *r_utf_block_name(int idx);
R_API wchar_t *r_utf8_to_utf16_l(const char *cstring, int len);
R_API int r_utf_block_idx (RRune ch);
R_API int *r_utf_block_list (const ut8 *str, int len, int **freq_list);
R_API RStrEnc r_utf_bom_encoding(const ut8 *ptr, int ptrlen);
#define r_utf16_to_utf8(wc) r_utf16_to_utf8_l ((wchar_t *)wc, -1)
#define r_utf8_to_utf16(cstring) r_utf8_to_utf16_l ((char *)cstring, -1)
#if __WINDOWS__
R_API char *r_acp_to_utf8_l(const char *str, int len);
R_API char *r_utf8_to_acp_l(const char *str, int len);
#define r_acp_to_utf8(str) r_acp_to_utf8_l ((char *)str, -1)
#define r_utf8_to_acp(cstring) r_utf8_to_acp_l ((char *)cstring, -1)
#endif // __WINDOWS__

#endif //  R_UTF8_H
