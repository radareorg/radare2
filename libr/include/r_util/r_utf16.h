#ifndef R_UTF16_H
#define R_UTF16_H

#ifdef __cplusplus
extern "C" {
#endif

/* For RRune definition */
#include "r_utf8.h"

R_API int r_utf16_decode(const ut8 *ptr, int ptrlen, RRune *ch, bool bigendian);
R_API int r_utf16le_decode(const ut8 *ptr, int ptrlen, RRune *ch);
R_API int r_utf16be_decode(const ut8 *ptr, int ptrlen, RRune *ch);
R_API int r_utf16le_encode(ut8 *ptr, RRune ch);

#ifdef __cplusplus
}
#endif

#endif //  R_UTF16_H
