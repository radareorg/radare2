#ifndef R_UTF32_H
#define R_UTF32_H

/* For RRune definition */
#include "r_utf8.h"

R_API int r_utf32_decode(const ut8 *ptr, int ptrlen, RRune *ch, bool bigendian);
R_API int r_utf32le_decode(const ut8 *ptr, int ptrlen, RRune *ch);
R_API int r_utf32le_decode(const ut8 *ptr, int ptrlen, RRune *ch);

#endif //  R_UTF32_H
