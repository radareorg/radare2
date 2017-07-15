#ifndef R_UTF16_H
#define R_UTF16_H

/* For RRune definition */
#include "r_utf8.h"

R_API int r_utf16le_decode(const ut8 *ptr, int ptrlen, RRune *ch);

#endif //  R_UTF16_H
