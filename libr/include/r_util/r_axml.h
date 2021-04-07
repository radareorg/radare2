/* radare - LGPL - Copyright 2021 - keegan */

#ifndef R_AXML_H
#define R_AXML_H

#ifdef __cplusplus
extern "C" {
#endif

R_API char *r_axml_decode(const ut8* buffer, const ut64 size);

#ifdef __cplusplus
}
#endif

#endif //  R_AXML_H
