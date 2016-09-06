#ifndef R_BASE91_H
#define R_BASE91_H

R_API int r_base91_encode(char *bout, const ut8 *bin, int len);
R_API int r_base91_decode(ut8 *bout, const char *bin, int len);
#endif //  R_BASE91_H
