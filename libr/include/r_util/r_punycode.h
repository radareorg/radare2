#ifndef R_PUNYCODE_H
#define R_PUNYCODE_H

R_API char *r_punycode_encode(const char*src, int srclen, int *dstlen);
R_API char *r_punycode_decode(const char *src, int srclen, int *dstlen);
#endif //  R_PUNYCODE_H
