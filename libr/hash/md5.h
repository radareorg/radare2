#include <r_types.h>

#if 0
/* MD5 context. */
typedef struct {
  UINT4 state[4];                                   /* state (ABCD) */
  UINT4 count[2];        /* number of bits, modulo 2^64 (lsb first) */
  unsigned char buffer[64];                         /* input buffer */
} MD5_CTX;
#endif

void MD5Init (MD5_CTX *);
void MD5Update (MD5_CTX *, const ut8*, unsigned int);
void MD5Final (ut8 [16], MD5_CTX *);
