#ifndef _INCLUDE_R_HASH_H_
#define _INCLUDE_R_HASH_H_

#include "r_types.h"

/* hashing */
typedef struct {
	ut32 state[4];
	ut32 count[2];
	ut8 buffer[64];
} MD5_CTX;

typedef struct {
	unsigned int H[5];
	unsigned int W[80];
	int lenW;
	unsigned int sizeHi, sizeLo;
} SHA_CTX;

#define SHA256_BLOCK_LENGTH 64
typedef struct _SHA256_CTX {
	ut32 state[8];
	ut64 bitcount;
	ut8 buffer[SHA256_BLOCK_LENGTH];
} SHA256_CTX;

#define SHA384_BLOCK_LENGTH 128
#define SHA512_BLOCK_LENGTH 128
typedef struct _SHA512_CTX {
	ut64 state[8];
	ut64 bitcount[2];
	ut8 buffer[SHA512_BLOCK_LENGTH];
} SHA512_CTX;
typedef SHA512_CTX SHA384_CTX;

typedef struct r_hash_t {
	MD5_CTX md5;
	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA384_CTX sha384;
	SHA512_CTX sha512;
	int rst;
	ut8 digest[128];
} RHash;

#define R_HASH_SIZE_MD4 16
#define R_HASH_SIZE_MD5 16
#define R_HASH_SIZE_SHA1 16
#define R_HASH_SIZE_SHA256 32
#define R_HASH_SIZE_SHA384 64
#define R_HASH_SIZE_SHA512 64

#define R_HASH_NONE 0
#define R_HASH_MD5 1
#define R_HASH_SHA1 2
#define R_HASH_SHA256 4
#define R_HASH_SHA384 8
#define R_HASH_SHA512 16
#define R_HASH_CRC16 32
#define R_HASH_CRC32 64
#define R_HASH_MD4 128
#define R_HASH_XOR 256
#define R_HASH_XORPAIR 512
#define R_HASH_PARITY 1024
#define R_HASH_ENTROPY 2048
#define R_HASH_HAMDIST 4096
#define R_HASH_PCPRINT 8192
#define R_HASH_MOD255 16384
#define R_HASH_ALL 0xFFFF

#ifdef R_API
/* OO */
R_API struct r_hash_t *r_hash_new(int _init);
R_API void r_hash_init(struct r_hash_t *ptr, int rst, int flags);
R_API void r_hash_free(struct r_hash_t *ctx);

/* methods */
R_API const ut8 *r_hash_do_md4(struct r_hash_t *ctx, const ut8 *input, ut32 len);
R_API const ut8 *r_hash_do_md5(struct r_hash_t *ctx, const ut8 *input, ut32 len);
R_API const ut8 *r_hash_do_sha1(struct r_hash_t *ctx, const ut8 *input, ut32 len);
R_API const ut8 *r_hash_do_sha256(struct r_hash_t *ctx, const ut8 *input, ut32 len);
R_API const ut8 *r_hash_do_sha384(struct r_hash_t *ctx, const ut8 *input, ut32 len);
R_API const ut8 *r_hash_do_sha512(struct r_hash_t *ctx, const ut8 *input, ut32 len);

/* static methods */
R_API ut64 r_hash_name_to_bits(const char *name);
R_API int r_hash_calculate(struct r_hash_t *ctx, int algobit, const ut8 *input, ut32 len);

/* checksums */
/* XXX : crc16 should use 0 as arg0 by default */
/* static methods */
R_API ut16 r_hash_crc16(ut16 crc, const ut8 *buffer, ut64 len);
R_API ut32 r_hash_crc32(const ut8 *buf, ut64 len);
R_API ut8 r_hash_xor(const ut8 *b, ut64 len);
R_API ut16 r_hash_xorpair(const ut8 *a, ut64 len);
R_API int r_hash_parity(const ut8 *buf, ut64 len);
R_API ut8 r_hash_mod255(const ut8 *b, ut64 len);
R_API const char *r_hash_name(int bit);

/* analysis */
R_API ut8  r_hash_hamdist(const ut8 *buf, int len);
R_API double r_hash_entropy(const ut8 *data, ut64 len);
R_API int r_hash_pcprint(const ut8 *buffer, ut64 len);
#endif

#endif
