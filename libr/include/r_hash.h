#ifndef R2_HASH_H
#define R2_HASH_H

#include "r_types.h"

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER (r_hash);

/* hashing */
typedef struct {
	ut32 state[4];
	ut32 count[2];
	ut8 buffer[64];
} R_MD5_CTX;

typedef struct {
	ut32 H[5];
	ut32 W[80];
	int lenW;
	ut32 sizeHi, sizeLo;
} R_SHA_CTX;

#define SHA256_BLOCK_LENGTH 64
typedef struct _SHA256_CTX {
	ut32 state[8];
	ut64 bitcount;
	ut8 buffer[SHA256_BLOCK_LENGTH];
} R_SHA256_CTX;

#define SHA384_BLOCK_LENGTH 128
#define SHA512_BLOCK_LENGTH 128
typedef struct _SHA512_CTX {
	ut64 state[8];
	ut64 bitcount[2];
	ut8 buffer[SHA512_BLOCK_LENGTH];
} R_SHA512_CTX;
typedef R_SHA512_CTX R_SHA384_CTX;

/* Fix names conflict with ruby bindings */
#define RHash struct r_hash_t

struct r_hash_t {
	R_MD5_CTX md5;
	R_SHA_CTX sha1;
	R_SHA256_CTX sha256;
	R_SHA384_CTX sha384;
	R_SHA512_CTX sha512;
	int rst;
	ut8 digest[128];
};

typedef struct r_hash_seed_t {
	int prefix;
	ut8 *buf;
	int len;
} RHashSeed;

#define R_HASH_SIZE_CRC16 2
#define R_HASH_SIZE_CRC32 4
#define R_HASH_SIZE_XXHASH 4
#define R_HASH_SIZE_MD4 16
#define R_HASH_SIZE_MD5 16
#define R_HASH_SIZE_SHA1 20
#define R_HASH_SIZE_SHA256 32
#define R_HASH_SIZE_SHA384 48
#define R_HASH_SIZE_SHA512 64
#define R_HASH_SIZE_ADLER32 4

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
#define R_HASH_XXHASH 32768
#define R_HASH_ADLER32 65536
#define R_HASH_ALL 0xFFFF

#ifdef R_API
/* OO */
R_API RHash *r_hash_new(int rst, int flags);
R_API void r_hash_free(RHash *ctx);

/* methods */
R_API ut8 *r_hash_do_md4(RHash *ctx, const ut8 *input, int len);
R_API ut8 *r_hash_do_md5(RHash *ctx, const ut8 *input, int len);
R_API ut8 *r_hash_do_sha1(RHash *ctx, const ut8 *input, int len);
R_API ut8 *r_hash_do_sha256(RHash *ctx, const ut8 *input, int len);
R_API ut8 *r_hash_do_sha384(RHash *ctx, const ut8 *input, int len);
R_API ut8 *r_hash_do_sha512(RHash *ctx, const ut8 *input, int len);
R_API ut8 *r_hash_do_xxhash(RHash *ctx, const ut8 *input, int len);

R_API char *r_hash_to_string(RHash *ctx, const char *name, const ut8 *data, int len);

/* static methods */
R_API const char *r_hash_name(ut64 bit);
R_API ut64 r_hash_name_to_bits(const char *name);
R_API int r_hash_size(ut64 bit);
R_API int r_hash_calculate(RHash *ctx, ut64 algobit, const ut8 *input, int len);

/* checksums */
/* XXX : crc16 should use 0 as arg0 by default */
/* static methods */
R_API ut8 r_hash_deviation(const ut8 *b, ut64 len);
R_API ut16 r_hash_crc16(ut16 crc, const ut8 *buffer, ut64 len);
R_API ut32 r_hash_crc32(const ut8 *buf, ut64 len);
R_API ut32 r_hash_adler32(const ut8 *buf, int len);
R_API ut32 r_hash_xxhash(const ut8 *buf, ut64 len);
R_API ut8 r_hash_xor(const ut8 *b, ut64 len);
R_API ut16 r_hash_xorpair(const ut8 *a, ut64 len);
R_API int r_hash_parity(const ut8 *buf, ut64 len);
R_API ut8 r_hash_mod255(const ut8 *b, ut64 len);

/* analysis */
R_API ut8  r_hash_hamdist(const ut8 *buf, int len);
R_API double r_hash_entropy(const ut8 *data, ut64 len);
R_API double r_hash_entropy_fraction(const ut8 *data, ut64 len);
R_API int r_hash_pcprint(const ut8 *buffer, ut64 len);

/* lifecycle */
R_API void r_hash_do_begin(RHash *ctx, int flags);
R_API void r_hash_do_end(RHash *ctx, int flags);
R_API void r_hash_do_spice(RHash *ctx, int algo, int loops, RHashSeed *seed);
#endif

#ifdef __cplusplus
}
#endif

#endif
