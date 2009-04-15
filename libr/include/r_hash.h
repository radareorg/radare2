#ifndef _INCLUDE_R_HASH_H_
#define _INCLUDE_R_HASH_H_

#include "r_types.h"

/* checksums */
/* XXX : crc16 should use 0 as arg0 by default */
u16 r_hash_crc16(u16 crc, const u8 *buffer, u64 len);
u32 r_hash_crc32(const u8 *buf, u64 len);
u8  r_hash_xor(const u8 *b, u64 len);
u16 r_hash_xorpair(const u8 *a, u64 len);
u8  r_hash_parity(u8 *buf, u64 len);
u8  r_hash_mod255(const u8 *b, u64 len);

/* analysis */
u8  r_hash_hamdist(const u8 *buf, u64 len);
double r_hash_entropy(const u8 *data, u64 len);
int r_hash_pcprint(u8 *buffer, u64 len);

/* hashing */
typedef struct {
  u32 state[4];
  u32 count[2];
  u8 buffer[64];
} MD5_CTX;

typedef struct {
  unsigned int H[5];
  unsigned int W[80];
  int lenW;
  unsigned int sizeHi, sizeLo;
} SHA_CTX;

#define SHA256_BLOCK_LENGTH		64
typedef struct _SHA256_CTX {
	u32 state[8];
	u64 bitcount;
	u8 buffer[SHA256_BLOCK_LENGTH];
} SHA256_CTX;

#define SHA384_BLOCK_LENGTH		128
#define SHA512_BLOCK_LENGTH		128
typedef struct _SHA512_CTX {
	u64 state[8];
	u64 bitcount[2];
	u8 buffer[SHA512_BLOCK_LENGTH];
} SHA512_CTX;
typedef SHA512_CTX SHA384_CTX;

struct r_hash_t {
	MD5_CTX md5;
	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA384_CTX sha384;
	SHA512_CTX sha512;
	int init;
	u8 digest[128];
};

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

const u8 *r_hash_state_md4(struct r_hash_t *ctx, const u8 *input, u32 len);
const u8 *r_hash_state_md5(struct r_hash_t *ctx, const u8 *input, u32 len);
const u8 *r_hash_state_sha1(struct r_hash_t *ctx, const u8 *input, u32 len);
const u8 *r_hash_state_sha256(struct r_hash_t *ctx, const u8 *input, u32 len);
const u8 *r_hash_state_sha384(struct r_hash_t *ctx, const u8 *input, u32 len);
const u8 *r_hash_state_sha512(struct r_hash_t *ctx, const u8 *input, u32 len);

/* OO */
struct r_hash_t *r_hash_state_new(int init);
void r_hash_init(struct r_hash_t *ptr, int flags);
void r_hash_state_init(struct r_hash_t *ctx, int flags);
void r_hash_state_free(struct r_hash_t *ctx);

#endif
