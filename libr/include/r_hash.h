#ifndef R2_HASH_H
#define R2_HASH_H

#include "r_types.h"

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER (r_hash);

#define MD5_CTX R_MD5_CTX

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

#if 1
typedef ut32 utcrc;
#define PFMTCRCx PFMT32x
#else
/* TODO: future expansion */
typedef ut64 utcrc;
#define PFMTCRCx PFMT64x
#endif
#define UTCRC_C(x) ((utcrc)(x))

typedef struct {
	utcrc crc;
	ut32 size;
	int reflect;
	utcrc poly;
	utcrc xout;
} R_CRC_CTX;

enum CRC_PRESETS {
	CRC_PRESET_32 = 0,
	CRC_PRESET_16,
	CRC_PRESET_32_ECMA_267,
	CRC_PRESET_32C,
	CRC_PRESET_24,
	CRC_PRESET_16_CITT,
	CRC_PRESET_16_USB,
	CRC_PRESET_16_HDLC,
	CRC_PRESET_15_CAN,
	CRC_PRESET_8_SMBUS,
	CRC_PRESET_CRC8_CDMA2000,
	CRC_PRESET_CRC8_DARC,
	CRC_PRESET_CRC8_DVB_S2,
	CRC_PRESET_CRC8_EBU,
	CRC_PRESET_CRC8_ICODE,
	CRC_PRESET_CRC8_ITU,
	CRC_PRESET_CRC8_MAXIM,
	CRC_PRESET_CRC8_ROHC,
	CRC_PRESET_CRC8_WCDMA,
	CRC_PRESET_CRC16_AUG_CCITT,
	CRC_PRESET_CRC16_BUYPASS,
	CRC_PRESET_CRC16_CDMA2000,
	CRC_PRESET_CRC16_DDS110,
	CRC_PRESET_CRC16_DECT_R,
	CRC_PRESET_CRC16_DECT_X,
	CRC_PRESET_CRC16_DNP,
	CRC_PRESET_CRC16_EN13757,
	CRC_PRESET_CRC16_GENIBUS,
	CRC_PRESET_CRC16_MAXIM,
	CRC_PRESET_CRC16_MCRF4XX,
	CRC_PRESET_CRC16_RIELLO,
	CRC_PRESET_CRC16_T10_DIF,
	CRC_PRESET_CRC16_TELEDISK,
	CRC_PRESET_CRC16_TMS37157,
	CRC_PRESET_CRCA,
	CRC_PRESET_CRC16_KERMIT,
	CRC_PRESET_CRC16_MODBUS,
	CRC_PRESET_CRC16_X25,
	CRC_PRESET_CRC16_XMODEM,
	CRC_PRESET_CRC32_BZIP2,
	CRC_PRESET_CRC32D,
	CRC_PRESET_CRC32_MPEG2,
	CRC_PRESET_CRC32_POSIX,
	CRC_PRESET_CRC32Q,
	CRC_PRESET_CRC32_JAMCRC,
	CRC_PRESET_CRC32_XFER,
	CRC_PRESET_SIZE
};

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
	bool rst;
	ut8 digest[128];
};

typedef struct r_hash_seed_t {
	int prefix;
	ut8 *buf;
	int len;
} RHashSeed;

#define R_HASH_SIZE_CRC8_SMBUS 1
#define R_HASH_SIZE_CRC8_CDMA2000 1
#define R_HASH_SIZE_CRC8_DARC 1
#define R_HASH_SIZE_CRC8_DVB_S2 1
#define R_HASH_SIZE_CRC8_EBU 1
#define R_HASH_SIZE_CRC8_ICODE 1
#define R_HASH_SIZE_CRC8_ITU 1
#define R_HASH_SIZE_CRC8_MAXIM 1
#define R_HASH_SIZE_CRC8_ROHC 1
#define R_HASH_SIZE_CRC8_WCDMA 1
#define R_HASH_SIZE_CRC15_CAN 2
#define R_HASH_SIZE_CRC16 2
#define R_HASH_SIZE_CRC16_HDLC 2
#define R_HASH_SIZE_CRC16_USB 2
#define R_HASH_SIZE_CRC16_CITT 2
#define R_HASH_SIZE_CRC16_AUG_CCITT 2
#define R_HASH_SIZE_CRC16_BUYPASS 2
#define R_HASH_SIZE_CRC16_CDMA2000 2
#define R_HASH_SIZE_CRC16_DDS110 2
#define R_HASH_SIZE_CRC16_DECT_R 2
#define R_HASH_SIZE_CRC16_DECT_X 2
#define R_HASH_SIZE_CRC16_DNP 2
#define R_HASH_SIZE_CRC16_EN13757 2
#define R_HASH_SIZE_CRC16_GENIBUS 2
#define R_HASH_SIZE_CRC16_MAXIM 2
#define R_HASH_SIZE_CRC16_MCRF4XX 2
#define R_HASH_SIZE_CRC16_RIELLO 2
#define R_HASH_SIZE_CRC16_T10_DIF 2
#define R_HASH_SIZE_CRC16_TELEDISK 2
#define R_HASH_SIZE_CRC16_TMS37157 2
#define R_HASH_SIZE_CRCA 2
#define R_HASH_SIZE_CRC16_KERMIT 2
#define R_HASH_SIZE_CRC16_MODBUS 2
#define R_HASH_SIZE_CRC16_X25 2
#define R_HASH_SIZE_CRC16_XMODEM 2
#define R_HASH_SIZE_CRC24 3
#define R_HASH_SIZE_CRC32 4
#define R_HASH_SIZE_CRC32C 4
#define R_HASH_SIZE_CRC32_ECMA_267 4
#define R_HASH_SIZE_CRC32_BZIP2 4
#define R_HASH_SIZE_CRC32D 4
#define R_HASH_SIZE_CRC32_MPEG2 4
#define R_HASH_SIZE_CRC32_POSIX 4
#define R_HASH_SIZE_CRC32Q 4
#define R_HASH_SIZE_CRC32_JAMCRC 4
#define R_HASH_SIZE_CRC32_XFER 4
#define R_HASH_SIZE_XXHASH 4
#define R_HASH_SIZE_MD4 16
#define R_HASH_SIZE_MD5 16
#define R_HASH_SIZE_SHA1 20
#define R_HASH_SIZE_SHA256 32
#define R_HASH_SIZE_SHA384 48
#define R_HASH_SIZE_SHA512 64
#define R_HASH_SIZE_ADLER32 4
/* entropy is double !! fail with size 4 */
#define R_HASH_SIZE_ENTROPY 4
#define R_HASH_SIZE_PCPRINT 1
#define R_HASH_SIZE_MOD255 1
#define R_HASH_SIZE_PARITY 1
#define R_HASH_SIZE_XOR 1
#define R_HASH_SIZE_XORPAIR 2
#define R_HASH_SIZE_HAMDIST 1
#define R_HASH_SIZE_LUHN 1

#define R_HASH_NBITS (8*sizeof(ut64))

#define R_HASH_NONE 0
#define R_HASH_MD5 1
#define R_HASH_SHA1 1 << 1
#define R_HASH_SHA256 1 << 2
#define R_HASH_SHA384 1 << 3
#define R_HASH_SHA512 1 << 4
#define R_HASH_CRC16 1 << 5
#define R_HASH_CRC32 1 << 6
#define R_HASH_MD4 1 << 7
#define R_HASH_XOR 1 << 8
#define R_HASH_XORPAIR 1 << 9
#define R_HASH_PARITY 1 << 10
#define R_HASH_ENTROPY 1 << 11
#define R_HASH_HAMDIST 1 << 12
#define R_HASH_PCPRINT 1 << 13
#define R_HASH_MOD255 1 << 14
#define R_HASH_XXHASH 1 << 15
#define R_HASH_ADLER32 1 << 16
#define R_HASH_BASE64 1 << 17
#define R_HASH_BASE91 1 << 18
#define R_HASH_PUNYCODE 1 << 19
#define R_HASH_LUHN 1 << 20
#define R_HASH_CRC8_SMBUS 1 << 21
#define R_HASH_CRC15_CAN 1 << 22
#define R_HASH_CRC16_HDLC 1 << 23
#define R_HASH_CRC16_USB 1 << 24
#define R_HASH_CRC16_CITT 1 << 25
#define R_HASH_CRC24 1 << 26
#define R_HASH_CRC32C 1 << 27
#define R_HASH_CRC32_ECMA_267 1 << 28
#define R_HASH_CRC8_CDMA2000 (1ULL << 29)
#define R_HASH_CRC8_DARC (1ULL << 30)
#define R_HASH_CRC8_DVB_S2 (1ULL << 31)
#define R_HASH_CRC8_EBU (1ULL << 32)
#define R_HASH_CRC8_ICODE (1ULL << 33)
#define R_HASH_CRC8_ITU (1ULL << 34)
#define R_HASH_CRC8_MAXIM (1ULL << 35)
#define R_HASH_CRC8_ROHC (1ULL << 36)
#define R_HASH_CRC8_WCDMA (1ULL << 37)
#define R_HASH_CRC16_AUG_CCITT (1ULL << 38)
#define R_HASH_CRC16_BUYPASS (1ULL << 39)
#define R_HASH_CRC16_CDMA2000 (1ULL << 40)
#define R_HASH_CRC16_DDS110 (1ULL << 41)
#define R_HASH_CRC16_DECT_R (1ULL << 42)
#define R_HASH_CRC16_DECT_X (1ULL << 43)
#define R_HASH_CRC16_DNP (1ULL << 44)
#define R_HASH_CRC16_EN13757 (1ULL << 45)
#define R_HASH_CRC16_GENIBUS (1ULL << 46)
#define R_HASH_CRC16_MAXIM (1ULL << 47)
#define R_HASH_CRC16_MCRF4XX (1ULL << 48)
#define R_HASH_CRC16_RIELLO (1ULL << 49)
#define R_HASH_CRC16_T10_DIF (1ULL << 50)
#define R_HASH_CRC16_TELEDISK (1ULL << 51)
#define R_HASH_CRC16_TMS37157 (1ULL << 52)
#define R_HASH_CRCA (1ULL << 53)
#define R_HASH_CRC16_KERMIT (1ULL << 54)
#define R_HASH_CRC16_MODBUS (1ULL << 55)
#define R_HASH_CRC16_X25 (1ULL << 56)
#define R_HASH_CRC16_XMODEM (1ULL << 57)
#define R_HASH_CRC32_BZIP2 (1ULL << 58)
#define R_HASH_CRC32D (1ULL << 59)
#define R_HASH_CRC32_MPEG2 (1ULL << 60)
#define R_HASH_CRC32_POSIX (1ULL << 61)
#define R_HASH_CRC32Q (1ULL << 62)
//#define R_HASH_CRC32_JAMCRC (1ULL << 63)
//#define R_HASH_CRC32_XFER  TODO: OOOps! No empty bitspace!
#define R_HASH_ALL ((1ULL << 63)-1)

#ifdef R_API
/* OO */
R_API RHash *r_hash_new(bool rst, int flags);
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
R_API ut32 r_hash_adler32(const ut8 *buf, int len);
R_API ut32 r_hash_xxhash(const ut8 *buf, ut64 len);
R_API ut8 r_hash_xor(const ut8 *b, ut64 len);
R_API ut16 r_hash_xorpair(const ut8 *a, ut64 len);
R_API int r_hash_parity(const ut8 *buf, ut64 len);
R_API ut8 r_hash_mod255(const ut8 *b, ut64 len);
R_API ut64 r_hash_luhn(const ut8 *buf, ut64 len);
R_API utcrc r_hash_crc_preset (const ut8 *data, ut32 size, enum CRC_PRESETS preset);

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
