#ifndef R2_HASH_H
#define R2_HASH_H

#include "r_types.h"
#include "r_util/r_mem.h"
#include "r_util/r_log.h"

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER (r_hash);

#if WANT_SSL_CRYPTO
#include <openssl/sha.h>
#include <openssl/md5.h>
typedef MD5_CTX RHashMD5Context;
typedef SHA_CTX RHashShaContext;
typedef SHA256_CTX RSha256Context;
typedef SHA512_CTX RSha384Context;
typedef SHA512_CTX RSha512Context;
#define SHA256_BLOCK_LENGTH SHA256_CBLOCK
#define SHA384_BLOCK_LENGTH SHA384_CBLOCK
#define SHA512_BLOCK_LENGTH SHA512_CBLOCK
#else
#define MD5_CTX RHashMD5Context

/* hashing */
typedef struct {
	ut32 state[4];
	ut32 count[2];
	ut8 buffer[64];
} RHashMD5Context;

typedef struct {
	ut32 H[5];
	ut32 W[80];
	int lenW;
	ut32 sizeHi, sizeLo;
} RHashShaContext;

#define SHA256_BLOCK_LENGTH 64
typedef struct _SHA256_CTX {
	ut32 state[8];
	ut64 bitcount;
	ut8 buffer[SHA256_BLOCK_LENGTH];
} RSha256Context;

#define SHA384_BLOCK_LENGTH 128
#define SHA512_BLOCK_LENGTH 128
typedef struct _SHA512_CTX {
	ut64 state[8];
	ut64 bitcount[2];
	ut8 buffer[SHA512_BLOCK_LENGTH];
} RSha512Context;

typedef RSha512Context RSha384Context;
#endif


/*
 * Since we have not enough space in bitmask, you may do fine
 * selection of required hash functions by the followed macros.
 *
 * TODO: subject to place in config
 */
//#define R_HAVE_CRC8_EXTRA 1
#define R_HAVE_CRC15_EXTRA 1
//#define R_HAVE_CRC16_EXTRA 1
#define R_HAVE_CRC24 1
#define R_HAVE_CRC32_EXTRA 1
#define R_HAVE_CRC64 1
#define R_HAVE_CRC64_EXTRA 1

/* select CRC-digest intergal holder */
#if R_HAVE_CRC64 || R_HAVE_CRC64_EXTRA
typedef ut64 utcrc;
#define PFMTCRCx PFMT64x
#else
typedef ut32 utcrc;
#define PFMTCRCx PFMT32x
#endif
#define UTCRC_C(x) ((utcrc)(x))

R_API ut8 r_hash_fletcher8(const ut8 *d, size_t length);
R_API ut16 r_hash_fletcher16(const ut8 *data, size_t len);
R_API ut32 r_hash_fletcher32(const ut8 *data, size_t len);
R_API ut64 r_hash_fletcher64(const ut8 *addr, size_t len);

typedef struct {
	utcrc crc;
	ut32 size;
	int reflect;
	utcrc poly;
	utcrc xout;
} R_CRC_CTX;

enum CRC_PRESETS {
	CRC_PRESET_8_SMBUS = 0,
#if R_HAVE_CRC8_EXTRA
	CRC_PRESET_CRC8_CDMA2000,
	CRC_PRESET_CRC8_DARC,
	CRC_PRESET_CRC8_DVB_S2,
	CRC_PRESET_CRC8_EBU,
	CRC_PRESET_CRC8_ICODE,
	CRC_PRESET_CRC8_ITU,
	CRC_PRESET_CRC8_MAXIM,
	CRC_PRESET_CRC8_ROHC,
	CRC_PRESET_CRC8_WCDMA,
#endif /* #if R_HAVE_CRC8_EXTRA */

#if R_HAVE_CRC15_EXTRA
	CRC_PRESET_15_CAN,
#endif /* R_HAVCE_CRC15_EXTRA */

	CRC_PRESET_16,
	CRC_PRESET_16_CITT,
	CRC_PRESET_16_USB,
	CRC_PRESET_16_HDLC,
#if R_HAVE_CRC16_EXTRA
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
#endif /* #if R_HAVE_CRC16_EXTRA */

#if R_HAVE_CRC24
	CRC_PRESET_24,
#endif /* #if R_HAVE_CRC24 */

	CRC_PRESET_32,
	CRC_PRESET_32_ECMA_267,
	CRC_PRESET_32C,
#if R_HAVE_CRC32_EXTRA
	CRC_PRESET_CRC32_BZIP2,
	CRC_PRESET_CRC32D,
	CRC_PRESET_CRC32_MPEG2,
	CRC_PRESET_CRC32_POSIX,
	CRC_PRESET_CRC32Q,
	CRC_PRESET_CRC32_JAMCRC,
	CRC_PRESET_CRC32_XFER,
#endif /* #if R_HAVE_CRC32_EXTRA */

#if R_HAVE_CRC64
	CRC_PRESET_CRC64,
#endif /* R_HAVE_CRC64 */

#if R_HAVE_CRC64_EXTRA
	CRC_PRESET_CRC64_ECMA182,
	CRC_PRESET_CRC64_WE,
	CRC_PRESET_CRC64_XZ,
	CRC_PRESET_CRC64_ISO,
#endif /* #if R_HAVE_CRC64_EXTRA */

	CRC_PRESET_SIZE
};

/* Fix names conflict with ruby bindings */
#define RHash struct r_hash_t

struct r_hash_t {
	RHashMD5Context md5;
	RHashShaContext sha1;
	RSha256Context sha256;
	RSha384Context sha384;
	RSha512Context sha512;
	bool rst;
	double entropy;
	ut8 R_ALIGNED(8) digest[128];
};

typedef struct r_hash_seed_t {
	int prefix;
	ut8 *buf;
	int len;
} RHashSeed;

#define R_HASH_SIZE_SSDEEP 128
#define R_HASH_SIZE_CRC8_SMBUS 1
#if R_HAVE_CRC8_EXTRA
#define R_HASH_SIZE_CRC8_CDMA2000 1
#define R_HASH_SIZE_CRC8_DARC 1
#define R_HASH_SIZE_CRC8_DVB_S2 1
#define R_HASH_SIZE_CRC8_EBU 1
#define R_HASH_SIZE_CRC8_ICODE 1
#define R_HASH_SIZE_CRC8_ITU 1
#define R_HASH_SIZE_CRC8_MAXIM 1
#define R_HASH_SIZE_CRC8_ROHC 1
#define R_HASH_SIZE_CRC8_WCDMA 1
#endif /* #if R_HAVE_CRC8_EXTRA */

#if R_HAVE_CRC15_EXTRA
#define R_HASH_SIZE_CRC15_CAN 2
#endif /* #if R_HAVE_CRC15_EXTRA */

#define R_HASH_SIZE_CRC16 2
#define R_HASH_SIZE_CRC16_HDLC 2
#define R_HASH_SIZE_CRC16_USB 2
#define R_HASH_SIZE_CRC16_CITT 2
#if R_HAVE_CRC16_EXTRA
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
#endif /* #if R_HAVE_CRC16_EXTRA */
#define R_HASH_SIZE_SIP 8

#if R_HAVE_CRC24
#define R_HASH_SIZE_CRC24 3
#endif /* #if R_HAVE_CRC24 */

#define R_HASH_SIZE_CRC32 4
#define R_HASH_SIZE_CRC32C 4
#define R_HASH_SIZE_CRC32_ECMA_267 4
#if R_HAVE_CRC32_EXTRA
#define R_HASH_SIZE_CRC32_BZIP2 4
#define R_HASH_SIZE_CRC32D 4
#define R_HASH_SIZE_CRC32_MPEG2 4
#define R_HASH_SIZE_CRC32_POSIX 4
#define R_HASH_SIZE_CRC32Q 4
#define R_HASH_SIZE_CRC32_JAMCRC 4
#define R_HASH_SIZE_CRC32_XFER 4
#endif /* #if R_HAVE_CRC32_EXTRA */

#if R_HAVE_CRC64
#define R_HASH_SIZE_CRC64 8
#endif /* #if R_HAVE_CRC64 */
#if R_HAVE_CRC64_EXTRA
#define R_HASH_SIZE_CRC64_ECMA182 8
#define R_HASH_SIZE_CRC64_WE 8
#define R_HASH_SIZE_CRC64_XZ 8
#define R_HASH_SIZE_CRC64_ISO 8
#endif /* #if R_HAVE_CRC64_EXTRA */

#define R_HASH_SIZE_XXHASH 4
#define R_HASH_SIZE_MD4 16
#define R_HASH_SIZE_MD5 16
#define R_HASH_SIZE_SHA1 20
#define R_HASH_SIZE_SHA256 32
#define R_HASH_SIZE_SHA384 48
#define R_HASH_SIZE_SHA512 64
#define R_HASH_SIZE_ADLER32 4
/* entropy is double !! size 0 for test in r_hash_tostring */
#define R_HASH_SIZE_ENTROPY 0
#define R_HASH_SIZE_PCPRINT 1
#define R_HASH_SIZE_MOD255 1
#define R_HASH_SIZE_PARITY 1
#define R_HASH_SIZE_XOR 1
#define R_HASH_SIZE_XORPAIR 2
#define R_HASH_SIZE_HAMDIST 1
#define R_HASH_SIZE_LUHN 1
#define R_HASH_SIZE_FLETCHER8 1
#define R_HASH_SIZE_FLETCHER16 2
#define R_HASH_SIZE_FLETCHER32 4
#define R_HASH_SIZE_FLETCHER64 8

#define R_HASH_NBITS (8*sizeof (ut64))

enum HASH_INDICES {
	R_HASH_IDX_MD5 = 0,
	R_HASH_IDX_SHA1,
	R_HASH_IDX_SHA256,
	R_HASH_IDX_SHA384,
	R_HASH_IDX_SHA512,
	R_HASH_IDX_MD4,
	R_HASH_IDX_XOR,
	R_HASH_IDX_XORPAIR,
	R_HASH_IDX_PARITY,
	R_HASH_IDX_ENTROPY,
	R_HASH_IDX_HAMDIST,
	R_HASH_IDX_PCPRINT,
	R_HASH_IDX_MOD255,
	R_HASH_IDX_XXHASH,
	R_HASH_IDX_ADLER32,
	R_HASH_IDX_BASE64,
	R_HASH_IDX_BASE91,
	R_HASH_IDX_PUNYCODE,
	R_HASH_IDX_LUHN,
	R_HASH_IDX_SSDEEP,

	R_HASH_IDX_CRC8_SMBUS,
#if R_HAVE_CRC8_EXTRA
	R_HASH_IDX_CRC8_CDMA2000,
	R_HASH_IDX_CRC8_DARC,
	R_HASH_IDX_CRC8_DVB_S2,
	R_HASH_IDX_CRC8_EBU,
	R_HASH_IDX_CRC8_ICODE,
	R_HASH_IDX_CRC8_ITU,
	R_HASH_IDX_CRC8_MAXIM,
	R_HASH_IDX_CRC8_ROHC,
	R_HASH_IDX_CRC8_WCDMA,
#endif /* #if R_HAVE_CRC8_EXTRA */

#if R_HAVE_CRC15_EXTRA
	R_HASH_IDX_CRC15_CAN,
#endif /* #if R_HAVE_CRC15_EXTRA */

	R_HASH_IDX_CRC16,
	R_HASH_IDX_CRC16_HDLC,
	R_HASH_IDX_CRC16_USB,
	R_HASH_IDX_CRC16_CITT,
#if R_HAVE_CRC16_EXTRA
	R_HASH_IDX_CRC16_AUG_CCITT,
	R_HASH_IDX_CRC16_BUYPASS,
	R_HASH_IDX_CRC16_CDMA2000,
	R_HASH_IDX_CRC16_DDS110,
	R_HASH_IDX_CRC16_DECT_R,
	R_HASH_IDX_CRC16_DECT_X,
	R_HASH_IDX_CRC16_DNP,
	R_HASH_IDX_CRC16_EN13757,
	R_HASH_IDX_CRC16_GENIBUS,
	R_HASH_IDX_CRC16_MAXIM,
	R_HASH_IDX_CRC16_MCRF4XX,
	R_HASH_IDX_CRC16_RIELLO,
	R_HASH_IDX_CRC16_T10_DIF,
	R_HASH_IDX_CRC16_TELEDISK,
	R_HASH_IDX_CRC16_TMS37157,
	R_HASH_IDX_CRCA,
	R_HASH_IDX_CRC16_KERMIT,
	R_HASH_IDX_CRC16_MODBUS,
	R_HASH_IDX_CRC16_X25,
	R_HASH_IDX_CRC16_XMODEM,
#endif /* #if R_HAVE_CRC16_EXTRA */

#if R_HAVE_CRC24
	R_HASH_IDX_CRC24,
#endif /* #if R_HAVE_CRC24 */

	R_HASH_IDX_CRC32,
	R_HASH_IDX_CRC32C,
	R_HASH_IDX_CRC32_ECMA_267,
#if R_HAVE_CRC32_EXTRA
	R_HASH_IDX_CRC32_BZIP2,
	R_HASH_IDX_CRC32D,
	R_HASH_IDX_CRC32_MPEG2,
	R_HASH_IDX_CRC32_POSIX,
	R_HASH_IDX_CRC32Q,
	R_HASH_IDX_CRC32_JAMCRC,
	R_HASH_IDX_CRC32_XFER,
#endif /* #if R_HAVE_CRC32_EXTRA */

#if R_HAVE_CRC64
	R_HASH_IDX_CRC64,
#endif /* #if R_HAVE_CRC64 */
#if R_HAVE_CRC64_EXTRA
	R_HASH_IDX_CRC64_ECMA182,
	R_HASH_IDX_CRC64_WE,
	R_HASH_IDX_CRC64_XZ,
	R_HASH_IDX_CRC64_ISO,
#endif /* #if R_HAVE_CRC64_EXTRA */

	R_HASH_IDX_FLETCHER8,
	R_HASH_IDX_FLETCHER16,
	R_HASH_IDX_FLETCHER32,
	R_HASH_IDX_FLETCHER64,
	R_HASH_IDX_SIP,
	R_HASH_IDX_ELF,
	R_HASH_NUM_INDICES
};

#define R_HASH_NONE 0
#define R_HASH_ELF (1ULL << R_HASH_IDX_ELF)
#define R_HASH_MD5 (1ULL << R_HASH_IDX_MD5)
#define R_HASH_SHA1 (1ULL << R_HASH_IDX_SHA1)
#define R_HASH_SHA256 (1ULL << R_HASH_IDX_SHA256)
#define R_HASH_SHA384 (1ULL << R_HASH_IDX_SHA384)
#define R_HASH_SHA512 (1ULL << R_HASH_IDX_SHA512)
#define R_HASH_MD4 (1ULL << R_HASH_IDX_MD4)
#define R_HASH_XOR (1ULL << R_HASH_IDX_XOR)
#define R_HASH_XORPAIR (1ULL << R_HASH_IDX_XORPAIR)
#define R_HASH_PARITY (1ULL << R_HASH_IDX_PARITY)
#define R_HASH_ENTROPY (1ULL << R_HASH_IDX_ENTROPY)
#define R_HASH_HAMDIST (1ULL << R_HASH_IDX_HAMDIST)
#define R_HASH_PCPRINT (1ULL << R_HASH_IDX_PCPRINT)
#define R_HASH_MOD255 (1ULL << R_HASH_IDX_MOD255)
#define R_HASH_XXHASH (1ULL << R_HASH_IDX_XXHASH)
#define R_HASH_ADLER32 (1ULL << R_HASH_IDX_ADLER32)
#define R_HASH_BASE64 (1ULL << R_HASH_IDX_BASE64)
#define R_HASH_BASE91 (1ULL << R_HASH_IDX_BASE91)
#define R_HASH_PUNYCODE (1ULL << R_HASH_IDX_PUNYCODE)
#define R_HASH_LUHN (1ULL << R_HASH_IDX_LUHN)
#define R_HASH_SSDEEP (1ULL << R_HASH_IDX_SSDEEP)
#define R_HASH_FLETCHER8 (1ULL << R_HASH_IDX_FLETCHER8)
#define R_HASH_FLETCHER16 (1ULL << R_HASH_IDX_FLETCHER16)
#define R_HASH_FLETCHER32 (1ULL << R_HASH_IDX_FLETCHER32)
#define R_HASH_FLETCHER64 (1ULL << R_HASH_IDX_FLETCHER64)

#define R_HASH_CRC8_SMBUS (1ULL << R_HASH_IDX_CRC8_SMBUS)
#if R_HAVE_CRC8_EXTRA
#define R_HASH_CRC8_CDMA2000 (1ULL << R_HASH_IDX_CRC8_CDMA2000)
#define R_HASH_CRC8_DARC (1ULL << R_HASH_IDX_CRC8_DARC)
#define R_HASH_CRC8_DVB_S2 (1ULL << R_HASH_IDX_CRC8_DVB_S2)
#define R_HASH_CRC8_EBU (1ULL << R_HASH_IDX_CRC8_EBU)
#define R_HASH_CRC8_ICODE (1ULL << R_HASH_IDX_CRC8_ICODE)
#define R_HASH_CRC8_ITU (1ULL << R_HASH_IDX_CRC8_ITU)
#define R_HASH_CRC8_MAXIM (1ULL << R_HASH_IDX_CRC8_MAXIM)
#define R_HASH_CRC8_ROHC (1ULL << R_HASH_IDX_CRC8_ROHC)
#define R_HASH_CRC8_WCDMA (1ULL << R_HASH_IDX_CRC8_WCDMA)
#endif /* #if R_HAVE_CRC8_EXTRA */

#if R_HAVE_CRC15_EXTRA
#define R_HASH_CRC15_CAN (1ULL << R_HASH_IDX_CRC15_CAN)
#endif /* #if R_HAVE_CRC15_EXTRA */

#define R_HASH_CRC16 (1ULL << R_HASH_IDX_CRC16)
#define R_HASH_CRC16_HDLC (1ULL << R_HASH_IDX_CRC16_HDLC)
#define R_HASH_CRC16_USB (1ULL << R_HASH_IDX_CRC16_USB)
#define R_HASH_CRC16_CITT (1ULL << R_HASH_IDX_CRC16_CITT)
#if R_HAVE_CRC16_EXTRA
#define R_HASH_CRC16_AUG_CCITT (1ULL << R_HASH_IDX_CRC16_AUG_CCITT)
#define R_HASH_CRC16_BUYPASS (1ULL << R_HASH_IDX_CRC16_BUYPASS)
#define R_HASH_CRC16_CDMA2000 (1ULL << R_HASH_IDX_CRC16_CDMA2000)
#define R_HASH_CRC16_DDS110 (1ULL << R_HASH_IDX_CRC16_DDS110)
#define R_HASH_CRC16_DECT_R (1ULL << R_HASH_IDX_CRC16_DECT_R)
#define R_HASH_CRC16_DECT_X (1ULL << R_HASH_IDX_CRC16_DECT_X)
#define R_HASH_CRC16_DNP (1ULL << R_HASH_IDX_CRC16_DNP)
#define R_HASH_CRC16_EN13757 (1ULL << R_HASH_IDX_CRC16_EN13757)
#define R_HASH_CRC16_GENIBUS (1ULL << R_HASH_IDX_CRC16_GENIBUS)
#define R_HASH_CRC16_MAXIM (1ULL << R_HASH_IDX_CRC16_MAXIM)
#define R_HASH_CRC16_MCRF4XX (1ULL << R_HASH_IDX_CRC16_MCRF4XX)
#define R_HASH_CRC16_RIELLO (1ULL << R_HASH_IDX_CRC16_RIELLO)
#define R_HASH_CRC16_T10_DIF (1ULL << R_HASH_IDX_CRC16_T10_DIF)
#define R_HASH_CRC16_TELEDISK (1ULL << R_HASH_IDX_CRC16_TELEDISK)
#define R_HASH_CRC16_TMS37157 (1ULL << R_HASH_IDX_CRC16_TMS37157)
#define R_HASH_CRCA (1ULL << R_HASH_IDX_CRCA)
#define R_HASH_CRC16_KERMIT (1ULL << R_HASH_IDX_CRC16_KERMIT)
#define R_HASH_CRC16_MODBUS (1ULL << R_HASH_IDX_CRC16_MODBUS)
#define R_HASH_CRC16_X25 (1ULL << R_HASH_IDX_CRC16_X25)
#define R_HASH_CRC16_XMODEM (1ULL << R_HASH_IDX_CRC16_XMODEM)
#endif /* #if R_HAVE_CRC16_EXTRA */

#if R_HAVE_CRC24
#define R_HASH_CRC24 (1ULL << R_HASH_IDX_CRC24)
#endif /* #if R_HAVE_CRC24 */

#define R_HASH_CRC32 (1ULL << R_HASH_IDX_CRC32)
#define R_HASH_CRC32C (1ULL << R_HASH_IDX_CRC32C)
#define R_HASH_CRC32_ECMA_267 (1ULL << R_HASH_IDX_CRC32_ECMA_267)
#if R_HAVE_CRC32_EXTRA
#define R_HASH_CRC32_BZIP2 (1ULL << R_HASH_IDX_CRC32_BZIP2)
#define R_HASH_CRC32D (1ULL << R_HASH_IDX_CRC32D)
#define R_HASH_CRC32_MPEG2 (1ULL << R_HASH_IDX_CRC32_MPEG2)
#define R_HASH_CRC32_POSIX (1ULL << R_HASH_IDX_CRC32_POSIX)
#define R_HASH_CRC32Q (1ULL << R_HASH_IDX_CRC32Q)
#define R_HASH_CRC32_JAMCRC (1ULL << R_HASH_IDX_CRC32_JAMCRC)
#define R_HASH_CRC32_XFER (1ULL << R_HASH_IDX_CRC32_XFER)
#endif /* #if R_HAVE_CRC32_EXTRA */

#if R_HAVE_CRC64
#define R_HASH_CRC64 (1ULL << R_HASH_IDX_CRC64)
#endif /* #if R_HAVE_CRC64 */
#if R_HAVE_CRC64_EXTRA
#define R_HASH_CRC64_ECMA182 (1ULL << R_HASH_IDX_CRC64_ECMA182)
#define R_HASH_CRC64_WE (1ULL << R_HASH_IDX_CRC64_WE)
#define R_HASH_CRC64_XZ (1ULL << R_HASH_IDX_CRC64_XZ)
#define R_HASH_CRC64_ISO (1ULL << R_HASH_IDX_CRC64_ISO)
#endif /* #if R_HAVE_CRC64 */
#define R_HASH_SIP (1ULL << R_HASH_IDX_SIP)

#define R_HASH_ALL ((1ULL << R_MIN(63, R_HASH_NUM_INDICES))-1)

#ifdef R_API
/* OO */
R_API RHash *r_hash_new(bool rst, ut64 flags);
R_API void r_hash_free(RHash *ctx);

/* methods */
R_API ut8 *r_hash_do_sip(RHash *ctx, const ut8 *input, int len);
R_API ut8 *r_hash_do_md4(RHash *ctx, const ut8 *input, int len);
R_API ut8 *r_hash_do_ssdeep(RHash *ctx, const ut8 *input, int len);
R_API ut8 *r_hash_do_md5(RHash *ctx, const ut8 *input, int len);
R_API ut8 *r_hash_do_sha1(RHash *ctx, const ut8 *input, int len);
R_API ut8 *r_hash_do_sha256(RHash *ctx, const ut8 *input, int len);
R_API ut8 *r_hash_do_sha384(RHash *ctx, const ut8 *input, int len);
R_API ut8 *r_hash_do_sha512(RHash *ctx, const ut8 *input, int len);
R_API ut8 *r_hash_do_hmac_sha256(RHash *ctx, const ut8 *input, int len, const ut8 *key, int klen);
R_API ut8 *r_hash_do_elf(RHash *ctx, const ut8 *input, int len);

R_API char *r_hash_tostring(RHash *ctx, const char *name, const ut8 *data, int len);

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
R_API char *r_hash_ssdeep(const ut8 *buf, size_t len);
R_API utcrc r_hash_crc_preset(const ut8 *data, ut32 size, enum CRC_PRESETS preset);
R_API ut64 r_hash_sip(const ut8* buf, ut64 len);

/* analysis */
R_API ut8  r_hash_hamdist(const ut8 *buf, int len);
R_API double r_hash_entropy(const ut8 *data, ut64 len);
R_API double r_hash_entropy_fraction(const ut8 *data, ut64 len);
R_API int r_hash_pcprint(const ut8 *buffer, ut64 len);

/* lifecycle */
R_API void r_hash_do_begin(RHash *ctx, ut64 flags);
R_API void r_hash_do_end(RHash *ctx, ut64 flags);
R_API void r_hash_do_spice(RHash *ctx, ut64 algo, int loops, RHashSeed *seed);
#endif

#ifdef __cplusplus
}
#endif

#endif
