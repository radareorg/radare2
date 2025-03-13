/* radare - LGPL - Copyright 2008-2024 - pancake */

#ifndef R2_CRYPTO_H
#define R2_CRYPTO_H

#include <r_types.h>
#include <r_th.h>
// #include <r_crypto/r_des.h>
#include <r_hash.h>
#include <r_lib.h>
#include <r_crypto/r_sm4.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_crypto);

enum {
	R_CRYPTO_MODE_ECB,
	R_CRYPTO_MODE_CBC,
	R_CRYPTO_MODE_OFB,
	R_CRYPTO_MODE_CFB,
};

// TODO: use encode/decode wordings?
enum {
	R_CRYPTO_DIR_NONE = -1,
	R_CRYPTO_DIR_HASH = 0,
	R_CRYPTO_DIR_DECRYPT = 1,
	R_CRYPTO_DIR_ENCRYPT = 2,
};

typedef struct r_crypto_t {
	struct r_crypto_plugin_t* h;
#if 0
	ut8 *key;
	ut8 *iv;
	int key_len;
	ut8 *output;
	int output_len;
	int output_size;
	int dir;
#endif
	bool bigendian;
	void *user;
	RList *plugins;
} RCrypto;

typedef struct r_crypto_job_t {
	struct r_crypto_plugin_t* h;
	struct r_crypto_t* c;
	int flag;
	ut8 *key;
	ut8 *iv;
	int key_len;
	ut8 *output;
	int output_len;
	int output_size;
	int dir;
	RList *plugins;
	ut32 sm4_sk[32];
	void *data;
	ut32 cps2key[2];
	ut8 rot_key;
	double entropy;
} RCryptoJob; // rename to CryptoState

typedef enum {
	R_CRYPTO_TYPE_ENCODER = 'e',
	R_CRYPTO_TYPE_HASH = 'h',
	R_CRYPTO_TYPE_ENCRYPT = 'c', // CIPHER
	R_CRYPTO_TYPE_SIGNATURE = 's',
	R_CRYPTO_TYPE_ALL = 'a'
} RCryptoType;

typedef bool (*RCryptoJobSetIVCallback)(RCryptoJob *ci, const ut8 *iv, int ivlen);
typedef bool (*RCryptoJobUpdateCallback)(RCryptoJob *ci, const ut8 *buf, int len);

typedef struct r_crypto_plugin_t {
	RPluginMeta meta;
	const char *implements;
	RCryptoType type;
	bool (*check)(const char *algo); // must be deprecated

	int (*get_key_size)(RCryptoJob *cry);
	RCryptoJobSetIVCallback set_iv;
	bool (*set_key)(RCryptoJob *ci, const ut8 *key, int keylen, int mode, int direction);

	RCryptoJob* (*begin)(RCrypto *cry);
	RCryptoJobUpdateCallback update;
	bool (*end)(RCryptoJob *ci, const ut8 *buf, int len);
#if 0
	bool (*init)(RCrypto *cry, struct r_crypto_plugin_t *cp);
#endif
	bool (*fini)(RCryptoJob *cj);
} RCryptoPlugin;

typedef ut64 RCryptoSelector;

#ifdef R_API
R_API void r_crypto_init(RCrypto *cry);
R_API bool r_crypto_add(RCrypto *cry, RCryptoPlugin *h);
R_API RCrypto *r_crypto_new(void);
R_API void r_crypto_free(RCrypto *cry);
R_API void r_crypto_list(RCrypto *cry, PrintfCallback cb_printf, int mode, RCryptoType type);

// R_API RCryptoHash *r_crypto_hash(RCrypto *cry, bool rst, const char *name);

R_API RCryptoJob *r_crypto_use(RCrypto *cry, const char *algo);
R_API bool r_crypto_job_set_key(RCryptoJob *cry, const ut8* key, int keylen, int mode, int direction);
R_API bool r_crypto_job_set_iv(RCryptoJob *cry, const ut8 *iv, int ivlen);

R_API RCryptoJob *r_crypto_job_new(RCrypto *cry, RCryptoPlugin *cp);
R_API void r_crypto_job_free(RCryptoJob *cj);

R_API RCryptoJob *r_crypto_begin(RCrypto *cry);
R_API bool r_crypto_job_update(RCryptoJob *cry, const ut8 *buf, int len);
R_API bool r_crypto_job_end(RCryptoJob *cry, const ut8 *buf, int len);
R_API int r_crypto_job_append(RCryptoJob *cry, const ut8 *buf, int len);
R_API ut8 *r_crypto_job_get_output(RCryptoJob *cry, int *size);
#endif

/* plugin pointers */
extern RCryptoPlugin r_crypto_plugin_aes;
extern RCryptoPlugin r_crypto_plugin_aes_cbc;
extern RCryptoPlugin r_crypto_plugin_aes_wrap;
extern RCryptoPlugin r_crypto_plugin_base64;
extern RCryptoPlugin r_crypto_plugin_base91;
extern RCryptoPlugin r_crypto_plugin_bech32;
extern RCryptoPlugin r_crypto_plugin_blowfish;
extern RCryptoPlugin r_crypto_plugin_cps2;
extern RCryptoPlugin r_crypto_plugin_des;
extern RCryptoPlugin r_crypto_plugin_ed25519;
extern RCryptoPlugin r_crypto_plugin_entropy;
extern RCryptoPlugin r_crypto_plugin_punycode;
extern RCryptoPlugin r_crypto_plugin_rc2;
extern RCryptoPlugin r_crypto_plugin_rc4;
extern RCryptoPlugin r_crypto_plugin_rc6;
extern RCryptoPlugin r_crypto_plugin_rot;
extern RCryptoPlugin r_crypto_plugin_rol;
extern RCryptoPlugin r_crypto_plugin_ror;
extern RCryptoPlugin r_crypto_plugin_serpent;
extern RCryptoPlugin r_crypto_plugin_sip;
extern RCryptoPlugin r_crypto_plugin_sm4;
extern RCryptoPlugin r_crypto_plugin_strhash;
extern RCryptoPlugin r_crypto_plugin_xor;

#define R_CRYPTO_NONE 0ULL
#define R_CRYPTO_RC2 1ULL
#define R_CRYPTO_RC4 1ULL<<1
#define R_CRYPTO_RC6 1ULL<<2
#define R_CRYPTO_AES_ECB 1ULL<<3
#define R_CRYPTO_AES_CBC 1ULL<<4
#define R_CRYPTO_AES_WRAP 1ULL<<5
#define R_CRYPTO_ROR 1ULL<<6
#define R_CRYPTO_ROL 1ULL<<7
#define R_CRYPTO_ROT 1ULL<<8
#define R_CRYPTO_BLOWFISH 1ULL<<9
#define R_CRYPTO_CPS2 1ULL<<10
#define R_CRYPTO_DES_ECB 1ULL<<11
#define R_CRYPTO_XOR 1ULL<<12
#define R_CRYPTO_SERPENT 1ULL<<13
#define R_CRYPTO_SM4_ECB  1ULL << 14
#define R_CRYPTO_BECH32   1ULL << 15
#define R_CRYPTO_ALL 0xFFFF

#define R_CODEC_NONE 0ULL
#define R_CODEC_B64 1ULL
#define R_CODEC_B91 1ULL<<1
#define R_CODEC_PUNYCODE 1ULL<<2
#define R_CODEC_ALL 0xFFFF

#ifdef __cplusplus
}
#endif

#endif
