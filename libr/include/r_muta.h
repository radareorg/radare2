/* radare - LGPL - Copyright 2008-2025 - pancake */

#ifndef R2_MUTA_H
#define R2_MUTA_H

#include <r_types.h>
#include <r_th.h>
#include <r_hash.h>
#include <r_lib.h>
#include <r_muta/r_sm4.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_muta);

enum { // this is aes-specific and should be part of options
	R_CRYPTO_MODE_ECB,
	R_CRYPTO_MODE_CBC,
	R_CRYPTO_MODE_OFB,
	R_CRYPTO_MODE_CFB,
};

// TODO: use encode/decode wordings? or just a bool?
enum {
	R_CRYPTO_DIR_NONE = -1,
	R_CRYPTO_DIR_HASH = 0,
	R_CRYPTO_DIR_DECRYPT = 1,
	R_CRYPTO_DIR_ENCRYPT = 2,
};

typedef struct r_muta_t {
	struct r_muta_plugin_t* h;
	bool bigendian;
	void *user;
	RList *plugins;
} RMuta;

typedef struct r_muta_session_t {
	struct r_muta_plugin_t* h;
	struct r_muta_t* c;
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
} RMutaSession; // rename to CryptoState

typedef enum {
	R_MUTA_TYPE_HASH,
	R_MUTA_TYPE_BASE,
	R_MUTA_TYPE_CRYPTO,
	R_MUTA_TYPE_SIGN,
	R_MUTA_TYPE_CHARSET,
	R_MUTA_TYPE_ALL = -1,
} RMutaType;

typedef bool (*RMutaSessionSetIVCallback)(RMutaSession *ci, const ut8 *iv, int ivlen);
typedef bool (*RMutaSessionUpdateCallback)(RMutaSession *ci, const ut8 *buf, int len);

typedef struct r_muta_plugin_t {
	RPluginMeta meta;
	const char *implements;
	RMutaType type;
	bool (*check)(const char *algo); // must be deprecated

	int (*get_key_size)(RMutaSession *cry);
	RMutaSessionSetIVCallback set_iv;
	bool (*set_key)(RMutaSession *ci, const ut8 *key, int keylen, int mode, int direction);

	RMutaSession* (*begin)(RMuta *cry);
	RMutaSessionUpdateCallback update;
	bool (*end)(RMutaSession *ci, const ut8 *buf, int len);
#if 0
	bool (*init)(RMuta *cry, struct r_muta_plugin_t *cp);
#endif
	bool (*fini)(RMutaSession *cj);
} RMutaPlugin;

typedef struct {
	ut8 *iv;
	ut8 *key;
	size_t key_len;
	int direction;
	// iv
	// ..
} RMutaOptions;

typedef ut64 RMutaSelector;

#ifdef R_API
R_API void r_muta_init(RMuta *cry);
R_API bool r_muta_add(RMuta *cry, RMutaPlugin *h);
R_API RMuta *r_muta_new(void);
R_API void r_muta_free(RMuta *cry);
R_API char *r_muta_list(RMuta *cry, RMutaType type, int mode);

// R_API RMutaHash *r_muta_hash(RMuta *cry, bool rst, const char *name);

#if 1
// DEPRECATE
R_API RMutaSession *r_muta_use(RMuta *cry, const char *algo);
R_API bool r_muta_session_set_key(RMutaSession *cry, const ut8* key, int keylen, int mode, int direction);
R_API bool r_muta_session_set_iv(RMutaSession *cry, const ut8 *iv, int ivlen);
#endif

R_API RMutaSession *r_muta_new_session(RMuta *mu, const char *algo, RMutaOptions *opt);


R_API RMutaSession *r_muta_session_new(RMuta *cry, RMutaPlugin *cp);
R_API void r_muta_session_free(RMutaSession *cj);

R_API RMutaSession *r_muta_begin(RMuta *cry);
R_API bool r_muta_session_update(RMutaSession *cry, const ut8 *buf, int len);
R_API bool r_muta_session_end(RMutaSession *cry, const ut8 *buf, int len);
R_API int r_muta_session_append(RMutaSession *cry, const ut8 *buf, int len);
R_API ut8 *r_muta_session_get_output(RMutaSession *cry, int *size);

#endif

// TODO: deprecate
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
#define R_CRYPTO_SM4_ECB 1ULL << 14
#define R_CRYPTO_BECH32 1ULL << 15
#define R_CRYPTO_ALL 0xFFFF


/* plugin pointers */
extern RMutaPlugin r_muta_plugin_null;
extern RMutaPlugin r_muta_plugin_aes;
extern RMutaPlugin r_muta_plugin_aes_cbc;
extern RMutaPlugin r_muta_plugin_aes_wrap;
extern RMutaPlugin r_muta_plugin_base64;
extern RMutaPlugin r_muta_plugin_base91;
extern RMutaPlugin r_muta_plugin_bech32;
extern RMutaPlugin r_muta_plugin_blowfish;
extern RMutaPlugin r_muta_plugin_cps2;
extern RMutaPlugin r_muta_plugin_des;
extern RMutaPlugin r_muta_plugin_ed25519;
extern RMutaPlugin r_muta_plugin_entropy;
extern RMutaPlugin r_muta_plugin_punycode;
extern RMutaPlugin r_muta_plugin_rc2;
extern RMutaPlugin r_muta_plugin_rc4;
extern RMutaPlugin r_muta_plugin_rc6;
extern RMutaPlugin r_muta_plugin_rot;
extern RMutaPlugin r_muta_plugin_rol;
extern RMutaPlugin r_muta_plugin_ror;
extern RMutaPlugin r_muta_plugin_serpent;
extern RMutaPlugin r_muta_plugin_sip;
extern RMutaPlugin r_muta_plugin_sm4;
extern RMutaPlugin r_muta_plugin_strhash;
extern RMutaPlugin r_muta_plugin_xor;
extern RMutaPlugin r_muta_plugin_add;
extern RMutaPlugin r_muta_plugin_charset_pokemon;

#ifdef __cplusplus
}
#endif

#endif
