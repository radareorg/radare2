/* radare - LGPL - Copyright 2008-2026 - pancake */

#ifndef R2_MUTA_H
#define R2_MUTA_H

#include <r_types.h>
#include <r_th.h>
#include <r_hash.h>
#include <r_bind.h>
#include <r_lib.h>
#include <r_muta/r_sm4.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_muta);

enum { // Cipher modes for encryption algorithms
	R_MUTA_CIPHER_MODE_ECB,
	R_MUTA_CIPHER_MODE_CBC,
	R_MUTA_CIPHER_MODE_OFB,
	R_MUTA_CIPHER_MODE_CFB,
};

// Operation types for muta processing
enum {
	R_MUTA_OPERATION_NONE = -1,
	R_MUTA_OPERATION_HASH = 0,
	R_MUTA_OPERATION_DECRYPT = 1,
	R_MUTA_OPERATION_ENCRYPT = 2,
};

typedef struct r_muta_result_t {
	ut8 *output;          // binary output (for hash, crypto, etc)
	int output_len;       // length of output
	int output_size;      // allocated size of output buffer
	double entropy;       // entropy value (if entropy operation)
	char *hex;            // hex-encoded output (optional, computed on demand)
	bool success;         // operation succeeded
	bool text_output;     // output is text, not binary
} RMutaResult;

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
	int dir;
	RList *plugins;
	ut32 sm4_sk[32];
	void *data;
	void *plugin_data; // Plugin-specific data (e.g., CPS2 keys)
	ut8 rot_key;
	char *subtype;
	RMutaResult *result;
} RMutaSession;

typedef enum {
	R_MUTA_TYPE_HASH,
	R_MUTA_TYPE_BASE,
	R_MUTA_TYPE_CRYPTO,
	R_MUTA_TYPE_SIGN,
	R_MUTA_TYPE_CHARSET,
	R_MUTA_TYPE_ALL = -1,
} RMutaType;

typedef bool (*RMutaSessionSetIVCallback)(RMutaSession *ms, const ut8 *iv, int ivlen);
typedef bool (*RMutaSessionUpdateCallback)(RMutaSession *ms, const ut8 *buf, int len);

typedef struct r_muta_plugin_t {
	RPluginMeta meta;
	const char *implements;
	bool (*check)(const char *algo);
	RMutaType type;
	bool text_output; // true if output is string, not binary

	int (*get_key_size)(RMutaSession *ms);
	RMutaSessionSetIVCallback set_iv;
	bool (*set_key)(RMutaSession *ms, const ut8 *key, int keylen, int mode, int direction);

	RMutaSession* (*begin)(RMuta *muta);
	RMutaSessionUpdateCallback update;
	bool (*end)(RMutaSession *ms, const ut8 *buf, int len);
#if 0
	bool (*init)(RMuta *muta, struct r_muta_plugin_t *cp);
#endif
	int (*decode)(RMutaSession *ms, const ut8 *in, int len, ut8 **out, int *consumed);
	bool (*fini)(RMutaSession *ms);
} RMutaPlugin;

typedef struct {
	ut8 *iv;
	ut8 *key;
	size_t key_len;
	int direction;
	// iv
	// ..
} RMutaOptions;

#ifdef R_API
R_API void r_muta_init(RMuta *muta);
R_API bool r_muta_add(RMuta *muta, RMutaPlugin *h);
R_API bool r_muta_del(RMuta *muta, RMutaPlugin *h);
R_API RMuta *R_NONNULL r_muta_new(void);
R_API void r_muta_free(RMuta *muta);
R_API char *r_muta_list(RMuta *muta, RMutaType type, int mode);
R_API void r_muta_bind(RMuta *muta, RMutaBind *bnd);

R_API RMutaPlugin *r_muta_find(RMuta *muta, const char *algo);
R_API RMutaType r_muta_algo_type(RMuta *muta, const char *algo);
R_API bool r_muta_algo_supports(RMuta *muta, const char *algo, RMutaType type);
R_API RMutaSession *r_muta_use(RMuta *muta, const char *algo);
R_API bool r_muta_session_set_subtype(RMutaSession *ms, const char *subtype);
R_API bool r_muta_session_set_key(RMutaSession *ms, const ut8* key, int keylen, int mode, int direction);
R_API bool r_muta_session_set_iv(RMutaSession *ms, const ut8 *iv, int ivlen);

R_API RMutaSession *r_muta_session_new(RMuta *muta, RMutaPlugin *cp);
R_API void r_muta_session_free(RMutaSession *ms);

R_API bool r_muta_session_update(RMutaSession *ms, const ut8 *buf, int len);
R_API bool r_muta_session_end(RMutaSession *ms, const ut8 *buf, int len);
R_API int r_muta_session_append(RMutaSession *ms, const ut8 *buf, int len);
R_API ut8 *r_muta_session_get_output(RMutaSession *ms, int *size);
R_API void r_muta_result_free(RMutaResult *res);

typedef int (*RMutaDecodeCallback)(void *, const ut8 *, int, ut8 **, int *);
R_API ut8 *r_muta_session_decode_string(RMutaSession *ms, const ut8 *input, int len, RMutaDecodeCallback decode_fn, void *decode_ctx);

// Simple wrapper for hash and entropy operations
R_API RMutaResult r_muta_process_simple(RMuta *muta, const char *algo, const ut8 *data, int len);

// Unified processing function for all operations (use r_muta_process_simple for simple cases)
R_API RMutaResult r_muta_process(RMuta *muta, const char *algo, const ut8 *data, int len,
	const ut8 *key, int key_len, const ut8 *iv, int iv_len, int direction);

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
extern RMutaPlugin r_muta_plugin_crc;
extern RMutaPlugin r_muta_plugin_ed25519;
extern RMutaPlugin r_muta_plugin_entropy;
extern RMutaPlugin r_muta_plugin_fletcher;
extern RMutaPlugin r_muta_plugin_md5;
extern RMutaPlugin r_muta_plugin_punycode;
extern RMutaPlugin r_muta_plugin_rc;
extern RMutaPlugin r_muta_plugin_rot;
extern RMutaPlugin r_muta_plugin_serpent;
extern RMutaPlugin r_muta_plugin_sha;
extern RMutaPlugin r_muta_plugin_sip;
extern RMutaPlugin r_muta_plugin_sm4;
extern RMutaPlugin r_muta_plugin_ssdeep;
extern RMutaPlugin r_muta_plugin_strhash;
extern RMutaPlugin r_muta_plugin_xor;
extern RMutaPlugin r_muta_plugin_add;
extern RMutaPlugin r_muta_plugin_charset_ascii;
extern RMutaPlugin r_muta_plugin_charset_ascii_ansi;
extern RMutaPlugin r_muta_plugin_charset_ascii_oem;
extern RMutaPlugin r_muta_plugin_charset_arabic_iso;
extern RMutaPlugin r_muta_plugin_charset_arabic_windows;
extern RMutaPlugin r_muta_plugin_charset_big5;
extern RMutaPlugin r_muta_plugin_charset_cyrillic_iso;
extern RMutaPlugin r_muta_plugin_charset_cyrillic_windows;
extern RMutaPlugin r_muta_plugin_charset_pokemon;
extern RMutaPlugin r_muta_plugin_charset_ebcdic37;
extern RMutaPlugin r_muta_plugin_charset_iso8859_1;
extern RMutaPlugin r_muta_plugin_charset_greek_iso;
extern RMutaPlugin r_muta_plugin_charset_greek_windows;
extern RMutaPlugin r_muta_plugin_charset_hebrew_iso;
extern RMutaPlugin r_muta_plugin_charset_hebrew_windows;
extern RMutaPlugin r_muta_plugin_charset_hiragana;
extern RMutaPlugin r_muta_plugin_charset_seven;
extern RMutaPlugin r_muta_plugin_charset_iso_646;
extern RMutaPlugin r_muta_plugin_charset_jis7;
extern RMutaPlugin r_muta_plugin_charset_katakana;
extern RMutaPlugin r_muta_plugin_charset_macintosh;
extern RMutaPlugin r_muta_plugin_charset_pokered;

#ifdef __cplusplus
}
#endif

#endif
