#ifndef _INCLUDE_CRYPTO_R_
#define _INCLUDE_CRYPTO_R_

#include <list.h>
#include <r_types.h>

enum {
	R_CRYPTO_MODE_ECB,
	R_CRYPTO_MODE_CBC,
	R_CRYPTO_MODE_OFB,
	R_CRYPTO_MODE_CFB,
};

enum {
	R_CRYPTO_DIR_CIPHER,
	R_CRYPTO_DIR_DECIPHER,
};

typedef struct r_crypto_t {
	struct r_crypto_plugin_t* h;
	ut8 *key;
	ut8 *iv;
	int key_len;
	ut8 *output;
	int output_len;
	int output_size;
	void *user;
	struct list_head handlers;
} RCrypto;

typedef struct r_crypto_plugin_t {
	const char *name;
	int (*get_key_size)(struct r_crypto_t* cry);
	int (*set_iv)(struct r_crypto_t* cry, const ut8 *iv);
	int (*set_key)(struct r_crypto_t* cry, const ut8 *key, int mode, int direction);
	int (*update)(struct r_crypto_t* cry, const ut8 *buf, int len);
	int (*final)(struct r_crypto_t* cry, const ut8 *buf, int len);
	int (*use)(const char *algo);
	int (*fini)(struct r_crypto_t *cry);
	struct list_head list;
} RCryptoPlugin;

#ifdef R_API
R_API struct r_crypto_t *r_crypto_init(struct r_crypto_t *cry, int hard);
R_API struct r_crypto_t *r_crypto_as_new(struct r_crypto_t *cry);
R_API int r_crypto_add(struct r_crypto_t *cry, struct r_crypto_plugin_t *h);
R_API struct r_crypto_t *r_crypto_new();
R_API struct r_crypto_t *r_crypto_free(struct r_crypto_t *cry);
R_API int r_crypto_use(struct r_crypto_t *cry, const char *algo);
R_API int r_crypto_set_key(struct r_crypto_t *cry, const ut8* key, int mode, int direction);
R_API int r_crypto_get_key_size(struct r_crypto_t *cry);
R_API int r_crypto_set_iv(struct r_crypto_t *cry, const ut8 *iv);
R_API int r_crypto_update(struct r_crypto_t *cry, ut8 *buf, int len);
R_API int r_crypto_final(struct r_crypto_t *cry, ut8 *buf, int len);
R_API int r_crypto_append(struct r_crypto_t *cry, const ut8 *buf, int len);
R_API ut8 *r_crypto_get_output(struct r_crypto_t *cry);
#endif

/* plugin pointers */
extern struct r_crypto_plugin_t r_crypto_plugin_aes;

#endif
