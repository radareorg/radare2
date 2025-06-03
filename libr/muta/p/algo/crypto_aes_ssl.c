#include <openssl/evp.h>
#include "crypto_aes.h"

// AES encryption or decryption with ECB mode of operation using OpenSSL.
bool aes_ecb (RCryptoAESState *st, ut8 *const ibuf, ut8 *const obuf, bool encrypt, const int blocks) {
	int length = 0;
	EVP_CIPHER const *mode;
	bool ret = true;

	if (st->key_size == 16) {
		mode = EVP_aes_128_ecb ();
	} else if (st->key_size == 24) {
		mode = EVP_aes_192_ecb ();
	} else if (st->key_size == 32) {
		mode = EVP_aes_256_ecb ();
	} else {
		R_LOG_ERROR ("Wrong key length");
		return false;
	}

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
	if (!ctx) {
		R_LOG_ERROR ("EVP_CIPHER_CTX_new failed");
		ret = false;
	}

	if (1 != EVP_CipherInit (ctx, mode, st->key, NULL, encrypt)) {
		R_LOG_ERROR ("EVP_CipherInit failed");
		ret = false;
	}

	// Disable padding
	EVP_CIPHER_CTX_set_padding (ctx, 0);

	if (1 != EVP_CipherUpdate (ctx, obuf, &length, ibuf, AES_BLOCK_SIZE * blocks)) {
		R_LOG_ERROR ("EVP_EncryptUpdate failed");
		ret = false;
	}

	EVP_CIPHER_CTX_free (ctx);
	return ret;
}

// AES key wrap or unwrap using OpenSSL.
R_IPI bool aes_wrap(RCryptoAESState *st, const ut8 *ibuf, ut8 *obuf, const ut8 *iv, bool encrypt, int blocks) {
	int length = 0;
	EVP_CIPHER const *mode;
	bool ret = true;

	if (st->key_size == 16) {
		mode = EVP_aes_128_wrap ();
	} else if (st->key_size == 24) {
		mode = EVP_aes_192_wrap ();
	} else if (st->key_size == 32) {
		mode = EVP_aes_256_wrap ();
	} else {
		R_LOG_ERROR ("Wrong key length");
		return false;
	}

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
	if (!ctx) {
		R_LOG_ERROR ("EVP_CIPHER_CTX_new failed");
		ret = false;
	}

	if (1 != EVP_CipherInit (ctx, mode, st->key, iv, encrypt)) {
		R_LOG_ERROR ("EVP_CipherInit failed");
		ret = false;
	}

	if (1 != EVP_CipherUpdate (ctx, obuf, &length, ibuf, AES_WRAP_BLOCK_SIZE * blocks)) {
		R_LOG_ERROR ("EVP_EncryptUpdate failed");
		ret = false;
	}

	EVP_CIPHER_CTX_free (ctx);
	return ret;
}

// AES encryption or decryption with CBC mode of operation using OpenSSL.
R_IPI bool aes_cbc(RCryptoAESState *st, ut8 *ibuf, ut8 *obuf, ut8 *iv, bool encrypt, const int blocks) {
	int length = 0;
	EVP_CIPHER const *mode;
	bool ret = true;

	if (st->key_size == 16) {
		mode = EVP_aes_128_cbc ();
	} else if (st->key_size == 24) {
		mode = EVP_aes_192_cbc ();
	} else if (st->key_size == 32) {
		mode = EVP_aes_256_cbc ();
	} else {
		R_LOG_ERROR ("Wrong key length");
		return false;
	}

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
	if (!ctx) {
		R_LOG_ERROR ("EVP_CIPHER_CTX_new failed");
		ret = false;
	}

	if (1 != EVP_CipherInit (ctx, mode, st->key, iv, encrypt)) {
		R_LOG_ERROR ("EVP_CipherInit failed");
		ret = false;
	}

	// Disable padding
	EVP_CIPHER_CTX_set_padding (ctx, 0);

	if (1 != EVP_CipherUpdate (ctx, obuf, &length, ibuf, AES_BLOCK_SIZE * blocks)) {
		R_LOG_ERROR ("EVP_CipherUpdate failed");
		ret = false;
	}

	EVP_CIPHER_CTX_free (ctx);
	return ret;
}
