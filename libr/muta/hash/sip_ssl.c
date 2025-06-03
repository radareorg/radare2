/* radare2 - LGPL - Copyright 2024 - Sylvain Pelissier */

#include <r_hash.h>
#include <openssl/evp.h>

#define SIPHASH_KEY_SIZE  16
#define SIPHASH_HASH_SIZE 8

R_API ut64 r_hash_sip(const ut8 *in, ut64 inlen) {
	OSSL_PARAM params[2];

	/* 	SipHash-2-4 using the key:
		0xb5d4c9eb79104a796fec8b1b428781d4 (big-endian)
	*/
	unsigned char key[SIPHASH_KEY_SIZE] = { 0xb5, 0xd4, 0xc9, 0xeb, 0x79, 0x10, 0x4a, 0x79, 0x6f, 0xec, 0x8b, 0x1b, 0x42, 0x87, 0x81, 0xd4 };
	unsigned char hash[SIPHASH_HASH_SIZE];
	size_t hash_len;

	// OpenSSL context initialization
	EVP_MAC *md = EVP_MAC_fetch (NULL, "SIPHASH", NULL);
	if (!md) {
		R_LOG_ERROR ("EVP_MAC_fetch failed");
	}
	EVP_MAC_CTX *ctx = EVP_MAC_CTX_new (md);
	if (!ctx) {
		R_LOG_ERROR ("EVP_MAC_CTX_new failed");
	}
	// Parameters
	size_t size = SIPHASH_HASH_SIZE;
	params[0] = OSSL_PARAM_construct_size_t ("size", &size);
	params[1] = OSSL_PARAM_construct_end ();

	// Hash
	if (!EVP_MAC_init (ctx, key, SIPHASH_KEY_SIZE, params)) {
		R_LOG_ERROR ("EVP_MAC_init failed");
	}

	if (!EVP_MAC_update (ctx, in, inlen)) {
		R_LOG_ERROR ("EVP_MAC_update failed");
	}

	if (!EVP_MAC_final (ctx, hash, &hash_len, SIPHASH_HASH_SIZE)) {
		R_LOG_ERROR ("EVP_MAC_final failed");
	}

	// Cleanup
	EVP_MAC_CTX_free (ctx);

	return r_read_le64 (hash);
}
