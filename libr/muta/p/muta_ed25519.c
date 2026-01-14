/* radare - ZLib - Copyright 2024-2025 - Sylvain Pelissier
 * Implementation of Ed25519 signature algorithm (RFC 8032)
 * Based on Orson Peters implementation: https://github.com/orlp/ed25519 */

#include <r_muta.h>
#include <r_muta/r_ed25519.h>
#include "../signature/ed25519/ge.h"
#include "../signature/ed25519/sc.h"
#include "../hash/sha2.h"

static bool ed25519_set_key(RMutaSession *ms, const ut8 *key, int keylen, int mode, int direction) {
	if (keylen != 32 && keylen != 64) {
		R_LOG_ERROR ("Invalid key length");
		return false;
	}
	ms->data = malloc (ED25519_PUBKEY_LENGTH);
	if (keylen == ED25519_SEED_LENGTH) {
		// Using a seed
		keylen = ED25519_PRIVKEY_LENGTH;
		ms->key = malloc (keylen);
		r_muta_ed25519_keypair (key, ms->key, (ut8 *)ms->data);
	} else if (keylen == ED25519_PRIVKEY_LENGTH) {
		ge_p3 A;
		memcpy (ms->key, key, keylen);
		ge_scalarmult_base (&A, ms->key);
		ge_p3_tobytes (ms->data, &A);
	}

	ms->key_len = keylen;
	ms->key[0] &= 248;
	ms->key[31] &= 63;
	ms->key[31] |= 64;
	ms->dir = direction;
	return true;
}

static int ed25519_get_key_size(RMutaSession *ms) {
	return ms->key_len;
}

static bool update(RMutaSession *ms, const ut8 *buf, int len) {
	ut8 *public_key = (ut8 *)ms->data;
	ut8 r[64];
	ge_p3 R;
	ut8 signature[64] = { 0 };

	// Signature (R, S)
	if (ms->dir == R_MUTA_OPERATION_ENCRYPT) {
		// r = H ( ms->key[32:64] || buf)
		RHash *ctx = r_hash_new (true, R_HASH_SHA512);
		r_sha512_init (&ctx->sha512);
		r_sha512_update (&ctx->sha512, ms->key + 32, 32);
		r_sha512_update (&ctx->sha512, buf, len);
		r_sha512_final (ctx->digest, &ctx->sha512);
		memcpy (r, ctx->digest, R_HASH_SIZE_SHA512);
		// R = r * B
		sc_reduce (r);
		ge_scalarmult_base (&R, r);
		ge_p3_tobytes (signature, &R);
		// S = r + H (R || A || buf) * ms->key[0:32]
		r_sha512_init (&ctx->sha512);
		r_sha512_update (&ctx->sha512, signature, 32);
		r_sha512_update (&ctx->sha512, public_key, 32);
		r_sha512_update (&ctx->sha512, buf, len);
		r_sha512_final (ctx->digest, &ctx->sha512);
		sc_reduce (ctx->digest);
		sc_muladd (signature + 32, ctx->digest, ms->key, r);
		r_hash_free (ctx);
	} else {
		return false;
	}
	r_muta_session_append (ms, signature, ED25519_SIG_LEN);
	return true;
}

static bool end(RMutaSession *ms, const ut8 *buf, int len) {
	return update (ms, buf, len);
}

RMutaPlugin r_muta_plugin_ed25519 = {
	.type = R_MUTA_TYPE_SIGN,
	.implements = "ed25519",
	.meta = {
		.name = "ed25519",
		.desc = "Elliptic curve pubkey cryptographic algorithm used for signing and verification",
		.author = "Sylvain Pelissier",
		.license = "Zlib",
	},
	.set_key = ed25519_set_key,
	.get_key_size = ed25519_get_key_size,
	.update = update,
	.end = end
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_ed25519,
	.version = R2_VERSION
};
#endif
