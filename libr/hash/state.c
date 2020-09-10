/* radare - LGPL - Copyright 2009-2017 pancake */

#include <r_hash.h>

#if HAVE_LIB_SSL
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#else
#include "md4.h"
#include "md5.h"
#include "sha1.h"
#include "sha2.h"
#endif

#define CHKFLAG(x) if (!flags || flags & (x))

R_API RHash *r_hash_new(bool rst, ut64 flags) {
	RHash *ctx = R_NEW0 (RHash);
	if (ctx) {
		r_hash_do_begin (ctx, flags);
		ctx->rst = rst;
	}
	return ctx;
}

R_API void r_hash_do_begin(RHash *ctx, ut64 flags) {
	CHKFLAG (R_HASH_MD5) r_hash_do_md5 (ctx, NULL, -1);
	CHKFLAG (R_HASH_SHA1) SHA1_Init (&ctx->sha1);
	CHKFLAG (R_HASH_SHA256) SHA256_Init (&ctx->sha256);
	CHKFLAG (R_HASH_SHA384) SHA384_Init (&ctx->sha384);
	CHKFLAG (R_HASH_SHA512) SHA512_Init (&ctx->sha512);
	ctx->rst = false;
}

R_API void r_hash_do_end(RHash *ctx, ut64 flags) {
	CHKFLAG (R_HASH_MD5) r_hash_do_md5 (ctx, NULL, -2);
	CHKFLAG (R_HASH_SHA1) SHA1_Final (ctx->digest, &ctx->sha1);
	CHKFLAG (R_HASH_SHA256) SHA256_Final (ctx->digest, &ctx->sha256);
	CHKFLAG (R_HASH_SHA384) SHA384_Final (ctx->digest, &ctx->sha384);
	CHKFLAG (R_HASH_SHA512) SHA512_Final (ctx->digest, &ctx->sha512);
	ctx->rst = true;
}

R_API void r_hash_free(RHash *ctx) {
	free (ctx);
}

R_API ut8 *r_hash_do_sha1(RHash *ctx, const ut8 *input, int len) {
	if (len < 0) {
		return NULL;
	}
	if (ctx->rst) {
		SHA1_Init (&ctx->sha1);
	}
	SHA1_Update (&ctx->sha1, input, len);
	if (ctx->rst || len == 0) {
		SHA1_Final (ctx->digest, &ctx->sha1);
	}
	return ctx->digest;
}

R_API ut8 *r_hash_do_sha256(RHash *ctx, const ut8 *input, int len) {
	if (len < 0) {
		return NULL;
	}
	if (ctx->rst) {
		SHA256_Init (&ctx->sha256);
	}
	SHA256_Update (&ctx->sha256, input, len);
	if (ctx->rst || len == 0) {
		SHA256_Final (ctx->digest, &ctx->sha256);
	}
	return ctx->digest;
}

R_API ut8 *r_hash_do_sha384(RHash *ctx, const ut8 *input, int len) {
	if (len < 0) {
		return NULL;
	}
	if (ctx->rst) {
		SHA384_Init (&ctx->sha384);
	}
	SHA384_Update (&ctx->sha384, input, len);
	if (ctx->rst || len == 0) {
		SHA384_Final (ctx->digest, &ctx->sha384);
	}
	return ctx->digest;
}

R_API ut8 *r_hash_do_sha512(RHash *ctx, const ut8 *input, int len) {
	if (len < 0) {
		return NULL;
	}
	if (ctx->rst) {
		SHA512_Init (&ctx->sha512);
	}
	SHA512_Update (&ctx->sha512, input, len);
	if (ctx->rst || len == 0) {
		SHA512_Final (ctx->digest, &ctx->sha512);
	}
	return ctx->digest;
}

R_API ut8 *r_hash_do_md5(RHash *ctx, const ut8 *input, int len) {
	if (len < 0) {
		if (len == -1) {
			MD5_Init (&ctx->md5);
		} else if (len == -2) {
			MD5_Final (ctx->digest, &ctx->md5);
		}
		return NULL;
	}
	if (ctx->rst) {
		MD5_Init (&ctx->md5);
	}
	if (len > 0) {
		MD5_Update (&ctx->md5, input, len);
	} else {
		MD5_Update (&ctx->md5, (const ut8 *) "", 0);
	}
	if (ctx->rst) {
		MD5_Final (ctx->digest, &ctx->md5);
	}
	return ctx->digest;
}

R_API ut8 *r_hash_do_md4(RHash *ctx, const ut8 *input, int len) {
	if (len >= 0) {
		MD4 (input, len, ctx->digest);
		return ctx->digest;
	}
	return NULL;
}

R_API ut8 *r_hash_do_hmac_sha256(RHash *ctx, const ut8 *input, int len, const ut8 *key, int klen) {
	if (len < 0 || klen < 0) {
		return NULL;
	}

	size_t i;
	ut8 bskey[SHA256_BLOCK_LENGTH]; // block-sized key
	ut8 kpad[SHA256_BLOCK_LENGTH]; // keypad for opad, ipad

	// If klen > block-size, bskey = Hash(key)
	memset (bskey, 0, SHA256_BLOCK_LENGTH);
	if (klen > SHA256_BLOCK_LENGTH) {
		SHA256_Init (&ctx->sha256);
		SHA256_Update (&ctx->sha256, key, klen);
		SHA256_Final (ctx->digest, &ctx->sha256);
		memcpy (bskey, ctx->digest, R_HASH_SIZE_SHA256);
	} else {
		memcpy (bskey, key, klen);
	}

	// XOR block-sized key with ipad 0x36
	memset (kpad, 0, SHA256_BLOCK_LENGTH);
	memcpy (kpad, bskey, SHA256_BLOCK_LENGTH);
	for (i = 0; i < SHA256_BLOCK_LENGTH; i++) {
		kpad[i] ^= 0x36;
	}

	// Inner hash (key ^ ipad || input)
	SHA256_Init (&ctx->sha256);
	SHA256_Update (&ctx->sha256, kpad, SHA256_BLOCK_LENGTH);
	SHA256_Update (&ctx->sha256, input, len);
	SHA256_Final (ctx->digest, &ctx->sha256);

	// XOR block-sized key with opad 0x5c
	memset (kpad, 0, SHA256_BLOCK_LENGTH);
	memcpy (kpad, bskey, SHA256_BLOCK_LENGTH);
	for (i = 0; i < SHA256_BLOCK_LENGTH; i++) {
		kpad[i] ^= 0x5c;
	}

	// Outer hash (key ^ opad || Inner hash)
	SHA256_Init (&ctx->sha256);
	SHA256_Update (&ctx->sha256, kpad, SHA256_BLOCK_LENGTH);
	SHA256_Update (&ctx->sha256, ctx->digest, R_HASH_SIZE_SHA256);
	SHA256_Final (ctx->digest, &ctx->sha256);

	return ctx->digest;
}
