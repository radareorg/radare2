/* radare - LGPL - Copyright 2009-2017 pancake */

#include <r_hash.h>
#include <r_util.h>

#if HAVE_LIB_SSL
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#  define r_SHA256_BLOCK_LENGTH SHA256_BLOCK_LENGTH

#  define r_SHA1_Init           SHA1_Init
#  define r_SHA1_Update         SHA1_Update
#  define r_SHA1_Final          SHA1_Final

#  define r_SHA256_Init         SHA256_Init
#  define r_SHA256_Update       SHA256_Update
#  define r_SHA256_Final        SHA256_Final

#  define r_SHA384_Init         SHA384_Init
#  define r_SHA384_Update       SHA384_Update
#  define r_SHA384_Final        SHA384_Final

#  define r_SHA512_Init         SHA512_Init
#  define r_SHA512_Update       SHA512_Update
#  define r_SHA512_Final        SHA512_Final

#  define r_MD5_Init            MD5_Init
#  define r_MD5_Update          MD5_Update
#  define r_MD5_Final           MD5_Final
#else
#include "md4.h"
#include "md5.h"
#include "sha1.h"
#include "sha2.h"
#endif

#define CHKFLAG(x) if (!flags || flags & (x))

R_API RHash *r_hash_new(bool rst, ut64 flags) {
	if (R_HASH_NUM_INDICES > 63) {
		// needs a non-bitmask way to do that, maybe using RBitmap
		R_LOG_WARN ("Too many hash algorithms registered, some may be unavailable");
	}
	RHash *ctx = R_NEW0 (RHash);
	if (ctx) {
		r_hash_do_begin (ctx, flags);
		ctx->rst = rst;
	}
	return ctx;
}

R_API void r_hash_do_begin(RHash *ctx, ut64 flags) {
	CHKFLAG (R_HASH_MD5) r_hash_do_md5 (ctx, NULL, -1);
	CHKFLAG (R_HASH_SHA1) r_SHA1_Init (&ctx->sha1);
	CHKFLAG (R_HASH_SHA256) r_SHA256_Init (&ctx->sha256);
	CHKFLAG (R_HASH_SHA384) r_SHA384_Init (&ctx->sha384);
	CHKFLAG (R_HASH_SHA512) r_SHA512_Init (&ctx->sha512);
	ctx->rst = false;
}

R_API void r_hash_do_end(RHash *ctx, ut64 flags) {
	CHKFLAG (R_HASH_MD5) r_hash_do_md5 (ctx, NULL, -2);
	CHKFLAG (R_HASH_SHA1) r_SHA1_Final (ctx->digest, &ctx->sha1);
	CHKFLAG (R_HASH_SHA256) r_SHA256_Final (ctx->digest, &ctx->sha256);
	CHKFLAG (R_HASH_SHA384) r_SHA384_Final (ctx->digest, &ctx->sha384);
	CHKFLAG (R_HASH_SHA512) r_SHA512_Final (ctx->digest, &ctx->sha512);
	ctx->rst = true;
}

R_API void r_hash_free(RHash *ctx) {
	free (ctx);
}

R_API ut8 *r_hash_do_sip(RHash *ctx, const ut8 *input, int len) {
	if (len < 0) {
		return NULL;
	}
	ut64 res = r_hash_sip (input, len);
	if (res) {
		memcpy (ctx->digest, &res, sizeof (res));
	}
	return ctx->digest;
}

R_API ut8 *r_hash_do_ssdeep(RHash *ctx, const ut8 *input, int len) {
	if (len < 0) {
		return NULL;
	}
	char *res = r_hash_ssdeep (input, len);
	if (res) {
		r_str_ncpy ((char *)ctx->digest, res, R_HASH_SIZE_SSDEEP);
		free (res);
	}
	return ctx->digest;
}

R_API ut8 *r_hash_do_sha1(RHash *ctx, const ut8 *input, int len) {
	if (len < 0) {
		return NULL;
	}
	if (ctx->rst) {
		r_SHA1_Init (&ctx->sha1);
	}
	r_SHA1_Update (&ctx->sha1, input, len);
	if (ctx->rst || len == 0) {
		r_SHA1_Final (ctx->digest, &ctx->sha1);
	}
	return ctx->digest;
}

R_API ut8 *r_hash_do_sha256(RHash *ctx, const ut8 *input, int len) {
	if (len < 0) {
		return NULL;
	}
	if (ctx->rst) {
		r_SHA256_Init (&ctx->sha256);
	}
	r_SHA256_Update (&ctx->sha256, input, len);
	if (ctx->rst || len == 0) {
		r_SHA256_Final (ctx->digest, &ctx->sha256);
	}
	return ctx->digest;
}

R_API ut8 *r_hash_do_sha384(RHash *ctx, const ut8 *input, int len) {
	if (len < 0) {
		return NULL;
	}
	if (ctx->rst) {
		r_SHA384_Init (&ctx->sha384);
	}
	r_SHA384_Update (&ctx->sha384, input, len);
	if (ctx->rst || len == 0) {
		r_SHA384_Final (ctx->digest, &ctx->sha384);
	}
	return ctx->digest;
}

R_API ut8 *r_hash_do_sha512(RHash *ctx, const ut8 *input, int len) {
	if (len < 0) {
		return NULL;
	}
	if (ctx->rst) {
		r_SHA512_Init (&ctx->sha512);
	}
	r_SHA512_Update (&ctx->sha512, input, len);
	if (ctx->rst || len == 0) {
		r_SHA512_Final (ctx->digest, &ctx->sha512);
	}
	return ctx->digest;
}

R_API ut8 *r_hash_do_md5(RHash *ctx, const ut8 *input, int len) {
	if (len < 0) {
		if (len == -1) {
			r_MD5_Init (&ctx->md5);
		} else if (len == -2) {
			r_MD5_Final (ctx->digest, &ctx->md5);
		}
		return NULL;
	}
	if (ctx->rst) {
		r_MD5_Init (&ctx->md5);
	}
	if (len > 0) {
		r_MD5_Update (&ctx->md5, input, len);
	} else {
		r_MD5_Update (&ctx->md5, (const ut8 *) "", 0);
	}
	if (ctx->rst) {
		r_MD5_Final (ctx->digest, &ctx->md5);
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
	ut8 bskey[r_SHA256_BLOCK_LENGTH]; // block-sized key
	ut8 kpad[r_SHA256_BLOCK_LENGTH]; // keypad for opad, ipad

	// If klen > block-size, bskey = Hash(key)
	memset (bskey, 0, r_SHA256_BLOCK_LENGTH);
	if (klen > r_SHA256_BLOCK_LENGTH) {
		r_SHA256_Init (&ctx->sha256);
		r_SHA256_Update (&ctx->sha256, key, klen);
		r_SHA256_Final (ctx->digest, &ctx->sha256);
		memcpy (bskey, ctx->digest, R_HASH_SIZE_SHA256);
	} else {
		memcpy (bskey, key, klen);
	}

	// XOR block-sized key with ipad 0x36
	memset (kpad, 0, r_SHA256_BLOCK_LENGTH);
	memcpy (kpad, bskey, r_SHA256_BLOCK_LENGTH);
	for (i = 0; i < r_SHA256_BLOCK_LENGTH; i++) {
		kpad[i] ^= 0x36;
	}

	// Inner hash (key ^ ipad || input)
	r_SHA256_Init (&ctx->sha256);
	r_SHA256_Update (&ctx->sha256, kpad, r_SHA256_BLOCK_LENGTH);
	r_SHA256_Update (&ctx->sha256, input, len);
	r_SHA256_Final (ctx->digest, &ctx->sha256);

	// XOR block-sized key with opad 0x5c
	memset (kpad, 0, r_SHA256_BLOCK_LENGTH);
	memcpy (kpad, bskey, r_SHA256_BLOCK_LENGTH);
	for (i = 0; i < r_SHA256_BLOCK_LENGTH; i++) {
		kpad[i] ^= 0x5c;
	}

	// Outer hash (key ^ opad || Inner hash)
	r_SHA256_Init (&ctx->sha256);
	r_SHA256_Update (&ctx->sha256, kpad, r_SHA256_BLOCK_LENGTH);
	r_SHA256_Update (&ctx->sha256, ctx->digest, R_HASH_SIZE_SHA256);
	r_SHA256_Final (ctx->digest, &ctx->sha256);

	return ctx->digest;
}
