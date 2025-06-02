/* radare - LGPL - Copyright 2009-2025 pancake */

#include <r_hash.h>
#include <r_util.h>

#include "md4.h"
#include "md5.h"
#include "sha1.h"
#include "sha2.h"

#define CHKFLAG(x) if (!flags || flags & (x))

R_API RHash *r_hash_new(bool rst, ut64 flags) {
	if (R_HASH_NUM_INDICES > 63) {
		// needs a non-bitmask way to do that, maybe using RBitmap
		R_LOG_WARN ("Too many hash algorithms registered, some may be unavailable");
	}
	RHash *ctx = R_NEW0 (RHash);
	r_hash_do_begin (ctx, flags);
	ctx->rst = rst;
	return ctx;
}

R_API void r_hash_do_begin(RHash *ctx, ut64 flags) {
	R_RETURN_IF_FAIL (ctx);
	CHKFLAG (R_HASH_MD5) r_hash_do_md5 (ctx, NULL, -1);
	CHKFLAG (R_HASH_SHA1) r_sha1_init (&ctx->sha1);
	CHKFLAG (R_HASH_SHA256) r_sha256_init (&ctx->sha256);
	CHKFLAG (R_HASH_SHA384) r_sha384_init (&ctx->sha384);
	CHKFLAG (R_HASH_SHA512) r_sha512_init (&ctx->sha512);
	ctx->rst = false;
}

R_API void r_hash_do_end(RHash *ctx, ut64 flags) {
	R_RETURN_IF_FAIL (ctx);
	CHKFLAG (R_HASH_MD5) r_hash_do_md5 (ctx, NULL, -2);
	CHKFLAG (R_HASH_SHA1) r_sha1_final (ctx->digest, &ctx->sha1);
	CHKFLAG (R_HASH_SHA256) r_sha256_final (ctx->digest, &ctx->sha256);
	CHKFLAG (R_HASH_SHA384) r_sha384_final (ctx->digest, &ctx->sha384);
	CHKFLAG (R_HASH_SHA512) r_sha512_final (ctx->digest, &ctx->sha512);
	ctx->rst = true;
}

R_API void r_hash_free(RHash *ctx) {
	free (ctx);
}

R_API ut8 *r_hash_do_sip(RHash *ctx, const ut8 *input, int len) {
	R_RETURN_VAL_IF_FAIL (ctx && input, NULL);
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
	R_RETURN_VAL_IF_FAIL (ctx && input, NULL);
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
	R_RETURN_VAL_IF_FAIL (ctx && input, NULL);
	if (len < 0) {
		return NULL;
	}
	if (ctx->rst) {
		r_sha1_init (&ctx->sha1);
	}
	r_sha1_update (&ctx->sha1, input, len);
	if (ctx->rst || len < 1) {
		r_sha1_final (ctx->digest, &ctx->sha1);
	}
	return ctx->digest;
}

R_API ut8 *r_hash_do_sha256(RHash *ctx, const ut8 *input, int len) {
	R_RETURN_VAL_IF_FAIL (ctx && input, NULL);
	if (len < 0) {
		return NULL;
	}
	if (ctx->rst) {
		r_sha256_init (&ctx->sha256);
	}
	r_sha256_update (&ctx->sha256, input, len);
	if (ctx->rst || len == 0) {
		r_sha256_final (ctx->digest, &ctx->sha256);
	}
	return ctx->digest;
}

R_API ut8 *r_hash_do_sha384(RHash *ctx, const ut8 *input, int len) {
	if (len < 0) {
		return NULL;
	}
	if (ctx->rst) {
		r_sha384_init (&ctx->sha384);
	}
	r_sha384_update (&ctx->sha384, input, len);
	if (ctx->rst || len == 0) {
		r_sha384_final (ctx->digest, &ctx->sha384);
	}
	return ctx->digest;
}

R_API ut8 *r_hash_do_sha512(RHash *ctx, const ut8 *input, int len) {
	R_RETURN_VAL_IF_FAIL (ctx && input, NULL);
	if (len < 0) {
		return NULL;
	}
	if (ctx->rst) {
		r_sha512_init (&ctx->sha512);
	}
	r_sha512_update (&ctx->sha512, input, len);
	if (ctx->rst || len == 0) {
		r_sha512_final (ctx->digest, &ctx->sha512);
	}
	return ctx->digest;
}

// https://www.sco.com/developers/gabi/latest/ch5.dynamic.html#hash
static unsigned long elf_hash(const unsigned char *name) {
	unsigned long h = 0, g;
	while (*name) {
		h = (h << 4) + *name++;
		g = h & 0xf0000000;
		if (g) {
			h ^= g >> 24;
		}
		h &= ~g;
	}
	return h;
}

R_API ut8 *r_hash_do_elf(RHash *ctx, const ut8 *input, int len) {
	unsigned long hash;
	if (len < 0) {
		hash = elf_hash (input);
	} else {
		ut8 *s = (ut8*) r_str_ndup ((const char*)input, len);
		hash = elf_hash (s);
		free (s);
	}
	memcpy (ctx->digest, &hash, sizeof (unsigned long));
	return ctx->digest;
}

R_API ut8 *r_hash_do_md5(RHash *ctx, const ut8 *input, int len) {
	if (len < 0) {
		if (len == -1) {
			r_hash_md5_init (&ctx->md5);
		} else if (len == -2) {
			r_hash_md5_final (ctx->digest, &ctx->md5);
		}
		return NULL;
	}
	if (ctx->rst) {
		r_hash_md5_init (&ctx->md5);
	}
	if (len > 0) {
		r_hash_md5_update (&ctx->md5, input, len);
	} else {
		r_hash_md5_update (&ctx->md5, (const ut8 *) "", 0);
	}
	if (ctx->rst) {
		r_hash_md5_final (ctx->digest, &ctx->md5);
	}
	return ctx->digest;
}

R_API ut8 *r_hash_do_md4(RHash *ctx, const ut8 *input, int len) {
	if (len >= 0) {
		r_hash_md4 (input, len, ctx->digest);
		return ctx->digest;
	}
	return NULL;
}

R_API ut8 *r_hash_do_hmac_sha256(RHash *ctx, const ut8 *input, int len, const ut8 *key, int klen) {
	if (len < 0 || klen < 0) {
		return NULL;
	}

	size_t i;
	ut8 bskey[R_SHA256_BLOCK_LENGTH]; // block-sized key
	ut8 kpad[R_SHA256_BLOCK_LENGTH]; // keypad for opad, ipad

	// If klen > block-size, bskey = Hash(key)
	memset (bskey, 0, R_SHA256_BLOCK_LENGTH);
	if (klen > R_SHA256_BLOCK_LENGTH) {
		r_sha256_init (&ctx->sha256);
		r_sha256_update (&ctx->sha256, key, klen);
		r_sha256_final (ctx->digest, &ctx->sha256);
		memcpy (bskey, ctx->digest, R_HASH_SIZE_SHA256);
	} else {
		memcpy (bskey, key, klen);
	}

	// XOR block-sized key with ipad 0x36
	memset (kpad, 0, R_SHA256_BLOCK_LENGTH);
	memcpy (kpad, bskey, R_SHA256_BLOCK_LENGTH);
	for (i = 0; i < R_SHA256_BLOCK_LENGTH; i++) {
		kpad[i] ^= 0x36;
	}

	// Inner hash (key ^ ipad || input)
	r_sha256_init (&ctx->sha256);
	r_sha256_update (&ctx->sha256, kpad, R_SHA256_BLOCK_LENGTH);
	r_sha256_update (&ctx->sha256, input, len);
	r_sha256_final (ctx->digest, &ctx->sha256);

	// XOR block-sized key with opad 0x5c
	memset (kpad, 0, R_SHA256_BLOCK_LENGTH);
	memcpy (kpad, bskey, R_SHA256_BLOCK_LENGTH);
	for (i = 0; i < R_SHA256_BLOCK_LENGTH; i++) {
		kpad[i] ^= 0x5c;
	}

	// Outer hash (key ^ opad || Inner hash)
	r_sha256_init (&ctx->sha256);
	r_sha256_update (&ctx->sha256, kpad, R_SHA256_BLOCK_LENGTH);
	r_sha256_update (&ctx->sha256, ctx->digest, R_HASH_SIZE_SHA256);
	r_sha256_final (ctx->digest, &ctx->sha256);

	return ctx->digest;
}
