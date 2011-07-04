/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

#include "r_hash.h"
#include "md5.h"
#include "sha1.h"
#include "sha2.h"
#include "md4.c" // included directly

#define CHKFLAG(f,x) if (f==0||f&x)

R_API struct r_hash_t *r_hash_new(int rst, int flags) {
	RHash *ctx = R_NEW (RHash);
	if (ctx) {
		CHKFLAG (flags, R_HASH_MD5)    MD5Init (&ctx->md5);
		CHKFLAG (flags, R_HASH_SHA1)   SHA1_Init (&ctx->sha1);
		CHKFLAG (flags, R_HASH_SHA256) SHA256_Init (&ctx->sha256);
		CHKFLAG (flags, R_HASH_SHA384) SHA384_Init (&ctx->sha384);
		CHKFLAG (flags, R_HASH_SHA512) SHA512_Init (&ctx->sha512);
		ctx->rst = rst;
	}
	return ctx;
}

R_API void r_hash_free(struct r_hash_t *ctx) {
	free (ctx);
}

R_API const ut8 *r_hash_do_md5(struct r_hash_t *ctx, const ut8 *input, ut32 len) {
	if (ctx->rst)
		MD5Init (&ctx->md5);
	MD5Update (&ctx->md5, input, len);
	if (ctx->rst || len == 0)
		MD5Final (&ctx->digest, &ctx->md5);
	return ctx->digest;
}

R_API const ut8 *r_hash_do_sha1(struct r_hash_t *ctx, const ut8 *input, ut32 len) {
	if (ctx->rst)
		SHA1_Init (&ctx->sha1);
	SHA1_Update (&ctx->sha1, input, len);
	if (ctx->rst || len == 0)
		SHA1_Final (ctx->digest, &ctx->sha1);
	return ctx->digest;
}

R_API const ut8 *r_hash_do_md4(struct r_hash_t *ctx, const ut8 *input, ut32 len) {
	mdfour (ctx->digest, input, len);
	return ctx->digest;
}

R_API const ut8 *r_hash_do_sha256(struct r_hash_t *ctx, const ut8 *input, ut32 len) {
	if (ctx->rst)
		SHA256_Init (&ctx->sha256);
	SHA256_Update (&ctx->sha256, input, len);
	if (ctx->rst || len == 0)
		SHA256_Final (ctx->digest, &ctx->sha256);
	return ctx->digest;
}

R_API const ut8 *r_hash_do_sha384(struct r_hash_t *ctx, const ut8 *input, ut32 len) {
	if (ctx->rst)
		SHA384_Init (&ctx->sha384);
	SHA384_Update (&ctx->sha384, input, len);
	if (ctx->rst || len == 0)
		SHA384_Final (ctx->digest, &ctx->sha384);
	return ctx->digest;
}

R_API const ut8 *r_hash_do_sha512(struct r_hash_t *ctx, const ut8 *input, ut32 len) {
	if (ctx->rst)
		SHA512_Init (&ctx->sha512);
	SHA512_Update (&ctx->sha512, input, len);
	if (ctx->rst || len == 0)
		SHA512_Final (ctx->digest, &ctx->sha512);
	return ctx->digest;
}
