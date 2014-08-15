/* radare - LGPL - Copyright 2009-2014 pancake<nopcode.org> */

// TODO: use ptr tablez here
#include "r_hash.h"
#include "md5.h"
#include "sha1.h"
#include "sha2.h"
R_API void mdfour(ut8 *out, const ut8 *in, int n);

#define CHKFLAG(f,x) if (f==0||f&x)

R_API RHash *r_hash_new(int rst, int flags) {
	RHash *ctx = R_NEW (RHash);
	if (ctx) {
		r_hash_do_begin (ctx, flags);
		ctx->rst = rst;
	}
	return ctx;
}

R_API void r_hash_do_begin(RHash *ctx, int flags) {
	CHKFLAG (flags, R_HASH_MD5) MD5Init (&ctx->md5);
	CHKFLAG (flags, R_HASH_SHA1) SHA1_Init (&ctx->sha1);
	CHKFLAG (flags, R_HASH_SHA256) SHA256_Init (&ctx->sha256);
	CHKFLAG (flags, R_HASH_SHA384) SHA384_Init (&ctx->sha384);
	CHKFLAG (flags, R_HASH_SHA512) SHA512_Init (&ctx->sha512);
	ctx->rst = 0;
}

R_API void r_hash_do_end(RHash *ctx, int flags) {
	CHKFLAG (flags, R_HASH_MD5) MD5Final (ctx->digest, &ctx->md5);
	CHKFLAG (flags, R_HASH_SHA1) SHA1_Final (ctx->digest, &ctx->sha1);
	CHKFLAG (flags, R_HASH_SHA256) SHA256_Final (ctx->digest, &ctx->sha256);
	CHKFLAG (flags, R_HASH_SHA384) SHA384_Final (ctx->digest, &ctx->sha384);
	CHKFLAG (flags, R_HASH_SHA512) SHA512_Final (ctx->digest, &ctx->sha512);
	ctx->rst = 1;
}

R_API void r_hash_free(RHash *ctx) {
	free (ctx);
}

R_API ut8 *r_hash_do_md5(RHash *ctx, const ut8 *input, int len) {
	if (len<0)
		return NULL;
	if (ctx->rst)
		MD5Init (&ctx->md5);
	if (len>0)
		MD5Update (&ctx->md5, input, len);
	if (ctx->rst || len == 0)
		MD5Final (&ctx->digest, &ctx->md5);
	return ctx->digest;
}

R_API ut8 *r_hash_do_sha1(RHash *ctx, const ut8 *input, int len) {
	if (len<0)
		return NULL;
	if (ctx->rst)
		SHA1_Init (&ctx->sha1);
	SHA1_Update (&ctx->sha1, input, len);
	if (ctx->rst || len == 0)
		SHA1_Final (ctx->digest, &ctx->sha1);
	return ctx->digest;
}

R_API ut8 *r_hash_do_md4(RHash *ctx, const ut8 *input, int len) {
	if (len<0) return NULL;
	mdfour (ctx->digest, input, len);
	return ctx->digest;
}

R_API ut8 *r_hash_do_sha256(RHash *ctx, const ut8 *input, int len) {
	if (len<0) return NULL;
	if (ctx->rst)
		SHA256_Init (&ctx->sha256);
	SHA256_Update (&ctx->sha256, input, len);
	if (ctx->rst || len == 0)
		SHA256_Final (ctx->digest, &ctx->sha256);
	return ctx->digest;
}

R_API ut8 *r_hash_do_sha384(RHash *ctx, const ut8 *input, int len) {
	if (len<0) return NULL;
	if (ctx->rst)
		SHA384_Init (&ctx->sha384);
	SHA384_Update (&ctx->sha384, input, len);
	if (ctx->rst || len == 0)
		SHA384_Final (ctx->digest, &ctx->sha384);
	return ctx->digest;
}

R_API ut8 *r_hash_do_sha512(RHash *ctx, const ut8 *input, int len) {
	if (len<0) return NULL;
	if (ctx->rst)
		SHA512_Init (&ctx->sha512);
	SHA512_Update (&ctx->sha512, input, len);
	if (ctx->rst || len == 0)
		SHA512_Final (ctx->digest, &ctx->sha512);
	return ctx->digest;
}
