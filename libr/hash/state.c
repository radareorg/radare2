/* This file is part of radare libr.
 * It is licensed under the LGPL license
 */

#include "r_hash.h"
#include "md5.h"
#include "sha1.h"
#include "sha2.h"

// TODO: to be moved to r_hash_internal.h
void mdfour(ut8 *out, const ut8 *in, int n);

#define CHKFLAG(f,x) if (f==0||f&x)

void r_hash_state_init(struct r_hash_t *ctx, int flags)
{
	CHKFLAG(flags,R_HASH_MD5)    MD5Init(&ctx->md5);
	CHKFLAG(flags,R_HASH_SHA1)   SHA1_Init(&ctx->sha1);
	CHKFLAG(flags,R_HASH_SHA256) SHA256_Init(&ctx->sha256);
	CHKFLAG(flags,R_HASH_SHA384) SHA384_Init(&ctx->sha384);
	CHKFLAG(flags,R_HASH_SHA512) SHA512_Init(&ctx->sha512);
}

struct r_hash_t *r_hash_state_new(int init)
{
	struct r_hash_t *ctx;
	ctx = malloc(sizeof(struct r_hash_t));
	ctx->init = init;
	r_hash_state_init(ctx, R_HASH_ALL);
	return ctx;
}

void r_hash_state_free(struct r_hash_t *ctx)
{
	free(ctx);
}

const ut8 *r_hash_state_md5(struct r_hash_t *ctx, const ut8 *input, ut32 len)
{
	if (ctx->init)
		MD5Init(&ctx->sha256);
	MD5Update(&ctx->md5, input, len);
	if (ctx->init || len == 0)
		MD5Final(&ctx->digest, &ctx->md5);
	return ctx->digest;
}

const ut8 *r_hash_state_sha1(struct r_hash_t *ctx, const ut8 *input, ut32 len)
{
	if (ctx->init)
		SHA1_Init(&ctx->sha1);
	SHA1_Update(&ctx->sha1, input, len);
	if (ctx->init || len == 0)
		SHA1_Final(ctx->digest, &ctx->sha1);
	return ctx->digest;
}

const ut8 *r_hash_state_md4(struct r_hash_t *ctx, const ut8 *input, ut32 len)
{
	mdfour(ctx->digest, input, len);
	return ctx->digest;
}

const ut8 *r_hash_state_sha256(struct r_hash_t *ctx, const ut8 *input, ut32 len)
{
	if (ctx->init)
		SHA256_Init(&ctx->sha256);
	SHA256_Update(&ctx->sha256, input, len);
	if (ctx->init || len == 0)
		SHA256_Final(ctx->digest, &ctx->sha256);
	return ctx->digest;
}

const ut8 *r_hash_state_sha384(struct r_hash_t *ctx, const ut8 *input, ut32 len)
{
	if (ctx->init)
		SHA384_Init(&ctx->sha384);
	SHA384_Update(&ctx->sha384, input, len);
	if (ctx->init || len == 0)
		SHA384_Final(ctx->digest, &ctx->sha384);
	return ctx->digest;
}

const ut8 *r_hash_state_sha512(struct r_hash_t *ctx, const ut8 *input, ut32 len)
{
	if (ctx->init)
		SHA512_Init(&ctx->sha512);
	SHA512_Update(&ctx->sha512, input, len);
	if (ctx->init || len == 0)
		SHA512_Final(ctx->digest, &ctx->sha512);
	return ctx->digest;
}
