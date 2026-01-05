/* radare - LGPL - Copyright 2024-2025 - pancake */

#include <r_lib.h>
#include <r_muta.h>
#include <r_hash.h>

static bool update(RMutaSession *cj, const ut8 *buf, int len) {
	RHash *ctx = r_hash_new (true, R_HASH_SHA384);
	if (!ctx) {
		return false;
	}
	r_hash_do_begin (ctx, R_HASH_SHA384);
	r_hash_do_sha384 (ctx, buf, len);
	r_hash_do_end (ctx, R_HASH_SHA384);
	r_muta_session_append (cj, ctx->digest, R_HASH_SIZE_SHA384);
	r_hash_free (ctx);
	return true;
}

RMutaPlugin r_muta_plugin_sha384 = {
	.meta = {
		.name = "sha384",
		.desc = "SHA384 hash",
		.author = "pancake",
		.license = "MIT",
	},
	.type = R_MUTA_TYPE_HASH,
	.implements = "sha384",
	.update = update,
	.end = update
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_sha384,
	.version = R2_VERSION
};
#endif