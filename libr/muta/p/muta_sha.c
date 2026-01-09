/* radare - LGPL - Copyright 2024-2026 - pancake */

#include <r_lib.h>
#include <r_muta.h>
#include <r_hash.h>

static bool sha_check(const char *algo) {
	return !strcmp (algo, "sha1") || !strcmp (algo, "sha256") ||
	       !strcmp (algo, "sha384") || !strcmp (algo, "sha512");
}

static bool sha_update(RMutaSession *cj, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (cj && buf, false);
	ut64 type = 0;
	if (cj->subtype) {
		if (!strcmp (cj->subtype, "sha1")) {
			type = R_HASH_SHA1;
		} else if (!strcmp (cj->subtype, "sha256")) {
			type = R_HASH_SHA256;
		} else if (!strcmp (cj->subtype, "sha384")) {
			type = R_HASH_SHA384;
		} else if (!strcmp (cj->subtype, "sha512")) {
			type = R_HASH_SHA512;
		}
	}
	if (!type) {
		return false;
	}
	RHash *ctx = r_hash_new (true, type);
	if (!ctx) {
		return false;
	}
	r_hash_do_begin (ctx, type);
	switch (type) {
	case R_HASH_SHA1:
		r_hash_do_sha1 (ctx, buf, len);
		break;
	case R_HASH_SHA256:
		r_hash_do_sha256 (ctx, buf, len);
		break;
	case R_HASH_SHA384:
		r_hash_do_sha384 (ctx, buf, len);
		break;
	case R_HASH_SHA512:
		r_hash_do_sha512 (ctx, buf, len);
		break;
	}
	r_hash_do_end (ctx, type);
	int digest_size = r_hash_size (type);
	r_muta_session_append (cj, ctx->digest, digest_size);
	r_hash_free (ctx);
	return true;
}

RMutaPlugin r_muta_plugin_sha = {
	.meta = {
		.name = "sha",
		.desc = "SHA1/SHA256/SHA384/SHA512 hash",
		.author = "pancake",
		.license = "MIT",
	},
	.type = R_MUTA_TYPE_HASH,
	.implements = "sha1,sha256,sha384,sha512",
	.check = sha_check,
	.update = sha_update,
	.end = sha_update
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_sha,
	.version = R2_VERSION
};
#endif
