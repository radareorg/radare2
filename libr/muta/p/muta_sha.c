/* radare - LGPL - Copyright 2024-2026 - pancake */

#include <r_lib.h>
#include <r_muta.h>
#include <r_hash.h>

typedef struct {
	RHash *ctx;
	ut64 type;
} ShaState;

static bool sha_check(const char *algo) {
	return !strcmp (algo, "sha1") || !strcmp (algo, "sha256") ||
		!strcmp (algo, "sha384") || !strcmp (algo, "sha512");
}

static RMutaSession *sha_begin(RMuta *muta) {
	RMutaSession *ms = r_muta_session_new (muta, muta->h);
	if (!ms) {
		return NULL;
	}
	return ms;
}

static bool sha_update(RMutaSession *ms, const ut8 *buf, int len) {
	ut64 type = 0;
	if (ms->subtype) {
		if (!strcmp (ms->subtype, "sha1")) {
			type = R_HASH_SHA1;
		} else if (!strcmp (ms->subtype, "sha256")) {
			type = R_HASH_SHA256;
		} else if (!strcmp (ms->subtype, "sha384")) {
			type = R_HASH_SHA384;
		} else if (!strcmp (ms->subtype, "sha512")) {
			type = R_HASH_SHA512;
		}
	}
	if (!type) {
		return false;
	}
	ShaState *state = ms->plugin_data;
	if (!state) {
		state = R_NEW0 (ShaState);
		state->type = type;
		state->ctx = r_hash_new (false, type);
		if (!state->ctx) {
			free (state);
			return false;
		}
		r_hash_do_begin (state->ctx, type);
		ms->plugin_data = state;
	}
	switch (type) {
	case R_HASH_SHA1:
		r_hash_do_sha1 (state->ctx, buf, len);
		break;
	case R_HASH_SHA256:
		r_hash_do_sha256 (state->ctx, buf, len);
		break;
	case R_HASH_SHA384:
		r_hash_do_sha384 (state->ctx, buf, len);
		break;
	case R_HASH_SHA512:
		r_hash_do_sha512 (state->ctx, buf, len);
		break;
	}
	return true;
}

static bool sha_end(RMutaSession *ms, const ut8 *buf, int len) {
	if (buf && len > 0) {
		if (!sha_update (ms, buf, len)) {
			return false;
		}
	}
	ShaState *state = ms->plugin_data;
	if (!state || !state->ctx) {
		return false;
	}
	r_hash_do_end (state->ctx, state->type);
	int digest_size = r_hash_size (state->type);
	r_muta_session_append (ms, state->ctx->digest, digest_size);
	r_hash_free (state->ctx);
	state->ctx = NULL;
	return true;
}

static bool sha_fini(RMutaSession *ms) {
	ShaState *state = ms->plugin_data;
	if (state) {
		r_hash_free (state->ctx);
		R_FREE (ms->plugin_data);
	}
	return true;
}

RMutaPlugin r_muta_plugin_sha = {
	.meta = {
		.name = "sha",
		.desc = "Secure Hash Algorithm (SHA)",
		.author = "pancake",
		.license = "MIT",
	},
	.type = R_MUTA_TYPE_HASH,
	.implements = "sha1,sha256,sha384,sha512",
	.check = sha_check,
	.begin = sha_begin,
	.update = sha_update,
	.end = sha_end,
	.fini = sha_fini
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_sha,
	.version = R2_VERSION
};
#endif
