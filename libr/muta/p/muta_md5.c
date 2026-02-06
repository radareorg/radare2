/* radare - LGPL - Copyright 2024-2025 - pancake */

#include <r_lib.h>
#include <r_muta.h>
#include <r_hash.h>

typedef struct {
	RHash *ctx;
} Md5State;

static RMutaSession *md5_begin(RMuta *muta) {
	RMutaSession *ms = r_muta_session_new (muta, muta->h);
	if (!ms) {
		return NULL;
	}
	return ms;
}

static bool md5_update(RMutaSession *ms, const ut8 *buf, int len) {
	Md5State *state = ms->plugin_data;
	if (!state) {
		state = R_NEW0 (Md5State);
		state->ctx = r_hash_new (false, R_HASH_MD5);
		if (!state->ctx) {
			free (state);
			return false;
		}
		r_hash_do_begin (state->ctx, R_HASH_MD5);
		ms->plugin_data = state;
	}
	r_hash_do_md5 (state->ctx, buf, len);
	return true;
}

static bool md5_end(RMutaSession *ms, const ut8 *buf, int len) {
	if (buf && len > 0) {
		if (!md5_update (ms, buf, len)) {
			return false;
		}
	}
	Md5State *state = ms->plugin_data;
	if (!state || !state->ctx) {
		return false;
	}
	r_hash_do_end (state->ctx, R_HASH_MD5);
	r_muta_session_append (ms, state->ctx->digest, R_HASH_SIZE_MD5);
	r_hash_free (state->ctx);
	state->ctx = NULL;
	return true;
}

static bool md5_fini(RMutaSession *ms) {
	Md5State *state = ms->plugin_data;
	if (state) {
		r_hash_free (state->ctx);
		R_FREE (ms->plugin_data);
	}
	return true;
}

RMutaPlugin r_muta_plugin_md5 = {
	.meta = {
		.name = "md5",
		.desc = "MD5 hash",
		.author = "pancake",
		.license = "MIT",
	},
	.type = R_MUTA_TYPE_HASH,
	.implements = "md5",
	.begin = md5_begin,
	.update = md5_update,
	.end = md5_end,
	.fini = md5_fini
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_md5,
	.version = R2_VERSION
};
#endif
