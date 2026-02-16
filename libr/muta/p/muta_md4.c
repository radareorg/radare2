/* radare - GPL-2.0-or-later - Copyright 2024-2026 - pancake */
/* MD4 algorithm from SMB by Andrew Tridgell - GPL */

#include <r_lib.h>
#include <r_muta.h>
#include <r_hash.h>

typedef struct {
	RHash *ctx;
} Md4State;

static RMutaSession *md4_begin(RMuta *muta) {
	RMutaSession *ms = r_muta_session_new (muta, muta->h);
	if (!ms) {
		return NULL;
	}
	return ms;
}

static bool md4_update(RMutaSession *ms, const ut8 *buf, int len) {
	Md4State *state = ms->plugin_data;
	if (!state) {
		state = R_NEW0 (Md4State);
		state->ctx = r_hash_new (false, R_HASH_MD4);
		if (!state->ctx) {
			free (state);
			return false;
		}
		r_hash_do_begin (state->ctx, R_HASH_MD4);
		ms->plugin_data = state;
	}
	r_hash_do_md4 (state->ctx, buf, len);
	return true;
}

static bool md4_end(RMutaSession *ms, const ut8 *buf, int len) {
	if (buf && len > 0) {
		if (!md4_update (ms, buf, len)) {
			return false;
		}
	}
	Md4State *state = ms->plugin_data;
	if (!state || !state->ctx) {
		return false;
	}
	r_hash_do_end (state->ctx, R_HASH_MD4);
	r_muta_session_append (ms, state->ctx->digest, R_HASH_SIZE_MD4);
	r_hash_free (state->ctx);
	state->ctx = NULL;
	return true;
}

static bool md4_fini(RMutaSession *ms) {
	Md4State *state = ms->plugin_data;
	if (state) {
		r_hash_free (state->ctx);
		R_FREE (ms->plugin_data);
	}
	return true;
}

RMutaPlugin r_muta_plugin_md4 = {
	.meta = {
		.name = "md4",
		.desc = "MD4 hash",
		.author = "Andrew Tridgell",
		.license = "GPL-2.0-or-later",
	},
	.type = R_MUTA_TYPE_HASH,
	.implements = "md4",
	.begin = md4_begin,
	.update = md4_update,
	.end = md4_end,
	.fini = md4_fini
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_md4,
	.version = R2_VERSION
};
#endif
