/* radare - LGPL - Copyright 2025 - pancake */

#include <r_lib.h>
#include <r_muta.h>

typedef struct {
	ut32 sum;
} AddState;

static bool add_update(RMutaSession *ms, const ut8 *buf, int len) {
	AddState *state = ms->plugin_data;
	if (!state) {
		state = R_NEW0 (AddState);
		ms->plugin_data = state;
	}
	int i;
	for (i = 0; i < len; i++) {
		state->sum += buf[i];
	}
	return true;
}

static bool add_end(RMutaSession *ms, const ut8 *buf, int len) {
	if (buf && len > 0) {
		if (!add_update (ms, buf, len)) {
			return false;
		}
	}
	AddState *state = ms->plugin_data;
	if (!state) {
		return false;
	}
	ut8 obuf[4];
	r_write_le32 (obuf, state->sum);
	r_muta_session_append (ms, obuf, 4);
	return true;
}

static bool add_fini(RMutaSession *ms) {
	R_FREE (ms->plugin_data);
	return true;
}

static int get_key_size(RMutaSession *ms) {
	return 4;
}

RMutaPlugin r_muta_plugin_add = {
	.type = R_MUTA_TYPE_HASH,
	.meta = {
		.name = "add",
		.desc = "Add checksum used by Tar (sum all bytes into ut32)",
		.author = "pancake",
		.license = "MIT",
	},
	.implements = "add",
	.get_key_size = get_key_size,
	.update = add_update,
	.end = add_end,
	.fini = add_fini
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_add,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
