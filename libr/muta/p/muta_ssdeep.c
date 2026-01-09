/* radare - MIT - Copyright 2026 - pancake */

#include <r_muta.h>

static bool update(RMutaSession *cj, const ut8 *buf, int len) {
	if (!buf || len < 1) {
		return false;
	}
	char *s = r_hash_ssdeep (buf, len);
	if (s) {
		int slen = strlen (s);
		r_muta_session_append (cj, (const ut8 *)s, slen);
		free (s);
		return true;
	}
	return false;
}

RMutaPlugin r_muta_plugin_ssdeep = {
	.meta = {
		.name = "ssdeep",
		.desc = "ssdeep fuzzy hash",
		.author = "pancake",
		.license = "MIT",
	},
	.type = R_MUTA_TYPE_HASH,
	.text_output = true,
	.implements = "ssdeep",
	.update = update,
	.end = update
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_ssdeep,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
