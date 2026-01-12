/* radare - MIT - Copyright 2024-2026 - pancake */

#include <r_muta.h>

static bool update(RMutaSession *cj, const ut8 *buf, int len) {
	if (!buf || len < 1) {
		return false;
	}
	cj->result.entropy = r_hash_entropy (buf, len);
	char str[32];
	int slen = snprintf (str, sizeof (str), "%.8f", cj->result.entropy);
	r_muta_session_append (cj, (const ut8 *)str, slen);
	return true;
}

RMutaPlugin r_muta_plugin_entropy = {
	.meta = {
		.name = "entropy",
		.desc = "Shannon entropy",
		.author = "pancake",
		.license = "MIT",
	},
	.type = R_MUTA_TYPE_HASH,
	.text_output = true,
	.implements = "entropy",
	.update = update,
	.end = update
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_entropy,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
