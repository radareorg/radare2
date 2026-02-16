/* radare - BSD-2-Clause - Copyright 2024-2026 - pancake */
/* xxhash algorithm by Yann Collet - BSD-2-Clause */

#include <r_lib.h>
#include <r_muta.h>
#include <r_hash.h>
#include <r_endian.h>

static bool xxhash_update(RMutaSession *ms, const ut8 *buf, int len) {
	ut8 digest[4];
	ut32 res = r_hash_xxhash (buf, len);
	r_write_be32 (digest, res);
	r_muta_session_append (ms, digest, 4);
	return true;
}

RMutaPlugin r_muta_plugin_xxhash = {
	.meta = {
		.name = "xxhash",
		.desc = "xxHash fast hash algorithm",
		.author = "Yann Collet",
		.license = "BSD-2-Clause",
	},
	.type = R_MUTA_TYPE_HASH,
	.implements = "xxhash",
	.update = xxhash_update,
	.end = xxhash_update
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_xxhash,
	.version = R2_VERSION
};
#endif
