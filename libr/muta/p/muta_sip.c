/* radare - LGPL - Copyright 2024 - pancake */

#include <r_lib.h>
#include <r_muta.h>

static bool update(RMutaSession *cj, const ut8 *buf, int len) {
	ut8 obuf[R_HASH_SIZE_SIP];
	uint64_t h = r_hash_sip (buf, len);
	cj->result.output = malloc (cj->result.output_size);
	r_write_ble64 (obuf, h, cj->c->bigendian);
	r_muta_session_append (cj, obuf, R_HASH_SIZE_SIP);
	return true;
}

RMutaPlugin r_muta_plugin_sip = {
	.meta = {
		.name = "sip",
		.desc = "SipHash-2-4",
		.author = "pancake",
		.license = "MIT",
	},
	.type = R_MUTA_TYPE_HASH,
	.implements = "sip",
	.update = update,
	.end = update
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_sip,
	.version = R2_VERSION
};
#endif
