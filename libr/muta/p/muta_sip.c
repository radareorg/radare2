/* radare - LGPL - Copyright 2024 - pancake */

#include <r_lib.h>
#include <r_muta.h>

static bool update(RMutaSession *ms, const ut8 *buf, int len) {
	if (!ms || !ms->c) {
		return false;
	}
	ut8 obuf[R_HASH_SIZE_SIP];
	uint64_t h = r_hash_sip (buf, len);
	r_write_ble64 (obuf, h, ms->c->bigendian);
	r_muta_session_append (ms, obuf, R_HASH_SIZE_SIP);
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
