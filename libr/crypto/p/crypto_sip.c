/* radare - LGPL - Copyright 2024 - pancake */

#include <r_lib.h>
#include <r_crypto.h>

static bool update(RCryptoJob *cj, const ut8 *buf, int len) {
	ut8 obuf[R_HASH_SIZE_SIP];
	uint64_t h = r_hash_sip (buf, len);
	cj->output = malloc (cj->output_size);
	r_write_ble64 (obuf, h, cj->c->bigendian);
	r_crypto_job_append (cj, obuf, R_HASH_SIZE_SIP);
	return true;
}

RCryptoPlugin r_crypto_plugin_sip = {
	.meta = {
		.name = "sip",
		.desc = "SipHash",
		.author = "pancake",
		.license = "MIT",
	},
	.type = R_CRYPTO_TYPE_HASHER,
	.implements = "sip",
	.update = update,
	.end = update
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_crypto_plugin_sip,
	.version = R2_VERSION
};
#endif
