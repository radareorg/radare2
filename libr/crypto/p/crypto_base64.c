#include <r_lib.h>
#include <r_crypto.h>
#include <r_util.h>

static bool base64_use(const char *algo) {
	return !strcmp (algo, "base64");
}

static int update(RCrypto *cry, const ut8 *buf, int len, bool to_encode) {
	int olen;
	ut8 *obuf;
	if (to_encode) {
		olen = ((len + 2) / 3 ) * 4;
		obuf = malloc (olen + 1);
		r_base64_encode (obuf, buf, len);
	} else {
		olen = (len / 4) * 3;
		if (len > 0)					//to prevent invalid access of memory
			olen -= (buf[len-1] == '=') ? ((buf[len-2] == '=') ? 2 : 1) : 0;
		obuf = malloc (olen + 1);
		olen = r_base64_decode (obuf, buf, len);
	}
	r_crypto_append (cry, obuf, olen);
	free (obuf);
	return 0;
}

static int final(RCrypto *cry, const ut8 *buf, int len, bool to_encode) {
	return update (cry, buf, len, to_encode);
}

RCryptoPlugin r_crypto_plugin_base64 = {
	.name = "base64",
	.use = base64_use,
	.update = update,
	.final = final
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_crypto_plugin_base64,
	.version = R2_VERSION
};
#endif
