#include <r_lib.h>
#include <r_crypto.h>
#include <r_util.h>

static int flag = 0;

static int base64_set_key(RCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	flag = direction;
	return true;
}

static int base64_get_key_size(RCrypto *cry) {
	return 0;
}

static bool base64_use(const char *algo) {
	return !strcmp (algo, "base64");
}

static int update(RCrypto *cry, const ut8 *buf, int len) {
	int olen = 0;
	ut8 *obuf = NULL;
	if (flag == 0) {
		olen = ((len + 2) / 3 ) * 4;
		obuf = malloc (olen + 1);
		r_base64_encode ((char *)obuf, (const ut8 *)buf, len);
	} else if (flag == 1) {
		olen = (len / 4) * 3;
		if (len > 0)					//to prevent invalid access of memory
			olen -= (buf[len-1] == '=') ? ((buf[len-2] == '=') ? 2 : 1) : 0;
		obuf = malloc (olen + 1);
		olen = r_base64_decode (obuf, (const char *)buf, len);
	}
	if (olen > 0) {
		r_crypto_append (cry, obuf, olen);
	}
	free (obuf);
	return 0;
}

static int final(RCrypto *cry, const ut8 *buf, int len) {
	return update (cry, buf, len);
}

RCryptoPlugin r_crypto_plugin_base64 = {
	.name = "base64",
	.set_key = base64_set_key,
	.get_key_size = base64_get_key_size,
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
