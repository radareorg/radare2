#include <r_lib.h>
#include <r_crypto.h>
#include <r_util.h>

#define INSIZE 32768

static int flag = 0;

static int base91_set_key(RCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	flag = direction;
	return true;
}

static int base91_get_key_size(RCrypto *cry) {
	return 0;
}

static bool base91_use(const char *algo) {
	return !strcmp (algo, "base91");
}

static int update(RCrypto *cry, const ut8 *buf, int len) {
	int olen = INSIZE; //a way to optimise memory allocation.
	ut8 *obuf = malloc (olen);
	if (flag == 0) {
		olen = r_base91_encode ((char *)obuf, (const ut8 *)buf, len);
	} else if (flag == 1) {
		olen = r_base91_decode (obuf, (const char *)buf, len);
	}
	r_crypto_append (cry, obuf, olen);
	free (obuf);
	return 0;
}

static int final(RCrypto *cry, const ut8 *buf, int len) {
	return update (cry, buf, len);
}

RCryptoPlugin r_crypto_plugin_base91 = {
	.name = "base91",
	.set_key = base91_set_key,
	.get_key_size = base91_get_key_size,
	.use = base91_use,
	.update = update,
	.final = final
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_crypto_plugin_base91,
	.version = R2_VERSION
};
#endif
