#include <r_lib.h>
#include <r_crypto.h>
#include <r_util.h>

#define INSIZE 32768

static int base91_set_key(RCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	return true;
}

static int base91_get_key_size(RCrypto *cry) {
	return 0;
}

static bool base91_use(const char *algo) {
	return !strcmp (algo, "base91");
}

static int update(RCrypto *cry, const ut8 *buf, int len, bool to_encode) {
	int olen = INSIZE; //a way to optimise memory allocation.
	ut8 *obuf = malloc (olen);
	if (to_encode) {
		olen = r_base91_encode (obuf, buf, len);
	} else {
		olen = r_base91_decode (obuf, buf, len);
	}
	r_crypto_append (cry, obuf, olen);
	free (obuf);
	return 0;
}

static int final(RCrypto *cry, const ut8 *buf, int len, bool to_encode) {
	return update (cry, buf, len, to_encode);
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
