/* radare - MIT - Copyright 2024 - pancake */

#include <r_crypto.h>

static bool update(RCryptoJob *cj, const ut8 *buf, int len) {
	if (!buf || len < 1) {
		return false;
	}
	ut64 i, count[256] = {0};
	double h = 0;
	for (i = 0; i < len; i++) {
		if (buf[i] < 0xff) {
			count[buf[i]]++;
		}
	}
	for (i = 0; i < 256; i++) {
		if (count[i]) {
			double p = (double) count[i] / len;
			h -= p * log2 (p);
		}
	}
	if (cj->entropy) {
		cj->entropy += h;
		cj->entropy /= 2;
	} else {
		cj->entropy = h;
	}
	return true;
}

static bool end(RCryptoJob *cj, const ut8 *buf, int len) {
	if (buf) {
		if (len > 0) {
			double e = update (cj, buf, len) / log2 ((double) R_MIN (len, 256));
			if  (cj->entropy) {
				cj->entropy += e;
				cj->entropy /= 2;
			} else {
				cj->entropy = e;
			}
		}
	} else {
		cj->entropy = 0;
	}
	return true;
}

RCryptoPlugin r_crypto_plugin_entropy = {
	.meta = {
		.name = "entropy",
		.desc = "Shannon entropy",
		.author = "pancake",
		.license = "MIT",
	},
	.type = R_CRYPTO_TYPE_HASHER,
	.update = update,
	.end = end
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_crypto_plugin_entropy,
	.version = R2_VERSION
};
#endif

