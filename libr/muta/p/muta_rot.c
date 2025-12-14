/* radare - LGPL - Copyright 2009-2024 - pancake */

#include <r_lib.h>
#include <r_muta.h>

static int mod(int a, int b) {
	if (b < 0) {
		return mod (-a, -b);
	}
	int ret = a % b;
	if (ret < 0) {
		ret += b;
	}
	return ret;
}

static bool rot_init(ut8 *rotkey, const ut8 *key, int keylen) {
	if (rotkey && key && keylen > 0) {
		int i = atoi ((const char *)key);
		*rotkey = (ut8)mod (i, 26);
		return true;
	}
	return false;
}

static void rot_crypt(ut8 key, const ut8 *inbuf, ut8 *outbuf, int buflen) {
	int i;
	for (i = 0; i < buflen; i++) {
		outbuf[i] = inbuf[i];
		if ((inbuf[i] < 'a' || inbuf[i] > 'z') && (inbuf[i] < 'A' || inbuf[i] > 'Z')) {
			continue;
		}
		outbuf[i] += key;
		outbuf[i] -= (inbuf[i] >= 'a' && inbuf[i] <= 'z')? 'a': 'A';
		outbuf[i] = mod (outbuf[i], 26);
		outbuf[i] += (inbuf[i] >= 'a' && inbuf[i] <= 'z')? 'a': 'A';
	}
}

static void rot_decrypt(ut8 key, const ut8 *inbuf, ut8 *outbuf, int buflen) {
	int i;
	for (i = 0; i < buflen; i++) {
		outbuf[i] = inbuf[i];
		if ((inbuf[i] < 'a' || inbuf[i] > 'z') && (inbuf[i] < 'A' || inbuf[i] > 'Z')) {
			continue;
		}
		outbuf[i] += 26; // adding so that subtracting does not make it negative
		outbuf[i] -= key;
		outbuf[i] -= (inbuf[i] >= 'a' && inbuf[i] <= 'z')? 'a': 'A';
		outbuf[i] = mod (outbuf[i], 26);
		outbuf[i] += (inbuf[i] >= 'a' && inbuf[i] <= 'z')? 'a': 'A';
	}
}

static bool rot_set_key(RMutaSession *cj, const ut8 *key, int keylen, int mode, int direction) {
	cj->flag = direction == R_CRYPTO_DIR_ENCRYPT;
	return rot_init (&cj->rot_key, key, keylen);
}

static int rot_get_key_size(RMutaSession *cj) {
	// Returning number of bytes occupied by ut8
	return 1;
}

static bool update(RMutaSession *cj, const ut8 *buf, int len) {
	ut8 *obuf = calloc (1, len);
	if (!obuf) {
		return false;
	}
	switch (cj->flag) {
	case R_CRYPTO_DIR_ENCRYPT:
		rot_crypt (cj->rot_key, buf, obuf, len);
		break;
	case R_CRYPTO_DIR_DECRYPT:
		rot_decrypt (cj->rot_key, buf, obuf, len);
		break;
	}
	r_muta_session_append (cj, obuf, len);
	free (obuf);
	return true;
}

RMutaPlugin r_muta_plugin_rot = {
	.type = R_MUTA_TYPE_CRYPTO,
	.meta = {
		.name = "rot",
		.desc = "Rotate Encryption",
		.author = "pancake",
		.license = "MIT",
	},
	.implements = "rot",
	.set_key = rot_set_key,
	.get_key_size = rot_get_key_size,
	.update = update,
	.end = update
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_rot,
	.version = R2_VERSION
};
#endif
