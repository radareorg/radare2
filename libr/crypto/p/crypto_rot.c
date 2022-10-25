/* radare - LGPL - Copyright 2009-2022 - pancake */

#include <r_lib.h>
#include <r_crypto.h>

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
		outbuf[i] -= (inbuf[i] >= 'a' && inbuf[i] <= 'z') ? 'a' : 'A';
		outbuf[i] = mod (outbuf[i], 26);
		outbuf[i] += (inbuf[i] >= 'a' && inbuf[i] <= 'z') ? 'a' : 'A';
	}
}

static void rot_decrypt(ut8 key, const ut8 *inbuf, ut8 *outbuf, int buflen) {
	int i;
	for (i = 0; i < buflen; i++) {
		outbuf[i] = inbuf[i];
		if ((inbuf[i] < 'a' || inbuf[i] > 'z') && (inbuf[i] < 'A' || inbuf[i] > 'Z')) {
			continue;
		}
		outbuf[i] += 26;	//adding so that subtracting does not make it negative
		outbuf[i] -= key;
		outbuf[i] -= (inbuf[i] >= 'a' && inbuf[i] <= 'z') ? 'a' : 'A';
		outbuf[i] = mod (outbuf[i], 26);
		outbuf[i] += (inbuf[i] >= 'a' && inbuf[i] <= 'z') ? 'a' : 'A';
	}
}

static bool rot_set_key(RCryptoJob *cj, const ut8 *key, int keylen, int mode, int direction) {
	cj->flag = direction;
	return rot_init (&cj->rot_key, key, keylen);
}

static int rot_get_key_size(RCryptoJob *cj) {
	//Returning number of bytes occupied by ut8
	return 1;
}

static bool update(RCryptoJob *cj, const ut8 *buf, int len) {
	ut8 *obuf = calloc (1, len);
	if (!obuf) {
		return false;
	}
	if (cj->flag == 0) {
		rot_crypt (cj->rot_key, buf, obuf, len);
	} else if (cj->flag == 1) {
		rot_decrypt (cj->rot_key, buf, obuf, len);
	}
	r_crypto_job_append (cj, obuf, len);
	free (obuf);
	return true;
}

RCryptoPlugin r_crypto_plugin_rot = {
	.name = "rot",
	.implements = "rot",
	.author = "pancake",
	.license = "MIT",
	.set_key = rot_set_key,
	.get_key_size = rot_get_key_size,
	.update = update,
	.end = update
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_crypto_plugin_rot,
	.version = R2_VERSION
};
#endif

