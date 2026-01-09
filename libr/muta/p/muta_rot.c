/* radare - LGPL - Copyright 2009-2026 - pancake */

#include <r_lib.h>
#include <r_muta.h>

#define MAX_ROT_KEY_SIZE 32768

static inline int rot_mod(int a, int b) {
	if (b < 0) {
		return rot_mod (-a, -b);
	}
	int ret = a % b;
	if (ret < 0) {
		ret += b;
	}
	return ret;
}

typedef enum {
	R_ROT_TYPE_ROT,
	R_ROT_TYPE_ROL,
	R_ROT_TYPE_ROR
} RRotType;

typedef struct rot_state {
	ut8 key[MAX_ROT_KEY_SIZE];
	int key_size;
	RRotType type;
	ut8 rot_shift;
} RRotState;

static bool rot_check(const char *algo) {
	return !strcmp (algo, "rot") || !strcmp (algo, "rol") || !strcmp (algo, "ror");
}

static bool rot_init(RRotState *state, const ut8 *key, int keylen, RRotType type) {
	if (!state || !key || keylen < 1) {
		return false;
	}
	state->type = type;
	if (type == R_ROT_TYPE_ROT) {
		const int shift = atoi ((const char *)key);
		state->rot_shift = (ut8)rot_mod (shift, 26);
	} else {
		if (keylen > MAX_ROT_KEY_SIZE) {
			keylen = MAX_ROT_KEY_SIZE;
		}
		state->key_size = keylen;
		int i;
		for (i = 0; i < keylen; i++) {
			state->key[i] = key[i];
		}
	}
	return true;
}

static void rot_crypt(ut8 key, const ut8 *ibuf, ut8 *obuf, int obuf_len) {
	int i;
	for (i = 0; i < obuf_len; i++) {
		obuf[i] = ibuf[i];
		if ((ibuf[i] < 'a' || ibuf[i] > 'z') && (ibuf[i] < 'A' || ibuf[i] > 'Z')) {
			continue;
		}
		obuf[i] += key;
		obuf[i] -= (ibuf[i] >= 'a' && ibuf[i] <= 'z')? 'a': 'A';
		obuf[i] = rot_mod (obuf[i], 26);
		obuf[i] += (ibuf[i] >= 'a' && ibuf[i] <= 'z')? 'a': 'A';
	}
}

static void rot_decrypt(ut8 key, const ut8 *ibuf, ut8 *obuf, int obuf_len) {
	int i;
	for (i = 0; i < obuf_len; i++) {
		obuf[i] = ibuf[i];
		if ((ibuf[i] < 'a' || ibuf[i] > 'z') && (ibuf[i] < 'A' || ibuf[i] > 'Z')) {
			continue;
		}
		obuf[i] += 26;
		obuf[i] -= key;
		obuf[i] -= (ibuf[i] >= 'a' && ibuf[i] <= 'z')? 'a': 'A';
		obuf[i] = rot_mod (obuf[i], 26);
		obuf[i] += (ibuf[i] >= 'a' && ibuf[i] <= 'z')? 'a': 'A';
	}
}

static void rol_crypt(RRotState *state, const ut8 *ibuf, ut8 *obuf, int obuf_len) {
	int i;
	for (i = 0; i < obuf_len; i++) {
		const ut8 count = state->key[i % state->key_size] & 7;
		const ut8 b = ibuf[i];
		obuf[i] = (b << count) | (b >> ((8 - count) & 7));
	}
}

static void ror_crypt(RRotState *state, const ut8 *ibuf, ut8 *obuf, int obuf_len) {
	int i;
	for (i = 0; i < obuf_len; i++) {
		const ut8 count = state->key[i % state->key_size] & 7;
		const ut8 b = ibuf[i];
		obuf[i] = (b >> count) | (b << ((8 - count) & 7));
	}
}

static bool rot_set_key(RMutaSession *cj, const ut8 *key, int keylen, int mode, int direction) {
	RRotState *state = (RRotState *)cj->data;
	RRotType type = R_ROT_TYPE_ROT;
	if (cj->subtype) {
		if (!strcmp (cj->subtype, "rol")) {
			type = R_ROT_TYPE_ROL;
		} else if (!strcmp (cj->subtype, "ror")) {
			type = R_ROT_TYPE_ROR;
		}
	}
	if (!state) {
		state = R_NEW0 (RRotState);
		cj->data = state;
	}
	cj->flag = direction;
	if (type == R_ROT_TYPE_ROT) {
		cj->flag = direction == R_CRYPTO_DIR_ENCRYPT;
	}
	return rot_init (state, key, keylen, type);
}

static int rot_get_key_size(RMutaSession *cj) {
	RRotState *state = (RRotState *)cj->data;
	if (!state || state->type == R_ROT_TYPE_ROT) {
		return 1;
	}
	return state->key_size;
}

static bool rot_fini(RMutaSession *cj) {
	R_FREE (cj->data);
	return true;
}

static bool rot_update(RMutaSession *cj, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (cj, false);
	RRotState *state = (RRotState *)cj->data;
	ut8 *obuf = calloc (1, len);
	if (!obuf) {
		return false;
	}
	switch (state->type) {
	case R_ROT_TYPE_ROT:
		switch (cj->flag) {
		case R_CRYPTO_DIR_ENCRYPT:
			rot_crypt (state->rot_shift, buf, obuf, len);
			break;
		case R_CRYPTO_DIR_DECRYPT:
			rot_decrypt (state->rot_shift, buf, obuf, len);
			break;
		default:
			free (obuf);
			return false;
		}
		break;
	case R_ROT_TYPE_ROL:
		if (cj->flag == R_CRYPTO_DIR_DECRYPT) {
			R_LOG_ERROR ("Use ROR instead of ROL for decryption");
			free (obuf);
			return false;
		}
		rol_crypt (state, buf, obuf, len);
		break;
	default:
		if (cj->flag != R_CRYPTO_DIR_ENCRYPT) {
			free (obuf);
			return false;
		}
		ror_crypt (state, buf, obuf, len);
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
		.desc = "Rotate algorithms (rot13, rol, ror)",
		.author = "pancake",
		.license = "MIT",
	},
	.implements = "rot,rol,ror",
	.check = rot_check,
	.set_key = rot_set_key,
	.get_key_size = rot_get_key_size,
	.update = rot_update,
	.end = rot_update,
	.fini = rot_fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_rot,
	.version = R2_VERSION
};
#endif
