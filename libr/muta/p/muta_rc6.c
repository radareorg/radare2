/* radare - LGPL - Copyright 2016-2024 - pancake */

#include <r_muta.h>

#define Pw 0xb7e15163
#define Qw 0x9e3779b9
#define BLOCK_SIZE 16
#define r 20
#define w 32
#define ROTL(x,y) (((x)<<((y)&(w-1))) | ((x)>>(w-((y)&(w-1)))))
#define ROTR(x,y) (((x)>>((y)&(w-1))) | ((x)<<(w-((y)&(w-1)))))

struct rc6_state {
	ut32 S[2*r+4];
	int key_size;
};

static bool rc6_init(struct rc6_state *const state, const ut8 *key, int keylen, int direction) {
	if (keylen != 128/8 && keylen != 192/8 && keylen != 256/8) {
		return false;
	}

	int u = w / 8;
	int c = keylen / u;
	int t = 2 * r + 4;
#ifdef _MSC_VER
	ut32 *L = (ut32*) malloc (sizeof (ut32) * c);
#else
	ut32 L[c];
#endif
	ut32 A = 0, B = 0, k = 0, j = 0;
	ut32 v = 3 * t; //originally v = 2 * ((c > t) ? c : t);

	int i, off;

	for (i = 0, off = 0; i < c; i++) {
		L[i] = ((key[off++] & 0xff));
		L[i] |= ((key[off++] & 0xff) << 8);
		L[i] |= ((key[off++] & 0xff) << 16);
		L[i] |= ((key[off++] & 0xff) << 24);
	}

	(state->S)[0] = Pw;
	for (i = 1; i < t; i++) {
		(state->S)[i] = (state->S)[i-1] + Qw;
	}

	for (i = 0; i < v; i++) {
		A = (state->S)[k] = ROTL(((state->S)[k] + A + B), 3);
		B = L[j] = ROTL((L[j] + A + B), (A + B));
		k = (k + 1) % t;
		j = (j + 1) % c;
	}

	state->key_size = keylen/8;
#ifdef _MSC_VER
	free (L);
#endif
	return true;
}

static void rc6_encrypt(struct rc6_state *const state, const ut8 *inbuf, ut8 *outbuf) {
	ut32 t, u;
	ut32 aux;
	ut32 data[BLOCK_SIZE / 4];
	int i;
	int off = 0;
	for (i = 0; i < BLOCK_SIZE / 4; i++) {
		data[i] = ((inbuf[off++] & 0xff));
		data[i] |= ((inbuf[off++] & 0xff) << 8);
		data[i] |= ((inbuf[off++] & 0xff) << 16);
		data[i] |= ((inbuf[off++] & 0xff) << 24);
	}

	ut32 A = data[0], B = data[1], C = data[2], D = data[3];

	// S is key
	B = B + (state->S)[0];
	D = D + (state->S)[1];

	for (i = 1; i <= r; i++) {
		t = ROTL(B * (2 * B + 1), 5);		//lgw == 5
		u = ROTL(D * (2 * D + 1), 5);
		A = ROTL(A ^ t, u) + (state->S)[2 * i];
		C = ROTL(C ^ u, t) + (state->S)[2 * i + 1];

		aux = A;
		A = B;
		B = C;
		C = D;
		D = aux;
	}

	A = A + (state->S)[2*(r+1)];
	C = C + (state->S)[2*(r+1)+1];
	data[0] = A;
	data[1] = B;
	data[2] = C;
	data[3] = D;

	for (i = 0; i < BLOCK_SIZE; i++) {
		outbuf[i] = (ut8)((data[i / 4] >> (i % 4) * 8) & 0xff);
	}
}

static void rc6_decrypt(struct rc6_state *const state, const ut8 *inbuf, ut8 *outbuf) {
	ut32 t, u;
	ut32 aux;
	ut32 data[BLOCK_SIZE / 4];
	int i;
	int off = 0;

	for (i = 0; i < BLOCK_SIZE / 4; i++) {
		data[i] = (inbuf[off++] & 0xff);
		data[i] |= ((inbuf[off++] & 0xff) << 8);
		data[i] |= ((inbuf[off++] & 0xff) << 16);
		data[i]	|= ((inbuf[off++] & 0xff) << 24);
	}

	ut32 A = data[0], B = data[1], C = data[2], D = data[3];

	C = C - (state->S)[2 * (r + 1) + 1];
	A = A - (state->S)[2 * (r + 1)];

	for (i = r; i >= 1; i--) {
		aux = D;
		D = C;
		C = B;
		B = A;
		A = aux;

		u = ROTL(D * (2 * D + 1), 5);
		t = ROTL(B * (2 * B + 1), 5);
		C = ROTR(C - (state->S)[2 * i + 1], t) ^ u;
		A = ROTR(A - (state->S)[2 * i], u) ^ t;
	}

	D = D - (state->S)[1];
	B = B - (state->S)[0];

	data[0] = A;
	data[1] = B;
	data[2] = C;
	data[3] = D;

	for (i = 0; i < BLOCK_SIZE; i++) {
		outbuf[i] = (ut8)((data[i / 4] >> (i % 4) * 8) & 0xff);
	}
}

static struct rc6_state *getnewstate(RMutaSession *cj) {
	free (cj->data);
	cj->data = R_NEW0 (struct rc6_state);
	return (struct rc6_state*)cj->data;
}

static bool rc6_set_key(RMutaSession *cj, const ut8 *key, int keylen, int mode, int direction) {
	struct rc6_state *st = getnewstate (cj);
	cj->flag = (direction == R_CRYPTO_DIR_DECRYPT);
	return rc6_init (st, key, keylen, direction);
}

static int rc6_get_key_size(RMutaSession *cj) {
	struct rc6_state *st = (struct rc6_state*)cj->data;
	return st? st->key_size: 0;
}

static bool update(RMutaSession *cj, const ut8 *buf, int len) {
	if (len % BLOCK_SIZE != 0) { //let user handle with with pad.
		R_LOG_ERROR ("Input should be multiple of 128bit");
		return false;
	}
	struct rc6_state *st = (struct rc6_state*)cj->data;
	if (!st) {
		R_LOG_ERROR ("No key set for rc6");
		return false;
	}

	const int blocks = len / BLOCK_SIZE;

	ut8 *obuf = calloc (1, len);
	if (!obuf) {
		return false;
	}

	int i;
	if (cj->flag) {
		for (i = 0; i < blocks; i++) {
			rc6_decrypt (st, buf + BLOCK_SIZE * i, obuf + BLOCK_SIZE * i);
		}
	} else {
		for (i = 0; i < blocks; i++) {
			rc6_encrypt (st, buf + BLOCK_SIZE * i, obuf + BLOCK_SIZE * i);
		}
	}

	r_muta_session_append (cj, obuf, len);
	free (obuf);
	return true;
}

RMutaPlugin r_muta_plugin_rc6 = {
	.type = R_MUTA_TYPE_CRYPTO,
	.meta = {
		.name = "rc6",
		.desc = "Rivest's Cipher 6",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.implements = "rc6",
	.set_key = rc6_set_key,
	.get_key_size = rc6_get_key_size,
	.update = update,
	.end = update
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_rc6,
	.version = R2_VERSION
};
#endif
