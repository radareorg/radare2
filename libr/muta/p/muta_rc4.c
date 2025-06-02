/* radare - LGPL - Copyright 2016-2025 - pancake */

#include <r_lib.h>
#include <r_muta.h>

struct rc4_state {
	ut8 perm[256];
	ut8 index1;
	ut8 index2;
	int key_size;
};

static __inline void swap_bytes(ut8 *a, ut8 *b) {
	if (a != b) {
		ut8 temp = *a;
		*a = *b;
		*b = temp;
	}
}

// Initialize an RC4 state buffer using the supplied arbitrary length key,
static bool rc4_init(struct rc4_state *const state, const ut8 *key, int keylen) {
	ut8 j;
	int i;

	if (!state || !key || keylen < 1) {
		return false;
	}
	state->key_size = keylen;
	/* Initialize state with identity permutation */
	for (i = 0; i < 256; i++) {
		state->perm[i] = (ut8)i;
	}
	state->index1 = 0;
	state->index2 = 0;

	/* Randomize the permutation using key data */
	for (j = i = 0; i < 256; i++) {
		j += state->perm[i] + key[i % keylen];
		swap_bytes (&state->perm[i], &state->perm[j]);
	}
	return true;
}

/*
 * Encrypt some data using the supplied RC4 state buffer.
 * The input and output buffers may be the same buffer.
 * Since RC4 is a stream cypher, this function is used
 * for both encryption and decryption.
 */
static void rc4_crypt(struct rc4_state *const state, const ut8 *inbuf, ut8 *outbuf, int buflen) {
	if (!state || !inbuf || !outbuf || buflen < 1) {
		return;
	}
	int i;
	ut8 j;

	for (i = 0; i < buflen; i++) {
		/* Update modification indices */
		state->index1++;
		state->index2 += state->perm[state->index1];
		/* Modify permutation */
		swap_bytes (&state->perm[state->index1], &state->perm[state->index2]);
		/* Encrypt/decrypt next byte */
		j = state->perm[state->index1] + state->perm[state->index2];
		outbuf[i] = inbuf[i] ^ state->perm[j];
	}
}

///////////////////////////////////////////////////////////

static bool rc4_set_key(RMutaSession *cj, const ut8 *key, int keylen, int mode, int direction) {
	free (cj->data);
	cj->data = R_NEW0 (struct rc4_state);
	struct rc4_state *st = (struct rc4_state *)cj->data;
	return rc4_init (st, key, keylen);
}

static int rc4_get_key_size(RMutaSession *cj) {
	struct rc4_state *st = (struct rc4_state *)cj->data;
	return st? st->key_size: 0;
}

static bool update(RMutaSession *cj, const ut8 *buf, int len) {
	ut8 *obuf = calloc (1, len);
	if (!obuf) {
		return false;
	}
	struct rc4_state *st = (struct rc4_state *)cj->data;
	rc4_crypt (st, buf, obuf, len);
	r_muta_session_append (cj, obuf, len);
	free (obuf);
	return false;
}

static bool end(RMutaSession *cj, const ut8 *buf, int len) {
	return update (cj, buf, len);
}

static bool fini(RMutaSession *cj) {
	R_FREE (cj->data);
	return true;
}

RMutaPlugin r_muta_plugin_rc4 = {
	.type = R_CRYPTO_TYPE_ENCRYPT,
	.meta = {
		.name = "rc4",
		.license = "LGPL-3.0-only",
		.author = "pancake",
		.desc = "Rivest Cipher 4",
	},
	.implements = "rc4",
	.set_key = rc4_set_key,
	.get_key_size = rc4_get_key_size,
	.update = update,
	.end = end,
	.fini = fini
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_rc4,
	.version = R2_VERSION
};
#endif

#if 0
int main() {
	ut8 out[32];
	struct rc4_state st;

	/* encrypt */
	rc4_init (&st, (const ut8*)"key", 3);
	rc4_crypt(&st, (const ut8*)"hello world", out, sizeof (out));

	/* decrypt */
	rc4_init (&st, (const ut8*)"key", 3);
	rc4_crypt(&st, out, out, sizeof (out));

	eprintf ("%s\n", (const char *)out); // must print "hello world"
}
#endif
