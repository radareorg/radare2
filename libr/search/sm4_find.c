/* radare2 - LGPL - Copyright 2022-2025 - Sylvain Pelissier */

#include <r_search.h>
#include <r_muta.h>
#include <r_util.h>

#define SM4_SEARCH_LENGTH 24
#define SM4_KEY_LENGTH    16

static ut32 sm4_word(const ut8 *buf, int index) {
	return r_read_at_le32 (buf, index * sizeof (ut32));
}

static bool sm4_key_test(const ut8 *buf) {
	ut32 w0 = sm4_word (buf, 0);
	ut32 w1 = sm4_word (buf, 1);
	ut32 w2 = sm4_word (buf, 2);
	ut32 w3 = sm4_word (buf, 3);
	ut32 w4 = sm4_word (buf, 4);
	ut32 w5 = sm4_word (buf, 5);
	return w4 == (w0 ^ sm4_RK (w1 ^ w2 ^ w3 ^ sm4_CK[4]))
		&& w5 == (w1 ^ sm4_RK (w2 ^ w3 ^ w4 ^ sm4_CK[5]));
}

// Display the corresponding master key which is not directly in memory for SM4.
static void sm4_master_key(const ut8 *buf, ut64 addr) {
	ut32 w0 = sm4_word (buf, 0);
	ut32 w1 = sm4_word (buf, 1);
	ut32 w2 = sm4_word (buf, 2);
	ut32 w3 = sm4_word (buf, 3);
	ut32 master_key[4] = { 0 };
	master_key[3] = w3 ^ (sm4_RK (w2 ^ w1 ^ w0 ^ sm4_CK[3]));
	master_key[2] = w2 ^ (sm4_RK (w1 ^ w0 ^ master_key[3] ^ sm4_CK[2]));
	master_key[1] = w1 ^ (sm4_RK (w0 ^ master_key[3] ^ master_key[2] ^ sm4_CK[1]));
	master_key[0] = w0 ^ (sm4_RK (master_key[3] ^ master_key[2] ^ master_key[1] ^ sm4_CK[0]));
	R_LOG_INFO ("Master key found: %08x%08x%08x%08x @%#8"PFMT64x, FK[0] ^ master_key[0], FK[1] ^ master_key[1], FK[2] ^ master_key[2], FK[3] ^ master_key[3], addr);
	return;
}

R_IPI int search_sm4_update(RSearch *s, ut64 from, const ut8 *buf, int len) {
	int i, t, last = len - SM4_SEARCH_LENGTH;
	RListIter *iter;
	RSearchKeyword *kw;
	const int old_nhits = s->nhits;

	r_list_foreach (s->kws, iter, kw) {
		for (i = 0; i < last + 1; i++) {
			if (sm4_key_test (buf + i)) {
				sm4_master_key (buf + i, from + i);
				kw->keyword_length = SM4_KEY_LENGTH;
				t = r_search_hit_new (s, kw, from + i);
				if (!t) {
					return -1;
				}
				if (t > 1) {
					return s->nhits - old_nhits;
				}
				i += SM4_SEARCH_LENGTH;
			}
		}
	}
	return -1;
}
