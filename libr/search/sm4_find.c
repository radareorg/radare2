/* radare2 - LGPL - Copyright 2022-2025 - Sylvain Pelissier */

#include <r_search.h>
#include <r_muta.h>
#include <r_util.h>

#define SM4_SEARCH_LENGTH 24
#define SM4_KEY_LENGTH    16

static bool sm4_key_test(const unsigned char *buf) {
	ut32 *ptr = (ut32 *)buf;
	return (ptr[4] == (ptr[0] ^ (sm4_RK (ptr[1] ^ ptr[2] ^ ptr[3] ^ sm4_CK[4])))) && (ptr[5] == (ptr[1] ^ (sm4_RK (ptr[2] ^ ptr[3] ^ ptr[4] ^ sm4_CK[5]))));
}

// Display the corresponding master key which is not directly in memory for SM4.
static void sm4_master_key(const unsigned char *buf, ut64 addr) {
	ut32 *ptr = (ut32 *)buf;
	ut32 master_key[4] = { 0 };
	master_key[3] = ptr[3] ^ (sm4_RK (ptr[2] ^ ptr[1] ^ ptr[0] ^ sm4_CK[3]));
	master_key[2] = ptr[2] ^ (sm4_RK (ptr[1] ^ ptr[0] ^ master_key[3] ^ sm4_CK[2]));
	master_key[1] = ptr[1] ^ (sm4_RK (ptr[0] ^ master_key[3] ^ master_key[2] ^ sm4_CK[1]));
	master_key[0] = ptr[0] ^ (sm4_RK (master_key[3] ^ master_key[2] ^ master_key[1] ^ sm4_CK[0]));
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
