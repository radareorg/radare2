/* radare2 - LGPL - Copyright 2022 - Sylvain Pelissier */
#include <r_crypto.h>
#include <r_search.h>
#include <r_util.h>

#define SM4_SEARCH_LENGTH 24
#define SM4_KEY_LENGTH    16

static bool sm4_key_test(const unsigned char *buf) {
	ut32 *ptr = (ut32 *)buf;
	return (ptr[4] == (ptr[0] ^ (sm4_RK (ptr[1] ^ ptr[2] ^ ptr[3] ^ sm4_CK[4])))) && (ptr[5] == (ptr[1] ^ (sm4_RK (ptr[2] ^ ptr[3] ^ ptr[4] ^ sm4_CK[5]))));
}

R_IPI int search_sm4_update(RSearch *s, ut64 from, const ut8 *buf, int len) {
	int i, t, last = len - SM4_SEARCH_LENGTH;
	RListIter *iter;
	RSearchKeyword *kw;
	const int old_nhits = s->nhits;

	r_list_foreach (s->kws, iter, kw) {
		for (i = 0; i < last + 1; i++) {
			if (sm4_key_test (buf + i)) {
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
