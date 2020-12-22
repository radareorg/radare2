/*
 * Find expanded AES keys in memory 
 * 
 * Algorithm discovered and developed by Victor Muñoz
 *  - PoC and source published at 24c3 at December 2007
 * 
 * Thanks for the great moments and code snippets!
 *
 * This source is public domain. Feel free to use it and distribute it.
 */

#include <r_search.h>
#include <r_crypto/r_aes.h>

#define AES128_SEARCH_LENGTH 24
#define AES192_SEARCH_LENGTH 32
#define AES256_SEARCH_LENGTH 40
#define AES128_KEY_LENGTH 16
#define AES192_KEY_LENGTH 24
#define AES256_KEY_LENGTH 32

static bool aes256_key_test(const unsigned char *buf) {
	bool word1 = buf[32] == (buf[0] ^ Sbox[buf[29]] ^ 1) \
		&& buf[33] == (buf[1] ^ Sbox[buf[30]]) \
		&& buf[34] == (buf[2] ^ Sbox[buf[31]]) \
		&& buf[35] == (buf[3] ^ Sbox[buf[28]]);
	bool word2 = (buf[36] == (buf[4] ^ buf[32]) \
		&& buf[37] == (buf[5] ^ buf[33]) \
		&& buf[38] == (buf[6] ^ buf[34]) \
		&& buf[39] == (buf[7] ^ buf[35]));
	return word1 && word2;
}

static bool aes192_key_test(const unsigned char *buf) {
	bool word1 = buf[24] == (buf[0] ^ Sbox[buf[21]] ^ 1) \
		&& buf[25] == (buf[1] ^ Sbox[buf[22]]) \
		&& buf[26] == (buf[2] ^ Sbox[buf[23]]) \
		&& buf[27] == (buf[3] ^ Sbox[buf[20]]);
	bool word2 = buf[28] == (buf[4] ^ buf[24]) \
		&& buf[29] == (buf[5] ^ buf[25]) \
		&& buf[30] == (buf[6] ^ buf[26]) \
		&& buf[31] == (buf[7] ^ buf[27]);
	return word1 && word2;
}

static bool aes128_key_test(const unsigned char *buf) {
	bool word1 = buf[16] == (buf[0] ^ Sbox[buf[13]] ^ 1) \
		&& buf[17] == (buf[1] ^ Sbox[buf[14]]) \
		&& buf[18] == (buf[2] ^ Sbox[buf[15]]) \
		&& buf[19] == (buf[3] ^ Sbox[buf[12]]);
	bool word2 = buf[20] == (buf[4] ^ buf[16]) \
		&& buf[21] == (buf[5] ^ buf[17]) \
		&& buf[22] == (buf[6] ^ buf[18]) \
		&& buf[23] == (buf[7] ^ buf[19]);
	return word1 && word2;
}

R_API int r_search_aes_update(RSearch *s, ut64 from, const ut8 *buf, int len) {
	int i, t, last = len - AES128_SEARCH_LENGTH;
	RListIter *iter;
	RSearchKeyword *kw;
	const int old_nhits = s->nhits;

	r_list_foreach (s->kws, iter, kw) {
		if (last >= 0) {
			for (i = 0; i < last; i++) {
				if (aes128_key_test (buf + i)) {
					kw->keyword_length = AES128_KEY_LENGTH;
					t = r_search_hit_new (s, kw, from + i);
					if (!t) {
						return -1;
					}
					if (t > 1) {
						return s->nhits - old_nhits;
					}
					i += AES128_SEARCH_LENGTH;
				}
				if (len - i - AES192_SEARCH_LENGTH >= 0 && aes192_key_test (buf + i)) {
					kw->keyword_length = AES192_KEY_LENGTH;
					t = r_search_hit_new (s, kw, from + i);
					if (!t) {
						return -1;
					}
					if (t > 1) {
						return s->nhits - old_nhits;
					}
					i = i + AES192_SEARCH_LENGTH;
				}
				if (len - i - AES256_SEARCH_LENGTH >= 0 && aes256_key_test (buf + i)) {
					kw->keyword_length = AES256_KEY_LENGTH;
					t = r_search_hit_new (s, kw, from + i);
					if (!t) {
						return -1;
					}
					if (t > 1) {
						return s->nhits - old_nhits;
					}
					i = i + AES256_SEARCH_LENGTH;
				}
			}
		}
	}
	return -1;
}