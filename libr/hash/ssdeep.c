/* radare2 - MIT - Copyright 2021 pancake */

// Inspired by https://github.com/glaslos/ssdeep/blob/master/ssdeep.go

#include <r_hash.h>
#include <r_util.h>

#define BLOCK_MIN 3
#define ROLLING_WINDOW 7
#define HASH_PRIME 0x01000193
#define HASH_INIT 0x28021967
#define SPAM_SUM_LENGTH 64

typedef struct {
	ut8 window[ROLLING_WINDOW];
	ut32 h1;
	ut32 h2;
	ut32 h3;
	ut32 bh1;
	ut32 bh2;
	size_t n;
	int bs; // block_size
	char hs1[64 + 1];
	int hs1_len;
	char hs2[64 + 1];
	int hs2_len;
} State;

static const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static inline ut32 sum_hash(ut8 c, ut32 h) {
	return (h * HASH_PRIME) ^ c;
}

static inline ut32 roll_sum(State *s) {
	return s->h1 + s->h2 + s->h3;
}

static inline void roll_hash(State *s, ut8 c) {
	s->h2 -= s->h1;
	s->h2 += ROLLING_WINDOW * c;
	s->h1 += c;
	s->h1 -= s->window[s->n];
	s->window[s->n] = c;
	s->n++;
	if (s->n == ROLLING_WINDOW) {
		s->n = 0;
	}
	s->h3 <<= 5;
	s->h3 ^= c;
}

static inline void process_byte(State *s, ut8 b) {
	s->bh1 = sum_hash (b, s->bh1);
	s->bh2 = sum_hash (b, s->bh2);
	roll_hash (s, b);

	ut32 rh = roll_sum (s);
	if (rh % s->bs == s->bs - 1) {
		if (s->hs1_len < SPAM_SUM_LENGTH - 1) {
			char ch = b64[s->bh1 % 64];
			s->hs1[s->hs1_len++] = ch;
			s->bh1 = HASH_INIT;
		}
		ut32 bs2 = s->bs * 2;
		if (rh % bs2 == bs2 - 1) {
			if (s->hs2_len < (SPAM_SUM_LENGTH / 2) - 1) {
				char ch = b64[s->bh2 % 64];
				s->hs2[s->hs2_len++] = ch;
				s->bh2 = HASH_INIT;
			}
		}
	}
}

static inline int get_blocksize(int n) {
	int bs = BLOCK_MIN;
	while (bs * SPAM_SUM_LENGTH < n) {
		bs *= 2;
	}
	return bs;
}

R_API char *r_hash_ssdeep(const ut8 *buf, size_t len) {
	State s = {0};
	s.bh1 = HASH_INIT;
	s.bh2 = HASH_INIT;
	s.bs = get_blocksize (len);
	for (;;) {
		size_t i;
		for (i = 0; i < len; i++) {
			process_byte (&s, buf[i]);
		}
		if (s.hs1_len < (SPAM_SUM_LENGTH / 2)) {
			s.bs /= 2;
			if (!s.bs) {
				// buffer too small, cant hash
				return NULL;
			}
			s.bh1 = HASH_INIT;
			s.bh2 = HASH_INIT;
			s.hs1_len = 0;
			s.hs2_len = 0;
			s.n = 0;
		} else {
			if (roll_sum (&s)) {
				// Finalize the hash string with the remaining data
				s.hs1[s.hs1_len++] = b64[s.bh1 % 64];
				s.hs2[s.hs2_len++] = b64[s.bh2 % 64];
			}
			break;
		}
	}
	return r_str_newf ("%d:%.*s:%.*s", s.bs, s.hs1_len, s.hs1, s.hs2_len, s.hs2);
}
