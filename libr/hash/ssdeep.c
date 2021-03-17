/* radare2 - MIT - Copyright 2021 pancake */

// Inspired by https://github.com/glaslos/ssdeep/blob/master/ssdeep.go

#include <r_hash.h>
#include <r_util.h>

#define BLOCK_MIN 3
#define ROLLING_WINDOW 7
#define HASH_PRIME (ut32)0x01000193
#define HASH_INIT (ut32)0x28021967
#define SPAM_SUM_LENGTH 64

typedef struct {
	ut8 window[ROLLING_WINDOW];
	ut32 h1;
	ut32 h2;
	ut32 h3;
	ut32 n;
	int bs; // block_size
	char hs1[64 + 1];
	int hs1_len;
	char hs2[64 + 1];
	int hs2_len;
} State;

static const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static inline ut32 sum_hash(ut8 c, ut32 h) {
	return (h * HASH_PRIME) ^ (ut32)c;
}

static inline ut32 roll_sum(State *s) {
	return s->h1 + s->h2 + s->h3;
}

static inline void roll_hash(State *s, ut8 c) {
	s->h2 -= s->h1;
	s->h2 += ROLLING_WINDOW * (ut32)c;
	s->h1 += (ut32)c;
	s->h1 -= (ut32)s->window[s->n];
	s->window[s->n] = c;
	s->n++;
	if (s->n == ROLLING_WINDOW) {
		s->n = 0;
	}
	s->h3 <<= 5;
	s->h3 ^= (ut32)c;
}

static inline void process_byte(State *s, ut8 b) {
	s->h1 = sum_hash (b, s->h1);
	s->h2 = sum_hash (b, s->h2);
	roll_hash (s, b);

	ut32 rh = roll_sum (s);
	if (rh % s->bs == (s->bs - 1)) {
		if (s->hs1_len < SPAM_SUM_LENGTH - 1) {
			char ch = b64[s->h1 % 64];
			s->hs1[s->hs1_len++] = ch;
			s->h1 = HASH_INIT;
		}
		if (rh % (s->bs * 2) == (s->bs * 2) - 1) {
			if (s->hs1_len < (SPAM_SUM_LENGTH / 2) - 1) {
				char ch = b64[s->h2 % 64];
				s->hs2[s->hs2_len++] = ch;
				s->h2 = HASH_INIT;
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
	s.h1 = HASH_INIT;
	s.h2 = HASH_INIT;
	s.bs = get_blocksize (len);
	size_t i;
	for (;;) {
		for (i = 0; i < len; i++) {
			process_byte (&s, buf[i]);
		}
		if (s.hs1_len < (SPAM_SUM_LENGTH / 2)) {
			s.bs /= 2;
			if (s.bs == 0) {
				// buffer too small, cant hash
				return NULL;
			}
			s.h1 = HASH_INIT;
			s.h2 = HASH_INIT;
			s.hs1_len = 0;
			s.hs2_len = 0;
		} else {
			int rh = roll_sum (&s);
			if (rh != 0) {
				// Finalize the hash string with the remaining data
				s.hs1[s.hs1_len++] = b64[s.h1 % 64];
				s.hs2[s.hs2_len++] = b64[s.h2 % 64];
			}
			break;
		}
	}
	return r_str_newf ("%d:%s:%s", s.bs, s.hs1, s.hs2);
}
