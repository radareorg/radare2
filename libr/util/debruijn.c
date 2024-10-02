/* radare - LGPL - Copyright 2014-2024 - crowell, pancake */

#include <r_util.h>

// The following two (commented out) lines are the character set used in peda.
// You may use this charset instead of the A-Za-z0-9 charset normally used.
// char* peda_charset =
//    "A%sB$nC-(D;)Ea0Fb1Gc2Hd3Ie4Jf5Kg6Lh7Mi8Nj9OkPlQmRnSoTpUqVrWsXtYuZvwxyz";

//TODO(crowell): Make charset configurable, allow banning characters.
static const char debruijn_charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";

// Generate a De Bruijn sequence.
// pnl = prenecklace
// lnp = lyndon prefix
static void de_bruijn_seq(int pnl_len_t, int lnp_len_p, int order,
		int maxlen, int size, int* pnl_a, char* sequence, const char* charset) {
	R_RETURN_IF_FAIL (charset && sequence);
	if (strlen (sequence) == maxlen) {
		return;
	}
	int i;
	if (pnl_len_t > order) {
		if (order % lnp_len_p == 0) {
			for (i = 1; i <= lnp_len_p; i++) {
				sequence[strlen (sequence)] = charset[pnl_a[i]];
				if (strlen (sequence) == maxlen) {
					return;
				}
			}
		}
	} else {
		pnl_a[pnl_len_t] = pnl_a[pnl_len_t - lnp_len_p];
		de_bruijn_seq (pnl_len_t + 1, lnp_len_p, order, maxlen, size, pnl_a, sequence, charset);
		for (i = pnl_a[pnl_len_t - lnp_len_p] + 1; i < size; i++) {
			pnl_a[pnl_len_t] = i;
			de_bruijn_seq (pnl_len_t + 1, pnl_len_t, order, maxlen,
					size, pnl_a, sequence, charset);
		}
	}
}

// Generate a De Bruijn sequence.
// Returns a string in the heap, caller must free the memory.
static char* de_bruijn(const char* charset, int order, int maxlen) {
	R_RETURN_VAL_IF_FAIL (charset, NULL);
	size_t size = strlen (charset);
	char *sequence = NULL;
	int* pnl_a = calloc (size * (size_t)order, sizeof (int));
	if (pnl_a) {
		sequence = calloc (maxlen + 1, 1);
		if (sequence) {
			de_bruijn_seq (1, 1, order, maxlen, size, pnl_a, sequence, charset);
		}
		free (pnl_a);
	}
	return sequence;
}

// Generate a cyclic pattern of desired size, and charset, return with starting
// offset of start.
// The returned string is malloced, and it is the responsibility of the caller
// to free the memory.
R_API char* r_debruijn_pattern(int size, int start, const char* charset) {
	size_t len;
	if (!charset) {
		charset = debruijn_charset;
	}
	if (start >= size) {
		return (char*)NULL;
	}
	char *pat = de_bruijn (charset, 3 /*subsequence length*/, size);
	if (!pat) {
		return NULL;
	}
	if (start == 0) {
		len = strlen (pat);
		if (size != len) {
			R_LOG_WARN ("requested pattern of length %d, generated length %d", size, (int)len);
		}
		return pat;
	}
	char *pat2 = malloc ((size - start) + 1);
	if (pat2) {
		r_str_ncpy (pat2, pat + start, size - start);
		len = strlen (pat2);
		if (size != len) {
			R_LOG_WARN ("requested pattern of length %d, generated length %d", size, (int)len);
		}
	}
	free (pat);
	return pat2;
}

// Finds the offset of a given value in a cyclic pattern of an integer.
R_API int r_debruijn_offset(ut64 value, bool is_big_endian) {
	// 0x10000 should be long enough. This is how peda works, and nobody complains
	// ... but is slow. Optimize for common case.
	int i, lens[2] = {0x1000, 0x10000};
	int retval = -1;
	char buf[9];
	if (value != 0 && value != UT64_MAX && value != UT32_MAX) {
		for (i = 0; i < 2 && retval == -1; i++) {
			char *pattern = r_debruijn_pattern (lens[i], 0, debruijn_charset);
			buf[8] = '\0';
			r_write_ble64 (buf, value, is_big_endian);
			char *needle = buf;
			for (; !*needle; needle++) {
				/* do nothing here */
			}
			char* pch = strstr (pattern, needle);
			if (pch) {
				retval = (int)(size_t)(pch - pattern);
			}
			free (pattern);
		}
	}
	return retval;
}
