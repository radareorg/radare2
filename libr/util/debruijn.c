/* radare - LGPL - Copyright 2014-2016 - crowell, pancake */

#include <r_util.h>

// The following two (commented out) lines are the character set used in peda.
// You may use this charset instead of the A-Za-z0-9 charset normally used.
// char* peda_charset =
//    "A%sB$nC-(D;)Ea0Fb1Gc2Hd3Ie4Jf5Kg6Lh7Mi8Nj9OkPlQmRnSoTpUqVrWsXtYuZvwxyz";

//TODO(crowell): Make charset configurable, to allow banning characters.
static const char* debruijn_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";

// Generate a De Bruijn sequence.
static void de_bruijn_seq(int prenecklace_len_t, int lyndon_prefix_len_p, int order,
		int maxlen, int size, int* prenecklace_a, char* sequence, const char* charset) {
	int j;
	if (!charset || !sequence || strlen (sequence) == maxlen) {
		return;
	}
	if (prenecklace_len_t > order) {
		if (order % lyndon_prefix_len_p == 0) {
			for (j = 1; j <= lyndon_prefix_len_p; j++) {
				sequence[strlen(sequence)] = charset[prenecklace_a[j]];
				if (strlen (sequence) == maxlen) {
					return;
				}
			}
		}
	} else {
		prenecklace_a[prenecklace_len_t] =
			prenecklace_a[prenecklace_len_t - lyndon_prefix_len_p];
		de_bruijn_seq(prenecklace_len_t + 1, lyndon_prefix_len_p, order, maxlen,
				size, prenecklace_a, sequence, charset);
		for (j = prenecklace_a[prenecklace_len_t - lyndon_prefix_len_p] + 1;
				j < size; j++) {
			prenecklace_a[prenecklace_len_t] = j;
			de_bruijn_seq (prenecklace_len_t + 1, prenecklace_len_t, order, maxlen,
					size, prenecklace_a, sequence, charset);
		}
	}
}

// Generate a De Bruijn sequence.
// The returned string is malloced, and it is the responsibility of the caller
// to free the memory.
static char* de_bruijn(const char* charset, int order, int maxlen) {
	if (!charset) {
		return NULL;
	}
	size_t size = strlen (charset);
	int* prenecklace_a = calloc (size * (size_t)order, sizeof (int));
	if (!prenecklace_a) {
		return NULL;
	}
	char* sequence = calloc (maxlen + 1, sizeof (char));
	if (!sequence) {
		free (prenecklace_a);
		return NULL;
	}
	de_bruijn_seq (1, 1, order, maxlen, size, prenecklace_a, sequence, charset);
	free (prenecklace_a);
	return sequence;
}

// Generate a cyclic pattern of desired size, and charset, return with starting
// offset of start.
// The returned string is malloced, and it is the responsibility of the caller
// to free the memory.
R_API char* r_debruijn_pattern(int size, int start, const char* charset) {
	char *pat, *pat2;
	ut64 len;
	if (!charset) {
		charset = debruijn_charset;
	}
	if (start >= size) {
		return (char*)NULL;
	}
	pat = de_bruijn (charset, 3 /*subsequence length*/, size);
	if (!pat) {
		return NULL;
	}
	if (start == 0) {
		len = strlen (pat);
		if (size != len) {
			eprintf ("warning: requested pattern of length %d, "
				 "generated length %"PFMT64d"\n", size, len);
		}
		return pat;
	}
	pat2 = calloc ((size - start) + 1, sizeof(char));
	if (!pat2) {
		free (pat);
		return NULL;
	}
	strncpy (pat2, pat + start, size - start);
	pat2[size-start] = 0;
	free (pat);
	len = strlen (pat2);
	if (size != len) {
		eprintf ("warning: requested pattern of length %d, "
				 "generated length %"PFMT64d"\n",
				 size, len);
	}
	return pat2;
}

// Finds the offset of a given value in a cyclic pattern of an integer.
R_API int r_debruijn_offset(ut64 value, bool is_big_endian) {
	char* needle, *pattern, buf[9];
	int retval = -1;
	char* pch;
	// 0x10000 should be long enough. This is how peda works, and nobody complains
	// ... but is slow. Optimize for common case.
	int lens[2] = {0x1000, 0x10000};
	int j;

	if (value == 0) {
		return -1;
	}

	for (j = 0; j < 2 && retval == -1; j++) {
		pattern = r_debruijn_pattern (lens[j], 0, debruijn_charset);

		buf[8] = '\0';
		if (is_big_endian) {
			r_write_be64 (buf, value);
		} else {
			r_write_le64 (buf, value);
		}
		for (needle = buf; !*needle; needle++) {
			/* do nothing here */
		}

		pch = strstr (pattern, needle);

		if (pch) {
			retval = (int)(size_t)(pch - pattern);
		}
		free (pattern);
	}
	return retval;
}
