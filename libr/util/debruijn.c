/* radare - LGPL - Copyright 2014 - crowell */

#include <r_util.h>

// For information about the algorithm, see Joe Sawada and Frank Ruskey, "An
// Efficient Algorithm for Generating Necklaces with Fixed Density"

// The following two (commented out) lines are the character set used in peda.
// You may use this charset instead of the A-Za-z0-9 charset normally used.
// char* peda_charset =
//    "A%sB$nC-(D;)Ea0Fb1Gc2Hd3Ie4Jf5Kg6Lh7Mi8Nj9OkPlQmRnSoTpUqVrWsXtYuZvwxyz";

//TODO(crowell): Make charset configurable, to allow banning characters.
static const char* debruijn_charset = "ABCDEFGHIJKLMNOPQRSTUVWZYZabcdefghijklmnopqrstuvwxyz1234567890";

// Generate a De Bruijn sequence.
static void de_bruijn_seq(int prenecklace_len_t, int lyndon_prefix_len_p, int order,
		int maxlen, int size, int* prenecklace_a, char* sequence,
		const char* charset) {
	int j;
	if (strlen(sequence) == maxlen) {
		return;
	}
	if (prenecklace_len_t > order) {
		if (order % lyndon_prefix_len_p == 0) {
			for (j = 1; j <= lyndon_prefix_len_p; ++j) {
				sequence[strlen(sequence)] = charset[prenecklace_a[j]];
				if (strlen(sequence) == maxlen) {
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
				j < size; ++j) {
			prenecklace_a[prenecklace_len_t] = j;
			de_bruijn_seq(prenecklace_len_t + 1, prenecklace_len_t, order, maxlen,
					size, prenecklace_a, sequence, charset);
		}
	}
}

// Generate a De Bruijn sequence.
// The returned string is malloced, and it is the responsibility of the caller
// to free the memory.
static char* de_bruijn(const char* charset, int order, int maxlen) {
	int size = strlen (charset);
	int* prenecklace_a = calloc(size * order, sizeof(int));
	char* sequence = calloc(maxlen + 1, sizeof(char));
	de_bruijn_seq(1, 1, order, maxlen, size, prenecklace_a, sequence, charset);
	free(prenecklace_a);
	return sequence;
}

// Generate a cyclic pattern of desired size, and charset, return with starting
// offset of start.
// The returned string is malloced, and it is the responsibility of the caller
// to free the memory.
R_API char* r_debruijn_pattern(int size, int start, const char* charset) {
	char *pat, *pat2;
	if (!charset)
		charset = debruijn_charset;
	if (start >= size) {
		return (char*)NULL;
	}
	pat = de_bruijn(charset, 3 /*subsequence length*/, size);
	if (start == 0)
		return pat;
	pat2 = calloc ((size - start) + 1, sizeof(char));
	strncpy (pat2, pat + start, size - start);
	pat2[size-start] = 0;
	free (pat);
	return pat2;
}

// In-place reverse a string.
static void reverse_string(char* str) {
	char *start = str, *end, temp;
	// Skip null and empty strings.
	if (!str || !*str)
		return;
	end = start + strlen (str) - 1;
	while (end > start) {
		temp = *start;
		*start = *end;
		*end = temp;
		++start;
		--end;
	}
}

// Generate a cyclic pattern of 0x10000 long.
// The returned string is malloced, and it is the responsibility of the caller
// to free the memory.
static char* cyclic_pattern_long() {
	// 0x10000 should be long enough. This is how peda works, and nobody
	// complains.
	return r_debruijn_pattern (0x10000, 0, debruijn_charset);
}

// Finds the offset of a given value in a cyclic pattern of an integer.
// Guest endian = 1 if little, 0 if big.
// Host endian = 1 if little, 0 if big.
R_API int r_debruijn_offset(ut64 value, int guest_endian) {
	ut64 needle_l[2];  // Hold the value as a string.
	char* needle, *pattern;

	if (value == 0)
		return -1;
	pattern = cyclic_pattern_long();

	needle_l[0] = value;
	needle_l[1] = 0;
	needle = (char*)&needle_l;
	// On little-endian systems with more bits than the binary being analyzed, we
	// may need to find the begin of this.
	while (!needle[0])
		needle++;

	// we should not guess the endian. its already handled by other functions 
	// and configure by the user in cfg.bigendian
	int n = 1;
	// little endian if true
	int host_endian = (*(char*)&n == 1) ? 1 : 0;
	if (host_endian != guest_endian)
		reverse_string (needle);

	char* pch = strstr (pattern, needle);
	int retval = -1;
	if (pch != NULL)
		retval = (int)(pch - pattern);
	free (pattern);
	return retval;
}
