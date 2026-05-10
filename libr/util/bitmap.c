/* radare - LGPL - Copyright 2017-2020 - pancake, crowell */

#include <r_util.h>

#define BITWORD_BITS (sizeof (RBitword) * 8)
#define BITWORD_BITS_MASK (BITWORD_BITS - 1)
#define BITWORD_TEST(x, y) (((x) >> (y)) & 1)

#if defined(__GNUC__) || defined(__clang__)
#define BITWORD_POPCOUNT(x) __builtin_popcountll ((unsigned long long)(x))
#define BITWORD_CTZ(x)      __builtin_ctzll ((unsigned long long)(x))
#else
static inline int BITWORD_POPCOUNT(RBitword x) {
	int count = 0;
	while (x) {
		x &= x - 1;
		count++;
	}
	return count;
}

static inline int BITWORD_CTZ(RBitword x) {
	int count = 0;
	while (!(x & 1)) {
		x >>= 1;
		count++;
	}
	return count;
}
#endif

static bool bitmap_word_count(size_t bits, size_t *count) {
	if (bits > SIZE_MAX - BITWORD_BITS_MASK) {
		return false;
	}
	*count = (bits + BITWORD_BITS_MASK) >> BITWORD_BITS_SHIFT;
	return true;
}

static bool bitmap_byte_count(size_t bits, size_t *count) {
	if (bits > SIZE_MAX - 7) {
		return false;
	}
	*count = (bits + 7) >> 3;
	return true;
}

static RBitword bitmap_tail_mask(size_t bits) {
	const size_t tail = bits & BITWORD_BITS_MASK;
	if (!tail) {
		return (RBitword)~(RBitword)0;
	}
	return ((RBitword)1 << tail) - 1;
}

R_API RBitmap *r_bitmap_new(size_t len) {
	RBitmap *b = R_NEW0 (RBitmap);
	if (!b) {
		return NULL;
	}
	size_t word_count = 0;
	if (!bitmap_word_count (len, &word_count)) {
		free (b);
		return NULL;
	}
	b->length = len;
	if (!word_count) {
		return b;
	}
	size_t alloc_size = 0;
	if (r_mul_overflow_size_t (word_count, sizeof (RBitword), &alloc_size)) {
		free (b);
		return NULL;
	}
	b->bitmap = calloc (word_count, sizeof (RBitword));
	if (!b->bitmap) {
		free (b);
		return NULL;
	}
	return b;
}

R_API void r_bitmap_set_bytes(RBitmap *b, const ut8 *buf, size_t len) {
	R_RETURN_IF_FAIL (b);
	size_t byte_count = 0;
	if (!bitmap_byte_count (b->length, &byte_count)) {
		return;
	}
	if (len > byte_count) {
		len = byte_count;
	}
	if (!len) {
		return;
	}
	R_RETURN_IF_FAIL (buf && b->bitmap);
	memcpy (b->bitmap, buf, len);
}

R_API void r_bitmap_free(RBitmap *b) {
	if (!b) {
		return;
	}
	free (b->bitmap);
	free (b);
}

R_API void r_bitmap_set(RBitmap *b, size_t bit) {
	R_RETURN_IF_FAIL (b);
	if (bit < b->length) {
		b->bitmap[(bit >> BITWORD_BITS_SHIFT)] |=
			((RBitword)1 << (bit & BITWORD_BITS_MASK));
	}
}

R_API void r_bitmap_unset(RBitmap *b, size_t bit) {
	R_RETURN_IF_FAIL (b);
	if (bit < b->length) {
		b->bitmap[(bit >> BITWORD_BITS_SHIFT)] &=
			~((RBitword)1 << (bit & BITWORD_BITS_MASK));
	}
}

R_API bool r_bitmap_test(const RBitmap *b, size_t bit) {
	R_RETURN_VAL_IF_FAIL (b, false);
	if (bit < b->length) {
		RBitword bword = b->bitmap[bit >> BITWORD_BITS_SHIFT];
		return BITWORD_TEST (bword, (bit & BITWORD_BITS_MASK));
	}
	return false;
}

R_API size_t r_bitmap_count(const RBitmap *b) {
	R_RETURN_VAL_IF_FAIL (b, 0);
	size_t word_count = 0;
	if (!bitmap_word_count (b->length, &word_count) || !word_count) {
		return 0;
	}
	R_RETURN_VAL_IF_FAIL (b->bitmap, 0);
	size_t count = 0;
	size_t i;
	for (i = 0; i < word_count; i++) {
		RBitword word = b->bitmap[i];
		if (i == word_count - 1) {
			word &= bitmap_tail_mask (b->length);
		}
		count += BITWORD_POPCOUNT (word);
	}
	return count;
}

R_API size_t r_bitmap_find_next_set(const RBitmap *b, size_t from) {
	R_RETURN_VAL_IF_FAIL (b, SZT_MAX);
	if (from >= b->length) {
		return SZT_MAX;
	}
	size_t word_count = 0;
	if (!bitmap_word_count (b->length, &word_count) || !word_count) {
		return SZT_MAX;
	}
	R_RETURN_VAL_IF_FAIL (b->bitmap, SZT_MAX);
	size_t word_index = from >> BITWORD_BITS_SHIFT;
	const size_t start_bit = from & BITWORD_BITS_MASK;
	RBitword word = b->bitmap[word_index];
	if (start_bit) {
		word &= ~(((RBitword)1 << start_bit) - 1);
	}
	while (word_index < word_count) {
		if (word_index == word_count - 1) {
			word &= bitmap_tail_mask (b->length);
		}
		if (word) {
			return (word_index << BITWORD_BITS_SHIFT) + BITWORD_CTZ (word);
		}
		word_index++;
		if (word_index < word_count) {
			word = b->bitmap[word_index];
		}
	}
	return SZT_MAX;
}
