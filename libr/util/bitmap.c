/* radare - LGPL - Copyright 2017-2020 - pancake, crowell */

#include <r_util.h>

#define BITWORD_BITS (sizeof (RBitword) * 8)
#define BITWORD_BITS_MASK (BITWORD_BITS - 1)
#define BITWORD_TEST(x, y) (((x) >> (y)) & 1)

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
	size_t word_count = 0;
	if (!bitmap_word_count (len, &word_count)) {
		return NULL;
	}
	RBitmap *b = R_NEW0 (RBitmap);
	b->length = len;
	if (!word_count) {
		return b;
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
		b->bitmap[bit >> BITWORD_BITS_SHIFT] |= (RBitword)1 << (bit & BITWORD_BITS_MASK);
	}
}

R_API void r_bitmap_unset(RBitmap *b, size_t bit) {
	R_RETURN_IF_FAIL (b);
	if (bit < b->length) {
		b->bitmap[bit >> BITWORD_BITS_SHIFT] &= ~((RBitword)1 << (bit & BITWORD_BITS_MASK));
	}
}

R_API bool r_bitmap_test(const RBitmap *b, size_t bit) {
	R_RETURN_VAL_IF_FAIL (b, false);
	if (bit >= b->length) {
		return false;
	}
	return BITWORD_TEST (b->bitmap[bit >> BITWORD_BITS_SHIFT], bit & BITWORD_BITS_MASK);
}

R_API size_t r_bitmap_count(const RBitmap *b) {
	R_RETURN_VAL_IF_FAIL (b, 0);
	size_t word_count = 0;
	if (!bitmap_word_count (b->length, &word_count) || !word_count) {
		return 0;
	}
	R_RETURN_VAL_IF_FAIL (b->bitmap, 0);
	const size_t last = word_count - 1;
	size_t count = 0;
	size_t i;
	for (i = 0; i < last; i++) {
		count += r_bits_popcount64 ((ut64)b->bitmap[i]);
	}
	count += r_bits_popcount64 ((ut64)(b->bitmap[last] & bitmap_tail_mask (b->length)));
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
	const size_t last = word_count - 1;
	size_t idx = from >> BITWORD_BITS_SHIFT;
	const size_t start_bit = from & BITWORD_BITS_MASK;
	RBitword word = b->bitmap[idx];
	if (start_bit) {
		word &= ~(((RBitword)1 << start_bit) - 1);
	}
	while (idx < last) {
		if (word) {
			return (idx << BITWORD_BITS_SHIFT) + r_bits_ctz64 ((ut64)word);
		}
		word = b->bitmap[++idx];
	}
	word &= bitmap_tail_mask (b->length);
	if (word) {
		return (last << BITWORD_BITS_SHIFT) + r_bits_ctz64 ((ut64)word);
	}
	return SZT_MAX;
}
