/* radare - LGPL - Copyright 2017-2020 - pancake, crowell */

#include <r_util.h>

#define BITMAP_TEST 0

#define BITWORD_BITS (sizeof(RBitword) * 8)
#define BITWORD_BITS_MASK (BITWORD_BITS - 1)
#define BITWORD_MULT(bit)  (((bit) + (BITWORD_BITS_MASK)) & ~(BITWORD_BITS_MASK))
#define BITWORD_TEST(x, y) (((x)>>(y)) & 1)

#define BITMAP_WORD_COUNT(bit) (BITWORD_MULT(bit) >> BITWORD_BITS_SHIFT)

R_API RBitmap *r_bitmap_new(size_t len) {
	RBitmap *b = R_NEW0 (RBitmap);
	if (!b) {
		return NULL;
	}
	b->length = len;
	b->bitmap = calloc (BITMAP_WORD_COUNT (len), sizeof (RBitword));
	return b;
}

R_API void r_bitmap_set_bytes(RBitmap *b, const ut8 *buf, int len) {
	if (b->length < len) {
		len = b->length;
	}
	memcpy (b->bitmap, buf, len);
}

R_API void r_bitmap_free(RBitmap *b) {
	free (b->bitmap);
	free (b);
}

R_API void r_bitmap_set(RBitmap *b, size_t bit) {
	if (bit < b->length) {
		b->bitmap[(bit >> BITWORD_BITS_SHIFT)] |=
			((RBitword)1 << (bit & BITWORD_BITS_MASK));
	}
}

R_API void r_bitmap_unset(RBitmap *b, size_t bit) {
	if (bit < b->length) {
		b->bitmap[(bit >> BITWORD_BITS_SHIFT)] &=
			~((RBitword)1 << (bit & BITWORD_BITS_MASK));
	}
}

R_API int r_bitmap_test(RBitmap *b, size_t bit) {
	if (bit < b->length) {
		RBitword bword = b->bitmap[ (bit >> BITWORD_BITS_SHIFT)];
		return BITWORD_TEST (bword, (bit & BITWORD_BITS_MASK));
	}
	return -1;
}
