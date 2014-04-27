/* radare - LGPL - Copyright 2011-2012 - pancake */
#include <r_util.h>

#define BITMAP_TEST 0

#if R_SYS_BITS == 4
#define BITWORD_BITS_SHIFT 5
#define RBitword ut32
#else
#define BITWORD_BITS_SHIFT 6
#define RBitword ut64
#endif

#define BITWORD_BITS (sizeof(RBitword) * 8)
#define BITWORD_BITS_MASK (BITWORD_BITS - 1)
#define BITWORD_MULT(bit)  ((bit + (BITWORD_BITS_MASK)) & ~(BITWORD_BITS_MASK))
#define BITWORD_TEST(x, y) ((x>>y) & 1)

#define BITMAP_WORD_COUNT(bit) (BITWORD_MULT(bit) >> BITWORD_BITS_SHIFT)

typedef struct r_bitmap_t {
	int length;
	RBitword *bitmap;
} RBitmap;

R_API RBitmap *r_bitmap_new(size_t len) {
	RBitmap *b = R_NEW (RBitmap);
	b->length = len;
	b->bitmap = calloc (BITMAP_WORD_COUNT (len), sizeof (RBitword));
	return b;
}

R_API void r_bitmap_set_bytes(RBitmap *b, const ut8 *buf, int len) {
	if (b->length < len)
		len = b->length;
	memcpy (b->bitmap, buf, len);
}

R_API void r_bitmap_free(RBitmap *b) {
	free (b->bitmap);
	free (b);
}

R_API void bitmap_set(RBitmap *b, size_t bit) {
	if (bit<b->length)
		b->bitmap[(bit >> BITWORD_BITS_SHIFT)] |= \
			((RBitword)1 << (bit & BITWORD_BITS_MASK));
}

R_API void r_bitmap_unset(RBitmap *b, size_t bit) {
	if (bit < b->length)
		b->bitmap[(bit >> BITWORD_BITS_SHIFT)] &= \
			~((RBitword)1 << (bit & BITWORD_BITS_MASK));
}

R_API int r_bitmap_test(RBitmap *b, size_t bit) {
	if (bit < b->length) {
		RBitword bword = b->bitmap[ (bit >> BITWORD_BITS_SHIFT)];
		return BITWORD_TEST (bword, (bit & BITWORD_BITS_MASK));
	}
	return -1;
}

#if BITMAP_TEST
#include <stdio.h>

#define MAX_VALUE (2343 + 1)
static const uint32_t test_values[] = { 1,2,3,4,8,34,543,2343 };
#define test_values_len (sizeof(test_values)/sizeof(uint32_t))

static void set_values(Bitmap *bitmap, const uint32_t *values, int len) {
	int i;
	for(i=0; i < len; i++) {
		bitmap_set(bitmap, values[i]);
	}
}

static void unset_values(Bitmap *bitmap, const uint32_t *values, int len) {
	int i;
	for(i=0; i < len; i++) {
		bitmap_unset(bitmap, values[i]);
	}
}

static void check_values(Bitmap *bitmap, const uint32_t *values, int len, bool is_set) {
	int i;
	for(i=0; i < len; i++) {
		assert(bitmap_test(bitmap, values[i]) == is_set);
	}
}

int main(int argc, char *argv[]) {
	Bitmap *bitmap = bitmap_new(MAX_VALUE);

	set_values(bitmap, test_values, test_values_len);

	check_values(bitmap, test_values, test_values_len, true);

	unset_values(bitmap, test_values, test_values_len);

	check_values(bitmap, test_values, test_values_len, false);
	bitmap_free(bitmap);
	return 0;
}

#endif
