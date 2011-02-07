#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#define BITMAP_TEST 1

#define BITMAP_32_WORD 1

typedef struct Bitmap Bitmap;
#if BITMAP_32_WORD
#define BITWORD_BITS_SHIFT 5
typedef uint32_t Bitword;
#else
#define BITWORD_BITS_SHIFT 6
typedef uint64_t Bitword;
#endif
#define BITWORD_BITS (sizeof(Bitword) * 8)
#define BITWORD_BITS_MASK (BITWORD_BITS - 1)
#define BITWORD_MULT(bit)  ((bit + (BITWORD_BITS_MASK)) & ~(BITWORD_BITS_MASK))
#define BITWORD_TEST(bword, bit) ((bword >> bit) & 1)

#define BITMAP_WORD_COUNT(bit) (BITWORD_MULT(bit) >> BITWORD_BITS_SHIFT)


struct Bitmap {
	size_t  length;
	Bitword *bitmap;
};

extern Bitmap *bitmap_new(size_t len) {
	Bitmap *bitmap = malloc(sizeof(Bitmap));
	bitmap->length = len;
	bitmap->bitmap = calloc(BITMAP_WORD_COUNT(len),sizeof(Bitword));
	return bitmap;
}

extern void bitmap_free(Bitmap *bitmap) {
	free(bitmap->bitmap);
	free(bitmap);
}

extern void bitmap_set(Bitmap *bitmap, size_t bit) {
	assert(bit < bitmap->length);
	bitmap->bitmap[(bit >> BITWORD_BITS_SHIFT)] |= ((Bitword)1 << (bit & BITWORD_BITS_MASK));
}

extern void bitmap_unset(Bitmap *bitmap, size_t bit) {
	assert(bit < bitmap->length);
	bitmap->bitmap[(bit >> BITWORD_BITS_SHIFT)] &= ~((Bitword)1 << (bit & BITWORD_BITS_MASK));
}

extern bool bitmap_test(Bitmap *bitmap, size_t bit) {
	assert(bit < bitmap->length);
	Bitword bword = bitmap->bitmap[(bit >> BITWORD_BITS_SHIFT)];
	return BITWORD_TEST(bword, (bit & BITWORD_BITS_MASK));
}

#ifdef BITMAP_TEST
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
