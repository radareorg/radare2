#ifndef R_BITMAP_H
#define R_BITMAP_H

#if R_SYS_ENDIAN

// using ut32/ut64 words in rbitmap makes it not endian-safe, better use byte words for now
// this is an abi breakage, so we must apply it only on big endian hosts where we dont check for abi yet
#define BITWORD_BITS_SHIFT 3
#define RBitword ut8

#else

#if R_SYS_BITS == 32
#define BITWORD_BITS_SHIFT 5
#define RBitword ut32
#else
#define BITWORD_BITS_SHIFT 6
#define RBitword ut64
#endif

#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_bitmap_t {
	size_t length;
	RBitword *bitmap;
} RBitmap;

R_API RBitmap *r_bitmap_new(size_t len);
/* len is the number of bytes available in buf */
R_API void r_bitmap_set_bytes(RBitmap *b, const ut8 *buf, size_t len);
R_API void r_bitmap_free(RBitmap *b);
R_API void r_bitmap_set(RBitmap *b, size_t bit);
R_API void r_bitmap_unset(RBitmap *b, size_t bit);
R_API bool r_bitmap_test(const RBitmap *b, size_t bit);
R_API size_t r_bitmap_count(const RBitmap *b);
/* returns the next set bit at or after from, or SZT_MAX if none */
R_API size_t r_bitmap_find_next_set(const RBitmap *b, size_t from);

#ifdef __cplusplus
}
#endif

#endif //  R_BITMAP_H
