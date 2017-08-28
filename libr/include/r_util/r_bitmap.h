#ifndef R_BITMAP_H
#define R_BITMAP_H

#if R_SYS_BITS == 4
#define BITWORD_BITS_SHIFT 5
#define RBitword ut32
#else
#define BITWORD_BITS_SHIFT 6
#define RBitword ut64
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_bitmap_t {
	int length;
	RBitword *bitmap;
} RBitmap;

R_API RBitmap *r_bitmap_new(size_t len);
R_API void r_bitmap_set_bytes(RBitmap *b, const ut8 *buf, int len);
R_API void r_bitmap_free(RBitmap *b);
R_API void r_bitmap_set(RBitmap *b, size_t bit);
R_API void r_bitmap_unset(RBitmap *b, size_t bit);
R_API int r_bitmap_test(RBitmap *b, size_t bit);

#ifdef __cplusplus
}
#endif

#endif //  R_BITMAP_H
