
#ifndef R2_HEAP_GLIBC_H
#define R2_HEAP_GLIBC_H

#ifdef __cplusplus
extern "C" {
#endif

#define NBINS 128
#define NSMALLBINS 64
#define NFASTBINS 10
#define BINMAPSHIFT 5
#define BITSPERMAP (1U << BINMAPSHIFT)
#define BINMAPSIZE (NBINS / BITSPERMAP)
#define INTERNAL_SIZE_T size_t
#define MAX(a,b) (((a)>(b))?(a):(b))
#define MALLOC_ALIGNMENT MAX (2 * sizeof (INTERNAL_SIZE_T),  __alignof__ (long double))
#define MALLOC_ALIGN_MASK (MALLOC_ALIGNMENT - 1)
#define SIZE_SZ (sizeof (INTERNAL_SIZE_T))
#define NPAD -6

#define largebin_index_32(sz)                                                \
(((((ut32)(sz)) >>  6) <= 38)?  56 + (((ut32)(sz)) >>  6): \
 ((((ut32)(sz)) >>  9) <= 20)?  91 + (((ut32)(sz)) >>  9): \
 ((((ut32)(sz)) >> 12) <= 10)? 110 + (((ut32)(sz)) >> 12): \
 ((((ut32)(sz)) >> 15) <=  4)? 119 + (((ut32)(sz)) >> 15): \
 ((((ut32)(sz)) >> 18) <=  2)? 124 + (((ut32)(sz)) >> 18): \
					126)
#define largebin_index_32_big(sz)                                            \
(((((ut32)(sz)) >>  6) <= 45)?  49 + (((ut32)(sz)) >>  6): \
 ((((ut32)(sz)) >>  9) <= 20)?  91 + (((ut32)(sz)) >>  9): \
 ((((ut32)(sz)) >> 12) <= 10)? 110 + (((ut32)(sz)) >> 12): \
 ((((ut32)(sz)) >> 15) <=  4)? 119 + (((ut32)(sz)) >> 15): \
 ((((ut32)(sz)) >> 18) <=  2)? 124 + (((ut32)(sz)) >> 18): \
                                        126)
#define largebin_index_64(sz)                                                \
(((((ut32)(sz)) >>  6) <= 48)?  48 + (((ut32)(sz)) >>  6): \
 ((((ut32)(sz)) >>  9) <= 20)?  91 + (((ut32)(sz)) >>  9): \
 ((((ut32)(sz)) >> 12) <= 10)? 110 + (((ut32)(sz)) >> 12): \
 ((((ut32)(sz)) >> 15) <=  4)? 119 + (((ut32)(sz)) >> 15): \
 ((((ut32)(sz)) >> 18) <=  2)? 124 + (((ut32)(sz)) >> 18): \
					126)
#define largebin_index(sz) \
  (SIZE_SZ == 8 ? largebin_index_64 (sz)                                     \
   : MALLOC_ALIGNMENT == 16 ? largebin_index_32_big (sz)                     \
   : largebin_index_32 (sz))

typedef struct r_malloc_chunk {
	INTERNAL_SIZE_T      prev_size;	 /* Size of previous chunk (if free).  */
	INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */

	struct r_malloc_chunk* fd;          /* double links -- used only if free. */
	struct r_malloc_chunk* bk;

	/* Only used for large blocks: pointer to next larger size.  */
	struct r_malloc_chunk* fd_nextsize; /* double links -- used only if free. */
	struct r_malloc_chunk* bk_nextsize;
} RHeapChunk;

typedef RHeapChunk *mfastbinptr;
typedef RHeapChunk *mchunkptr;

typedef struct r_malloc_state { 
	/* mutex_t mutex; */
	int mutex; 					/* serialized access */ 
	int flags; 					/* flags */
	mfastbinptr fastbinsY[NFASTBINS];		/* array of fastchunks */
	mchunkptr top; 					/* top chunk's base addr */ 
	mchunkptr last_remainder;			/* remainder top chunk's addr */
	mchunkptr bins[NBINS * 2 - 2];   		/* array of remainder free chunks */
	unsigned int binmap[BINMAPSIZE]; 		/* bitmap of bins */

	struct r_malloc_state *next; 			/* double linked list of chunks */
	struct r_malloc_state *next_free; 		/* double linked list of free chunks */

	INTERNAL_SIZE_T system_mem; 			/* current allocated memory of current arena */
	INTERNAL_SIZE_T max_system_mem;  		/* maximum system memory */
} RHeap_MallocState; 

typedef struct r_heap_info {
	RHeap_MallocState ar_ptr;	/* Arena for this heap. */
	struct r_heap_info *prev; 	/* Previous heap. */
	size_t size;   			/* Current size in bytes. */
	size_t mprotect_size;		/* Size in bytes that has been mprotected PROT_READ|PROT_WRITE.  */

	/* Make sure the following data is properly aligned, particularly
	that sizeof (heap_info) + 2 * SIZE_SZ is a multiple of
	MALLOC_ALIGNMENT. */
	char pad[NPAD * SIZE_SZ & MALLOC_ALIGN_MASK];
} RHeapInfo;

#ifdef __cplusplus
}
#endif

#endif

