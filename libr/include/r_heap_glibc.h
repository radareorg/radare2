#ifndef R2_HEAP_GLIBC_H
#define R2_HEAP_GLIBC_H

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_heap_glibc);

#define PRINTF_A(color, fmt , ...) r_cons_printf (color fmt Color_RESET, __VA_ARGS__)
#define PRINTF_YA(fmt, ...) PRINTF_A (Color_YELLOW, fmt, __VA_ARGS__)
#define PRINTF_GA(fmt, ...) PRINTF_A (Color_GREEN, fmt, __VA_ARGS__)
#define PRINTF_BA(fmt, ...) PRINTF_A (Color_BLUE, fmt, __VA_ARGS__)
#define PRINTF_RA(fmt, ...) PRINTF_A (Color_RED, fmt, __VA_ARGS__)

#define PRINT_A(color, msg) r_cons_print (color msg Color_RESET)
#define PRINT_YA(msg) PRINT_A (Color_YELLOW, msg)
#define PRINT_GA(msg) PRINT_A (Color_GREEN, msg)
#define PRINT_BA(msg) PRINT_A (Color_BLUE, msg)
#define PRINT_RA(msg) PRINT_A (Color_RED, msg)

#define NBINS 128
#define NSMALLBINS 64
#define NFASTBINS 10
#define BINMAPSHIFT 5
#define SZ core->dbg->bits
#define BITSPERMAP (1U << BINMAPSHIFT)
#define BINMAPSIZE (NBINS / BITSPERMAP)
#define MAX(a,b) (((a)>(b))?(a):(b))
#define MALLOC_ALIGNMENT MAX (2 * SZ,  __alignof__ (long double))
#define MALLOC_ALIGN_MASK (MALLOC_ALIGNMENT - 1)
#define NPAD -6

#define largebin_index_32(size)				       \
(((((ut32)(size)) >>  6) <= 38)?  56 + (((ut32)(size)) >>  6): \
 ((((ut32)(size)) >>  9) <= 20)?  91 + (((ut32)(size)) >>  9): \
 ((((ut32)(size)) >> 12) <= 10)? 110 + (((ut32)(size)) >> 12): \
 ((((ut32)(size)) >> 15) <=  4)? 119 + (((ut32)(size)) >> 15): \
 ((((ut32)(size)) >> 18) <=  2)? 124 + (((ut32)(size)) >> 18): \
					126)
#define largebin_index_32_big(size)                            \
(((((ut32)(size)) >>  6) <= 45)?  49 + (((ut32)(size)) >>  6): \
 ((((ut32)(size)) >>  9) <= 20)?  91 + (((ut32)(size)) >>  9): \
 ((((ut32)(size)) >> 12) <= 10)? 110 + (((ut32)(size)) >> 12): \
 ((((ut32)(size)) >> 15) <=  4)? 119 + (((ut32)(size)) >> 15): \
 ((((ut32)(size)) >> 18) <=  2)? 124 + (((ut32)(size)) >> 18): \
                                        126)
#define largebin_index_64(size)                                \
(((((ut32)(size)) >>  6) <= 48)?  48 + (((ut32)(size)) >>  6): \
 ((((ut32)(size)) >>  9) <= 20)?  91 + (((ut32)(size)) >>  9): \
 ((((ut32)(size)) >> 12) <= 10)? 110 + (((ut32)(size)) >> 12): \
 ((((ut32)(size)) >> 15) <=  4)? 119 + (((ut32)(size)) >> 15): \
 ((((ut32)(size)) >> 18) <=  2)? 124 + (((ut32)(size)) >> 18): \
					126)

#define largebin_index(size) \
  (SZ == 8 ? largebin_index_64 (size) : largebin_index_32 (size))

/* Not works 32 bit on 64 emulation
#define largebin_index(size) \
  (SZ == 8 ? largebin_index_64 (size)                          \
   : MALLOC_ALIGNMENT == 16 ? largebin_index_32_big (size)     \
   : largebin_index_32 (size))
*/

typedef struct r_malloc_chunk_64 {
	ut64 prev_size;   /* Size of previous chunk (if free).  */
	ut64 size;        /* Size in bytes, including overhead. */

	ut64 fd;          /* double links -- used only if free. */
	ut64 bk;

	/* Only used for large blocks: pointer to next larger size.  */
	ut64 fd_nextsize; /* double links -- used only if free. */
	ut64 bk_nextsize;
} RHeapChunk_64;

typedef struct r_malloc_chunk_32 {
	ut32 prev_size;	/* Size of previous chunk (if free).  */
	ut32 size;       	/* Size in bytes, including overhead. */

	ut32 fd;	        /* double links -- used only if free. */
	ut32 bk;

	/* Only used for large blocks: pointer to next larger size.  */
	ut32 fd_nextsize; 	/* double links -- used only if free. */
	ut32 bk_nextsize;
} RHeapChunk_32;

/*
typedef RHeapChunk64 *mfastbinptr64;
typedef RHeapChunk64 *mchunkptr64;

typedef RHeapChunk32 *mfastbinptr32;
typedef RHeapChunk32 *mchunkptr32;
*/

typedef struct r_malloc_state_32 { 
	int mutex; 				/* serialized access */ 
	int flags; 				/* flags */
	ut32 fastbinsY[NFASTBINS];		/* array of fastchunks */
	ut32 top; 				/* top chunk's base addr */ 
	ut32 last_remainder;			/* remainder top chunk's addr */
	ut32 bins[NBINS * 2 - 2];   		/* array of remainder free chunks */
	unsigned int binmap[BINMAPSIZE]; 	/* bitmap of bins */

	ut32 next; 				/* double linked list of chunks */
	ut32 next_free; 			/* double linked list of free chunks */

	ut32 system_mem; 			/* current allocated memory of current arena */
	ut32 max_system_mem;  			/* maximum system memory */
} RHeap_MallocState_32; 

typedef struct r_malloc_state_64 { 
	int mutex; 				/* serialized access */ 
	int flags; 				/* flags */
	ut64 fastbinsY[NFASTBINS];		/* array of fastchunks */
	ut64 top; 				/* top chunk's base addr */ 
	ut64 last_remainder;			/* remainder top chunk's addr */
	ut64 bins[NBINS * 2 - 2];   		/* array of remainder free chunks */
	unsigned int binmap[BINMAPSIZE]; 	/* bitmap of bins */

	ut64 next; 				/* double linked list of chunks */
	ut64 next_free; 			/* double linked list of free chunks */

	ut64 system_mem;	 		/* current allocated memory of current arena */
	ut64 max_system_mem;  			/* maximum system memory */
} RHeap_MallocState_64; 

typedef struct r_heap_info_32 {
	ut32 ar_ptr;			/* Arena for this heap. */
	ut32 prev;		 	/* Previous heap. */
	ut32 size;   			/* Current size in bytes. */
	ut32 mprotect_size;		/* Size in bytes that has been mprotected PROT_READ|PROT_WRITE.  */

	/* Make sure the following data is properly aligned, particularly
	that sizeof (heap_info) + 2 * SZ is a multiple of
	MALLOC_ALIGNMENT. */	
	/* char pad[NPAD * SZ & MALLOC_ALIGN_MASK]; */
} RHeapInfo_32;

typedef struct r_heap_info_64 {
	ut64 ar_ptr;			/* Arena for this heap. */
	ut64 prev;		 	/* Previous heap. */
	ut64 size;   			/* Current size in bytes. */
	ut64 mprotect_size;		/* Size in bytes that has been mprotected PROT_READ|PROT_WRITE.  */

	/* Make sure the following data is properly aligned, particularly
	that sizeof (heap_info) + 2 * SZ is a multiple of
	MALLOC_ALIGNMENT. */
	/* char pad[NPAD * SZ & MALLOC_ALIGN_MASK]; */
} RHeapInfo_64;

#ifdef __cplusplus
}
#endif
#endif

