#ifndef R2_HEAP_GLIBC_H
#define R2_HEAP_GLIBC_H

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_heap_glibc);

#define PRINTF_A(color, fmt , ...) r_cons_printf (color fmt Color_RESET, __VA_ARGS__)
#define PRINTF_YA(fmt, ...) PRINTF_A ("%s", fmt, pal->offset, __VA_ARGS__)
#define PRINTF_GA(fmt, ...) PRINTF_A ("%s", fmt, pal->args, __VA_ARGS__)
#define PRINTF_BA(fmt, ...) PRINTF_A ("%s", fmt, pal->num, __VA_ARGS__)
#define PRINTF_RA(fmt, ...) PRINTF_A ("%s", fmt, pal->invalid, __VA_ARGS__)

#define PRINT_A(color, msg) r_cons_print (color msg Color_RESET)
#define PRINT_YA(msg) r_cons_printf ("%s" msg Color_RESET, pal->offset)
#define PRINT_GA(msg) r_cons_printf ("%s" msg Color_RESET, pal->args)
#define PRINT_BA(msg) r_cons_printf ("%s" msg Color_RESET, pal->num)
#define PRINT_RA(msg) r_cons_printf ("%s" msg Color_RESET, pal->invalid)

#define PREV_INUSE 0x1
#define IS_MMAPPED 0x2
#define NON_MAIN_ARENA 0x4

#define NBINS 128
#define NSMALLBINS 64
#define NFASTBINS 10
#define BINMAPSHIFT 5
#define SZ core->dbg->bits
#define FASTBIN_IDX_TO_SIZE(i) ((SZ * 4) + (SZ * 2) * (i - 1))
#define BITSPERMAP (1U << BINMAPSHIFT)
#define BINMAPSIZE (NBINS / BITSPERMAP)
#define MAX(a,b) (((a)>(b))?(a):(b))
#define NPAD -6
#define TCACHE_MAX_BINS 64
#define TCACHE_FILL_COUNT 7

#define MMAP_ALIGN_32 0x14
#define MMAP_ALIGN_64 0x18
#define MMAP_OFFSET 0x8

#define HDR_SZ_32 0x8
#define HDR_SZ_64 0x10
#define TC_HDR_SZ 0x10
#define TC_SZ_32 0x0
#define TC_SZ_64 0x10

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
	int mutex;                              /* serialized access */
	int flags;                              /* flags */
	ut32 fastbinsY[NFASTBINS];              /* array of fastchunks */
	ut32 top;                               /* top chunk's base addr */
	ut32 last_remainder;                    /* remainder top chunk's addr */
	ut32 bins[NBINS * 2 - 2];               /* array of remainder free chunks */
	unsigned int binmap[BINMAPSIZE];        /* bitmap of bins */
	ut32 next;                              /* double linked list of chunks */
	ut32 next_free;                         /* double linked list of free chunks */
	unsigned int attached_threads;          /* threads attached */
	ut32 system_mem;                        /* current allocated memory of current arena */
	ut32 max_system_mem;                    /* maximum system memory */
} RHeap_MallocState_32;

typedef struct r_malloc_state_64 {
	int mutex;                              /* serialized access */
	int flags;                              /* flags */
	ut64 fastbinsY[NFASTBINS];              /* array of fastchunks */
	ut64 top;                               /* top chunk's base addr */
	ut64 last_remainder;                    /* remainder top chunk's addr */
	ut64 bins[NBINS * 2 - 2];               /* array of remainder free chunks */
	unsigned int binmap[BINMAPSIZE];        /* bitmap of bins */
	ut64 next;                              /* double linked list of chunks */
	ut64 next_free;                         /* double linked list of free chunks */
	unsigned int attached_threads;          /* threads attached */
	ut64 system_mem;                        /* current allocated memory of current arena */
	ut64 max_system_mem;                    /* maximum system memory */
} RHeap_MallocState_64;

typedef struct r_tcache_perthread_struct_32 {
	ut8 counts[TCACHE_MAX_BINS];
	ut32 entries[TCACHE_MAX_BINS];
} RHeapTcache_32;

typedef struct r_tcache_perthread_struct_64 {
	ut8 counts[TCACHE_MAX_BINS];
	ut64 entries[TCACHE_MAX_BINS];
} RHeapTcache_64;

typedef struct r_malloc_state_tcache_32 {
	int mutex;                              /* serialized access */
	int flags;                              /* flags */
	int have_fast_chunks;                   /* have fast chunks */
	ut32 fastbinsY[NFASTBINS + 1];          /* array of fastchunks */
	ut32 top;                               /* top chunk's base addr */
	ut32 last_remainder;                    /* remainder top chunk's addr */
	ut32 bins[NBINS * 2 - 2];               /* array of remainder free chunks */
	unsigned int binmap[BINMAPSIZE];        /* bitmap of bins */
	ut32 next;                              /* double linked list of chunks */
	ut32 next_free;                         /* double linked list of free chunks */
	unsigned int attached_threads;          /* threads attached */
	ut32 system_mem;                        /* current allocated memory of current arena */
	ut32 max_system_mem;                    /* maximum system memory */
} RHeap_MallocState_tcache_32;

typedef struct r_malloc_state_tcache_64 {
	int mutex;                              /* serialized access */
	int flags;                              /* flags */
	int have_fast_chunks;                   /* have fast chunks */
	ut64 fastbinsY[NFASTBINS];              /* array of fastchunks */
	ut64 top;                               /* top chunk's base addr */
	ut64 last_remainder;                    /* remainder top chunk's addr */
	ut64 bins[NBINS * 2 - 2];               /* array of remainder free chunks */
	unsigned int binmap[BINMAPSIZE];        /* bitmap of bins */
	ut64 next;                              /* double linked list of chunks */
	ut64 next_free;                         /* double linked list of free chunks */
	unsigned int attached_threads;          /* threads attached */
	ut64 system_mem;                        /* current allocated memory of current arena */
	ut64 max_system_mem;                    /* maximum system memory */
} RHeap_MallocState_tcache_64;

typedef struct r_malloc_state {
	int mutex;                              /* serialized access */
	int flags;                              /* flags */
	unsigned int binmap[BINMAPSIZE];        /* bitmap of bins */

	/*tcache*/
	int have_fast_chunks;                   /* have fast chunks */
	unsigned int attached_threads;          /* threads attached */

	/*32 bits members*/
	ut32 fastbinsY_32[NFASTBINS + 1];       /* array of fastchunks */
	ut32 top_32;                            /* top chunk's base addr */
	ut32 last_remainder_32;                 /* remainder top chunk's addr */
	ut32 bins_32[NBINS * 2 - 2];            /* array of remainder free chunks */
	ut32 next_32;                           /* double linked list of chunks */
	ut32 next_free_32;                      /* double linked list of free chunks */
	ut32 system_mem_32;                     /* current allocated memory of current arena */
	ut32 max_system_mem_32;                 /* maximum system memory */

	/*64 bits members */
	ut64 fastbinsY_64[NFASTBINS];           /* array of fastchunks */
	ut64 top_64;                            /* top chunk's base addr */
	ut64 last_remainder_64;                 /* remainder top chunk's addr */
	ut64 bins_64[NBINS * 2 - 2];            /* array of remainder free chunks */
	ut64 next_64;                           /* double linked list of chunks */
	ut64 next_free_64;                      /* double linked list of free chunks */
	ut64 system_mem_64;                     /* current allocated memory of current arena */
	ut64 max_system_mem_64;                 /* maximum system memory */
} MallocState;

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
