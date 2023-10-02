// https://github.com/YeonwooSung/MemoryAllocation

#include <stdio.h>
#include <stdbool.h>
#include <math.h>
#include <stdint.h>
#include "sdb/sdb.h"
#include "sdb/heap.h"

// generic global
SdbGlobalHeap Gheap = {NULL, NULL};
// local heap allocator api
const SdbGlobalHeap sdb_gh_libc = { NULL, NULL, NULL };

SDB_API char *sdb_strdup(const char *s) {
	size_t sl = strlen (s) + 1;
	char *p = (char *)sdb_gh_malloc (sl);
	if (p) {
		memcpy (p, s, sl);
	}
	return p;
}

#if __SDB_WINDOWS__
#include <windows.h>
#else
#include <unistd.h>
#include <sys/mman.h>
#include <sys/time.h>

// Size 16
typedef struct free_list {
	struct free_list *next;
	struct free_list *prev;
} free_list;

typedef struct sdb_heap_t {
	// Globals
	int *last_address;
	free_list *free_list_start;
	// To reduce number of mmap calls.
	int last_mapped_size; // 1;
} SdbHeap;

SDB_API void sdb_heap_fini(SdbHeap *heap);
SDB_API void *sdb_heap_realloc(SdbHeap *heap, void *ptr, int size);

static SdbHeap sdb_gh_custom_data = { NULL, NULL, 1};
const SdbGlobalHeap sdb_gh_custom = {
	(SdbHeapRealloc)sdb_heap_realloc,
	(SdbHeapFini)sdb_heap_fini,
	&sdb_gh_custom_data
};

#define USED false
#define FREE true

typedef struct Header {
	int size;
	bool free : 1;
	bool has_prev : 1;
	bool has_next : 1;
} Header;

// Size field is not necessary in used blocks.
typedef struct Footer {
	int size;
	bool free : 1;
} Footer;


#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
#define SDB_PAGE_SIZE sysconf(_SC_PAGESIZE)
#define CEIL(X) ((X - (int)(X)) > 0 ? (int)(X + 1) : (int)(X))
#define PAGES(size) (CEIL(size / (double)SDB_PAGE_SIZE))
#define MIN_SIZE (ALIGN(sizeof(free_list) + META_SIZE))
#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))

// Meta sizes.
#define META_SIZE ALIGN(sizeof(Header) + sizeof(Footer))
#define HEADER_SIZE ALIGN(sizeof(Header))
#define FOOTER_SIZE ALIGN(sizeof(Footer))

// Get pointer to the payload (passing the pointer to the header).
static void *add_offset(void *ptr) {
	return (void *)((const ut8*)ptr + HEADER_SIZE);
}

// Get poiner to the header (passing pointer to the payload).
static void *remove_offset(void *ptr) {
	return (void *)((const ut8*)ptr - HEADER_SIZE);
}

static void *getFooter(void *header_ptr) {
	return (void*)((ut8*)header_ptr + ((Header *)header_ptr)->size - FOOTER_SIZE);
}

static void setFree(void *ptr, int val) {
	((Header *)ptr)->free = val;
	Footer *footer = (Footer *)getFooter(ptr);
	footer->free = val;
	// Copy size to footer size field.
	footer->size = ((Header *)ptr)->size;
}

// Set size in the header.
static inline void setSizeHeader(void *ptr, int size) {
	((Header *)ptr)->size = size;
}

#if 0
// Set size in the header.
static inline void setSizeFooter(void *ptr, int size) {
	((Footer *)getFooter(ptr))->size = size;
}
#endif

// Get size of the free list item.
static inline int getSize(void *ptr) {
	return ((Header *)remove_offset (ptr))->size;
}

static void remove_from_free_list(SdbHeap *heap, void *block) {
	setFree(block, USED);

	free_list *free_block = (free_list *)add_offset(block);
	free_list *next = free_block->next;
	free_list *prev = free_block->prev;
	if (!prev) {
		if (!next) {
			// free_block is the only block in the free list.
			heap->free_list_start = NULL;
		} else {
			// Remove first element in the free list.
			heap->free_list_start = next;
			next->prev = NULL;
		}
	} else {
		if (!next) {
			// Remove last element of the free list.
			prev->next = NULL;
		} else {
			// Remove element in the middle.
			prev->next = next;
			next->prev = prev;
		}
	}
}

static void append_to_free_list(SdbHeap *heap, void *ptr) {
	setFree (ptr, FREE);

	free_list eew = {};
	free_list *new_ptr = (free_list *)add_offset (ptr);
	*new_ptr = eew;

	if (heap->free_list_start) {
		// Insert in the beginning.
		new_ptr->next = heap->free_list_start;
		new_ptr->prev = NULL;
		heap->free_list_start->prev = new_ptr;
		heap->free_list_start = new_ptr;
	} else {
		// No elements in the free list
		heap->free_list_start = new_ptr;
		new_ptr->prev = NULL;
		new_ptr->next = NULL;
	}
}

// Find a free block that is large enough to store 'size' bytes.
// Returns NULL if not found.
static free_list *find_free_block(SdbHeap *heap, int size) {
	free_list *current = heap->free_list_start;
	while (current) {
		if (getSize (current) >= size) {
			// Return a pointer to the free block.
			return current;
		}
		current = current->next;
	}
	return NULL;
}

// Split memory into multiple blocks after some part of it was requested
// (requested + the rest).
static void split(SdbHeap *heap, void *start_ptr, int total, int requested) {
	void *new_block_ptr = (void*)((ut8*)start_ptr + requested);
	int block_size = total - requested;

	// Size that was left after allocating memory.
	// Needs to be large enough to store another block (min size is needed in order
	// to store free list element there after it is freed).
	if (block_size < (int)MIN_SIZE) {
		// Not enough size to split.
		return;
	}
	// Change size of the prev (recently allocated) block.
	setSizeHeader(start_ptr, requested);
	((Header *)start_ptr)->has_next = true;

	// Add a header for newly created block (right block).
	Header header = {block_size, FREE, true, ((Header *)start_ptr)->has_next};
	Header *new_block_header = (Header *)new_block_ptr;
	*new_block_header = header;
	Footer footer = {block_size, FREE};
	*((Footer *)getFooter(new_block_header)) = footer;
	append_to_free_list (heap, new_block_header);
}

static void *sdb_heap_malloc(SdbHeap *heap, int size) {
	if (size <= 0) {
		return NULL;
	}
	// Size of the block can't be smaller than MIN_SIZE, as we need to store
	// free list in the body + header and footer on each side respectively.
	int required_size = MAX (ALIGN (size + META_SIZE), MIN_SIZE);
	// Try to find a block big enough in already allocated memory.
	free_list *free_block = find_free_block (heap, required_size);

	if (free_block) {
		// Header ptr
		void *address = remove_offset (free_block);
		// Mark block as used.
		setFree(address, USED);
		// Split the block into two, where the second is free.
		split (heap, address, ((Header *)address)->size, required_size);
		remove_from_free_list (heap, address);
		return add_offset (address);
	}

	// No free block was found. Allocate size requested + header (in full pages).
	// Each next allocation will be doubled in size from the previous one
	// (to decrease the number of mmap sys calls we make).
	// int bytes = MAX (PAGES (required_size), heap->last_mapped_size) * SDB_PAGE_SIZE;
	size_t bytes = PAGES(MAX (PAGES (required_size), heap->last_mapped_size)) * SDB_PAGE_SIZE;
	heap->last_mapped_size *= 2;

	// last_address my not be returned by mmap, but makes it more efficient if it happens.
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0
#endif
	void *new_region = mmap (heap->last_address, bytes, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (new_region == MAP_FAILED) {
		perror ("mmap");
		return NULL;
	}
	// Create a header/footer for new block.
	Header header = {(int)bytes, USED, false, false};
	Header *header_ptr = (Header *)new_region;
	*header_ptr = header;
	Footer footer = {};
	footer.free = USED;
	*((Footer *)getFooter(new_region)) = footer;

	if (new_region == heap->last_address && heap->last_address != 0) {
		// if we got a block of memory after the last block, as we requested.
		header_ptr->has_prev = true;
		// change has_next of the prev block
		Footer *prev_footer = (Footer *)(header_ptr - FOOTER_SIZE);
		((Header *)header_ptr - (prev_footer->size))->has_next = true;
	}
	// Split new region.
	split (heap, new_region, bytes, required_size);
	// Update last_address for the next allocation.
	heap->last_address = (int*)((ut8*)new_region + bytes);
	// Return address behind the header (i.e. header is hidden).
	return add_offset (new_region);
}

static void coalesce(SdbHeap *heap, void *ptr) {
	Header *current_header = (Header *)ptr;
	Footer *current_footer = (Footer *)getFooter(ptr);
	if (current_header->has_prev && ((Footer *)((ut8*)ptr - FOOTER_SIZE))->free) {
		int prev_size = ((Footer *)((ut8*)ptr - FOOTER_SIZE))->size;
		Header *prev_header = (Header *)((ut8*)ptr - prev_size);
		Footer *prev_footer = (Footer *)((Footer *)((ut8*)ptr - FOOTER_SIZE));

		// Merge with previous block.
		remove_from_free_list (heap, current_header);
		// Add size of prev block to the size of current block
		prev_header->size += current_header->size;
		prev_footer->size = prev_header->size;
		current_header = prev_header;
	}
	void *next = (void*)((ut8*)ptr + current_header->size);
	if (current_header->has_next && ((Header *)next)->free) {
		int size = ((Header *)next)->size;
		// merge with next block.
		remove_from_free_list (heap, (ut8*)ptr + current_header->size);
		// Add size of next block to the size of current block.
		current_header->size += size;
		current_footer->size = current_header->size;
	}
}

static int unmap(SdbHeap *heap, void *start_address, int size) {
	remove_from_free_list (heap, start_address);
	// Reset has_next, has_prev of neighbours.
	Header *header = (Header *)start_address;
	if (header->has_prev) {
		// Get prev header, set has_next to false.
		int prev_size = ((Footer *)((ut8*)start_address - FOOTER_SIZE))->size;
		Header *prev_header = (Header *)((ut8*)start_address - prev_size);
		prev_header->has_next = false;
	} 
	if (header->has_next) {
		// Get next header, set has_prev to false.
		int this_size = header->size;
		Header *next_header = (Header *)((ut8*)start_address + this_size);
		next_header->has_prev = false;
	}

	// If this is the last block we've allocated using mmap, need to change last_address.
	if (heap->last_address == start_address) {
		heap->last_address = (int *)((ut8*)start_address - size);
	}
	return munmap (start_address, (size_t)size);
}

static void sdb_heap_free(SdbHeap *heap, void *ptr) {
	if (!ptr) {
		return;
	}
	void *start_address = remove_offset (ptr);

	// Check if it has already been freed.
	// Does not handle case when start_address passed was never allocated.
	if (((Header *)start_address)->free) {
		return;
	}

	Header *header = (Header *)start_address;
	int size = header->size;
	uintptr_t addr = (uintptr_t)header;
	if (size % SDB_PAGE_SIZE == 0 && (addr % SDB_PAGE_SIZE) == 0) {
		// if: full page is free (or multiple consecutive pages), page-aligned -> can munmap it.
		unmap (heap, start_address, size);
	} else {
		append_to_free_list (heap, start_address);
		coalesce (heap, start_address);
		// if we are left with a free block of size bigger than PAGE_SIZE that is
		// page-aligned, munmap that part.
		if (size >= SDB_PAGE_SIZE && (addr % SDB_PAGE_SIZE) == 0) {
			split (heap, start_address, size, (size / SDB_PAGE_SIZE) * SDB_PAGE_SIZE);
			unmap (heap, start_address, (size / SDB_PAGE_SIZE) * SDB_PAGE_SIZE);
		}
	}
}

#if 0
static void copy_block(int *src, int *dst, int size) {
	// bettter do memcpy here
	int i;
	// Know that it is 8-bit aligned, so can copy whole ints.
	for (i = 0; i * sizeof(int) < size; i++) {
		dst[i] = src[i];
	}
}
#endif

SDB_API void sdb_heap_init(SdbHeap *heap) {
	heap->last_address = NULL;
	heap->free_list_start = NULL;
	heap->last_mapped_size = 1;
}

SDB_API void sdb_heap_fini(SdbHeap *heap) {
#if 1
	free_list *current = heap->free_list_start;
	while (current) {
		free_list *next = current->next;
		sdb_heap_free (heap, current);
		current = next;
	}
#endif
}

SDB_API void *sdb_heap_realloc(SdbHeap *heap, void *ptr, int size) {
	// If ptr is NULL, realloc() is identical to a call to malloc() for size bytes.
	if (!ptr) {
		return sdb_heap_malloc (heap, size);
	}
	// If size is zero and ptr is not NULL, a new, minimum sized object (MIN_SIZE) is
	// allocated and the original object is freed.
	if (size == 0 && ptr) {
		sdb_heap_free (heap, ptr);
		return sdb_heap_malloc (heap, 1);
	}

	int required_size = META_SIZE + size;
	// If there is enough space, expand the block.
	int current_size = getSize (ptr);

	// if user requests to shorten the block.
	if (size < current_size) {
		return ptr;
	}
	Header *current_header = (Header *)ptr;
	Footer *current_footer = (Footer *)getFooter(ptr);
	// Next block exists and is free.
	if (current_header->has_next && ((Header *)ptr + current_size)->free) {
		int available_size = current_size + getSize ((ut8*)ptr + current_size);
		// Size is enough.
		if (available_size >= required_size) {
			Header *next_header = (Header *)((ut8*)ptr + current_size);
			remove_from_free_list (heap, next_header);
			// Add size of next block to the size of current block.
			current_header->size += size;
			current_footer->size = current_header->size;

			// split if possible.
			split (heap, current_header, available_size, required_size);
			return ptr;
		}
	}

	// Not enough room to enlarge -> allocate new region.
	void *new_ptr = sdb_heap_malloc (heap, size);
	// Copy old data.
	// copy_block(ptr, new_ptr, current_size);
	memcpy (ptr, new_ptr, current_size);

	// Free old location.
	sdb_heap_free (heap, ptr);
	return new_ptr;
}

#endif
