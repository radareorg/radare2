#ifndef R_ARENA_H
#define R_ARENA_H

#include <stddef.h>
#include <stdint.h>
#include <r_types.h>

#ifdef __cplusplus
extern "C" {
#endif

// Helper type to pass ptr+len around by value
typedef struct r_slice_t {
	const uint8_t *ptr;
	size_t len;
	size_t cap;
} RSlice;

static inline RSlice r_slice(const void *ptr, size_t len) {
	return (RSlice){ .ptr = (const uint8_t *)ptr, .len = len, .cap = len };
}

static inline bool r_slice_is_empty(RSlice slice) {
	return slice.ptr == NULL || slice.len == 0;
}

static inline size_t r_slice_len(RSlice slice) {
	return slice.len;
}

static inline const uint8_t *r_slice_ptr(RSlice slice) {
	return slice.ptr;
}

static inline RSlice r_empty_slice(void) {
	return (RSlice){ NULL, 0, 0 };
}

static inline RSlice r_slice_to(RSlice slice, size_t to) {
	if (to >= slice.len) {
		to = slice.len;
	}
	return (RSlice){ .ptr = slice.ptr, .len = to, .cap = slice.cap };
}

static inline RSlice r_slice_from(RSlice slice, size_t from) {
	if (from >= slice.len) {
		return r_empty_slice ();
	}
	return (RSlice){ .ptr = slice.ptr + from, .len = slice.len - from, .cap = slice.cap };
}

static inline RSlice r_slice_from_to(RSlice slice, size_t from, size_t to) {
	if (from >= slice.len || from > to) {
		return r_empty_slice ();
	}
	if (to >= slice.len) {
		to = slice.len;
	}
	RSlice r = {
		.ptr = slice.ptr + from,
		.len = to - from,
		.cap = slice.cap
	};
	return r;
}

// Arena Allocator - Linked list of fixed-size blocks, backed with malloc/free
//
// Facts:
// - Each arena has a list of blocks (allocated on demand)
// - Block size is fixed at arena creation
// - Fast bump allocation within current block
// - Separate list for "huge" blocks (1 alloc per block)
// - When block is full, allocate new block and link it
// - Reset frees all blocks except first (reuse)
// - Destroy frees everything

// Single memory block in the arena
typedef struct r_arena_block_t {
	struct r_arena_block_t *next; // Next block in list (NULL if last)
	size_t used; // Bytes used in this block
	size_t capacity; // Total capacity of this block
	uint8_t data[]; // Flexible array member - actual memory
} RArenaBlock;

// Arena itself
typedef struct r_arena_t {
	RArenaBlock *current; // Current block we're allocating from
	RArenaBlock *first; // First block (kept for reset)

	RArenaBlock *huge; // Requests larger than block size go here (1 block = 1 alloc)

	size_t block_size; // Fixed size for all blocks
	size_t total_allocated; // Total bytes allocated across all blocks
	size_t default_alignment; // Default alignment (usually 8)
} RArena;

#define ARENA_DEFAULT_BLOCK_SIZE (256 * 1024)
#define ARENA_MIN_BLOCK_SIZE 4096
#define ARENA_DEFAULT_ALIGNMENT 8

R_API RArena *r_arena_new(void);
R_API RArena *r_arena_new_with(size_t block_size);
R_API void *r_arena_alloc(RArena *arena, size_t size);
R_API void *r_arena_calloc(RArena *arena, size_t size);
R_API RSlice r_arena_salloc(RArena *arena, size_t size);
R_API RSlice r_arena_scalloc(RArena *arena, size_t size);
R_API void *r_arena_alloc_aligned(RArena *arena, size_t size, size_t alignment);
R_API void *r_arena_calloc_aligned(RArena *arena, size_t size, size_t alignment);
R_API void r_arena_reset(RArena *arena);
R_API void r_arena_free(RArena *arena);

// move functions call r_free () on its arguments if successfully allocated and copied to arena
// spush_ funcs return slices
R_API char *r_arena_push_str(RArena *arena, const char *str);
R_API char *r_arena_move_str(RArena *arena, char *str);
R_API char *r_arena_push_strf(RArena *arena, const char *fmt, ...);
R_API char *r_arena_push_strn(RArena *arena, const char *str, size_t n);
R_API void *r_arena_push(RArena *arena, const void *mem, size_t n);
R_API void *r_arena_move(RArena *arena, void *mem, size_t n);

R_API RSlice r_arena_spush_str(RArena *arena, const char *str);
R_API RSlice r_arena_spush_strf(RArena *arena, const char *fmt, ...);
R_API RSlice r_arena_spush_strn(RArena *arena, const char *str, size_t n);
R_API RSlice r_arena_spush(RArena *arena, const RSlice other);

R_API size_t r_arena_used(const RArena *arena);
R_API size_t r_arena_capacity(const RArena *arena);
R_API size_t r_arena_block_count(const RArena *arena);

#ifdef __cplusplus
}
#endif

#endif // R_ARENA_H
