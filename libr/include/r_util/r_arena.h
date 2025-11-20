#ifndef R_ARENA_H
#define R_ARENA_H

#include <stddef.h>
#include <stdint.h>
#include <r_types.h>

#ifdef __cplusplus
extern "C" {
#endif

// Arena Allocator - Linked list of fixed-size blocks, backed with malloc/free
//
// Facts:
// - Each arena has a list of blocks (allocated on demand)
// - Block size is fixed at arena creation
// - Fast bump allocation within current block
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
	size_t block_size; // Fixed size for all blocks
	size_t total_allocated; // Total bytes allocated across all blocks
	size_t default_alignment; // Default alignment (usually 8)
} RArena;

// 64kb ought to be enough for anybody. Or just use `arena_create_with`
#define ARENA_DEFAULT_BLOCK_SIZE (64 * 1024)
#define ARENA_DEFAULT_ALIGNMENT 8

R_API RArena *r_arena_create(void);
R_API RArena *r_arena_create_with(size_t block_size);
R_API void *r_arena_alloc(RArena *arena, size_t size);
R_API void *r_arena_calloc(RArena *arena, size_t size);
R_API void *r_arena_alloc_aligned(RArena *arena, size_t size, size_t alignment);
R_API void *r_arena_calloc_aligned(RArena *arena, size_t size, size_t alignment);
R_API void r_arena_reset(RArena *arena);
R_API void r_arena_destroy(RArena *arena);

R_API char *r_arena_push_str(RArena *arena, const char *str);
R_API char *r_arena_push_strn(RArena *arena, const char *str, size_t n);
R_API void *r_arena_push(RArena *arena, const void *mem, size_t n);

R_API size_t r_arena_used(const RArena *arena);
R_API size_t r_arena_capacity(const RArena *arena);
R_API size_t r_arena_block_count(const RArena *arena);

#ifdef __cplusplus
}
#endif

#endif // R_ARENA_H
