#include <assert.h>
#include <r_util/r_alloc.h>
#include <r_util/r_arena.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

_Static_assert (sizeof (size_t) >= sizeof (void *), "size_t must fit pointer");
_Static_assert (sizeof (uintptr_t) >= sizeof (void *),
	"uintptr_t must fit pointer");

static inline uintptr_t align_address(uintptr_t address, size_t alignment) {
	assert (alignment > 0 && (alignment &(alignment - 1)) == 0);
	return (address + alignment - 1) & ~ (alignment - 1);
}

static RArenaBlock *arena_block_create(size_t capacity) {
	RArenaBlock *block =
		(RArenaBlock *)r_malloc (sizeof (RArenaBlock) + capacity);
	if (!block) {
		return NULL;
	}

	block->next = NULL;
	block->used = 0;
	block->capacity = capacity;

	return block;
}

static void arena_block_free_chain(RArenaBlock *block) {
	while (block) {
		RArenaBlock *next = block->next;
		r_free (block);
		block = next;
	}
}

// Create arena with specified block size
R_API RArena *r_arena_create_with(size_t block_size) {
	if (block_size == 0) {
		block_size = ARENA_DEFAULT_BLOCK_SIZE;
	}

	RArena *arena = (RArena *)r_malloc (sizeof (RArena));
	if (!arena) {
		return NULL;
	}

	RArenaBlock *first_block = arena_block_create (block_size);
	if (!first_block) {
		r_free (arena);
		return NULL;
	}

	arena->current = first_block;
	arena->first = first_block;
	arena->block_size = block_size;
	arena->total_allocated = 0;
	arena->default_alignment = ARENA_DEFAULT_ALIGNMENT;

	return arena;
}

// Create arena with default block size
R_API RArena *r_arena_create(void) {
	return r_arena_create_with (0);
}

// Return what current offset would be if we require a certain alignment for it
static size_t r_arena_aligned_offset(RArena *arena, size_t alignment) {
	RArenaBlock *block = arena->current;
	uintptr_t current_addr = (uintptr_t) (block->data + block->used);
	uintptr_t aligned_addr = align_address (current_addr, alignment);
	size_t padding = aligned_addr - current_addr;
	return block->used + padding;
}

// Allocate memory from arena with specified alignment
R_API void *r_arena_alloc_aligned(RArena *arena, size_t size, size_t alignment) {
	if (!arena || size == 0) {
		return NULL;
	}

	RArenaBlock *block = arena->current;

	size_t aligned_offset = r_arena_aligned_offset (arena, alignment);
	size_t required = aligned_offset + size;

	// Check if allocation fits in current block
	if (required > block->capacity) {
		// Don't support allocations larger than block_size
		if (size > arena->block_size) {
			return NULL;
		}

		RArenaBlock *new_block = arena_block_create (arena->block_size);
		if (!new_block) {
			return NULL;
		}

		block->next = new_block;
		arena->current = new_block;
		block = new_block;

		aligned_offset = r_arena_aligned_offset (arena, alignment);
		required = aligned_offset + size;

		// Can't satisfy with given block size
		if (required > block->capacity) {
			return NULL;
		}
	}

	void *ptr = block->data + aligned_offset;
	block->used = required;
	arena->total_allocated += size;

	return ptr;
}

// Allocate memory from arena with default alignment
R_API void *r_arena_alloc(RArena *arena, size_t size) {
	if (!arena) {
		return NULL;
	}
	return r_arena_alloc_aligned (arena, size, arena->default_alignment);
}

// Reset arena - free all blocks except first, reset first block
R_API void r_arena_reset(RArena *arena) {
	if (!arena) {
		return;
	}

	// Free all blocks except first
	if (arena->first->next) {
		arena_block_free_chain (arena->first->next);
		arena->first->next = NULL;
	}

	// Reset first block
	arena->first->used = 0;
	arena->current = arena->first;
	arena->total_allocated = 0;
}

// Destroy arena - free all blocks and arena itself
R_API void r_arena_destroy(RArena *arena) {
	if (!arena) {
		return;
	}

	arena_block_free_chain (arena->first);
	r_free (arena);
}

// Get total bytes allocated from arena
R_API size_t r_arena_used(const RArena *arena) {
	if (!arena) {
		return 0;
	}
	return arena->total_allocated;
}

// Get total capacity across all blocks
R_API size_t r_arena_capacity(const RArena *arena) {
	if (!arena) {
		return 0;
	}

	size_t total = 0;
	RArenaBlock *block = arena->first;
	while (block) {
		total += block->capacity;
		block = block->next;
	}

	return total;
}

// Get number of blocks in arena
R_API size_t r_arena_block_count(const RArena *arena) {
	if (!arena) {
		return 0;
	}

	size_t count = 0;
	RArenaBlock *block = arena->first;
	while (block) {
		count++;
		block = block->next;
	}

	return count;
}

// Allocate and zero-initialize memory
R_API void *r_arena_calloc(RArena *arena, size_t size) {
	void *ptr = r_arena_alloc (arena, size);
	if (ptr) {
		memset (ptr, 0, size);
	}
	return ptr;
}

// Allocate and zero-initialize memory from arena with specified alignment
R_API void *r_arena_calloc_aligned(RArena *arena, size_t size, size_t alignment) {
	void *ptr = r_arena_alloc_aligned (arena, size, alignment);
	if (ptr) {
		memset (ptr, 0, size);
	}
	return ptr;
}


// Copy null-terminated string into arena
R_API char *r_arena_push_str(RArena *arena, const char *str) {
	if (!arena || !str) {
		return NULL;
	}

	size_t len = strlen (str);
	char *copy = (char *)r_arena_alloc (arena, len + 1);
	if (copy) {
		memcpy (copy, str, len + 1); // Include null terminator
	}
	return copy;
}

// Copy at most n characters of string into arena
R_API char *r_arena_push_strn(RArena *arena, const char *str, size_t n) {
	if (!arena || !str) {
		return NULL;
	}

	size_t len = 0;
	while (len < n && str[len] != '\0') {
		len++;
	}

	char *copy = (char *)r_arena_alloc (arena, len + 1);
	if (copy) {
		memcpy (copy, str, len);
		copy[len] = '\0';
	}
	return copy;
}

// Copy arbitrary memory into arena
R_API void *r_arena_push(RArena *arena, const void *mem, size_t n) {
	if (!arena || !mem || n == 0) {
		return NULL;
	}

	void *copy = r_arena_alloc (arena, n);
	if (copy) {
		memcpy (copy, mem, n);
	}
	return copy;
}
