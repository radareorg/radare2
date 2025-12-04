/* radare2 - LGPL - Copyright 2025 - quetzal */

#include <r_util/r_assert.h>
#include <r_util/r_alloc.h>
#include <r_util/r_arena.h>

#if 1
_Static_assert (sizeof (size_t) >= sizeof (void *), "size_t must fit pointer");
_Static_assert (sizeof (uintptr_t) >= sizeof (void *), "uintptr_t must fit pointer");
#endif

static inline uintptr_t align_address(uintptr_t address, size_t alignment) {
	R_RETURN_VAL_IF_FAIL (alignment > 0 && (alignment &(alignment - 1)) == 0, 0);
	return (address + alignment - 1) & ~ (alignment - 1);
}

static RArenaBlock *arena_block_new(size_t capacity) {
	RArenaBlock *block = (RArenaBlock *)r_malloc (sizeof (RArenaBlock) + capacity);
	if (block) {
		block->next = NULL;
		block->used = 0;
		block->capacity = capacity;
	}
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
R_API RArena *r_arena_new_with(size_t block_size) {
	if (block_size == 0) {
		block_size = ARENA_DEFAULT_BLOCK_SIZE;
	}
	if (block_size < ARENA_MIN_BLOCK_SIZE) {
		block_size = ARENA_MIN_BLOCK_SIZE;
	}

	RArena *arena = R_NEW0 (RArena);
	RArenaBlock *first_block = arena_block_new (block_size);
	if (!first_block) {
		r_free (arena);
		return NULL;
	}

	arena->current = first_block;
	arena->first = first_block;
	arena->block_size = block_size;
	arena->total_allocated = 0;
	arena->default_alignment = ARENA_DEFAULT_ALIGNMENT;
	arena->huge = NULL;

	return arena;
}

// Create arena with default block size
R_API RArena *r_arena_new(void) {
	return r_arena_new_with (0);
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
	R_RETURN_VAL_IF_FAIL (arena && size > 0, NULL);
	// Validate alignment is power of 2
	R_RETURN_VAL_IF_FAIL (alignment > 0 && (alignment &(alignment - 1)) == 0, NULL);
	RArenaBlock *block = arena->current;

	size_t aligned_offset = r_arena_aligned_offset (arena, alignment);
	size_t required = aligned_offset + size;

	// Check if allocation fits in current block
	if (required > block->capacity) {
		if (size > arena->block_size) {
			// Try to satisfy this allocation with huge-block
			RArenaBlock *blk = arena_block_new (size);
			if (!blk) {
				return NULL;
			}
			blk->next = arena->huge;
			arena->huge = blk;
			arena->total_allocated += size;
			return blk->data;
		}
		RArenaBlock *new_block = arena_block_new (arena->block_size);
		if (!new_block) {
			return NULL;
		}
		block->next = new_block;
		arena->current = new_block;
		block = new_block;

		aligned_offset = r_arena_aligned_offset (arena, alignment);
		required = aligned_offset + size;
	}

	void *ptr = block->data + aligned_offset;
	block->used = required;
	// Note: total_allocated tracks requested sizes, not actual space used (which includes padding)
	arena->total_allocated += size;

	return ptr;
}

// Allocate memory from arena with default alignment
R_API void *r_arena_alloc(RArena *arena, size_t size) {
	R_RETURN_VAL_IF_FAIL (arena && size > 0, NULL);
	return r_arena_alloc_aligned (arena, size, arena->default_alignment);
}

// Reset arena - free all blocks except first, reset first block
R_API void r_arena_reset(RArena *arena) {
	R_RETURN_IF_FAIL (arena);

	// Free all blocks except first
	if (arena->first->next) {
		arena_block_free_chain (arena->first->next);
		arena->first->next = NULL;
	}

	// Free all huge blocks
	if (arena->huge) {
		arena_block_free_chain (arena->huge);
		arena->huge = NULL;
	}

	// Reset first block
	arena->first->used = 0;
	arena->current = arena->first;
	arena->total_allocated = 0;
}

// Destroy arena - free all blocks and arena itself
R_API void r_arena_free(RArena *arena) {
	// ignore NULL arena here
	if (R_LIKELY (arena)) {
		arena_block_free_chain (arena->first);
		arena_block_free_chain (arena->huge);
		r_free (arena);
	}
}

// Get total bytes allocated from arena
R_API size_t r_arena_used(const RArena *arena) {
	R_RETURN_VAL_IF_FAIL (arena, 0);
	return arena->total_allocated;
}

// Get total capacity across all blocks
R_API size_t r_arena_capacity(const RArena *arena) {
	R_RETURN_VAL_IF_FAIL (arena, 0);

	size_t total = 0;
	RArenaBlock *block = arena->first;
	while (block) {
		total += block->capacity;
		block = block->next;
	}

	// Include huge blocks in capacity calculation
	block = arena->huge;
	while (block) {
		total += block->capacity;
		block = block->next;
	}

	return total;
}

// Get number of blocks in arena
R_API size_t r_arena_block_count(const RArena *arena) {
	R_RETURN_VAL_IF_FAIL (arena, 0);

	size_t count = 0;
	RArenaBlock *block = arena->first;
	while (block) {
		count++;
		block = block->next;
	}

	return count;
}

// Allocate a slice
R_API RSlice r_arena_salloc(RArena *arena, size_t size) {
	R_RETURN_VAL_IF_FAIL (arena, ((RSlice){ 0 }));
	void *ptr = r_arena_alloc (arena, size);
	return (RSlice){ .ptr = ptr, .len = size, .cap = size };
}

// Allocate a slice and zero-initialize memory
R_API RSlice r_arena_scalloc(RArena *arena, size_t size) {
	void *ptr = r_arena_calloc (arena, size);
	if (ptr) {
		return (RSlice){ .ptr = ptr, .len = size, .cap = size };
	}
	return r_empty_slice ();
}

// Allocate and zero-initialize memory
R_API void *r_arena_calloc(RArena *arena, size_t size) {
	R_RETURN_VAL_IF_FAIL (arena, NULL);
	void *ptr = r_arena_alloc (arena, size);
	if (ptr) {
		memset (ptr, 0, size);
	}
	return ptr;
}

// Allocate and zero-initialize memory from arena with specified alignment
R_API void *r_arena_calloc_aligned(RArena *arena, size_t size, size_t alignment) {
	R_RETURN_VAL_IF_FAIL (arena, NULL);
	// Validate alignment is power of 2
	R_RETURN_VAL_IF_FAIL (alignment > 0 && (alignment &(alignment - 1)) == 0, NULL);
	void *ptr = r_arena_alloc_aligned (arena, size, alignment);
	if (ptr) {
		memset (ptr, 0, size);
	}
	return ptr;
}

// Copy null-terminated string into arena
R_API char *r_arena_push_str(RArena *arena, const char *str) {
	R_RETURN_VAL_IF_FAIL (arena, NULL);
	if (!str) {
		return NULL;
	}

	size_t len = strlen (str);
	char *copy = (char *)r_arena_alloc (arena, len + 1);
	memcpy (copy, str, len + 1); // Include null terminator

	return copy;
}

// Copy null-terminated string into arena and free it
R_API char *r_arena_move_str(RArena *arena, char *str) {
	R_RETURN_VAL_IF_FAIL (arena, NULL);
	if (!str) {
		return NULL;
	}

	size_t len = strlen (str);
	char *copy = (char *)r_arena_alloc (arena, len + 1);
	if (copy) {
		memcpy (copy, str, len + 1); // Include null terminator
	}

	r_free (str);

	return copy;
}

static char *r_arena_push_vstrf(RArena *arena, const char *fmt, va_list ap) {
	R_RETURN_VAL_IF_FAIL (arena && fmt, NULL);

	if (!strchr (fmt, '%')) {
		char *p = r_arena_push_str (arena, fmt);
		return p;
	}
	va_list ap2;
	va_copy (ap2, ap);
	int ret = vsnprintf (NULL, 0, fmt, ap2);
	ret++;
	char *p = r_arena_alloc (arena, ret);
	(void)vsnprintf (p, ret, fmt, ap);

	va_end (ap2);
	return p;
}

// Allocates buffer on arena and formats string into it
R_API char *r_arena_push_strf(RArena *arena, const char *fmt, ...) {
	R_RETURN_VAL_IF_FAIL (arena && fmt, NULL);

	va_list args;
	va_start (args, fmt);
	char *s = r_arena_push_vstrf (arena, fmt, args);
	va_end (args);
	return s;
}

// Copy at most n characters of string into arena
R_API char *r_arena_push_strn(RArena *arena, const char *str, size_t n) {
	R_RETURN_VAL_IF_FAIL (arena, NULL);
	if (!str) {
		return NULL;
	}

	size_t len = strnlen (str, n);
	char *copy = (char *)r_arena_alloc (arena, len + 1);
	if (copy) {
		memcpy (copy, str, len);
		copy[len] = '\0';
	}
	return copy;
}

// Copy arbitrary memory into arena
R_API void *r_arena_push(RArena *arena, const void *mem, size_t n) {
	R_RETURN_VAL_IF_FAIL (arena, NULL);
	if (!mem || !n) {
		return NULL;
	}

	void *copy = r_arena_alloc (arena, n);
	memcpy (copy, mem, n);

	return copy;
}

// Copy arbitrary memory into arena and free it
R_API void *r_arena_move(RArena *arena, void *mem, size_t n) {
	R_RETURN_VAL_IF_FAIL (arena && mem && n > 0, NULL);
	// if we are asked to move 0 bytes - return NULL, but free mem
	if (!n) {
		r_free (mem);
		return NULL;
	}
	void *copy = r_arena_alloc (arena, n);
	memcpy (copy, mem, n);
	r_free (mem);
	return copy;
}

// Here go slice versions of push_* funcs
R_API RSlice r_arena_spush_str(RArena *arena, const char *str) {
	void *s = r_arena_push_str (arena, str);
	if (R_LIKELY (s)) {
		size_t len = strlen (str);
		return (RSlice){ .ptr = s, .len = len, .cap = len };
	}
	return r_empty_slice ();
}

R_API RSlice r_arena_spush_strf(RArena *arena, const char *fmt, ...) {
	va_list args;
	va_start (args, fmt);
	char *s = r_arena_push_vstrf (arena, fmt, args);
	va_end (args);
	if (s) {
		size_t len = strlen (s);
		return (RSlice){ .ptr = (uint8_t *)s, .len = len, .cap = len };
	}
	return r_empty_slice ();
}

R_API RSlice r_arena_spush_strn(RArena *arena, const char *str, size_t n) {
	char *s = r_arena_push_strn (arena, str, n);
	if (R_LIKELY (s)) {
		size_t len = strlen (s);
		return (RSlice){ .ptr = (uint8_t *)s, .len = len, .cap = len };
	}
	return r_empty_slice ();
}

R_API RSlice r_arena_spush(RArena *arena, RSlice other) {
	void *p = r_arena_push (arena, other.ptr, other.len);
	if (R_LIKELY (p)) {
		return (RSlice){ .ptr = p, .len = other.len, .cap = other.len };
	}
	return r_empty_slice ();
}
