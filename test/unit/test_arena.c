#include <r_util.h>
#include "minunit.h"
#include <string.h>

// ============================================================================
// RSlice Tests
// ============================================================================

static bool test_r_empty_slice(void) {
	RSlice slice = r_empty_slice ();
	mu_assert_null (slice.ptr, "empty slice ptr should be NULL");
	mu_assert_eq (slice.len, 0, "empty slice len should be 0");
	mu_end;
}

static bool test_r_slice_to(void) {
	uint8_t data[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	RSlice slice = { .ptr = data, .len = 10 };

	// Normal case
	RSlice result = r_slice_to (slice, 5);
	mu_assert_ptreq (result.ptr, data, "slice_to should preserve ptr");
	mu_assert_eq (result.len, 5, "slice_to should set length to 5");

	// Boundary case: to = len
	result = r_slice_to (slice, 10);
	mu_assert_eq (result.len, 10, "slice_to at boundary should preserve length");

	// Out of bounds: to > len
	result = r_slice_to (slice, 20);
	mu_assert_eq (result.len, 10, "slice_to beyond length should cap at original length");

	// Edge case: to = 0
	result = r_slice_to (slice, 0);
	mu_assert_eq (result.len, 0, "slice_to(0) should new empty slice");
	mu_assert_ptreq (result.ptr, data, "slice_to(0) should preserve ptr");

	mu_end;
}

static bool test_r_slice_from(void) {
	uint8_t data[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	RSlice slice = { .ptr = data, .len = 10 };

	// Normal case
	RSlice result = r_slice_from (slice, 5);
	mu_assert_ptreq (result.ptr, data + 5, "slice_from should offset ptr by 5");
	mu_assert_eq (result.len, 5, "slice_from(5) on len 10 should have len 5");

	// Boundary case: from = len
	result = r_slice_from (slice, 10);
	mu_assert_null (result.ptr, "slice_from at boundary should return empty slice");
	mu_assert_eq (result.len, 0, "slice_from at boundary should have len 0");

	// Out of bounds: from > len
	result = r_slice_from (slice, 20);
	mu_assert_null (result.ptr, "slice_from beyond length should return empty slice");
	mu_assert_eq (result.len, 0, "slice_from beyond length should have len 0");

	// Edge case: from = 0
	result = r_slice_from (slice, 0);
	mu_assert_ptreq (result.ptr, data, "slice_from(0) should preserve ptr");
	mu_assert_eq (result.len, 10, "slice_from(0) should preserve length");

	mu_end;
}

static bool test_r_slice_from_to(void) {
	uint8_t data[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	RSlice slice = { .ptr = data, .len = 10 };

	// Normal case
	RSlice result = r_slice_from_to (slice, 2, 7);
	mu_assert_ptreq (result.ptr, data + 2, "slice_from_to should offset ptr by from");
	mu_assert_eq (result.len, 5, "slice_from_to(2, 7) should have len 5");

	// Boundary case: from = 0, to = len
	result = r_slice_from_to (slice, 0, 10);
	mu_assert_ptreq (result.ptr, data, "slice_from_to(0, len) should preserve ptr");
	mu_assert_eq (result.len, 10, "slice_from_to(0, len) should preserve length");

	// to > len (should cap at len)
	result = r_slice_from_to (slice, 5, 20);
	mu_assert_ptreq (result.ptr, data + 5, "slice_from_to with to > len should offset ptr");
	mu_assert_eq (result.len, 5, "slice_from_to with to > len should cap at length");

	// from >= len
	result = r_slice_from_to (slice, 10, 15);
	mu_assert_null (result.ptr, "slice_from_to with from >= len should return empty");
	mu_assert_eq (result.len, 0, "slice_from_to with from >= len should have len 0");

	// from > to (invalid range)
	result = r_slice_from_to (slice, 7, 2);
	mu_assert_null (result.ptr, "slice_from_to with from > to should return empty");
	mu_assert_eq (result.len, 0, "slice_from_to with from > to should have len 0");

	// from = to (empty range)
	result = r_slice_from_to (slice, 5, 5);
	mu_assert_ptreq (result.ptr, data + 5, "slice_from_to with from = to should offset ptr");
	mu_assert_eq (result.len, 0, "slice_from_to with from = to should have len 0");

	mu_end;
}

static bool test_r_slice_chaining(void) {
	uint8_t data[20] = { 0 };
	for (int i = 0; i < 20; i++) {
		data[i] = i;
	}
	RSlice slice = { .ptr = data, .len = 20 };

	// Chain operations
	RSlice result = r_slice_from (slice, 5); // [5..20)
	result = r_slice_to (result, 10); // [5..15)
	result = r_slice_from (result, 2); // [7..15)

	mu_assert_ptreq (result.ptr, data + 7, "chained operations should correctly offset");
	mu_assert_eq (result.len, 8, "chained operations should have correct length");
	mu_assert_eq (result.ptr[0], 7, "chained slice should start at correct element");
	mu_assert_eq (result.ptr[7], 14, "chained slice should end at correct element");

	mu_end;
}

// ============================================================================
// RArena Tests
// ============================================================================

static bool test_r_arena_new_free(void) {
	RArena *arena = r_arena_new ();
	mu_assert_notnull (arena, "arena should be newd");
	mu_assert_notnull (arena->first, "arena should have first block");
	mu_assert_ptreq (arena->current, arena->first, "current should point to first");
	mu_assert_eq (arena->block_size, ARENA_DEFAULT_BLOCK_SIZE, "should use default block size");
	mu_assert_eq (arena->default_alignment, ARENA_DEFAULT_ALIGNMENT, "should use default alignment");

	r_arena_free (arena);

	// Test free with NULL
	r_arena_free (NULL); // Should not crash

	mu_end;
}

static bool test_r_arena_new_with(void) {
	// Custom block size
	RArena *arena = r_arena_new_with (8192);
	mu_assert_notnull (arena, "arena with custom size should be newd");
	mu_assert_eq (arena->block_size, 8192, "should use custom block size");
	r_arena_free (arena);

	// Zero block size (should use default)
	arena = r_arena_new_with (0);
	mu_assert_notnull (arena, "arena with zero size should be newd");
	mu_assert_eq (arena->block_size, ARENA_DEFAULT_BLOCK_SIZE, "zero size should use default");
	r_arena_free (arena);

	// Small block size (should be clamped to 4k)
	arena = r_arena_new_with (100);
	mu_assert_notnull (arena, "arena with small size should be newd");
	mu_assert_eq (arena->block_size, 4096, "small size should be clamped to 4096");
	r_arena_free (arena);

	mu_end;
}

static bool test_r_arena_alloc_basic(void) {
	RArena *arena = r_arena_new ();

	// Basic allocation
	void *ptr1 = r_arena_alloc (arena, 100);
	mu_assert_notnull (ptr1, "should allocate 100 bytes");

	void *ptr2 = r_arena_alloc (arena, 200);
	mu_assert_notnull (ptr2, "should allocate 200 bytes");
	mu_assert ("pointers should be different", ptr1 != ptr2);

	// Verify we can write to allocated memory
	memset (ptr1, 0xAA, 100);
	memset (ptr2, 0xBB, 200);
	mu_assert_eq (((uint8_t *)ptr1)[0], 0xAA, "should be able to write to first allocation");
	mu_assert_eq (((uint8_t *)ptr2)[0], 0xBB, "should be able to write to second allocation");

	// Zero size
	void *ptr = r_arena_alloc (arena, 0);
	mu_assert_null (ptr, "alloc with zero size should return NULL");

	r_arena_free (arena);
	mu_end;
}

static bool test_r_arena_alloc_aligned(void) {
	RArena *arena = r_arena_new ();

	// Test various alignments
	void *ptr8 = r_arena_alloc_aligned (arena, 100, 8);
	mu_assert_notnull (ptr8, "should allocate with 8-byte alignment");
	mu_assert_eq ((uintptr_t)ptr8 % 8, 0, "pointer should be 8-byte aligned");

	void *ptr16 = r_arena_alloc_aligned (arena, 100, 16);
	mu_assert_notnull (ptr16, "should allocate with 16-byte alignment");
	mu_assert_eq ((uintptr_t)ptr16 % 16, 0, "pointer should be 16-byte aligned");

	void *ptr32 = r_arena_alloc_aligned (arena, 100, 32);
	mu_assert_notnull (ptr32, "should allocate with 32-byte alignment");
	mu_assert_eq ((uintptr_t)ptr32 % 32, 0, "pointer should be 32-byte aligned");

	void *ptr64 = r_arena_alloc_aligned (arena, 100, 64);
	mu_assert_notnull (ptr64, "should allocate with 64-byte alignment");
	mu_assert_eq ((uintptr_t)ptr64 % 64, 0, "pointer should be 64-byte aligned");

	r_arena_free (arena);
	mu_end;
}

static bool test_r_arena_calloc(void) {
	RArena *arena = r_arena_new ();

	// Allocate and verify zeroed
	uint8_t *ptr = r_arena_calloc (arena, 100);
	mu_assert_notnull (ptr, "should allocate zeroed memory");

	bool all_zero = true;
	for (int i = 0; i < 100; i++) {
		if (ptr[i] != 0) {
			all_zero = false;
			break;
		}
	}
	mu_assert ("allocated memory should be zeroed", all_zero);

	// Test calloc_aligned
	ptr = r_arena_calloc_aligned (arena, 100, 16);
	mu_assert_notnull (ptr, "should allocate aligned zeroed memory");
	mu_assert_eq ((uintptr_t)ptr % 16, 0, "pointer should be 16-byte aligned");

	all_zero = true;
	for (int i = 0; i < 100; i++) {
		if (ptr[i] != 0) {
			all_zero = false;
			break;
		}
	}
	mu_assert ("aligned allocated memory should be zeroed", all_zero);

	r_arena_free (arena);
	mu_end;
}

static bool test_r_arena_salloc(void) {
	RArena *arena = r_arena_new ();

	// Test salloc (slice alloc)
	RSlice slice = r_arena_salloc (arena, 100);
	mu_assert_notnull (slice.ptr, "slice should be allocated");
	mu_assert_eq (slice.len, 100, "slice length should be 100");

	// Test scalloc (slice calloc)
	RSlice zslice = r_arena_scalloc (arena, 50);
	mu_assert_notnull (zslice.ptr, "zeroed slice should be allocated");
	mu_assert_eq (zslice.len, 50, "zeroed slice length should be 50");

	bool all_zero = true;
	size_t i;
	for (i = 0; i < zslice.len; i++) {
		if (zslice.ptr[i] != 0) {
			all_zero = false;
			break;
		}
	}
	mu_assert ("scalloc should return zeroed memory", all_zero);

	r_arena_free (arena);
	mu_end;
}

static bool test_r_arena_push_str(void) {
	RArena *arena = r_arena_new ();

	const char *test_str = "Hello, Arena!";
	char *copy = r_arena_push_str (arena, test_str);
	mu_assert_notnull (copy, "string should be copied");
	mu_assert_streq (copy, test_str, "copied string should match original");
	mu_assert ("strings should be at different addresses", copy != test_str);

	// Verify null terminator
	mu_assert_eq (copy[strlen (test_str)], '\0', "string should be null-terminated");

	// NULL string
	copy = r_arena_push_str (arena, NULL);
	mu_assert_null (copy, "push_str with NULL should return NULL");

	r_arena_free (arena);
	mu_end;
}

static bool test_r_arena_push_strn(void) {
	RArena *arena = r_arena_new ();

	const char *test_str = "Hello, Arena!";

	// Copy first 5 characters
	char *copy = r_arena_push_strn (arena, test_str, 5);
	mu_assert_notnull (copy, "substring should be copied");
	mu_assert_streq (copy, "Hello", "copied substring should match");
	mu_assert_eq (strlen (copy), 5, "copied string should be 5 chars");

	// Copy more than available (should stop at null terminator)
	copy = r_arena_push_strn (arena, "Hi", 100);
	mu_assert_notnull (copy, "should handle n > strlen");
	mu_assert_streq (copy, "Hi", "should copy entire string");
	mu_assert_eq (strlen (copy), 2, "should stop at null terminator");

	// Copy zero characters
	copy = r_arena_push_strn (arena, test_str, 0);
	mu_assert_notnull (copy, "should handle n = 0");
	mu_assert_streq (copy, "", "should copy empty string");

	r_arena_free (arena);
	mu_end;
}

static bool test_r_arena_push_strf(void) {
	RArena *arena = r_arena_new ();

	// Simple format
	char *str = r_arena_push_strf (arena, "Number: %d", 42);
	mu_assert_notnull (str, "formatted string should be allocated");
	mu_assert_streq (str, "Number: 42", "formatted string should match");

	// Multiple format specifiers
	str = r_arena_push_strf (arena, "%s %d %s", "Hello", 123, "World");
	mu_assert_notnull (str, "complex format should work");
	mu_assert_streq (str, "Hello 123 World", "complex format should match");

	// No format specifiers (optimization path)
	str = r_arena_push_strf (arena, "Plain string");
	mu_assert_notnull (str, "plain string should be allocated");
	mu_assert_streq (str, "Plain string", "plain string should match");

	r_arena_free (arena);
	mu_end;
}

static bool test_r_arena_push(void) {
	RArena *arena = r_arena_new ();

	uint8_t data[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

	// Copy memory
	uint8_t *copy = r_arena_push (arena, data, 10);
	mu_assert_notnull (copy, "memory should be copied");
	mu_assert_memeq (copy, data, 10, "copied memory should match");
	mu_assert ("copy should be at different address", copy != data);

	// NULL memory
	void *ptr = r_arena_push (arena, NULL, 10);
	mu_assert_null (ptr, "push with NULL memory should return NULL");

	// Zero size
	ptr = r_arena_push (arena, data, 0);
	mu_assert_null (ptr, "push with zero size should return NULL");

	r_arena_free (arena);
	mu_end;
}

static bool test_r_arena_spush_functions(void) {
	RArena *arena = r_arena_new ();

	// Test spush_str
	const char *test_str = "Hello";
	RSlice str_slice = r_arena_spush_str (arena, test_str);
	mu_assert_notnull (str_slice.ptr, "spush_str should allocate");
	mu_assert_eq (str_slice.len, strlen (test_str), "spush_str length should match");
	mu_assert_memeq (str_slice.ptr, (uint8_t *)test_str, strlen (test_str), "spush_str content should match");

	// Test spush_strf
	RSlice fmt_slice = r_arena_spush_strf (arena, "Number: %d", 42);
	mu_assert_notnull (fmt_slice.ptr, "spush_strf should allocate");
	mu_assert_eq (fmt_slice.len, 10, "spush_strf length should be 10");

	// Test spush_strn
	RSlice strn_slice = r_arena_spush_strn (arena, "Hello World", 5);
	mu_assert_notnull (strn_slice.ptr, "spush_strn should allocate");
	mu_assert_eq (strn_slice.len, 5, "spush_strn length should be 5");

	// Test spush (copy slice)
	uint8_t data[5] = { 1, 2, 3, 4, 5 };
	RSlice orig = { .ptr = data, .len = 5 };
	RSlice copy_slice = r_arena_spush (arena, orig);
	mu_assert_notnull (copy_slice.ptr, "spush should allocate");
	mu_assert_eq (copy_slice.len, 5, "spush length should match");
	mu_assert_memeq (copy_slice.ptr, data, 5, "spush content should match");

	r_arena_free (arena);
	mu_end;
}

static bool test_r_arena_reset(void) {
	RArena *arena = r_arena_new ();

	// Allocate some memory
	void *ptr1 = r_arena_alloc (arena, 1000);
	void *ptr2 = r_arena_alloc (arena, 2000);
	mu_assert_notnull (ptr1, "first allocation should succeed");
	mu_assert_notnull (ptr2, "second allocation should succeed");

	size_t used_before = r_arena_used (arena);
	mu_assert ("should have allocated memory", used_before > 0);

	// Reset arena
	r_arena_reset (arena);

	size_t used_after = r_arena_used (arena);
	mu_assert_eq (used_after, 0, "used should be zero after reset");
	mu_assert_eq (r_arena_block_count (arena), 1, "should have only first block after reset");

	// Should be able to allocate again
	void *ptr3 = r_arena_alloc (arena, 500);
	mu_assert_notnull (ptr3, "should be able to allocate after reset");

	r_arena_free (arena);
	mu_end;
}

static bool test_r_arena_multiple_blocks(void) {
	// Create arena with small block size to force multiple blocks
	RArena *arena = r_arena_new_with (8192);

	mu_assert_eq (r_arena_block_count (arena), 1, "should start with 1 block");

	// Allocate enough to span multiple blocks
	void *ptr1 = r_arena_alloc (arena, 4000);
	mu_assert_notnull (ptr1, "first large allocation should succeed");
	mu_assert_eq (r_arena_block_count (arena), 1, "should still be 1 block");

	void *ptr2 = r_arena_alloc (arena, 4000);
	mu_assert_notnull (ptr2, "second large allocation should succeed");
	mu_assert_eq (r_arena_block_count (arena), 1, "should still be 1 block");

	// This should trigger a new block
	void *ptr3 = r_arena_alloc (arena, 4000);
	mu_assert_notnull (ptr3, "third allocation should trigger new block");
	mu_assert_eq (r_arena_block_count (arena), 2, "should have 2 blocks now");

	// Verify all pointers are usable
	memset (ptr1, 0xAA, 4000);
	memset (ptr2, 0xBB, 4000);
	memset (ptr3, 0xCC, 4000);

	mu_assert_eq (((uint8_t *)ptr1)[0], 0xAA, "first block should be writable");
	mu_assert_eq (((uint8_t *)ptr2)[0], 0xBB, "first block should be writable");
	mu_assert_eq (((uint8_t *)ptr3)[0], 0xCC, "second block should be writable");

	r_arena_free (arena);
	mu_end;
}

static bool test_r_arena_stats(void) {
	RArena *arena = r_arena_new ();

	// Initial state
	mu_assert_eq (r_arena_used (arena), 0, "initial used should be 0");
	mu_assert_eq (r_arena_block_count (arena), 1, "should start with 1 block");
	size_t initial_capacity = r_arena_capacity (arena);
	mu_assert ("should have initial capacity", initial_capacity > 0);

	// Allocate some memory
	r_arena_alloc (arena, 1000);
	mu_assert_eq (r_arena_used (arena), 1000, "used should be 1000");

	r_arena_alloc (arena, 500);
	mu_assert_eq (r_arena_used (arena), 1500, "used should be 1500");

	r_arena_free (arena);
	mu_end;
}

static bool test_r_arena_huge_allocation(void) {
	// Create arena with small block size
	RArena *arena = r_arena_new_with (8192);

	// Try to allocate more than block size (should use huge block mechanism)
	void *huge = r_arena_alloc (arena, 16384);
	mu_assert_notnull (huge, "huge allocation should succeed");

	// Should be able to write to it
	memset (huge, 0xFF, 16384);
	mu_assert_eq (((uint8_t *)huge)[0], 0xFF, "huge allocation should be writable");
	mu_assert_eq (((uint8_t *)huge)[16383], 0xFF, "huge allocation should be writable at end");

	// Regular allocations should still work
	void *regular = r_arena_alloc (arena, 100);
	mu_assert_notnull (regular, "regular allocation should still work after huge allocation");

	r_arena_free (arena);
	mu_end;
}

static bool test_r_arena_stress(void) {
	RArena *arena = r_arena_new ();

	// Allocate many small chunks
	void *ptrs[100];
	for (int i = 0; i < 100; i++) {
		ptrs[i] = r_arena_alloc (arena, 100);
		mu_assert_notnull (ptrs[i], "allocation should succeed in stress test");
		memset (ptrs[i], i & 0xFF, 100);
	}

	// Verify all chunks are distinct and writable
	for (int i = 0; i < 100; i++) {
		mu_assert_eq (((uint8_t *)ptrs[i])[0], i & 0xFF, "chunk should have correct value");
	}

	// Reset and allocate again
	r_arena_reset (arena);

	for (int i = 0; i < 100; i++) {
		void *ptr = r_arena_alloc (arena, 200);
		mu_assert_notnull (ptr, "allocation should succeed after reset");
	}

	r_arena_free (arena);
	mu_end;
}

// ============================================================================
// Test Runner
// ============================================================================

static int all_tests(void) {
	// RSlice tests
	mu_run_test (test_r_empty_slice);
	mu_run_test (test_r_slice_to);
	mu_run_test (test_r_slice_from);
	mu_run_test (test_r_slice_from_to);
	mu_run_test (test_r_slice_chaining);

	// RArena basic tests
	mu_run_test (test_r_arena_new_free);
	mu_run_test (test_r_arena_new_with);
	mu_run_test (test_r_arena_alloc_basic);
	mu_run_test (test_r_arena_alloc_aligned);
	mu_run_test (test_r_arena_calloc);
	mu_run_test (test_r_arena_salloc);

	// RArena push tests
	mu_run_test (test_r_arena_push_str);
	mu_run_test (test_r_arena_push_strn);
	mu_run_test (test_r_arena_push_strf);
	mu_run_test (test_r_arena_push);
	mu_run_test (test_r_arena_spush_functions);

	// RArena management tests
	mu_run_test (test_r_arena_reset);
	mu_run_test (test_r_arena_multiple_blocks);
	mu_run_test (test_r_arena_stats);
	mu_run_test (test_r_arena_huge_allocation);
	mu_run_test (test_r_arena_stress);

	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
