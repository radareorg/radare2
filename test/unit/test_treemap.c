#define r_print_treemap fault_print_treemap
#include <r_util.h>
#include "minunit.h"

#if R2__UNIX__
#include <sys/mman.h>
#endif

static bool fail_allocation;
static size_t allocation_size;
static int allocation_calls;

static void *fault_calloc(size_t count, size_t size) {
	allocation_calls++;
	if (r_mul_overflow_size_t (count, size, &allocation_size) || fail_allocation) {
		return NULL;
	}
	return calloc (count, size);
}

#define calloc fault_calloc
#include "../../libr/util/treemap.c"
#undef calloc

bool test_treemap_small(void) {
	const ut32 values[] = { 1 };
	char *map = r_print_treemap (1, values, NULL, 6, 3);
	mu_assert_notnull (map, "small canvas allocated");
	mu_assert_streq_free (map, "+----+\n|1   |\n+----+\n", "small canvas rendering");
	mu_end;
}

bool test_treemap_large_dimensions(void) {
	const ut32 values[] = { 1 };
	const char *labels[] = { "box" };
	const int dimensions[][2] = { { 5000, 3 }, { 8, 5000 } };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (dimensions); i++) {
		const int width = dimensions[i][0];
		const int height = dimensions[i][1];
		const size_t stride = (size_t)width + 1;
		char *map = r_print_treemap (1, values, labels, width, height);
		mu_assert_notnull (map, "valid canvas beyond 4096 allocated");
		mu_assert_eq (strlen (map), stride * height, "canvas length");
		mu_assert_notnull (strstr (map, "box"), "label rendered");
		int row;
		for (row = 0; row < height; row++) {
			const size_t offset = (size_t)row * stride;
			const char border = row == 0 || row == height - 1? '+': '|';
			mu_assert_eq (map[offset], border, "left border");
			mu_assert_eq (map[offset + width - 1], border, "right border");
			mu_assert_eq (map[offset + width], '\n', "row separator");
		}
		free (map);
	}
	mu_end;
}

bool test_treemap_invalid_dimensions(void) {
	const ut32 values[] = { 1 };
	const int dimensions[][2] = { { 0, 3 }, { 6, 0 }, { -1, 3 }, { 6, -1 } };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (dimensions); i++) {
		allocation_calls = 0;
		mu_assert_null (r_print_treemap (1, values, NULL, dimensions[i][0], dimensions[i][1]), "invalid dimensions rejected");
		mu_assert_eq (allocation_calls, 0, "invalid dimensions do not allocate");
	}
	mu_end;
}

bool test_treemap_allocation_size(void) {
	const ut32 values[] = { 1 };
	const int dimensions[][2] = {
		{ 65535, 65536 },
		{ 65534, 65537 },
		{ ST32_MAX, 1 },
		{ ST32_MAX, ST32_MAX }
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (dimensions); i++) {
		const ut64 expected = ((ut64)dimensions[i][0] + 1) * dimensions[i][1] + 1;
		allocation_calls = 0;
		allocation_size = 0;
		fail_allocation = true;
		char *map = r_print_treemap (1, values, NULL, dimensions[i][0], dimensions[i][1]);
		fail_allocation = false;
		mu_assert_null (map, "allocation failure handled");
		if (expected > SIZE_MAX) {
			mu_assert_eq (allocation_calls, 0, "size overflow rejected before allocation");
		} else {
			mu_assert_eq (allocation_calls, 1, "representable canvas reaches allocator");
			mu_assert_eq (allocation_size, expected, "allocation includes all rows and terminator");
		}
	}
	mu_end;
}

bool test_treemap_large_offsets(void) {
#if SIZE_MAX > UT32_MAX && (R2__WINDOWS__ || R2__UNIX__)
	const int width = 65535;
	const int height = 65536;
	const int y = height - 3;
	const size_t stride = (size_t)width + 1;
	const size_t size = stride * height;
#if R2__WINDOWS__
	char *map = VirtualAlloc (NULL, size, MEM_RESERVE, PAGE_NOACCESS);
	mu_assert_notnull (map, "reserve sparse canvas");
#else
	char *map = mmap (NULL, size, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
	mu_assert_true (map != MAP_FAILED, "reserve sparse canvas");
#endif
	int row;
	for (row = y; row < height; row++) {
		char *start = map + (size_t)row * stride;
#if R2__WINDOWS__
		mu_assert_notnull (VirtualAlloc (start, stride, MEM_COMMIT, PAGE_READWRITE), "commit canvas row");
#else
		mu_assert_eq (mprotect (start, stride, PROT_READ | PROT_WRITE), 0, "commit canvas row");
#endif
	}
	fflush (stdout);
	drawBox (&map, width, height, 0, y, 6, 3, "mark");
	mu_assert_memeq (map + (size_t)y * stride, "+----+", 6, "top border above signed offset range");
	mu_assert_memeq (map + (size_t)(y + 1) * stride, "|mark|", 6, "label above signed offset range");
	mu_assert_memeq (map + (size_t)(y + 2) * stride, "+----+", 6, "bottom border above signed offset range");
#if R2__WINDOWS__
	mu_assert_true (VirtualFree (map, 0, MEM_RELEASE), "release sparse canvas");
#else
	mu_assert_eq (munmap (map, size), 0, "release sparse canvas");
#endif
	mu_end;
#else
	mu_ignore;
#endif
}

bool all_tests(void) {
	mu_run_test (test_treemap_small);
	mu_run_test (test_treemap_large_dimensions);
	mu_run_test (test_treemap_invalid_dimensions);
	mu_run_test (test_treemap_allocation_size);
	mu_run_test (test_treemap_large_offsets);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
