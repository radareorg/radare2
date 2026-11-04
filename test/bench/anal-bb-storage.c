#include <r_anal.h>
#include <time.h>
#if __APPLE__
#include <malloc/malloc.h>
#elif __linux__
#include <malloc.h>
#endif

R_VEC_TYPE (InlineBlocks, RAnalBlock);

static size_t allocated(void *ptr) {
#if __APPLE__
	return ptr? malloc_size (ptr): 0;
#elif __linux__
	return ptr? malloc_usable_size (ptr): 0;
#else
	return 0;
#endif
}

static double cpu_time(void) {
	struct timespec ts;
	clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &ts);
	return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static volatile ut64 result;

static __attribute__((noinline)) ut64 walk_ptr(RVecAnalBlockPtr *vectors, size_t count) {
	ut64 sum = 0;
	size_t i;
	for (i = 0; i < count; i++) {
		RAnalBlock **b;
		R_VEC_FOREACH (&vectors[i], b) {
			sum += (*b)->addr + (*b)->size + (*b)->jump + (*b)->fail;
		}
	}
	return sum;
}

static __attribute__((noinline)) ut64 walk_inline(InlineBlocks *vectors, size_t count) {
	ut64 sum = 0;
	size_t i;
	for (i = 0; i < count; i++) {
		RAnalBlock *b;
		R_VEC_FOREACH (&vectors[i], b) {
			sum += b->addr + b->size + b->jump + b->fail;
		}
	}
	return sum;
}

int main(int argc, char **argv) {
	if (argc != 4) {
		fprintf (stderr, "Usage: %s ptr|pool|inline blocks initial-capacity\n", argv[0]);
		return 1;
	}
	bool inlined = !strcmp (argv[1], "inline");
	bool pooled = !strcmp (argv[1], "pool");
	size_t n = strtoul (argv[2], NULL, 0);
	size_t initial = strtoul (argv[3], NULL, 0);
	if (!n || n > 1024 || !initial || initial > 8) {
		return 1;
	}
	size_t count = 4096, total = n * count, i, j;
	double build = cpu_time ();
	RVecAnalBlockPtr *ptrs = inlined? NULL: calloc (count, sizeof (*ptrs));
	InlineBlocks *values = inlined? calloc (count, sizeof (*values)): NULL;
	RAnalBlock *pool = pooled? calloc (total, sizeof (*pool)): NULL;
	if ((inlined && !values) || (!inlined && !ptrs) || (pooled && !pool)) {
		return 1;
	}
	size_t bytes = allocated (inlined? (void *)values: (void *)ptrs) + allocated (pool);
	size_t allocations = 1 + pooled, growths = 0;
	for (i = 0; i < count; i++) {
		bool ok = inlined? InlineBlocks_reserve (&values[i], initial): RVecAnalBlockPtr_reserve (&ptrs[i], initial);
		if (!ok) {
			return 1;
		}
		allocations++;
		for (j = 0; j < n; j++) {
			size_t before = inlined? R_VEC_CAPACITY (&values[i]): R_VEC_CAPACITY (&ptrs[i]);
			RAnalBlock *b = inlined? InlineBlocks_emplace_back (&values[i])
				: pooled? &pool[i * n + j]: calloc (1, sizeof (*b));
			if (!b) {
				return 1;
			}
			b->addr = (i * n + j) * 16;
			b->size = 16;
			b->jump = b->addr + 16;
			b->fail = b->addr + 32;
			if (!inlined) {
				RVecAnalBlockPtr_push_back (&ptrs[i], &b);
				if (!pooled) {
					allocations++;
					bytes += allocated (b);
				}
			}
			size_t after = inlined? R_VEC_CAPACITY (&values[i]): R_VEC_CAPACITY (&ptrs[i]);
			growths += before != after;
		}
		bytes += inlined? allocated (R_VEC_START_ITER (&values[i])): allocated (R_VEC_START_ITER (&ptrs[i]));
	}
	build = cpu_time () - build;
	size_t repeats = 30000000 / total + 1;
	ut64 expected = 24 * total * (total - 1) + 64 * total;
	ut64 sum = inlined? walk_inline (values, count): walk_ptr (ptrs, count);
	if (sum != expected) {
		return 1;
	}
	double walk = cpu_time ();
	for (i = 0; i < repeats; i++) {
		result = inlined? walk_inline (values, count): walk_ptr (ptrs, count);
	}
	walk = (cpu_time () - walk) * 1e9 / (total * repeats);
	double teardown = cpu_time ();
	for (i = 0; i < count; i++) {
		if (inlined) {
			InlineBlocks_fini (&values[i]);
		} else {
			if (!pooled) {
				RAnalBlock **b;
				R_VEC_FOREACH (&ptrs[i], b) {
					free (*b);
				}
			}
			RVecAnalBlockPtr_fini (&ptrs[i]);
		}
	}
	free (values);
	free (ptrs);
	free (pool);
	teardown = cpu_time () - teardown;
	printf ("{\"mode\":\"%s\",\"blocks_per_function\":%zu,\"initial\":%zu,"
		"\"functions\":%zu,\"block_size\":%zu,\"vector_size\":%zu,"
		"\"storage_bytes\":%zu,\"allocations\":%zu,\"growths\":%zu,"
		"\"build_ns_per_block\":%.3f,\"free_ns_per_block\":%.3f,\"walk_ns_per_block\":%.3f}\n",
		argv[1], n, initial, count, sizeof (RAnalBlock), sizeof (InlineBlocks), bytes, allocations, growths,
		build * 1e9 / total, teardown * 1e9 / total, walk);
	return 0;
}
