#include <r_anal.h>
#include <time.h>

static double cpu_time(void) {
	struct timespec ts;
	clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &ts);
	return ts.tv_sec + ts.tv_nsec * 1e-9;
}

#if !BB_ORDER_CACHE
static int block_cmp(RAnalBlock *const *a, RAnalBlock *const *b) {
	return ((*a)->addr > (*b)->addr) - ((*a)->addr < (*b)->addr);
}
#endif

static volatile ut64 result;

int main(int argc, char **argv) {
	size_t n = argc > 1? strtoul (argv[1], NULL, 0): 64;
	const char *order = argc > 2? argv[2]: "asc";
	if (!n || n > 8192 || (n & (n - 1))) {
		return 1;
	}
	RAnal *anal = r_anal_new ();
	size_t count = R_MAX (1, 4096 / n);
	size_t total = count * n;
	RAnalFunction **functions = calloc (count, sizeof (*functions));
	RAnalBlock **blocks = calloc (total, sizeof (*blocks));
	if (!blocks || !functions) {
		return 1;
	}
	size_t i, fidx;
	for (i = 0; i < count; i++) {
		functions[i] = r_anal_function_new (anal);
	}
	for (i = 0; i < total; i++) {
		blocks[i] = r_anal_create_block (anal, 0x100 + i * 32, 0);
	}
	// Keep unrelated blocks in the global index without making them members.
	RAnalFunction *other = r_anal_function_new (anal);
	for (i = 0; i < 32768; i++) {
		RAnalBlock *b = r_anal_create_block (anal, 0x1000000 + i * 32, 0);
		r_anal_function_add_block (other, b);
		r_unref (b);
	}
	double build = cpu_time ();
	for (fidx = 0; fidx < count; fidx++) {
		for (i = 0; i < n; i++) {
			size_t index = !strcmp (order, "desc")? n - i - 1: !strcmp (order, "shuffle")? (i * 4051) & (n - 1): i;
			r_anal_function_add_block (functions[fidx], blocks[fidx * n + index]);
		}
	}
	build = (cpu_time () - build) * 1e9 / total;
	double prepare = cpu_time ();
	for (i = 0; i < count; i++) {
#if BB_ORDER_CACHE
		r_anal_function_sort_blocks (functions[i]);
#else
		RVecAnalBlockPtr_sort (&functions[i]->bbs, block_cmp);
#endif
	}
	prepare = (cpu_time () - prepare) * 1e9 / total;
	ut64 sum = 0;
	size_t queries = 200000;
	double hits = cpu_time ();
	for (i = 0; i < queries; i++) {
		fidx = (i * 13) % count;
		ut64 addr = 0x100 + (fidx * n + ((i * 4051) & (n - 1))) * 32;
		RAnalBlock *b = r_anal_function_bbget_at (anal, functions[fidx], addr);
		if (!b || b->addr != addr) {
			return 1;
		}
		sum += b->addr;
	}
	hits = (cpu_time () - hits) * 1e9 / queries;
	double misses = cpu_time ();
	for (i = 0; i < queries; i++) {
		fidx = (i * 13) % count;
		ut64 addr = 0x101 + (fidx * n + ((i * 4051) & (n - 1))) * 32;
		if (r_anal_function_bbget_at (anal, functions[fidx], addr)) {
			return 1;
		}
	}
	misses = (cpu_time () - misses) * 1e9 / queries;
	result = sum;
	bool foreign_match = r_anal_function_bbget_at (anal, functions[0], 0x1000000) != NULL;
	printf ("{\"blocks\":%zu,\"order\":\"%s\",\"insert_ns_per_block\":%.3f,"
		"\"prepare_ns_per_block\":%.3f,\"hit_ns\":%.3f,\"miss_ns\":%.3f,\"foreign_match\":%s}\n",
		n, order, build, prepare, hits, misses, foreign_match? "true": "false");
	for (i = 0; i < total; i++) {
		r_unref (blocks[i]);
	}
	free (blocks);
	for (i = 0; i < count; i++) {
		r_anal_function_free (functions[i]);
	}
	free (functions);
	r_anal_function_free (other);
	r_anal_free (anal);
	return 0;
}
