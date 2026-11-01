#include <r_core.h>
#include <stddef.h>
#include <sys/resource.h>
#include <time.h>
#if __APPLE__
#include <malloc/malloc.h>
#elif __linux__
#include <malloc.h>
#endif

typedef struct {
	size_t bytes;
	size_t allocations;
} Memory;

static void account(Memory *mem, const void *ptr) {
	if (ptr) {
#if __APPLE__
		mem->bytes += malloc_size (ptr);
#elif __linux__
		mem->bytes += malloc_usable_size ((void *)ptr);
#endif
		mem->allocations++;
	}
}

static void account_up(Memory *mem, HtUP *ht, bool vectors) {
	if (!ht) {
		return;
	}
	account (mem, ht);
	account (mem, ht->table);
	ut32 i, j;
	for (i = 0; i < ht->size; i++) {
		HtUPBucket *bucket = &ht->table[i];
		account (mem, bucket->arr);
		for (j = 0; j < bucket->count; j++) {
			void *value = bucket->arr[j].value;
			account (mem, value);
			if (vectors) {
				account (mem, R_VEC_START_ITER ((RVecAnalVarPtr *)value));
			}
		}
	}
}

static void account_labels(Memory *mem, HtPP *ht) {
	if (!ht) {
		return;
	}
	account (mem, ht);
	account (mem, ht->table);
	ut32 i, j;
	for (i = 0; i < ht->size; i++) {
		HtPPBucket *bucket = &ht->table[i];
		account (mem, bucket->arr);
		for (j = 0; j < bucket->count; j++) {
			account (mem, bucket->arr[j].key);
			account (mem, bucket->arr[j].value);
		}
	}
}

static void account_function(Memory *mem, RAnalFunction *f) {
	account (mem, f);
	account (mem, f->name);
	account (mem, f->realname);
	account (mem, f->pin);
	account (mem, f->fingerprint);
	account (mem, f->diff);
	if (f->diff) {
		account (mem, f->diff->name);
	}
	account (mem, R_VEC_START_ITER (&f->bbs));
	account (mem, R_VEC_START_ITER (&f->vars));
	account_up (mem, f->labels, false);
	account_up (mem, f->inst_vars, true);
	account_labels (mem, f->label_addrs);
	RAnalVar **v;
	R_VEC_FOREACH (&f->vars, v) {
		account (mem, *v);
		account (mem, (*v)->name);
		account (mem, (*v)->type);
		account (mem, (*v)->regname);
		account (mem, (*v)->comment);
		account (mem, R_VEC_START_ITER (&(*v)->accesses));
		account (mem, R_VEC_START_ITER (&(*v)->constraints));
	}
	account (mem, f->imports);
	RListIter *it;
	char *import;
	r_list_foreach (f->imports, it, import) {
		account (mem, it);
		account (mem, import);
	}
}

static double cpu_time(void) {
	struct timespec ts;
	clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &ts);
	return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static volatile ut64 walk_result;

int main(int argc, char **argv) {
	RCore *core = r_core_new ();
	r_config_set_b (core->config, "scr.interactive", false);
	r_config_set_i (core->config, "scr.color", 0);
	Memory fresh = {0};
	RAnalFunction *empty = r_anal_function_new (core->anal);
	account_function (&fresh, empty);
	Memory fresh_one = fresh;
	if (!RVecAnalBlockPtr_reserve (&empty->bbs, 8)) {
		return 1;
	}
	account (&fresh_one, R_VEC_START_ITER (&empty->bbs));
	r_anal_function_free (empty);
	if (argc < 2 || !r_core_file_open (core, argv[1], R_PERM_R, 0)
		|| !r_core_bin_load (core, argv[1], UT64_MAX)) {
		r_core_free (core);
		return 1;
	}
	double cpu = cpu_time ();
	r_core_cmd0 (core, argc > 2? argv[2]: "aaa");
	cpu = cpu_time () - cpu;
	Memory functions = {0}, blocks = {0};
	size_t nf = 0, nb = 0, memberships = 0, empty_labels = 0, empty_vars = 0;
	size_t used_diff = 0, fingerprints = 0, pins = 0, imports = 0;
	size_t one_block = 0, capacity = 0;
	ut64 checksum = 0;
	RListIter *it;
	RAnalFunction *f;
	r_list_foreach (core->anal->fcns, it, f) {
		nf++;
		account_function (&functions, f);
		empty_labels += !f->labels || !f->labels->count;
		empty_vars += !f->inst_vars || !f->inst_vars->count;
		used_diff += f->diff && f->diff->type != R_ANAL_DIFF_TYPE_NULL;
		fingerprints += f->fingerprint != NULL;
		pins += f->pin != NULL;
		imports += f->imports != NULL;
		memberships += RVecAnalBlockPtr_length (&f->bbs);
		one_block += RVecAnalBlockPtr_length (&f->bbs) == 1;
		capacity += R_VEC_CAPACITY (&f->bbs);
	}
	RBIter bit;
	RAnalBlock *b;
	r_rbtree_foreach (core->anal->bb_tree, bit, b, RAnalBlock, _rb) {
		nb++;
		account (&blocks, b);
		checksum += b->addr * 0x9e3779b97f4a7c15ULL ^ b->size ^ b->jump ^ b->fail;
	}
	size_t pass, repeats = memberships? 30000000 / memberships + 1: 1;
	double walk = cpu_time ();
	for (pass = 0; pass < repeats; pass++) {
		ut64 sum = 0;
		r_list_foreach (core->anal->fcns, it, f) {
			sum += r_anal_function_realsize (f);
		}
		walk_result = sum;
	}
	walk = memberships? (cpu_time () - walk) * 1e9 / (memberships * repeats): 0;
	size_t heap = 0;
#if __APPLE__
	malloc_statistics_t stats;
	malloc_zone_statistics (NULL, &stats);
	heap = stats.size_in_use;
#endif
	struct rusage usage;
	getrusage (RUSAGE_SELF, &usage);
	size_t rss = usage.ru_maxrss;
#if __linux__
	rss *= 1024;
#endif
	printf ("{\"function_size\":%zu,\"block_size\":%zu,\"vector_size\":%zu,"
		"\"function_align\":%zu,\"vector_align\":%zu,\"bbs_offset\":%zu,\"vars_offset\":%zu,\"block_addr_offset\":%zu,"
		"\"fresh_bytes\":%zu,\"fresh_allocations\":%zu,\"cpu_s\":%.6f,"
		"\"fresh_one_bytes\":%zu,\"one_block_functions\":%zu,\"block_capacity\":%zu,"
		"\"functions\":%zu,\"blocks\":%zu,\"memberships\":%zu,"
		"\"function_owned_bytes\":%zu,\"function_allocations\":%zu,"
		"\"block_object_bytes\":%zu,\"empty_labels\":%zu,\"empty_inst_vars\":%zu,"
		"\"used_diff\":%zu,\"fingerprints\":%zu,\"pins\":%zu,\"imports\":%zu,"
		"\"walk_ns_per_block\":%.6f,\"heap_in_use\":%zu,\"peak_rss\":%zu,"
		"\"checksum\":\"%016"PFMT64x"\"}\n",
		sizeof (RAnalFunction), sizeof (RAnalBlock), sizeof (RVecAnalBlockPtr),
		(size_t)__alignof__ (RAnalFunction), (size_t)__alignof__ (RVecAnalBlockPtr),
		offsetof (RAnalFunction, bbs), offsetof (RAnalFunction, vars), offsetof (RAnalBlock, addr),
		fresh.bytes, fresh.allocations, cpu, fresh_one.bytes, one_block, capacity, nf, nb, memberships,
		functions.bytes, functions.allocations, blocks.bytes, empty_labels, empty_vars,
		used_diff, fingerprints, pins, imports, walk, heap, rss, checksum);
	r_core_free (core);
	return 0;
}
