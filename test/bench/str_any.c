#include <r_util.h>

#if defined(__GNUC__) || defined(__clang__)
#define NOINLINE __attribute__((noinline))
#elif defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE
#endif

#define SANITIZERS(F, X) F("sanitizer_") X("asan_") X("hwasan_") X("ubsan_") X("tsan_") X("msan_")
#define HASHES(F, X) F("sha1") X("sha256") X("sha384") X("sha512")
#define FORMATS(F, X) F("printf") X("fprintf") X("dprintf") X("sprintf") X("snprintf") X("asprintf") \
	X("syslog") X("err") X("errx") X("warn") X("warnx") X("wprintf") X("fwprintf") X("swprintf") \
	X("__printf_chk") X("__fprintf_chk") X("__sprintf_chk") X("__snprintf_chk")

#define ITEM(str) str,
#define FIRST_ARG(str) str
#define NEXT_ARG(str) , str
#define CMP(str) || !strcmp (key, str)
#define PREFIX(str) || r_str_startswith (key, str)
#define SUFFIX(str) || (length < sizeof (str) && !memcmp (key, (str) + sizeof (str) - 1 - length, length))
#define SUBSTRING(str) || strstr (str, key)

static inline bool cmp_loop(const char *key, const char *const *items, size_t count) {
	size_t i;
	for (i = 0; i < count; i++) {
		if (!strcmp (key, items[i])) {
			return true;
		}
	}
	return false;
}

static inline bool prefix_loop(const char *key, const char *const *items, size_t count) {
	size_t i;
	for (i = 0; i < count; i++) {
		if (r_str_startswith (key, items[i])) {
			return true;
		}
	}
	return false;
}

static inline bool suffix_loop(const char *key, const char *const *items, size_t count) {
	const size_t length = strlen (key);
	size_t i;
	for (i = 0; i < count; i++) {
		const size_t item_length = strlen (items[i]);
		if (length <= item_length && !memcmp (key, items[i] + item_length - length, length)) {
			return true;
		}
	}
	return false;
}

static inline bool substring_loop(const char *key, const char *const *items, size_t count) {
	size_t i;
	for (i = 0; i < count; i++) {
		if (strstr (items[i], key)) {
			return true;
		}
	}
	return false;
}

#define DEFINE_MATCHERS(name, LIST) \
	static const char *const name##_items[] = { LIST (ITEM, ITEM) }; \
	static NOINLINE bool name##_cmp_loop(const char *key) { \
		return *key && cmp_loop (key, name##_items, R_ARRAY_SIZE (name##_items)); \
	} \
	static NOINLINE bool name##_cmp_chain(const char *key) { return *key && (false LIST (CMP, CMP)); } \
	static NOINLINE bool name##_cmp_macro(const char *key) { return R_STR_CMP_ANY (key, LIST (FIRST_ARG, NEXT_ARG)); } \
	static NOINLINE bool name##_prefix_loop(const char *key) { \
		return *key && prefix_loop (key, name##_items, R_ARRAY_SIZE (name##_items)); \
	} \
	static NOINLINE bool name##_prefix_chain(const char *key) { return *key && (false LIST (PREFIX, PREFIX)); } \
	static NOINLINE bool name##_prefix_macro(const char *key) { return R_STR_STARTSWITH_ANY (key, LIST (FIRST_ARG, NEXT_ARG)); } \
	static NOINLINE bool name##_suffix_loop(const char *key) { \
		return *key && suffix_loop (key, name##_items, R_ARRAY_SIZE (name##_items)); \
	} \
	static NOINLINE bool name##_suffix_chain(const char *key) { \
		const size_t length = strlen (key); return *key && (false LIST (SUFFIX, SUFFIX)); \
	} \
	static NOINLINE bool name##_suffix_macro(const char *key) { return R_STR_ENDSWITH_ANY (key, LIST (FIRST_ARG, NEXT_ARG)); } \
	static NOINLINE bool name##_substring_loop(const char *key) { \
		return *key && substring_loop (key, name##_items, R_ARRAY_SIZE (name##_items)); \
	} \
	static NOINLINE bool name##_substring_chain(const char *key) { return *key && (false LIST (SUBSTRING, SUBSTRING)); } \
	static NOINLINE bool name##_substring_macro(const char *key) { return R_STR_STRSTR_ANY (key, LIST (FIRST_ARG, NEXT_ARG)); }

DEFINE_MATCHERS (sanitizers, SANITIZERS)
DEFINE_MATCHERS (hashes, HASHES)
DEFINE_MATCHERS (formats, FORMATS)

typedef bool (*Matcher)(const char *key);
typedef struct {
	const char *name;
	const char *const *items;
	size_t count;
	Matcher matchers[4][3];
} Dataset;

#define DATASET(name) { #name, name##_items, R_ARRAY_SIZE (name##_items), { \
	{ name##_cmp_loop, name##_cmp_chain, name##_cmp_macro }, \
	{ name##_prefix_loop, name##_prefix_chain, name##_prefix_macro }, \
	{ name##_suffix_loop, name##_suffix_chain, name##_suffix_macro }, \
	{ name##_substring_loop, name##_substring_chain, name##_substring_macro } } }

#define KEY_COUNT 4096
#define TRIALS 5
static volatile size_t result_sink;

static ut32 next_random(ut32 *state) {
	*state = *state * 1664525 + 1013904223;
	return *state;
}

static char *make_key(const Dataset *dataset, int operation, bool hit, ut32 random) {
	const char *item = dataset->items[random % dataset->count];
	const size_t length = strlen (item);
	char *key = malloc (length + 16);
	if (!key) {
		return NULL;
	}
	if (hit) {
		switch (operation) {
		case 0:
			strcpy (key, item);
			break;
		case 1:
			strcpy (key, item);
			strcpy (key + length, "_report");
			break;
		case 2:
			strcpy (key, item + length / 2);
			break;
		case 3:
			memcpy (key, item + length / 4, length / 2);
			key[length / 2] = 0;
			break;
		}
	} else {
		strcpy (key, item);
		if ((random >> 16) & 1) {
			key[0] = '!';
		} else {
			key[length - 1] = '!';
		}
		if (dataset->matchers[operation][0] (key)) {
			strcpy (key, "!missing");
		}
	}
	return key;
}

static NOINLINE double measure(Matcher matcher, char **keys, int repeats) {
	size_t matches = 0;
	const ut64 start = r_time_now_mono ();
	int repeat, i;
	for (repeat = 0; repeat < repeats; repeat++) {
		for (i = 0; i < KEY_COUNT; i++) {
			matches += matcher (keys[i]);
		}
	}
	const ut64 elapsed = r_time_now_mono () - start;
	result_sink = matches;
	return elapsed * 1000.0 / ((double)repeats * KEY_COUNT);
}

int main(int argc, char **argv) {
	const int repeats = argc > 1? atoi (argv[1]): 128;
	if (repeats < 1 || repeats > 100000) {
		fprintf (stderr, "Usage: %s [repeats: 1..100000]\n", argv[0]);
		return 1;
	}
	const Dataset datasets[] = { DATASET (sanitizers), DATASET (hashes), DATASET (formats) };
	const char *operations[] = { "CMP", "STARTSWITH", "ENDSWITH", "STRSTR" };
	const int hit_rates[] = { 0, 50, 100 };
#ifdef __clang__
	printf ("# Clang %s\n", __clang_version__);
#elif defined(__GNUC__)
	printf ("# GCC %s\n", __VERSION__);
#endif
#ifdef __OPTIMIZE__
	printf ("# compiler optimization enabled\n");
#else
	printf ("# compiler optimization disabled\n");
#endif
	printf ("# %d keys, %d repeats, best of %d trials; nanoseconds per lookup\n", KEY_COUNT, repeats, TRIALS);
	printf ("dataset,items,operation,hit_percent,loop_ns,chain_ns,macro_ns,macro_over_loop,macro_over_chain\n");
	size_t d;
	int operation, rate, i, method, trial;
	for (d = 0; d < R_ARRAY_SIZE (datasets); d++) {
		for (operation = 0; operation < 4; operation++) {
			for (rate = 0; rate < 3; rate++) {
				char *keys[KEY_COUNT];
				ut32 state = 12345;
				for (i = 0; i < KEY_COUNT; i++) {
					const bool hit = i * 100 / KEY_COUNT < hit_rates[rate];
					keys[i] = make_key (&datasets[d], operation, hit, next_random (&state));
					if (!keys[i]) {
						return 1;
					}
					for (method = 0; method < 3; method++) {
						if (datasets[d].matchers[operation][method] (keys[i]) != hit) {
							fprintf (stderr, "Result mismatch: %s/%s method %d key %s\n",
								datasets[d].name, operations[operation], method, keys[i]);
							return 1;
						}
					}
				}
				for (i = KEY_COUNT - 1; i > 0; i--) {
					const int other = next_random (&state) % (i + 1);
					char *key = keys[i];
					keys[i] = keys[other];
					keys[other] = key;
				}
				double best[] = { 1e30, 1e30, 1e30 };
				for (trial = 0; trial < TRIALS; trial++) {
					for (method = 0; method < 3; method++) {
						const int index = (method + trial) % 3;
						const double elapsed = measure (datasets[d].matchers[operation][index], keys, repeats);
						best[index] = R_MIN (best[index], elapsed);
					}
				}
				printf ("%s,%zu,%s,%d,%.2f,%.2f,%.2f,%.2f,%.2f\n", datasets[d].name, datasets[d].count,
					operations[operation], hit_rates[rate], best[0], best[1], best[2], best[2] / best[0], best[2] / best[1]);
				fflush (stdout);
				for (i = 0; i < KEY_COUNT; i++) {
					free (keys[i]);
				}
			}
		}
	}
	return 0;
}
