#ifndef SDB_H
#define SDB_H

#if !defined(O_BINARY) && !defined(_MSC_VER)
#undef O_BINARY
#define O_BINARY 0
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"
#include "sdbht.h"
#include "ls.h"
#include "dict.h"
#include "cdb.h"
#include "cdb_make.h"
#include "sdb_version.h"

/* Key value sizes */
#define SDB_MIN_VALUE 1
#define SDB_MAX_VALUE 0xffffff
#define SDB_MIN_KEY 1
#define SDB_MAX_KEY 0xff

#if !defined(SZT_ADD_OVFCHK)
#define SZT_ADD_OVFCHK(x, y) ((SIZE_MAX - (x)) <= (y))
#endif

	/* printf format check attributes */
#if defined(__clang__) || defined(__GNUC__)
#define SDB_PRINTF_CHECK(fmt, dots) __attribute__ ((format (printf, fmt, dots)))
#else
#define SDB_PRINTF_CHECK(fmt, dots)
#endif

#if __SDB_WINDOWS__ && !__CYGWIN__
#include <windows.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <io.h>
#ifndef _MSC_VER
extern __attribute__((dllimport)) void *__cdecl _aligned_malloc(size_t, size_t);
extern __attribute__((dllimport)) void __cdecl _aligned_free(void *memblock);
extern char *strdup (const char *);
#else
#include <process.h>
#include <windows.h>
#include <malloc.h> // for _aligned_malloc
#define ftruncate _chsize
#endif

//#define SDB_MODE 0
#define SDB_MODE _S_IWRITE | _S_IREAD
#else
#define SDB_MODE 0644
//#define SDB_MODE 0600
#endif

//#define SDB_RS '\x1e'
#define SDB_RS ','
#define SDB_SS ","
#define SDB_MAX_PATH 256
#define SDB_NUM_BASE 16
#define SDB_NUM_BUFSZ 64

#define SDB_OPTION_NONE 0
#define SDB_OPTION_ALL 0xff
#define SDB_OPTION_SYNC    (1 << 0)
#define SDB_OPTION_NOSTAMP (1 << 1)
#define SDB_OPTION_FS      (1 << 2)
#define SDB_OPTION_JOURNAL (1 << 3)

#define SDB_LIST_UNSORTED 0
#define SDB_LIST_SORTED 1

// This size implies trailing zero terminator, this is 254 chars + 0
#define SDB_KSZ 0xff
#define SDB_VSZ 0xffffff

typedef struct sdb_gperf_t {
	const char *name;
	const char *(*get)(const char *k);
	unsigned int *(*hash)(const char *k);
} SdbGperf;

typedef struct sdb_t {
	char *dir; // path+name
	char *path;
	char *name;
	int fd;
	int refs; // reference counter
	int lock;
	int journal;
	struct cdb db;
	struct cdb_make m;
	HtPP *ht;
	ut32 eod;
	ut32 pos;
	SdbGperf *gp;
	int fdump;
	char *ndump;
	ut64 expire;
	ut64 last; // timestamp of last change
	int options;
	int ns_lock; // TODO: merge into options?
	SdbList *ns;
	SdbList *hooks;
	SdbKv tmpkv;
	ut32 depth;
	bool timestamped;
	SdbMini mht;
} Sdb;

typedef struct sdb_ns_t {
	char *name;
	ut32 hash;
	Sdb *sdb;
} SdbNs;

SDB_API Sdb* sdb_new0(void);
SDB_API Sdb* sdb_new(const char *path, const char *file, int lock);

SDB_API int sdb_open(Sdb *s, const char *file);
SDB_API int sdb_open_gperf(Sdb *s, SdbGperf *g);
SDB_API void sdb_close(Sdb *s);

SDB_API void sdb_config(Sdb *s, int options);
SDB_API bool sdb_free(Sdb* s);
SDB_API void sdb_file(Sdb* s, const char *dir);
SDB_API bool sdb_merge(Sdb* d, Sdb *s);
SDB_API int sdb_count(Sdb* s);
SDB_API void sdb_reset(Sdb* s);
SDB_API void sdb_setup(Sdb* s, int options);
SDB_API void sdb_drain(Sdb*, Sdb*);

// Copy everything, including namespaces, from src to dst
SDB_API void sdb_copy(Sdb *src, Sdb *dst);

SDB_API bool sdb_stats(Sdb *s, ut32 *disk, ut32 *mem);
SDB_API bool sdb_dump_hasnext (Sdb* s);

typedef bool (*SdbForeachCallback)(void *user, const char *k, const char *v);
SDB_API bool sdb_foreach(Sdb* s, SdbForeachCallback cb, void *user);
SDB_API SdbList *sdb_foreach_list(Sdb* s, bool sorted);
SDB_API SdbList *sdb_foreach_list_filter(Sdb* s, SdbForeachCallback filter, bool sorted);
SDB_API SdbList *sdb_foreach_match(Sdb* s, const char *expr, bool sorted);

SDB_API int sdb_query(Sdb* s, const char *cmd);
SDB_API int sdb_queryf(Sdb* s, const char *fmt, ...);
SDB_API int sdb_query_lines(Sdb *s, const char *cmd);
SDB_API char *sdb_querys(Sdb* s, char *buf, size_t len, const char *cmd);
SDB_API char *sdb_querysf(Sdb* s, char *buf, size_t buflen, const char *fmt, ...);
SDB_API int sdb_query_file(Sdb *s, const char* file);
SDB_API bool sdb_exists(Sdb*, const char *key);
SDB_API bool sdb_remove(Sdb*, const char *key, ut32 cas);
SDB_API int sdb_unset(Sdb*, const char *key, ut32 cas);
SDB_API int sdb_unset_like(Sdb *s, const char *k);
SDB_API char** sdb_like(Sdb *s, const char *k, const char *v, SdbForeachCallback cb);

// diffing
typedef struct sdb_diff_t {
	const SdbList *path;
	const char *k;
	const char *v; // if null, k is a namespace
	bool add;
} SdbDiff;

// Format diff in a readable form into str. str, size and return are like in snprintf.
SDB_API int sdb_diff_format(char *str, int size, const SdbDiff *diff);

typedef void (*SdbDiffCallback)(const SdbDiff *diff, void *user);

// Returns true iff the contents of a and b are equal including contained namespaces
// If cb is non-null, it will be called subsequently with differences. 
SDB_API bool sdb_diff(Sdb *a, Sdb *b, SdbDiffCallback cb, void *cb_user);

// Gets a pointer to the value associated with `key`.
SDB_API char *sdb_get(Sdb*, const char *key, ut32 *cas);

// Gets a pointer to the value associated with `key` and returns in `vlen` the
// length of the value string.
SDB_API char *sdb_get_len(Sdb*, const char *key, int *vlen, ut32 *cas);

// Gets a const pointer to the value associated with `key`
SDB_API const char *sdb_const_get(Sdb*, const char *key, ut32 *cas);

// Gets a const pointer to the value associated with `key` and returns in
// `vlen` the length of the value string.
SDB_API const char *sdb_const_get_len(Sdb* s, const char *key, int *vlen, ut32 *cas);
SDB_API int sdb_set(Sdb*, const char *key, const char *data, ut32 cas);
SDB_API int sdb_set_owned(Sdb* s, const char *key, char *val, ut32 cas);
SDB_API int sdb_concat(Sdb *s, const char *key, const char *value, ut32 cas);
SDB_API int sdb_uncat(Sdb *s, const char *key, const char *value, ut32 cas);
SDB_API int sdb_add(Sdb* s, const char *key, const char *val, ut32 cas);
SDB_API bool sdb_sync(Sdb*);
SDB_API void sdbkv_free(SdbKv *kv);

/* num.c */
SDB_API bool sdb_num_exists(Sdb*, const char *key);
SDB_API int  sdb_num_base(const char *s);
SDB_API ut64 sdb_num_get(Sdb* s, const char *key, ut32 *cas);
SDB_API int  sdb_num_set(Sdb* s, const char *key, ut64 v, ut32 cas);
SDB_API int  sdb_num_add(Sdb *s, const char *key, ut64 v, ut32 cas);
SDB_API ut64 sdb_num_inc(Sdb* s, const char *key, ut64 n, ut32 cas);
SDB_API ut64 sdb_num_dec(Sdb* s, const char *key, ut64 n, ut32 cas);
SDB_API int  sdb_num_min(Sdb* s, const char *key, ut64 v, ut32 cas);
SDB_API int  sdb_num_max(Sdb* s, const char *key, ut64 v, ut32 cas);

/* ptr */
SDB_API int sdb_ptr_set(Sdb *db, const char *key, void *p, ut32 cas);
SDB_API void* sdb_ptr_get(Sdb *db, const char *key, ut32 *cas);

/* create db */
SDB_API bool sdb_disk_create(Sdb* s);
SDB_API bool sdb_disk_insert(Sdb* s, const char *key, const char *val);
SDB_API bool sdb_disk_finish(Sdb* s);
SDB_API bool sdb_disk_unlink(Sdb* s);

/* plaintext sdb files */
SDB_API bool sdb_text_save_fd(Sdb *s, int fd, bool sort);
SDB_API bool sdb_text_save(Sdb *s, const char *file, bool sort);
SDB_API bool sdb_text_load_buf(Sdb *s, char *buf, size_t sz);
SDB_API bool sdb_text_load(Sdb *s, const char *file);
SDB_API bool sdb_text_check(Sdb *s, const char *file);

/* iterate */
SDB_API void sdb_dump_begin(Sdb* s);
SDB_API SdbKv *sdb_dump_next(Sdb* s);
SDB_API bool sdb_dump_dupnext(Sdb* s, char *key, char **value, int *_vlen);

/* journaling */
SDB_API bool sdb_journal_close(Sdb *s);
SDB_API bool sdb_journal_open(Sdb *s);
SDB_API int sdb_journal_load(Sdb *s);
SDB_API bool sdb_journal_log(Sdb *s, const char *key, const char *val);
SDB_API bool sdb_journal_clear(Sdb *s);
SDB_API bool sdb_journal_unlink(Sdb *s);

/* numeric */
SDB_API char *sdb_itoa(ut64 n, char *s, int base);
SDB_API ut64  sdb_atoi(const char *s);
SDB_API const char *sdb_itoca(ut64 n);

/* locking */
SDB_API bool sdb_lock(const char *s);
SDB_API const char *sdb_lock_file(const char *f);
SDB_API void sdb_unlock(const char *s);
SDB_API bool sdb_unlink(Sdb* s);
SDB_API int sdb_lock_wait(const char *s UNUSED);

/* expiration */
SDB_API bool sdb_expire_set(Sdb* s, const char *key, ut64 expire, ut32 cas);
SDB_API ut64 sdb_expire_get(Sdb* s, const char *key, ut32 *cas);
SDB_API ut64 sdb_now(void);
SDB_API ut64 sdb_unow(void);
SDB_API ut32 sdb_hash(const char *key);
SDB_API ut32 sdb_hash_len(const char *key, ut32 *len);
SDB_API ut8 sdb_hash_byte(const char *s);

/* json api */
// SDB_API int sdb_js0n(const unsigned char *js, RangstrType len, RangstrType *out);
SDB_API bool sdb_isjson(const char *k);
SDB_API char *sdb_json_get_str (const char *json, const char *path);
SDB_API bool sdb_json_get_bool(const char *json, const char *path);

SDB_API char *sdb_json_get(Sdb* s, const char *key, const char *p, ut32 *cas);
SDB_API bool sdb_json_set(Sdb* s, const char *k, const char *p, const char *v, ut32 cas);
SDB_API int sdb_json_num_get(Sdb* s, const char *k, const char *p, ut32 *cas);
SDB_API int sdb_json_num_set(Sdb* s, const char *k, const char *p, int v, ut32 cas);
SDB_API int sdb_json_num_dec(Sdb* s, const char *k, const char *p, int n, ut32 cas);
SDB_API int sdb_json_num_inc(Sdb* s, const char *k, const char *p, int n, ut32 cas);

SDB_API char *sdb_json_indent(const char *s, const char *tab);
SDB_API char *sdb_json_unindent(const char *s);

typedef struct {
	char *buf;
	size_t blen;
	size_t len;
} SdbJsonString;

SDB_API const char *sdb_json_format(SdbJsonString* s, const char *fmt, ...);
#define sdb_json_format_free(x) free ((x)->buf)

// namespace
SDB_API Sdb* sdb_ns(Sdb *s, const char *name, int create);
SDB_API Sdb *sdb_ns_path(Sdb *s, const char *path, int create);
SDB_API void sdb_ns_init(Sdb* s);
SDB_API void sdb_ns_free(Sdb* s);
SDB_API void sdb_ns_lock(Sdb *s, int lock, int depth);
SDB_API void sdb_ns_sync(Sdb* s);
SDB_API int sdb_ns_set(Sdb *s, const char *name, Sdb *r);
SDB_API bool sdb_ns_unset(Sdb *s, const char *name, Sdb *r);

// array
SDB_API bool sdb_array_contains(Sdb* s, const char *key, const char *val, ut32 *cas);
SDB_API bool sdb_array_contains_num(Sdb *s, const char *key, ut64 val, ut32 *cas);
SDB_API int sdb_array_indexof(Sdb *s, const char *key, const char *val, ut32 cas);
SDB_API int sdb_array_set(Sdb* s, const char *key, int idx, const char *val, ut32 cas);
SDB_API int sdb_array_set_num(Sdb* s, const char *key, int idx, ut64 val, ut32 cas);
SDB_API bool sdb_array_append(Sdb *s, const char *key, const char *val, ut32 cas);
SDB_API bool sdb_array_append_num(Sdb *s, const char *key, ut64 val, ut32 cas);
SDB_API bool sdb_array_prepend(Sdb *s, const char *key, const char *val, ut32 cas);
SDB_API bool sdb_array_prepend_num(Sdb *s, const char *key, ut64 val, ut32 cas);
SDB_API char *sdb_array_get(Sdb* s, const char *key, int idx, ut32 *cas);
SDB_API ut64 sdb_array_get_num(Sdb* s, const char *key, int idx, ut32 *cas);
SDB_API int sdb_array_get_idx(Sdb *s, const char *key, const char *val, ut32 cas); // agetv
SDB_API int sdb_array_insert(Sdb* s, const char *key, int idx, const char *val, ut32 cas);
SDB_API int sdb_array_insert_num(Sdb* s, const char *key, int idx, ut64 val, ut32 cas);
SDB_API int sdb_array_unset(Sdb* s, const char *key, int n, ut32 cas); // leaves empty bucket
SDB_API int sdb_array_delete(Sdb* s, const char *key, int n, ut32 cas);
SDB_API void sdb_array_sort(Sdb* s, const char *key, ut32 cas);
SDB_API void sdb_array_sort_num(Sdb* s, const char *key, ut32 cas);
// set

// Adds string `val` at the end of array `key`.
SDB_API int sdb_array_add(Sdb* s, const char *key, const char *val, ut32 cas);

// Adds number `val` at the end of array `key`.
SDB_API int sdb_array_add_num(Sdb* s, const char *key, ut64 val, ut32 cas);

// Adds string `val` in the sorted array `key`.
SDB_API int sdb_array_add_sorted(Sdb *s, const char *key, const char *val, ut32 cas);

// Adds number `val` in the sorted array `key`.
SDB_API int sdb_array_add_sorted_num(Sdb *s, const char *key, ut64 val, ut32 cas);

// Removes the string `val` from the array `key`.
SDB_API int sdb_array_remove(Sdb *s, const char *key, const char *val, ut32 cas);

// Removes the number `val` from the array `key`.
SDB_API int sdb_array_remove_num(Sdb* s, const char *key, ut64 val, ut32 cas);

// helpers
SDB_API char *sdb_anext(char *str, char **next);
SDB_API const char *sdb_const_anext(const char *str);
SDB_API int sdb_alen(const char *str);
SDB_API int sdb_alen_ignore_empty(const char *str);
SDB_API int sdb_array_size(Sdb* s, const char *key);
SDB_API int sdb_array_length(Sdb* s, const char *key);

int sdb_array_list(Sdb* s, const char *key);

// Adds the string `val` to the start of array `key`.
SDB_API bool sdb_array_push(Sdb *s, const char *key, const char *val, ut32 cas);

// Returns the string at the start of array `key` or
// NULL if there are no elements.
SDB_API char *sdb_array_pop(Sdb *s, const char *key, ut32 *cas);

// Adds the number `val` to the start of array `key`.
SDB_API int sdb_array_push_num(Sdb *s, const char *key, ut64 num, ut32 cas);

// Returns the number at the start of array `key`.
SDB_API ut64 sdb_array_pop_num(Sdb *s, const char *key, ut32 *cas);

SDB_API char *sdb_array_pop_head(Sdb *s, const char *key, ut32 *cas);
SDB_API char *sdb_array_pop_tail(Sdb *s, const char *key, ut32 *cas);

typedef void (*SdbHook)(Sdb *s, void *user, const char *k, const char *v);

SDB_API void sdb_global_hook(SdbHook hook, void *user);
SDB_API bool sdb_hook(Sdb* s, SdbHook cb, void* user);
SDB_API bool sdb_unhook(Sdb* s, SdbHook h);
SDB_API int sdb_hook_call(Sdb *s, const char *k, const char *v);
SDB_API void sdb_hook_free(Sdb *s);
/* Util.c */
SDB_API int sdb_isnum(const char *s);
SDB_API bool sdb_isempty(Sdb *s);

SDB_API const char *sdb_type(const char *k);
SDB_API bool sdb_match(const char *str, const char *glob);
SDB_API int sdb_bool_set(Sdb *db, const char *str, bool v, ut32 cas);
SDB_API bool sdb_bool_get(Sdb *db, const char *str, ut32 *cas);

// base64
SDB_API ut8 *sdb_decode(const char *in, int *len);
SDB_API char *sdb_encode(const ut8 *bin, int len);
SDB_API void sdb_encode_raw(char *bout, const ut8 *bin, int len);
SDB_API int sdb_decode_raw(ut8 *bout, const char *bin, int len);

// binfmt
SDB_API char *sdb_fmt(const char *fmt, ...) SDB_PRINTF_CHECK(1, 2);
SDB_API int sdb_fmt_init(void *p, const char *fmt);
SDB_API void sdb_fmt_free(void *p, const char *fmt);
SDB_API int sdb_fmt_tobin(const char *_str, const char *fmt, void *stru);
SDB_API char *sdb_fmt_tostr(void *stru, const char *fmt);
SDB_API char** sdb_fmt_array(const char *list);
SDB_API ut64* sdb_fmt_array_num(const char *list);

// raw array helpers
SDB_API char *sdb_array_compact(char *p);
SDB_API char *sdb_aslice(char *out, int from, int to);
#define sdb_aforeach(x,y) \
	{ char *next; \
	if (y) for (x=y;;) { \
		x = sdb_anext (x, &next);
#define sdb_aforeach_next(x) \
	if (!next) break; \
	*(next-1) = ','; \
	x = next; } }

#ifdef __cplusplus
}
#endif

#endif
