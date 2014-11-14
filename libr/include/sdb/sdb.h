#ifndef SDB_H
#define SDB_H

#ifndef O_BINARY
#define O_BINARY 0
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"
#include "ht.h"
#include "ls.h"
#include "cdb.h"
#include "cdb_make.h"
#include "sdb-version.h"

#undef R_MAX
#define R_MAX(x,y) (((x)>(y))?(x):(y))
#undef r_offsetof
#define r_offsetof(type, member) ((unsigned long) &((type*)0)->member)

#define SDB_MODE 0644
//#define SDB_MODE 0600

//#define SDB_RS '\x1e'
#define SDB_RS ','
#define SDB_SS ","
#define SDB_MAX_PATH 256
#define SDB_NUM_BASE 16

#define SDB_OPTION_NONE 0
#define SDB_OPTION_ALL 0xff
#define SDB_OPTION_SYNC 1
#define SDB_OPTION_NOSTAMP 2
#define SDB_OPTION_FS 4

// This size implies trailing zero terminator, this is 254 chars + 0
#define SDB_KSZ 0xff

typedef struct sdb_kv {
	char key[SDB_KSZ];
	char *value;
	int value_len;
	ut64 expire;
	ut32 cas;
} SdbKv;

typedef struct sdb_t {
	char *dir; // path+name
	char *path;
	char *name;
	int fd;
	int refs; // reference counter
	int lock;
	struct cdb db;
	struct cdb_make m;
	SdbHash *ht;
	ut32 eod;
	ut32 pos;
	int fdump;
	char *ndump;
	ut64 expire;
	ut64 last; // timestamp of last change
	int options;
	int ns_lock; // TODO: merge into options?
	SdbList *ns;
	SdbList *hooks;
	SdbKv tmpkv;
} Sdb;

typedef struct sdb_ns_t {
	char *name;
	ut32 hash;
	Sdb *sdb;
} SdbNs;

SDB_API Sdb* sdb_new0 ();
Sdb* sdb_new (const char *path, const char *file, int lock);

int sdb_open (Sdb *s, const char *file);
void sdb_close (Sdb *s);

void sdb_config (Sdb *s, int options);
int  sdb_free (Sdb* s);
void sdb_file (Sdb* s, const char *dir);
void sdb_reset (Sdb* s);
void sdb_setup (Sdb* s, int options);
void sdb_drain (Sdb*, Sdb*);

int  sdb_query (Sdb* s, const char *cmd);
int  sdb_queryf (Sdb* s, const char *fmt, ...);
int  sdb_query_lines (Sdb *s, const char *cmd);
char *sdb_querys (Sdb* s, char *buf, size_t len, const char *cmd);
char *sdb_querysf (Sdb* s, char *buf, size_t buflen, const char *fmt, ...);
int  sdb_query_file(Sdb *s, const char* file);
int  sdb_exists (Sdb*, const char *key);
int  sdb_unset (Sdb*, const char *key, ut32 cas);
int  sdb_unset_matching(Sdb *s, const char *k);
char *sdb_get (Sdb*, const char *key, ut32 *cas);
const char *sdb_const_get (Sdb*, const char *key, ut32 *cas);
const char *sdb_const_get_len (Sdb* s, const char *key, int *vlen, ut32 *cas);
int  sdb_set (Sdb*, const char *key, const char *data, ut32 cas);
int  sdb_set_owned (Sdb* s, const char *key, char *val, ut32 cas);
int  sdb_concat(Sdb *s, const char *key, const char *value, ut32 cas);
int  sdb_uncat(Sdb *s, const char *key, const char *value, ut32 cas);
int  sdb_add (Sdb* s, const char *key, const char *val, ut32 cas);
void sdb_list(Sdb*);
int  sdb_sync (Sdb*);
void sdb_kv_free (SdbKv *kv);

/* num.c */
int  sdb_num_exists (Sdb*, const char *key);
int  sdb_num_base (const char *s);
ut64 sdb_num_get  (Sdb* s, const char *key, ut32 *cas);
int  sdb_num_set  (Sdb* s, const char *key, ut64 v, ut32 cas);
int  sdb_num_add  (Sdb *s, const char *key, ut64 v, ut32 cas);
ut64 sdb_num_inc  (Sdb* s, const char *key, ut64 n, ut32 cas);
ut64 sdb_num_dec  (Sdb* s, const char *key, ut64 n, ut32 cas);
int  sdb_num_min  (Sdb* s, const char *key, ut64 v, ut32 cas);
int  sdb_num_max  (Sdb* s, const char *key, ut64 v, ut32 cas);

typedef int (*SdbForeachCallback)(void *user, const char *k, const char *v);
int sdb_foreach (Sdb* s, SdbForeachCallback cb, void *user);

/* create db */
int sdb_disk_create (Sdb* s);
int sdb_disk_insert (Sdb* s, const char *key, const char *val);
int sdb_disk_finish (Sdb* s);
int sdb_disk_unlink (Sdb* s);

/* iterate */
void sdb_dump_begin (Sdb* s);
SdbKv *sdb_dump_next (Sdb* s);
int sdb_dump_dupnext (Sdb* s, char **key, char **value, int *_vlen);

/* numeric */
char *sdb_itoa (ut64 n, char *s, int base);
ut64  sdb_atoi (const char *s);

/* locking */
int sdb_lock(const char *s);
const char *sdb_lock_file(const char *f);
void sdb_unlock(const char *s);
SDB_API int sdb_unlink (Sdb* s);
SDB_API int sdb_lock_wait(const char *s UNUSED);

/* expiration */
int sdb_expire_set(Sdb* s, const char *key, ut64 expire, ut32 cas);
ut64 sdb_expire_get(Sdb* s, const char *key, ut32 *cas);
ut64 sdb_now (void);
ut64 sdb_unow (void);
ut32 sdb_hash (const char *key);

/* json api */
int sdb_isjson (const char *k);
char *sdb_json_get (Sdb* s, const char *key, const char *p, ut32 *cas);
int sdb_json_set (Sdb* s, const char *k, const char *p, const char *v, ut32 cas);
int sdb_json_num_get (Sdb* s, const char *k, const char *p, ut32 *cas);
int sdb_json_num_set (Sdb* s, const char *k, const char *p, int v, ut32 cas);
int sdb_json_num_dec(Sdb* s, const char *k, const char *p, int n, ut32 cas);
int sdb_json_num_inc(Sdb* s, const char *k, const char *p, int n, ut32 cas);

char *sdb_json_indent(const char *s);
char *sdb_json_unindent(const char *s);

typedef struct {
	char *buf;
	size_t blen;
	size_t len;
} SdbJsonString;

const char *sdb_json_format(SdbJsonString* s, const char *fmt, ...);
#define sdb_json_format_free(x) free ((x)->buf)

// namespace
Sdb* sdb_ns (Sdb *s, const char *name, int create);
Sdb *sdb_ns_path(Sdb *s, const char *path, int create);
void sdb_ns_init (Sdb* s);
void sdb_ns_free (Sdb* s);
void sdb_ns_lock(Sdb *s, int lock, int depth);
void sdb_ns_sync (Sdb* s);
int sdb_ns_set (Sdb *s, const char *name, Sdb *r);
int sdb_ns_unset (Sdb *s, const char *name);

// array
int sdb_array_contains (Sdb* s, const char *key, const char *val, ut32 *cas);
SDB_API int sdb_array_contains_num(Sdb *s, const char *key, ut64 val, ut32 *cas);
SDB_API int sdb_array_indexof(Sdb *s, const char *key, const char *val, ut32 cas);
int sdb_array_set (Sdb* s, const char *key, int idx, const char *val, ut32 cas);
int sdb_array_set_num (Sdb* s, const char *key, int idx, ut64 val, ut32 cas);
char *sdb_array_get (Sdb* s, const char *key, int idx, ut32 *cas);
ut64 sdb_array_get_num (Sdb* s, const char *key, int idx, ut32 *cas);
int sdb_array_get_idx (Sdb *s, const char *key, const char *val, ut32 cas); // agetv
int sdb_array_insert (Sdb* s, const char *key, int idx, const char *val, ut32 cas);
int sdb_array_insert_num (Sdb* s, const char *key, int idx, ut64 val, ut32 cas);
int sdb_array_unset (Sdb* s, const char *key, int n, ut32 cas); // leaves empty bucket
int sdb_array_delete (Sdb* s, const char *key, int n, ut32 cas);
// set
int sdb_array_add (Sdb* s, const char *key, const char *val, ut32 cas);
int sdb_array_add_num (Sdb* s, const char *key, ut64 val, ut32 cas);
int sdb_array_remove (Sdb *s, const char *key, const char *val, ut32 cas);
int sdb_array_remove_num (Sdb* s, const char *key, ut64 val, ut32 cas);
// helpers
char *sdb_anext(char *str, char **next);
const char *sdb_const_anext(const char *str, const char **next);
int sdb_alen(const char *str);
int sdb_array_size(Sdb* s, const char *key);
int sdb_array_length(Sdb* s, const char *key);

int sdb_array_list(Sdb* s, const char *key);
int sdb_array_push(Sdb *s, const char *key, const char *val, ut32 cas);
char *sdb_array_pop(Sdb *s, const char *key, ut32 *cas);
int sdb_array_push_num(Sdb *s, const char *key, ut64 num, ut32 cas);
ut64 sdb_array_pop_num(Sdb *s, const char *key, ut32 *cas);

typedef void (*SdbHook)(Sdb *s, void *user, const char *k, const char *v);

void sdb_global_hook(SdbHook hook, void *user);
int sdb_hook(Sdb* s, SdbHook cb, void* user);
int sdb_unhook(Sdb* s, SdbHook h);
int sdb_hook_call(Sdb *s, const char *k, const char *v);
void sdb_hook_free(Sdb *s);
/* Util.c */
int sdb_check_value (const char *s);
int sdb_check_key (const char *s);
int sdb_isnum (const char *s);

const char *sdb_type(const char *k);
int sdb_match (const char *str, const char *glob);
int sdb_bool_set(Sdb *db, const char *str, int v, ut32 cas);
int sdb_bool_get(Sdb *db, const char *str, ut32 *cas);

// base64
ut8 *sdb_decode (const char *in, int *len);
char *sdb_encode(const ut8 *bin, int len);
void sdb_encode_raw(char *bout, const ut8 *bin, int len);
int sdb_decode_raw(ut8 *bout, const char *bin, int len);

// binfmt
char *sdb_fmt(int n, const char *fmt, ...);
int sdb_fmt_init (void *p, const char *fmt);
void sdb_fmt_free (void *p, const char *fmt);
int sdb_fmt_tobin(const char *_str, const char *fmt, void *stru);
char *sdb_fmt_tostr(void *stru, const char *fmt);
SDB_API char** sdb_fmt_array(const char *list);
SDB_API ut64* sdb_fmt_array_num(const char *list);

// raw array helpers
char *sdb_array_compact(char *p);
char *sdb_aslice(char *out, int from, int to);
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
