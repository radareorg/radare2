#ifndef _INCLUDE_SDB_H_
#define _INCLUDE_SDB_H_

#ifndef O_BINARY
#define O_BINARY 0
#endif

#if defined(__GNUC__)
#define SDB_VISIBLE __attribute__((visibility("default")))
#else
#define SDB_VISIBLE
#endif

#if __WIN32__ || __CYGWIN__ || MINGW32
#undef __WINDOWS__
#define __WINDOWS__ 1
#include <windows.h>
#define DIRSEP '\\'
#else
#define DIRSEP '/'
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "ht.h"
#include "ls.h"
#include "cdb.h"
#include "cdb_make.h"

#include "sdb-version.h"

#define SDB_RS '\x1e'
#define SDB_SS "\x1e"
#define SDB_MAX_PATH 256

// todo. store last used
// todo. sync?
// todo. 

#define SDB_KSZ 0xff

typedef struct sdb_kv {
	char key[SDB_KSZ];
	char *value;
	ut64 expire;
	ut32 cas;
} SdbKv;

typedef struct sdb_t {
	char *dir; // path+name
	char *path;
	char *name;
	int fd;
	int lock;
	struct cdb db;
	struct cdb_make m;
	SdbHash *ht;
	ut32 eod;
	int fdump;
	char *ndump;
	ut64 expire;
	SdbList *ns;
	SdbList *hooks;
	SdbKv tmpkv;
} Sdb;

typedef struct sdb_ns_t {
	ut32 hash;
	Sdb *sdb;
} SdbNs;

Sdb* sdb_new (const char *path, const char *file, int lock);
void sdb_free (Sdb* s);
void sdb_drop (Sdb* s);
void sdb_file (Sdb* s, const char *dir);
void sdb_reset (Sdb* s);

int sdb_query (Sdb* s, const char *cmd);
int sdb_queryf (Sdb* s, const char *fmt, ...);
int sdb_query_lines (Sdb *s, const char *cmd);
char *sdb_querys (Sdb* s, char *buf, size_t len, const char *cmd);
char *sdb_querysf (Sdb* s, char *buf, size_t buflen, const char *fmt, ...);
SDB_VISIBLE int sdb_query_file(Sdb *s, const char* file);
int sdb_exists (Sdb*, const char *key);
int sdb_nexists (Sdb*, const char *key);
int sdb_remove (Sdb*, const char *key, ut32 cas);
char *sdb_get (Sdb*, const char *key, ut32 *cas);
const char *sdb_getc (Sdb*, const char *key, ut32 *cas);
int sdb_set (Sdb*, const char *key, const char *data, ut32 cas);
int sdb_concat(Sdb *s, const char *key, const char *value, ut32 cas);
int sdb_add (Sdb* s, const char *key, const char *val, ut32 cas);
void sdb_list(Sdb*);
int sdb_sync (Sdb*);
void sdb_kv_free (struct sdb_kv *kv);
void sdb_flush (Sdb* s);

typedef int (*SdbForeachCallback)(void *user, const char *k, const char *v);
void sdb_foreach (Sdb* s, SdbForeachCallback cb, void *user);

/* create db */
int sdb_create (Sdb* s);
int sdb_append (Sdb* s, const char *key, const char *val);
int sdb_finish (Sdb* s);

/* iterate */
void sdb_dump_begin (Sdb* s);
SDB_VISIBLE SdbKv *sdb_dump_next (Sdb* s);
int sdb_dump_dupnext (Sdb* s, char **key, char **value);

/* numeric */
R_API char *sdb_itoa(ut64 n, char *s);
R_API ut64 sdb_atoi(const char *s);
ut64 sdb_getn (Sdb* s, const char *key, ut32 *cas);
int sdb_setn (Sdb* s, const char *key, ut64 v, ut32 cas);
ut64 sdb_inc (Sdb* s, const char *key, ut64 n, ut32 cas);
ut64 sdb_dec (Sdb* s, const char *key, ut64 n, ut32 cas);

/* locking */
int sdb_lock(const char *s);
const char *sdb_lockfile(const char *f);
void sdb_unlock(const char *s);

/* expiration */
int sdb_expire(Sdb* s, const char *key, ut64 expire);
ut64 sdb_get_expire(Sdb* s, const char *key);
// int sdb_get_cas(Sdb* s, const char *key) -> takes no sense at all..
ut64 sdb_now (void);
ut64 sdb_unow (void);
ut32 sdb_hash (const char *key, int klen);
#define sdb_hashstr(x) sdb_hash(x,strlen(x))

/* json api */
char *sdb_json_get (Sdb* s, const char *key, const char *p, ut32 *cas);
int sdb_json_geti (Sdb* s, const char *k, const char *p);
int sdb_json_seti (Sdb* s, const char *k, const char *p, int v, ut32 cas);
int sdb_json_set (Sdb* s, const char *k, const char *p, const char *v, ut32 cas);

int sdb_json_dec(Sdb* s, const char *k, const char *p, int n, ut32 cas);
int sdb_json_inc(Sdb* s, const char *k, const char *p, int n, ut32 cas);

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
Sdb* sdb_ns(Sdb *s, const char *name);
void sdb_ns_init(Sdb* s);
void sdb_ns_free(Sdb* s);
void sdb_ns_sync (Sdb* s);

// array
int sdb_aexists(Sdb* s, const char *key, const char *val);
int sdb_aadd(Sdb* s, const char *key, int idx, const char *val, ut32 cas);
int sdb_aaddn(Sdb* s, const char *key, int idx, ut64 val, ut32 cas);
int sdb_aset(Sdb* s, const char *key, int idx, const char *val, ut32 cas);
int sdb_asetn(Sdb* s, const char *key, int idx, ut64 val, ut32 cas);
char *sdb_aget(Sdb* s, const char *key, int idx, ut32 *cas);
ut64 sdb_agetn(Sdb* s, const char *key, int idx, ut32 *cas);
SDB_VISIBLE int sdb_agetv(Sdb *s, const char *key, const char *val, ut32 cas);
int sdb_ains(Sdb* s, const char *key, int idx, const char *val, ut32 cas);
int sdb_ainsn(Sdb* s, const char *key, int idx, ut64 val, ut32 cas);
int sdb_adel(Sdb* s, const char *key, int n, ut32 cas);
int sdb_adeln(Sdb* s, const char *key, ut64 val, ut32 cas);
int sdb_adels(Sdb *s, const char *key, const char *val, ut32 cas);
// helpers
char *sdb_astring(char *str, int *hasnext);
int sdb_alen(const char *str);
int sdb_alength(Sdb* s, const char *key);
int sdb_alist(Sdb* s, const char *key);
const char *sdb_anext(const char *str);
const char *sdb_aindex(const char *str, int idx);

typedef void (*SdbHook)(Sdb *s, void *user, const char *k, const char *v);

void sdb_global_hook(SdbHook hook, void *user);
int sdb_hook(Sdb* s, SdbHook cb, void* user);
int sdb_unhook(Sdb* s, SdbHook h);
int sdb_hook_call(Sdb *s, const char *k, const char *v);
void sdb_hook_free(Sdb *s);
int sdb_apush(Sdb *s, const char *key, const char *val, ut32 cas);
char *sdb_apop(Sdb *s, const char *key, ut32 *cas);

#ifdef __cplusplus
}
#endif

#endif
