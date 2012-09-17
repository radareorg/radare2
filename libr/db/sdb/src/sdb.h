#ifndef _INCLUDE_SDB_H_
#define _INCLUDE_SDB_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "ht.h"
#include "ls.h"
#include "cdb.h"
#include "cdb_make.h"

#include "sdb-version.h"

typedef struct sdb_ns_t {
// todo. store last used
// todo. sync?
// todo. 
	ut32 hash;
	struct sdb_t *sdb;
} SdbNs;

typedef struct sdb_t {
	char *dir;
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
} Sdb;


// XXX: use buckets here, drop these limits
#define SDB_BLOCK 4096
#define SDB_KSZ 64
#define SDB_VSZ (SDB_BLOCK-sizeof(ut64)-SDB_KEYSIZE)

typedef struct sdb_kv {
	char key[SDB_KSZ]; // key = 64
	char value[SDB_VSZ]; // value = 4032
	ut64 expire;
	ut32 cas;
} SdbKv;

Sdb* sdb_new (const char *dir, int lock);
void sdb_free (Sdb* s);
void sdb_file (Sdb* s, const char *dir);
void sdb_reset (Sdb *s);

int sdb_query (Sdb *s, const char *cmd);
int sdb_exists (Sdb*, const char *key);
int sdb_nexists (Sdb*, const char *key);
int sdb_remove (Sdb*, const char *key, ut32 cas);
char *sdb_get (Sdb*, const char *key, ut32 *cas);
const char *sdb_getc (Sdb*, const char *key, ut32 *cas);
int sdb_set (Sdb*, const char *key, const char *data, ut32 cas);
int sdb_add (Sdb *s, const char *key, const char *val, ut32 cas);
void sdb_list(Sdb*);
int sdb_sync (Sdb*);
void sdb_kv_free (struct sdb_kv *kv);
void sdb_flush (Sdb* s);

/* create db */
int sdb_create (Sdb *s);
int sdb_append (Sdb *s, const char *key, const char *val);
int sdb_finish (Sdb *s);

/* iterate */
void sdb_dump_begin (Sdb* s);
int sdb_dump_next (Sdb* s, char *key, char *value); // XXX: needs refactor?

/* numeric */
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
ut64 sdb_now ();
ut64 sdb_unow ();
ut32 sdb_hash (const char *key, int klen);
#define sdb_hashstr(x) sdb_hash(x,strlen(x))

/* json api */
char *sdb_json_get (Sdb *s, const char *key, const char *p, ut32 *cas);
int sdb_json_geti (Sdb *s, const char *k, const char *p);
int sdb_json_seti (Sdb *s, const char *k, const char *p, int v, ut32 cas);
int sdb_json_set (Sdb *s, const char *k, const char *p, const char *v, ut32 cas);

int sdb_json_dec(Sdb *s, const char *k, const char *p, int n, ut32 cas);
int sdb_json_inc(Sdb *s, const char *k, const char *p, int n, ut32 cas);

char *sdb_json_indent(const char *s);
char *sdb_json_unindent(const char *s);

typedef struct {
	char *buf;
	int blen;
	int len;
} SdbJsonString;

const char *sdb_json_format(SdbJsonString* s, const char *fmt, ...);
#define sdb_json_format_free(x) free ((x)->buf)

// namespace
Sdb *sdb_ns(Sdb *s, const char *name);
void sdb_ns_init(Sdb *s);
void sdb_ns_free(Sdb *s);
void sdb_ns_sync (Sdb *s);

#ifdef __cplusplus
}
#endif

#endif
