#ifndef _INCLUDE_SDB_H_
#define _INCLUDE_SDB_H_

#include "ht.h"
#include "ls.h"
#include "cdb.h"
#include "cdb_make.h"

typedef struct sdb_t {
	char *dir;
	int fd;
	int lock;
	struct cdb db;
	struct cdb_make m;
	SdbHash *ht;
	ut32 eod;
} Sdb;

#define SDB_BLOCK 4096
#define SDB_KEYSIZE 32
#define SDB_VALUESIZE (SDB_BLOCK-sizeof(ut64)-SDB_KEYSIZE)

typedef struct sdb_kv {
	char key[SDB_KEYSIZE];
	char value[SDB_VALUESIZE];
	ut64 expire;
} SdbKv;

Sdb* sdb_new (const char *dir, int lock);
void sdb_free (Sdb* s);
void sdb_file (Sdb* s, const char *dir);
void sdb_reset (Sdb *s);

int sdb_exists (Sdb*, const char *key);
int sdb_nexists (Sdb*, const char *key);
int sdb_delete (Sdb*, const char *key);
char *sdb_get (Sdb*, const char *key);
int sdb_set (Sdb*, const char *key, const char *data);
void sdb_list(Sdb*);
int sdb_sync (Sdb*);
void sdb_kv_free (struct sdb_kv *kv);
void sdb_dump_begin (Sdb* s);
int sdb_add (struct cdb_make *c, const char *key, const char *data);
int sdb_dump_next (Sdb* s, char *key, char *value);
void sdb_flush (Sdb* s);

ut64 sdb_getn (Sdb* s, const char *key);
void sdb_setn (Sdb* s, const char *key, ut64 v);
ut64 sdb_inc (Sdb* s, const char *key, ut64 n);
ut64 sdb_dec (Sdb* s, const char *key, ut64 n);

int sdb_lock(const char *s);
const char *sdb_lockfile(const char *f);
void sdb_unlock(const char *s);
int sdb_expire(Sdb* s, const char *key, ut64 expire);
ut64 sdb_get_expire(Sdb* s, const char *key);
ut64 sdb_now ();
ut32 sdb_hash ();

#endif
