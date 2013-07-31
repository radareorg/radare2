/* sdb - LGPLv3 - Copyright 2011-2013 - pancake */

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include "sdb.h"

// XXX: deprecate, or use the one inside Sdb*
static ut32 pos = 0L;

static inline int nextcas() {
	static ut32 cas = 1;
	if (!cas) cas++;
	return cas++;
}

// TODO: use mmap instead of read.. much faster!
SDB_VISIBLE Sdb* sdb_new (const char *dir, int lock) {
	Sdb* s;
	if (lock && !sdb_lock (sdb_lockfile (dir)))
		return NULL;
	s = malloc (sizeof (Sdb));
	if (dir && *dir) {
		s->dir = strdup (dir);
		s->fd = open (dir, O_RDONLY|O_BINARY);
		// if (s->fd == -1) // must fail if we cant open for write in sync
	} else {
		s->dir = NULL;
		s->fd = -1;
	}
	s->fdump = -1;
	s->ndump = NULL;
	s->ns = ls_new ();
	s->ht = ht_new ();
	s->lock = lock;
	s->expire = 0LL;
	s->tmpkv.value = NULL;
	//s->ht->list->free = (SdbListFree)sdb_kv_free;
	// if open fails ignore
	cdb_init (&s->db, s->fd);
	cdb_findstart (&s->db);
	return s;
}

SDB_VISIBLE void sdb_file (Sdb* s, const char *dir) {
	if (s->lock)
		sdb_unlock (sdb_lockfile (s->dir));
	free (s->dir);
	s->dir = (dir && *dir)? strdup (dir): NULL;
	if (s->lock)
		sdb_lock (sdb_lockfile (s->dir));
}

static void sdb_fini(Sdb* s, int donull) {
	if (!s) return;
	cdb_free (&s->db);
	if (s->lock)
		sdb_unlock (sdb_lockfile (s->dir));
	ls_free (s->ns);
	ht_free (s->ht);
	if (s->fd != -1)
		close (s->fd);
	s->fd = -1;
	free (s->ndump);
	free (s->dir);
	free (s->tmpkv.value);

	if (donull) {
		s->ns = NULL;
		s->ht = NULL;
		s->dir = NULL;
		s->ndump = NULL;
		s->tmpkv.value = NULL;
	}
}

SDB_VISIBLE void sdb_free (Sdb* s) {
	sdb_fini (s, 0);
	free (s);
}

SDB_VISIBLE const char *sdb_getc (Sdb* s, const char *key, ut32 *cas) {
	ut32 hash, pos, len, keylen;
	SdbKv *kv;
	ut64 now = 0LL;

	if (cas) *cas = 0;
	if (!s||!key) return NULL;
	keylen = strlen (key)+1;
	hash = sdb_hash (key, keylen);

	/* search in memory */
	kv = (SdbKv*)ht_lookup (s->ht, hash);
	if (kv) {
		if (*kv->value) {
			if (kv->expire) {
				if (!now) now = sdb_now ();
				if (now > kv->expire) {
					sdb_remove (s, key, 0);
					return NULL;
				}
			}
			if (cas) *cas = kv->cas;
			return kv->value;
		}
		return NULL;
	}

	/* search in disk */
	if (s->fd == -1)
		return NULL;
	cdb_findstart (&s->db);
	if (!cdb_findnext (&s->db, hash, key, keylen))
		return NULL;
	len = cdb_datalen (&s->db);
	if (len == 0)
		return NULL;
	pos = cdb_datapos (&s->db);
	return s->db.map+pos;
}

SDB_VISIBLE char *sdb_get (Sdb* s, const char *key, ut32 *cas) {
	char *buf;
	ut32 hash, pos, len, keylen;
	SdbKv *kv;
	ut64 now = 0LL;

	if (cas) *cas = 0;
	if (!s || !key) return NULL;
	keylen = strlen (key)+1;
	hash = sdb_hash (key, keylen);

	/* search in memory */
	kv = (SdbKv*)ht_lookup (s->ht, hash);
	if (kv) {
		if (*kv->value) {
			if (kv->expire) {
				if (!now) now = sdb_now ();
				if (now > kv->expire) {
					sdb_remove (s, key, 0);
					return NULL;
				}
			}
			if (cas) *cas = kv->cas;
			return strdup (kv->value); // XXX too many mallocs
		}
		return NULL;
	}

	/* search in disk */
	if (s->fd == -1)
		return NULL;
	cdb_findstart (&s->db);

	if (!cdb_findnext (&s->db, hash, key, keylen))
		return NULL;
	len = cdb_datalen (&s->db);
	if (len == 0)
		return NULL;
	if (!(buf = malloc (len+1))) // XXX too many mallocs
		return NULL;
	pos = cdb_datapos (&s->db);
	cdb_read (&s->db, buf, len, pos);
	buf[len] = 0;
	return buf;
}

SDB_VISIBLE int sdb_remove (Sdb* s, const char *key, ut32 cas) {
	return key? sdb_set (s, key, "", cas): 0;
}

// set if not defined
SDB_VISIBLE int sdb_add (Sdb* s, const char *key, const char *val, ut32 cas) {
	if (sdb_exists (s, key))
		return 0;
	return sdb_set (s, key, val, cas);
}

SDB_VISIBLE int sdb_exists (Sdb* s, const char *key) {
	char ch;
	SdbKv *kv;
	int klen = strlen (key);
	ut32 pos, hash = sdb_hash (key, klen);
	kv = (SdbKv*)ht_lookup (s->ht, hash);
	if (kv) return (*kv->value)? 1: 0;
	if (s->fd == -1)
		return 0;
	cdb_findstart (&s->db);
	if (cdb_findnext (&s->db, hash, key, klen)) {
		pos = cdb_datapos (&s->db);
		cdb_read (&s->db, &ch, 1, pos);
		return ch != 0;
	}
	return 0;
}

SDB_VISIBLE void sdb_reset (Sdb* s) {
	ht_free (s->ht);
	s->ht = ht_new ();
}

// TODO: too many allocs here. use slices
SdbKv* sdb_kv_new (const char *k, const char *v) {
	int vl = strlen (v)+1;
	SdbKv *kv = R_NEW (SdbKv);
	strncpy (kv->key, k, sizeof (kv->key)-1);
	kv->value = malloc (vl);
	memcpy (kv->value, v, vl);
	kv->cas = nextcas ();
	kv->expire = 0LL;
	return kv;
}

SDB_VISIBLE void sdb_kv_free (SdbKv *kv) {
	free (kv->value);
	free (kv);
}

SDB_VISIBLE int sdb_set (Sdb* s, const char *key, const char *val, ut32 cas) {
	SdbHashEntry *e;
	SdbKv *kv;
	ut32 hash, klen;
	if (!s || !key || !val)
		return 0;
	klen = strlen (key)+1;
	hash = sdb_hash (key, klen);
	cdb_findstart (&s->db);
	e = ht_search (s->ht, hash);
	if (e) {
		if (cdb_findnext (&s->db, hash, key, klen)) {
			int vl = strlen (val)+1;
			kv = e->data;
			if (cas && kv->cas != cas)
				return 0;
			kv->cas = cas = nextcas ();
			free (kv->value);
			kv->value = malloc (vl);
			memcpy (kv->value, val, vl);
		} else ht_remove_entry (s->ht, e);
		return cas;
	}
	kv = sdb_kv_new (key, val);
	kv->cas = nextcas ();
	ht_insert (s->ht, hash, kv, NULL);
	return kv->cas;
}

SDB_VISIBLE void sdb_list (Sdb* s) {
	SdbKv *kv;
	SdbListIter *iter;
	ls_foreach (s->ht->list, iter, kv) {
		printf ("%s=%s\n", kv->key, kv->value);
	}
}

SDB_VISIBLE int sdb_sync (Sdb* s) {
	SdbListIter it, *iter;
	char *k, *v;
	SdbKv *kv;

	if (!sdb_create (s))
		return 0;
	sdb_dump_begin (s);
	while (sdb_dump_dupnext (s, &k, &v)) {
		ut32 hash = sdb_hash (k, 0);
		SdbHashEntry *hte = ht_search (s->ht, hash);
		if (hte) {
			kv = (SdbKv*)hte->data;
			if (*kv->value) 
				sdb_append (s, kv->key, kv->value);
			// XXX: This fails if key is dupped
			//else printf ("remove (%s)\n", kv->key);
			ls_delete (s->ht->list, hte->iter);
			hte->iter = NULL;
			ht_remove_entry (s->ht, hte);
		} else if (*v)
			sdb_append (s, k, v);
		free (k);
		free (v);
	}
	/* append new keyvalues */
	ls_foreach (s->ht->list, iter, kv) {
		if (*kv->value && kv->expire == 0LL)
			sdb_append (s, kv->key, kv->value);
		if (kv->expire == 0LL) {
			it.n = iter->n;
			sdb_remove (s, kv->key, 0);
			iter = &it;
		}
	}
	sdb_finish (s);
	return 0;
}

static int getbytes(int fd, char *b, int len) {
	if (read (fd, b, len) != len)
		return -1;
	pos += len;
	return len;
}

SDB_VISIBLE void sdb_dump_begin (Sdb* s) {
	if (s->fd != -1) {
		seek_set (s->fd, 0);
		pos = 2048;
		seek_set (s->fd, 2048);
	} else pos = 0;
}

SDB_VISIBLE SdbKv *sdb_dump_next (Sdb* s) {
	char *k = NULL, *v = NULL;
	if (!sdb_dump_dupnext (s, &k, &v))
		return NULL;
	strcpy (s->tmpkv.key, k); // no overflow here?
	free (k);
	free (s->tmpkv.value);
	s->tmpkv.value = v;
	return &s->tmpkv;
}

SDB_VISIBLE int sdb_dump_dupnext (Sdb* s, char **key, char **value) {
	ut32 vlen, klen;
	if (s->fd==-1 || !getkvlen (s->fd, &klen, &vlen))
		return 0;
	if (klen<1 || vlen<1)
		return 0;
	if (key) {
		*key = 0;
		if (klen>0) {
			*key = malloc (klen+1);
			if (getbytes (s->fd, *key, klen) == -1) {
				free (*key);
				*key = NULL;
				return 0;
			}
			(*key)[klen] = 0;
		}
	}
	if (value) {
		*value = 0;
		if (vlen>0) {
			*value = malloc (vlen+10);
			if (getbytes (s->fd, *value, vlen)==-1) {
				if (key) {
					free (*key);
					*key = NULL;
				}
				free (*value);
				*value = NULL;
				return 0;
			}
			(*value)[vlen] = 0;
		}
	}
	pos += 4; // XXX no
	return 1;
}

SDB_VISIBLE ut64 sdb_now () {
        struct timeval now;
        gettimeofday (&now, NULL);
	return now.tv_sec;
}

SDB_VISIBLE ut64 sdb_unow () {
	ut64 x;
        struct timeval now;
        gettimeofday (&now, NULL);
	x = now.tv_sec;
	x <<= 32;
	x += now.tv_usec;
        return x;
}

static ut64 parse_expire (ut64 e) {
	const ut64 month = 30 * 24 * 60 * 60;
	if (e>0 && e<month) e += sdb_now ();
	return e;
}

SDB_VISIBLE int sdb_expire(Sdb* s, const char *key, ut64 expire) {
	char *buf;
	ut32 hash, pos, len;
	SdbKv *kv;
	if (key == NULL) {
		s->expire = parse_expire (expire);
		return 1;
	}
	hash = sdb_hash (key, 0);
	kv = (SdbKv*)ht_lookup (s->ht, hash);
	if (kv) {
		if (*kv->value) {
			kv->expire = parse_expire (expire);
			return 1;
		}
		return 0;
	}
	if (s->fd == -1)
		return 0;
	cdb_findstart (&s->db);
	if (!cdb_findnext (&s->db, hash, key, strlen (key)))
		return 0;
	pos = cdb_datapos (&s->db);
	len = cdb_datalen (&s->db);
	if (!(buf = malloc (len+1)))
		return 0;
	cdb_read (&s->db, buf, len, pos);
	buf[len] = 0;
	sdb_set (s, key, buf, 0); // TODO use cas here?
	free (buf);
	return sdb_expire (s, key, expire); // recursive
}

SDB_VISIBLE ut64 sdb_get_expire(Sdb* s, const char *key) {
	SdbKv *kv;
	ut32 hash = sdb_hash (key, 0);
	kv = (SdbKv*)ht_lookup (s->ht, hash);
	if (kv && *kv->value)
		return kv->expire;
	return 0LL;
}

SDB_VISIBLE void sdb_flush(Sdb* s) {
	ht_free (s->ht);
	s->ht = ht_new ();
	close (s->fd);
	s->fd = -1;
}

#if __WINDOWS__
#define r_sys_mkdir(x) (CreateDirectory(x,NULL)!=0)
#ifndef ERROR_ALREADY_EXISTS
#define ERROR_ALREADY_EXISTS 183
#endif
#define r_sys_mkdir_failed() (GetLastError () != 183)
#else
#define r_sys_mkdir(x) (mkdir(x,0755)!=-1)
#define r_sys_mkdir_failed() (errno != EEXIST)
#endif

static int r_sys_rmkdir(char *dir) {
        char *path = dir, *ptr = path;
        if (*ptr==DIRSEP) ptr++;
        while ((ptr = strchr (ptr, DIRSEP))) {
                *ptr = 0;
                if (!r_sys_mkdir (path) && r_sys_mkdir_failed ()) {
                        fprintf (stderr, "r_sys_rmkdir: fail %s\n", dir);
                        free (path);
                        return 0;
                }
                *ptr = DIRSEP;
                ptr++;
        }
        return 1;
}

/* sdb-create api */
SDB_VISIBLE int sdb_create (Sdb* s) {
	int nlen;
	char *str;
	if (!s || !s->dir || s->fdump != -1) return 0; // cannot re-create
	nlen = strlen (s->dir);
	str = malloc (nlen+5);
	if (!str) return 0;
	strcpy (str, s->dir);
	r_sys_rmkdir (str);
	strcpy (str+nlen, ".tmp");
	s->fdump = open (str, O_BINARY|O_RDWR|O_CREAT|O_TRUNC, 0644);
	if (s->fdump == -1) {
		fprintf (stderr, "sdb: Cannot open '%s' for writing.\n", str);
		free (str);
		return 0;
	}
	cdb_make_start (&s->m, s->fdump);
	s->ndump = str;
	return 1;
}

SDB_VISIBLE int sdb_append (Sdb* s, const char *key, const char *val) {
	struct cdb_make *c = &s->m;
	if (!key || !val) return 0;
	//if (!*val) return 0; //undefine variable if no value
	return cdb_make_add (c, key, strlen (key)+1, val, strlen (val)+1);
}

#define IFRET(x) if(x)ret=0
SDB_VISIBLE int sdb_finish (Sdb* s) {
	int ret = 1;
	IFRET (!cdb_make_finish (&s->m));
#if USE_MMAN
	IFRET (fsync (s->fdump));
#endif
	IFRET (close (s->fdump));
	s->fdump = -1;
	IFRET (rename (s->ndump, s->dir));
	free (s->ndump);
	s->ndump = NULL;
	return ret;
}

SDB_VISIBLE void sdb_drop (Sdb* s) {
	sdb_fini (s, 1);
	unlink (s->dir);
}
