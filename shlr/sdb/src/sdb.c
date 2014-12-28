/* sdb - LGPLv3 - Copyright 2011-2014 - pancake */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "sdb.h"

static inline int nextcas() {
	static ut32 cas = 1;
	if (!cas) cas++;
	return cas++;
}

static SdbHook global_hook = NULL;
static void* global_user = NULL;

SDB_API void sdb_global_hook(SdbHook hook, void *user) {
	global_hook = hook;
	global_user = user;
}

// TODO: use mmap instead of read.. much faster!
SDB_API Sdb* sdb_new0 () {
	return sdb_new (NULL, NULL, 0);
}

SDB_API Sdb* sdb_new (const char *path, const char *name, int lock) {
        struct stat st = {0};
	Sdb* s = R_NEW0 (Sdb);
	if (!s) return NULL;
	s->fd = -1;
	s->dir = NULL;
	s->refs = 1;
	if (path && !*path)
		path = NULL;
	if (name && *name) {
		if (path && *path) {
			int plen = strlen (path);
			int nlen = strlen (name);
			s->dir = malloc (plen+nlen+2);
			memcpy (s->dir, path, plen);
			s->dir[plen] = '/';
			memcpy (s->dir+plen+1, name, nlen+1);
			s->path = strdup (path);
		} else {
			s->dir = strdup (name);
		}
		switch (lock) {
		case 1:
			if (!sdb_lock (sdb_lock_file (s->dir)))
				goto fail;
			break;
		case 2:
			if (!sdb_lock_wait (sdb_lock_file (s->dir)))
				goto fail;
			break;
		}
		if (sdb_open (s, s->dir) != -1) {
			if (fstat (s->fd, &st) != -1)
				if ((S_IFREG & st.st_mode) != S_IFREG)
					goto fail;
			s->last = st.st_mtime;
		} else {
			s->last = sdb_now ();
			// TODO: must fail if we cant open for write in sync
		}
		s->name = strdup (name);
	} else {
		s->last = sdb_now ();
		s->fd = -1;
	}
	s->fdump = -1;
	s->ndump = NULL;
	s->ns = ls_new (); // TODO: should be NULL
	if (!s->ns)
		goto fail;
	s->ns->free = NULL;
	if (!s->ns) goto fail;
	s->ht = ht_new ((SdbListFree)sdb_kv_free);
	s->lock = lock;
	// s->ht->list->free = (SdbListFree)sdb_kv_free;
	// if open fails ignore
	if (global_hook)
		sdb_hook (s, global_hook, global_user);
	cdb_init (&s->db, s->fd);
	return s;
fail:
	if (s->fd != -1) {
		close (s->fd);
		s->fd = -1;
	}
	free (s->dir);
	free (s->name);
	free (s->path);
	free (s);
	return NULL;
}

// XXX: this is wrong. stuff not stored in memory is lost
SDB_API void sdb_file (Sdb* s, const char *dir) {
	if (s->lock)
		sdb_unlock (sdb_lock_file (s->dir));
	free (s->dir);
	s->dir = (dir && *dir)? strdup (dir): NULL;
	if (s->lock)
		sdb_lock (sdb_lock_file (s->dir));
}

static void sdb_fini(Sdb* s, int donull) {
	if (!s) return;
	sdb_hook_free (s);
	cdb_free (&s->db);
	if (s->lock)
		sdb_unlock (sdb_lock_file (s->dir));
	sdb_ns_free (s);
	s->refs = 0;
	free (s->name);
	free (s->path);
	ls_free (s->ns);
	ht_free (s->ht);
	if (s->fd != -1) {
		close (s->fd);
		s->fd = -1;
	}
	free (s->ndump);
	free (s->dir);
	free (s->tmpkv.value);
	s->tmpkv.value_len = 0;
	if (donull)
		memset (s, 0, sizeof (Sdb));
}

SDB_API int sdb_free (Sdb* s) {
	if (s && s->ht && s->refs) {
		s->refs--;
		if (s->refs<1) {
			s->refs = 0;
			sdb_fini (s, 0);
			s->ht = NULL;
			free (s);
			return 1;
		}
	}
	return 0;
}

SDB_API const char *sdb_const_get_len (Sdb* s, const char *key, int *vlen, ut32 *cas) {
	ut32 hash, pos, len, keylen;
	ut64 now = 0LL;
	SdbKv *kv;
	if (cas) *cas = 0;
	if (!s||!key) return NULL;
	// TODO: optimize, iterate once
	keylen = strlen (key)+1;
	hash = sdb_hash (key);
	/* search in memory */
	kv = (SdbKv*)ht_lookup (s->ht, hash);
	if (kv) {
		if (*kv->value) {
			if (kv->expire) {
				if (!now) now = sdb_now ();
				if (now > kv->expire) {
					sdb_unset (s, key, 0);
					return NULL;
				}
			}
			if (cas) *cas = kv->cas;
			if (vlen) *vlen = kv->value_len;
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
	if (vlen)
		*vlen = len;
	pos = cdb_datapos (&s->db);
	return s->db.map+pos;
}

SDB_API const char *sdb_const_get (Sdb* s, const char *key, ut32 *cas) {
	return sdb_const_get_len (s, key, NULL, cas);
}

// TODO: add sdb_getf?

SDB_API char *sdb_get (Sdb* s, const char *key, /*OUT*/ut32 *cas) {
	ut32 hash, pos, len, keylen;
	ut64 now = 0LL;
	SdbKv *kv;
	char *buf;

	if (cas) *cas = 0;
	if (!s || !key) return NULL;
	keylen = strlen (key)+1;
	hash = sdb_hash (key);//keylen-1);

	/* search in memory */
	kv = (SdbKv*)ht_lookup (s->ht, hash);
	if (kv) {
		if (*kv->value) {
			if (kv->expire) {
				if (!now) now = sdb_now ();
				if (now > kv->expire) {
					sdb_unset (s, key, 0);
					return NULL;
				}
			}
			if (cas) *cas = kv->cas;
			return strdup (kv->value);
		}
		return NULL;
	}

	/* search in disk */
	if (s->fd == -1)
		return NULL;
	cdb_findstart (&s->db);
	if (!cdb_findnext (&s->db, hash, key, keylen))
		return NULL;
	if ((len = cdb_datalen (&s->db))<1)
		return NULL;
	if (!(buf = malloc (len+1))) // XXX too many mallocs
		return NULL;
	pos = cdb_datapos (&s->db);
	cdb_read (&s->db, buf, len, pos);
	buf[len] = 0;
	return buf;
}

SDB_API int sdb_unset (Sdb* s, const char *key, ut32 cas) {
	return key? sdb_set (s, key, "", cas): 0;
}

// alias for '-key=str'.. '+key=str' concats
SDB_API int sdb_uncat(Sdb *s, const char *key, const char *value, ut32 cas) {
	// remove 'value' from current key value.
	// TODO: cas is ignored here
	char *p, *v = sdb_get (s, key, NULL);
	int vlen = strlen (value);
	int mod = 0;
	while ((p = strstr (v, value))) {
		memmove (p, p+vlen, strlen (p+vlen)+1);
		mod = 1;
	}
	if (mod) sdb_set_owned (s, key, v, 0);
	else free (v);
	return 0;
}

SDB_API int sdb_concat(Sdb *s, const char *key, const char *value, ut32 cas) {
	int kl, vl;
	const char *p;
	char *o;
	if (!s || !key || !*key || !value || !*value)
		return 0;
	p = sdb_const_get_len (s, key, &kl, 0);
	if (!p) return sdb_set (s, key, value, cas);
	kl--;
	//kl = strlen (p);
	vl = strlen (value);
	o = malloc (kl+vl+1);
	memcpy (o, p, kl);
	memcpy (o+kl, value, vl+1);
	return sdb_set_owned (s, key, o, cas);
}

// set if not defined
SDB_API int sdb_add (Sdb* s, const char *key, const char *val, ut32 cas) {
	if (sdb_exists (s, key))
		return 0;
	return sdb_set (s, key, val, cas);
}

SDB_API int sdb_exists (Sdb* s, const char *key) {
	char ch;
	SdbKv *kv;
	int klen = strlen (key)+1;
	ut32 pos, hash = sdb_hash (key);
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

SDB_API int sdb_open (Sdb *s, const char *file) {
	if (!s) return -1;
	if (file) {
		char *realfile = strdup (file);
		sdb_close (s);
		s->fd = open (realfile, O_RDONLY|O_BINARY);
		free (s->dir);
		s->dir = realfile;
	} else {
		if (s->fd != -1) {
			close (s->fd);
			s->fd = -1;
		}
		if (s->dir) {
			free (s->dir);
			s->dir = NULL;
		}
	}
	return s->fd;
}

SDB_API void sdb_close (Sdb *s) {
	(void)sdb_open (s, NULL);
}

SDB_API void sdb_reset (Sdb* s) {
	if (!s) return;
	/* ignore disk cache, file is not removed, but we will ignore
	 * its values when syncing again */
	sdb_close (s);
	/* empty memory hashtable */
	if (s->ht)
		ht_free (s->ht);
	s->ht = ht_new ((SdbListFree)sdb_kv_free);
}

// TODO: too many allocs here. use slices
SDB_API SdbKv* sdb_kv_new (const char *k, const char *v) {
	SdbKv *kv;
	int vl;
	if (!sdb_check_key (k))
		return NULL;
	if (v) {
		if (!sdb_check_value (v))
			return NULL;
		vl = strlen (v)+1;
	} else {
		vl = 0;
	}
	kv = R_NEW (SdbKv);
	strncpy (kv->key, k, sizeof (kv->key)-1);
	kv->value_len = vl;
	if (vl) {
		kv->value = malloc (vl);
		memcpy (kv->value, v, vl);
	} else kv->value = NULL;
	kv->cas = nextcas ();
	kv->expire = 0LL;
	return kv;
}

SDB_API void sdb_kv_free (SdbKv *kv) {
	free (kv->value);
	free (kv);
}

static int sdb_set_internal (Sdb* s, const char *key, char *val, int owned, ut32 cas) {
	ut32 hash, klen;
	SdbHashEntry *e;
	SdbKv *kv;
	int vlen;
	if (!s || !key)
		return 0;
	if (!sdb_check_key (key))
		return 0;
	if (!val) val = "";
	if (!sdb_check_value (val))
		return 0;
	klen = strlen (key)+1;
	vlen = strlen (val)+1;
	hash = sdb_hash (key);
	cdb_findstart (&s->db);
	e = ht_search (s->ht, hash);
	if (e) {
		if (cdb_findnext (&s->db, hash, key, klen)) {
			kv = e->data;
			if (cas && kv->cas != cas)
				return 0;
			kv->cas = cas = nextcas ();
			if (owned) {
				kv->value_len = vlen;
				free (kv->value);
				kv->value = val; // owned
			} else {
				if (vlen>kv->value_len) {
					free (kv->value);
					kv->value = strdup (val);
				} else {
					memcpy (kv->value, val, vlen);
				}
				kv->value_len = vlen;
			}
		} else ht_delete_entry (s->ht, e);
		sdb_hook_call (s, key, val);
		return cas;
	}
	// empty values are also stored
	// TODO store only the ones that are in the CDB
	if (owned) {
		kv = sdb_kv_new (key, NULL);
		if (kv) {
			kv->value = val;
			kv->value_len = vlen;
		}
	} else {
		kv = sdb_kv_new (key, val);
	}
	if (kv) {
		kv->cas = nextcas ();
		ht_insert (s->ht, hash, kv, NULL);
		sdb_hook_call (s, key, val);
		return kv->cas;
	}
	sdb_hook_call (s, key, val);
	return 0;
}

SDB_API int sdb_set_owned (Sdb* s, const char *key, char *val, ut32 cas) {
	return sdb_set_internal (s, key, val, 1, cas);
}

SDB_API int sdb_set (Sdb* s, const char *key, const char *val, ut32 cas) {
	return sdb_set_internal (s, key, (char*)val, 0, cas);
}

SDB_API int sdb_foreach (Sdb* s, SdbForeachCallback cb, void *user) {
	SdbListIter *iter;
	char *k, *v;
	SdbKv *kv;
	sdb_dump_begin (s);
	while (sdb_dump_dupnext (s, &k, &v, NULL)) {
		ut32 hash = sdb_hash (k);
		SdbHashEntry *hte = ht_search (s->ht, hash);
		if (hte) {
			free (k);
			free (v);
			kv = (SdbKv*)hte->data;
			if (!*kv->value) {
				// deleted = 1;
				continue;
			}
			if (!cb (user, kv->key, kv->value))
				return 0;
		} else {
			int ret = cb (user, k, v);
			free (k);
			free (v);
			if (!ret) return 0;
		}
	}
	ls_foreach (s->ht->list, iter, kv) {
		if (!kv->value || !*kv->value)
			continue;
		if (!cb (user, kv->key, kv->value))
			return 0;
	}
	return 1;
}

// TODO: reuse sdb_foreach DEPRECATE WTF NOT READING THE CDB?
SDB_API void sdb_list (Sdb* s) {
	SdbListIter *iter;
	SdbKv *kv;
	if (!s || !s->ht)
		return;
	ls_foreach (s->ht->list, iter, kv) {
		if (!kv->value || !*kv->value)
			continue;
		printf ("%s=%s\n", kv->key, kv->value);
	}
}

SDB_API int sdb_sync (Sdb* s) {
	SdbListIter it, *iter;
	char *k, *v;
	SdbKv *kv;

	if (!s || !sdb_disk_create (s))
		return 0;
// TODO: use sdb_foreach here
	sdb_dump_begin (s);
	/* iterate over all keys in disk database */
	while (sdb_dump_dupnext (s, &k, &v, NULL)) {
		ut32 hash = sdb_hash (k);
		/* find that key in the memory storage */
		SdbHashEntry *hte = ht_search (s->ht, hash);
		if (hte) {
			kv = (SdbKv*)hte->data;
			if (kv && *kv->value) {
				/* asume k = kv->key */
				sdb_disk_insert (s, k, kv->value);
			}
			// XXX: This fails if key is dupped
			//else printf ("remove (%s)\n", kv->key);
			ls_delete (s->ht->list, hte->iter);
			hte->iter = NULL;
			ht_delete_entry (s->ht, hte);
		} else if (v && *v) {
			sdb_disk_insert (s, k, v);
		}
		free (k);
		free (v);
	}
	/* append new keyvalues */
	ls_foreach (s->ht->list, iter, kv) {
		if (*kv->value && kv->expire == 0LL)
			sdb_disk_insert (s, kv->key, kv->value);
		if (kv->expire == 0LL) {
			it.n = iter->n;
			sdb_unset (s, kv->key, 0);
			iter = &it;
		}
	}
	sdb_disk_finish (s);
	// TODO: sdb_reset memory state?
	return 1;
}

// TODO: optimize: do not use syscalls here. we can just do mmap and pointer arithmetics
static int getbytes(Sdb *s, char *b, int len) {
	if (read (s->fd, b, len) != len)
		return -1;
	s->pos += len;
	return len;
}

SDB_API void sdb_dump_begin (Sdb* s) {
	if (s->fd != -1)
		seek_set (s->fd, (s->pos=2048));
	else s->pos = 0;
}

SDB_API SdbKv *sdb_dump_next (Sdb* s) {
	int vl = 0;
	char *k = NULL, *v = NULL;
	// we dont need to malloc, because all values are null terminated in memory.
	if (!sdb_dump_dupnext (s, &k, &v, &vl))
		return NULL;
	vl--;
	strncpy (s->tmpkv.key, k, SDB_KSZ-1);
	s->tmpkv.key[SDB_KSZ-1] = '\0';
	free (k);
	free (s->tmpkv.value);
	s->tmpkv.value = v;
	s->tmpkv.value_len = vl;
	return &s->tmpkv;
}

// TODO: make it static? internal api?
SDB_API int sdb_dump_dupnext (Sdb* s, char **key, char **value, int *_vlen) {
	ut32 vlen = 0, klen = 0;
	if (key) *key = NULL;
	if (value) *value = NULL;
	if (_vlen)
		*_vlen = 0;
	if (s->fd==-1)
		return 0;
	if (!cdb_getkvlen (s->fd, &klen, &vlen))
		return 0;
	if (klen<1 || vlen<1)
		return 0;
	if (_vlen)
		*_vlen = vlen;
	if (key) {
		*key = 0;
		if (klen>0 && klen<0xff) {
			*key = malloc (klen+1);
			if (getbytes (s, *key, klen) == -1) {
				free (*key);
				*key = NULL;
				return 0;
			}
			(*key)[klen] = 0;
		}
	}
	if (value) {
		*value = 0;
		if (vlen>0 && vlen<0xffffff) {
			*value = malloc (vlen+10);
			if (!*value) {
				if (key) {
					free (*key);
					*key = NULL;
				}
				return 0;
			}
			if (getbytes (s, *value, vlen)==-1) {
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
	s->pos += 4; // XXX no.
	return 1;
}

static inline ut64 parse_expire (ut64 e) {
	const ut64 month = 30 * 24 * 60 * 60;
	if (e>0 && e<month) e += sdb_now ();
	return e;
}

SDB_API int sdb_expire_set(Sdb* s, const char *key, ut64 expire, ut32 cas) {
	char *buf;
	ut32 hash, pos, len;
	SdbKv *kv;
	if (key == NULL) {
		s->expire = parse_expire (expire);
		return 1;
	}
	hash = sdb_hash (key);
	kv = (SdbKv*)ht_lookup (s->ht, hash);
	if (kv) {
		if (*kv->value) {
			if (!cas || cas == kv->cas) {
				kv->expire = parse_expire (expire);
				return 1;
			} else return 0;
		}
		return 0;
	}
	if (s->fd == -1)
		return 0;
	cdb_findstart (&s->db);
	if (!cdb_findnext (&s->db, hash, key, strlen (key)+1))
		return 0;
	pos = cdb_datapos (&s->db);
	len = cdb_datalen (&s->db);
	if (len <1 || len == UT32_MAX)
		return 0;
	if (!(buf = malloc (len+1)))
		return 0;
	cdb_read (&s->db, buf, len, pos);
	buf[len] = 0;
	sdb_set_owned (s, key, buf, cas);
	return sdb_expire_set (s, key, expire, cas); // recursive
}

SDB_API ut64 sdb_expire_get(Sdb* s, const char *key, ut32 *cas) {
	SdbKv *kv;
	ut32 hash = sdb_hash (key);
	kv = (SdbKv*)ht_lookup (s->ht, hash);
	if (kv && *kv->value) {
		if (cas) *cas = kv->cas;
		return kv->expire;
	}
	return 0LL;
}

SDB_API int sdb_hook(Sdb* s, SdbHook cb, void* user) {
	int i = 0;
	SdbHook hook;
	SdbListIter *iter;
	if (s->hooks) {
		ls_foreach (s->hooks, iter, hook) {
			if (!(i%2) && (hook == cb))
				return 0;
			i++;
		}
	} else {
		s->hooks = ls_new ();
		s->hooks->free = NULL;
	}
	ls_append (s->hooks, cb);
	ls_append (s->hooks, user);
	return 1;
}

SDB_API int sdb_unhook(Sdb* s, SdbHook h) {
	int i = 0;
	SdbHook hook;
	SdbListIter *iter, *iter2;
	ls_foreach (s->hooks, iter, hook) {
		if (!(i%2) && (hook == h)) {
			iter2 = iter->n;
			ls_delete (s->hooks, iter);
			ls_delete (s->hooks, iter2);
			return 1;
		}
		i++;
	}
	return 0;
}

SDB_API int sdb_hook_call(Sdb *s, const char *k, const char *v) {
	SdbListIter *iter;
	SdbHook hook;
	int i = 0;
	if (s->last)
		s->last = sdb_now ();
	ls_foreach (s->hooks, iter, hook) {
		if (!(i%2) && k && iter->n) {
			void *u = iter->n->data;
			hook (s, u, k, v);
		}
		i++;
	}
	return i>>1;
}

SDB_API void sdb_hook_free(Sdb *s) {
	ls_free (s->hooks);
	s->hooks = NULL;
}

SDB_API void sdb_config(Sdb *s, int options) {
	s->options = options;
	if (options & SDB_OPTION_SYNC) {
		// sync on every query
	}
	if (options & SDB_OPTION_NOSTAMP) {
		// sync on every query
		s->last = 0LL;
	}
	if (options & SDB_OPTION_FS) {
		// have access to fs (handle '.' or not in query)
	}
}

SDB_API int sdb_unlink (Sdb* s) {
	// nullify Sdb
	sdb_fini (s, 1);
	// remove from disk
	return sdb_disk_unlink (s);
}

SDB_API void sdb_drain(Sdb *s, Sdb *f) {
	if (!s || !f) return;
	f->refs = s->refs;
	sdb_fini (s, 1);
	*s = *f;
	free (f);
}

#if 0
SDB_API void sdb_drain(Sdb *s, Sdb *f) {
	// drain f contents into s
	sdb_fini (s, 0);
	memcpy (s, f, sizeof (Sdb));
	// invalidates f, but doenst free's
	// invalidate = close fd, free'd mem hashtable
	memset (f, 0, sizeof (Sdb));
}
#endif

typedef struct {
	Sdb *sdb;
	const char *key;
} UnsetCallbackData;

static int unset_cb(void *user, const char *k, const char *v) {
	UnsetCallbackData *ucd = user;
	if (sdb_match (k, ucd->key))
		sdb_unset (ucd->sdb, k, 0);
	return 1;
}

// TODO: rename to sdb_unset_similar ?
SDB_API int sdb_unset_matching(Sdb *s, const char *k) {
	UnsetCallbackData ucd = { s, k };
	return sdb_foreach (s, unset_cb, &ucd);
}
