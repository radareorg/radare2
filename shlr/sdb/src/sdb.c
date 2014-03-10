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
SDB_API Sdb* sdb_new (const char *path, const char *name, int lock) {
        struct stat st = {0};
	Sdb* s = R_NEW (Sdb);
	if (name && *name) {
		if (path && *path) {
			int plen = strlen (path);
			int nlen = strlen (name);
			s->dir = malloc (plen+nlen+2);
			memcpy (s->dir, path, plen);
			s->dir[plen] = '/';
			memcpy (s->dir+plen+1, name, nlen+1);
		} else s->dir = strdup (name);
		if (lock && !sdb_lock (sdb_lockfile (s->dir)))
			goto fail;
		if (stat (s->dir, &st)!=-1)
			if ((S_IFREG & st.st_mode)!=S_IFREG)
				goto fail;
		s->fd = open (s->dir, O_RDONLY|O_BINARY);
		// if (s->fd == -1) // must fail if we cant open for write in sync
		if (s->fd != -1)
			s->last = st.st_mtime;
		else s->last = sdb_now ();
		s->name = strdup (name);
		s->path = path? strdup (path): NULL;
	} else {
		s->dir = NULL;
		s->last = sdb_now ();
		s->name = NULL;
		s->path = NULL;
		s->fd = -1;
	}
	s->options = 0;
	s->fdump = -1;
	s->ndump = NULL;
	s->ns = ls_new (); // TODO: should be NULL
	if (!s->ns) goto fail;
	s->hooks = NULL;
	s->ht = ht_new ((SdbListFree)sdb_kv_free);
	s->lock = lock;
	s->expire = 0LL;
	s->tmpkv.value = NULL;
	//s->ht->list->free = (SdbListFree)sdb_kv_free;
	// if open fails ignore
	if (global_hook)
		sdb_hook (s, global_hook, global_user);
	cdb_init (&s->db, s->fd);
	cdb_findstart (&s->db);
	return s;
fail:
	free (s->dir);
	free (s);
	return NULL;
}

// XXX: this is wrong. stuff not stored in memory is lost
SDB_API void sdb_file (Sdb* s, const char *dir) {
	if (s->lock)
		sdb_unlock (sdb_lockfile (s->dir));
	free (s->dir);
	s->dir = (dir && *dir)? strdup (dir): NULL;
	if (s->lock)
		sdb_lock (sdb_lockfile (s->dir));
}

static void sdb_fini(Sdb* s, int donull) {
	if (!s) return;
	sdb_hook_free (s);
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

SDB_API void sdb_free (Sdb* s) {
	sdb_fini (s, 0);
	free (s);
}

SDB_API const char *sdb_const_get (Sdb* s, const char *key, ut32 *cas) {
	ut32 hash, pos, len, keylen;
	ut64 now = 0LL;
	SdbKv *kv;

	if (cas) *cas = 0;
	if (!s||!key) return NULL;
	keylen = strlen (key)+1;
	hash = sdb_hash (key, 0); //keylen-1);

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

SDB_API char *sdb_get (Sdb* s, const char *key, ut32 *cas) {
	ut32 hash, pos, len, keylen;
	ut64 now = 0LL;
	SdbKv *kv;
	char *buf;

	if (cas) *cas = 0;
	if (!s || !key) return NULL;
	keylen = strlen (key)+1;
	hash = sdb_hash (key, keylen-1);

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
	if (!(len = cdb_datalen (&s->db)))
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

SDB_API int sdb_concat(Sdb *s, const char *key, const char *value, ut32 cas) {
	int ret, kl, vl;
	const char *p;
	char *o;
	if (!s || !key || !*key || !value || !*value)
		return 0;
	p = sdb_const_get (s, key, 0);
	if (!p) return sdb_set (s, key, value, cas);
	kl = strlen (p);
	vl = strlen (value);
	o = malloc (kl+vl+1);
	memcpy (o, p, kl);
	memcpy (o+kl, value, vl+1);
	ret = sdb_set (s, key, o, cas);
	free (o);
	return ret;
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

SDB_API void sdb_reset (Sdb* s) {
	/* disable disk cache */
	close (s->fd);
	s->fd = -1;
	/* empty memory hashtable */
	ht_free (s->ht);
	s->ht = ht_new ((SdbListFree)sdb_kv_free);
}

// TODO: too many allocs here. use slices
SDB_API SdbKv* sdb_kv_new (const char *k, const char *v) {
	int vl = strlen (v)+1;
	SdbKv *kv = R_NEW (SdbKv);
	strncpy (kv->key, k, sizeof (kv->key)-1);
	kv->value = malloc (vl);
	memcpy (kv->value, v, vl);
	kv->cas = nextcas ();
	kv->expire = 0LL;
	return kv;
}

SDB_API void sdb_kv_free (SdbKv *kv) {
	free (kv->value);
	free (kv);
}

SDB_API int sdb_set (Sdb* s, const char *key, const char *val, ut32 cas) {
	ut32 hash, klen;
	SdbHashEntry *e;
	SdbKv *kv;
	if (!s || !key)
		return 0;
	if (!sdb_check_key (key))
		return 0;
	if (!val) val = "";
	if (!sdb_check_value (val))
		return 0;
	klen = strlen (key)+1;
	hash = sdb_hash (key, klen-1);
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
		} else ht_del_entry (s->ht, e);
		sdb_hook_call (s, key, val);
		return cas;
	}
	if (!*val)
		return 0;
	kv = sdb_kv_new (key, val);
	kv->cas = nextcas ();
	ht_insert (s->ht, hash, kv, NULL);
	sdb_hook_call (s, key, val);
	return kv->cas;
}

SDB_API int sdb_foreach (Sdb* s, SdbForeachCallback cb, void *user) {
	SdbListIter *iter;
	char *k, *v;
	SdbKv *kv;
	sdb_dump_begin (s);
	while (sdb_dump_dupnext (s, &k, &v)) {
		ut32 hash = sdb_hash (k, 0);
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
			if (!cb (user, k, v)) {
				free (k);
				free (v);
				return 0;
			}
		}
		free (k);
		free (v);
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

	if (!sdb_disk_create (s))
		return 0;
// TODO: use sdb_foreach here
	sdb_dump_begin (s);
	while (sdb_dump_dupnext (s, &k, &v)) {
		ut32 hash = sdb_hash (k, 0);
		SdbHashEntry *hte = ht_search (s->ht, hash);
		if (hte) {
			kv = (SdbKv*)hte->data;
			if (*kv->value) 
				sdb_disk_insert (s, kv->key, kv->value);
			// XXX: This fails if key is dupped
			//else printf ("remove (%s)\n", kv->key);
			ls_del (s->ht->list, hte->iter);
			hte->iter = NULL;
			ht_del_entry (s->ht, hte);
		} else if (*v)
			sdb_disk_insert (s, k, v);
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
	return 1;
}

// TODO: optimize: do not use syscalls here
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
	char *k = NULL, *v = NULL;
	if (!sdb_dump_dupnext (s, &k, &v))
		return NULL;
	strncpy (s->tmpkv.key, k, SDB_KSZ-1);
	s->tmpkv.key[SDB_KSZ-1] = '\0';
	free (k);
	free (s->tmpkv.value);
	s->tmpkv.value = v;
	return &s->tmpkv;
}

SDB_API int sdb_dump_dupnext (Sdb* s, char **key, char **value) {
	ut32 vlen, klen;
	if (s->fd==-1)
		return 0;
	if (!cdb_getkvlen (s->fd, &klen, &vlen))
		return 0;
	if (klen<1 || vlen<1)
		return 0;
	if (key) {
		*key = 0;
		if (klen>0) {
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
		if (vlen>0) {
			*value = malloc (vlen+10);
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
	s->pos += 4; // XXX no
	return 1;
}

static inline ut64 parse_expire (ut64 e) {
	const ut64 month = 30 * 24 * 60 * 60;
	if (e>0 && e<month) e += sdb_now ();
	return e;
}

SDB_API int sdb_expire_set(Sdb* s, const char *key, ut64 expire) {
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
	if (len == UT32_MAX || !len) {
		return 0;
	}
	if (!(buf = malloc (len+1)))
		return 0;
	cdb_read (&s->db, buf, len, pos);
	buf[len] = 0;
	sdb_set (s, key, buf, 0); // TODO use cas here?
	free (buf);
	return sdb_expire_set (s, key, expire); // recursive
}

SDB_API ut64 sdb_expire_get(Sdb* s, const char *key) {
	SdbKv *kv;
	ut32 hash = sdb_hash (key, 0);
	kv = (SdbKv*)ht_lookup (s->ht, hash);
	if (kv && *kv->value)
		return kv->expire;
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
			ls_del (s->hooks, iter);
			ls_del (s->hooks, iter2);
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

SDB_API void sdb_unlink (Sdb* s) {
	sdb_fini (s, 1);
	if (s->dir && *(s->dir))
		unlink (s->dir);
}
