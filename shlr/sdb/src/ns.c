/* sdb - LGPLv3 - Copyright 2011-2014 - pancake */

#include "sdb.h"

SDB_API void sdb_ns_lock(Sdb *s, int lock, int depth) {
	SdbListIter *it;
	SdbNs *ns;
	s->ns_lock = lock;
	if (depth) { // handles -1 as infinite
		ls_foreach (s->ns, it, ns) {
			sdb_ns_lock (ns->sdb, lock, depth-1);
		}
	}
}

SDB_API void sdb_ns_free(Sdb *s) {
	SdbListIter next;
	SdbListIter *it;
	SdbNs *ns;
	if (s)
	ls_foreach (s->ns, it, ns) {
	// TODO: Implement and use ls_foreach_safe
		next.n = it->n;
		sdb_ns_free (ns->sdb);
		sdb_free (ns->sdb);
		ns->sdb = NULL;

		free (ns->name);
		ns->name = NULL;
		ls_delete (s->ns, it); // free (it)
		it = &next;
	}
}

static SdbNs *sdb_ns_new (Sdb *s, const char *name, ut32 hash) {
	char dir[SDB_MAX_PATH];
	SdbNs *ns;
	if (s->dir && *s->dir && name && *name) {
		int dir_len = strlen (s->dir);
		int name_len = strlen (name);
		if ((dir_len+name_len+3)>SDB_MAX_PATH)
			return NULL;
		memcpy (dir, s->dir, dir_len);
		memcpy (dir+dir_len, ".", 1);
		memcpy (dir+dir_len+1, name, name_len+1);
	} else dir[0] = 0;
	ns = malloc (sizeof (SdbNs));
	if (!ns) return NULL;
	ns->hash = hash;
	ns->name = name? strdup (name): NULL;
	ns->sdb = sdb_new (dir, ns->name, 0);
	return ns;
}

SDB_API int sdb_ns_set (Sdb *s, const char *name, Sdb *r) {
	SdbNs *ns;
	SdbListIter *it;
	ut32 hash = sdb_hashstr (name);
	ls_foreach (s->ns, it, ns) {
		if (ns->hash == hash) {
			// implicit?
			//sdb_free (ns->sdb);
			r->refs++; // sdb_ref / sdb_unref //
			if (ns->sdb != r)
				sdb_free (ns->sdb);
			ns->sdb = r;
			return 1;
		}
	}
	if (s->ns_lock)
		return 0;
	ns = malloc (sizeof (SdbNs));
	ns->name = strdup (name);
	ns->hash = hash;
	ns->sdb = r;
	ls_append (s->ns, ns);
	return 1;
}

SDB_API Sdb *sdb_ns(Sdb *s, const char *name) {
	SdbNs *ns;
	SdbListIter *it;
	ut32 hash;
	if (!name || !*name)
		return NULL;
	hash = sdb_hashstr (name);
	ls_foreach (s->ns, it, ns) {
		if (ns->hash == hash)
			return ns->sdb;
	}
	if (s->ns_lock)
		return NULL;
	ns = sdb_ns_new (s, name, hash);
	if (!ns) return NULL;
	ls_append (s->ns, ns);
	return ns->sdb;
}

SDB_API void sdb_ns_sync (Sdb *s) {
	SdbNs *ns;
	SdbListIter *it;
	ls_foreach (s->ns, it, ns) {
		sdb_ns_sync (ns->sdb);
		sdb_sync (ns->sdb);
	}
	sdb_sync (s);
}
