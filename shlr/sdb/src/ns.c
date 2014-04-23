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

static int in_list(SdbList *list, void *item) {
	SdbNs *ns;
	SdbListIter *it;
	if (list && item)
	ls_foreach (list, it, ns) {
		if (item == ns)
			return 1;
	}
	return 0;
}

static void ns_free(Sdb *s, SdbList *list) {
	SdbListIter next;
	SdbListIter *it;
	SdbList *ons;
	int deleted;
	SdbNs *ns;
	if (!list || !s) return;
	// TODO: Implement and use ls_foreach_safe
	if (in_list (list, s))
		return;
	ls_append (list, s);
	ls_foreach (s->ns, it, ns) {
		deleted = 0;
		next.n = it->n;
		if (!in_list (list, ns)) {
			ls_append (list, ns);
			ls_append (list, ns->sdb);
			ns_free (ns->sdb, list);
			if (s->ns)
				s->ns->free = NULL;
			ls_delete (s->ns, it); // free (it)
			deleted = 1;
			if (ns->sdb && ns->sdb->ns)
			ons = ns->sdb->ns;
			ns->sdb->ns = NULL;
			if (sdb_free (ns->sdb)) {
				ns->sdb = NULL;
				free (ns->name);
				ns->name = NULL;
			}
			if (ns && ns->sdb)
				ns->sdb->ns = ons;
		}
		if (!deleted) {
			s->ns->free = NULL;
			ls_delete (s->ns, it); // free (it)
		}
		it = &next;
	}
}


SDB_API void sdb_ns_free(Sdb *s) {
	SdbList *list = ls_new ();
	ns_free (s, NULL);
	ls_free (list);
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
	//ns->sdb = sdb_new (dir, ns->name, 0);
	ns->sdb = sdb_new0 ();
	// TODO: generate path
	if (!ns->sdb) {
		free (ns->name);
		free (ns);
		ns = NULL;
	}
	free (ns->sdb->path);
	if (dir && *dir)
		ns->sdb->path = strdup (dir);
	free (ns->sdb->name);
	if (name && *name)
		ns->sdb->name = strdup (name);
	return ns;
}

SDB_API int sdb_ns_set (Sdb *s, const char *name, Sdb *r) {
	SdbNs *ns;
	SdbListIter *it;
	ut32 hash = sdb_hashstr (name);
	ls_foreach (s->ns, it, ns) {
		if (ns->hash == hash) {
			if (ns->sdb == r)
				return 0;
			sdb_free (ns->sdb);
			r->refs++; // sdb_ref / sdb_unref //
			ns->sdb = r;
			return 1;
		}
	}
	if (s->ns_lock)
		return 0;
	ns = R_NEW (SdbNs);
	ns->name = strdup (name);
	ns->hash = hash;
	ns->sdb = r;
	ls_append (s->ns, ns);
	return 1;
}

SDB_API Sdb *sdb_ns(Sdb *s, const char *name) {
	SdbListIter *it;
	SdbNs *ns;
	ut32 hash;
	if (!s || !name || !*name)
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

static void ns_sync (Sdb *s, SdbList *list) {
	SdbNs *ns;
	SdbListIter *it;
	ls_foreach (s->ns, it, ns) {
		if (in_list (list, ns))
			continue;
		ls_append (list, ns);
		ns_sync (ns->sdb, list);
		sdb_sync (ns->sdb);
	}
	sdb_sync (s);
}

SDB_API void sdb_ns_sync (Sdb *s) {
	SdbList *list = ls_new ();
	ns_sync (s, list);
	ls_free (list);
}
