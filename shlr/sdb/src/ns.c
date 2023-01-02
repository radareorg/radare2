/* sdb - MIT - Copyright 2011-2022 - pancake */

#include "sdb/sdb.h"

SDB_API void sdb_ns_lock(Sdb *s, int lock, int depth) {
	SdbListIter *it;
	SdbNs *ns;
	s->ns_lock = lock;
	if (depth) { // handles -1 as infinite
		ls_foreach_cast (s->ns, it, SdbNs*, ns) {
			sdb_ns_lock (ns->sdb, lock, depth - 1);
		}
	}
}

static int in_list(SdbList *list, void *item) {
	SdbNs *ns;
	SdbListIter *it;
	if (list && item) {
		ls_foreach_cast (list, it, SdbNs*, ns) {
			if (item == ns) {
				return 1;
			}
		}
	}
	return 0;
}

static void ns_free(Sdb *s, SdbList *list) {
	SdbListIter next;
	SdbListIter *it;
	int deleted;
	SdbNs *ns;
	if (!list || !s) {
		return;
	}
	// TODO: Implement and use ls_foreach_safe
	if (in_list (list, s)) {
		return;
	}
	ls_append (list, s);
	ls_foreach_cast (s->ns, it, SdbNs*, ns) {
		deleted = 0;
		next.n = it->n;
		if (!in_list (list, ns)) {
			ls_delete (s->ns, it); // free (it)
			free (ns->name);
			ns->name = NULL;
			deleted = 1;
			if (ns->sdb) {
				if (sdb_free (ns->sdb)) {
					ns->sdb = NULL;
					free (ns->name);
					ns->name = NULL;
				}
			}
			ls_append (list, ns);
			ls_append (list, ns->sdb);
			ns_free (ns->sdb, list);
			sdb_free (ns->sdb);
		}
		if (!deleted) {
			sdb_free (ns->sdb);
			s->ns->free = NULL;
			ls_delete (s->ns, it); // free (it)
		}
		free (ns);
		it = &next;
	}
	ls_free (s->ns);
	s->ns = NULL;
}

SDB_API void sdb_ns_free(Sdb *s) {
	SdbList *list;
	if (!s) {
		return;
	}
	list = ls_new ();
	list->free = NULL;
	ns_free (s, list);
	ls_free (list);
	ls_free (s->ns);
	s->ns = NULL;
}

static SdbNs *sdb_ns_new (Sdb *s, const char *name, ut32 hash) {
	char dir[SDB_MAX_PATH];
	SdbNs *ns;
	if (s->dir && *s->dir && name && *name) {
		int dir_len = strlen (s->dir);
		int name_len = strlen (name);
		if ((dir_len+name_len+3)>SDB_MAX_PATH) {
			return NULL;
		}
		memcpy (dir, s->dir, dir_len);
		memcpy (dir + dir_len, ".", 1);
		memcpy (dir + dir_len + 1, name, name_len + 1);
	} else {
		dir[0] = 0;
	}
	ns = (SdbNs *)sdb_gh_malloc (sizeof (SdbNs));
	if (!ns) {
		return NULL;
	}
	ns->hash = hash;
	ns->name = name? sdb_strdup (name): NULL;
	//ns->sdb = sdb_new (dir, ns->name, 0);
	ns->sdb = sdb_new0 ();
	// TODO: generate path

	if (ns->sdb) {
		sdb_gh_free (ns->sdb->path);
		ns->sdb->path = NULL;
		if (*dir) {
			ns->sdb->path = sdb_strdup (dir);
		}
		sdb_gh_free (ns->sdb->name);
		if (name && *name) {
			ns->sdb->name = sdb_strdup (name);
		}
	} else {
		sdb_gh_free (ns->name);
		sdb_gh_free (ns);
		ns = NULL;
	}
	return ns;
}

SDB_API bool sdb_ns_unset(Sdb *s, const char *name, Sdb *r) {
	SdbNs *ns;
	SdbListIter *it;
	if (s && (name || r)) {
		ls_foreach_cast (s->ns, it, SdbNs*, ns) {
			if (name && (!strcmp (name, ns->name))) {
				ls_delete (s->ns, it);
				return true;
			}
			if (r && ns->sdb == r) {
				ls_delete (s->ns, it);
				return true;
			}
		}
	}
	return false;
}

SDB_API int sdb_ns_set(Sdb *s, const char *name, Sdb *r) {
	SdbNs *ns;
	SdbListIter *it;
	ut32 hash = sdb_hash (name);
	if (!s || !r || !name) {
		return 0;
	}
	ls_foreach_cast (s->ns, it, SdbNs*, ns) {
		if (ns->hash == hash) {
			if (ns->sdb == r) {
				return 0;
			}
			sdb_free (ns->sdb);
			r->refs++; // sdb_ref / sdb_unref //
			ns->sdb = r;
			return 1;
		}
	}
	if (s->ns_lock) {
		return 0;
	}
	ns = R_NEW (SdbNs);
	if (!ns) {
		return 0;
	}
	ns->name = sdb_strdup (name);
	if (!ns->name) {
		sdb_gh_free (ns);
		return 0;
	}
	ns->hash = hash;
	ns->sdb = r;
	r->refs++;
	ls_append (s->ns, ns);
	return 1;
}

SDB_API Sdb *sdb_ns(Sdb *s, const char *name, int create) {
	SdbListIter *it;
	SdbNs *ns;
	ut32 hash;
	if (!s || !name || !*name) {
		return NULL;
	}
	hash = sdb_hash (name);
	ls_foreach_cast (s->ns, it, SdbNs*, ns) {
		if (ns->hash == hash) {
			return ns->sdb;
		}
	}
	if (!create) {
		return NULL;
	}
	if (s->ns_lock) {
		return NULL;
	}
	ns = sdb_ns_new (s, name, hash);
	if (!ns) {
		return NULL;
	}
	ls_append (s->ns, ns);
	return ns->sdb;
}

SDB_API Sdb *sdb_ns_path(Sdb *s, const char *path, int create) {
	char *ptr, *str;
	char *slash;

	if (!s || !path || !*path) {
		return s;
	}
	ptr = str = sdb_strdup (path);
	do {
		slash = strchr (ptr, '/');
		if (slash)
			*slash = 0;
		s = sdb_ns (s, ptr, create);
		if (!s) break;
		if (slash)
			ptr = slash+1;
	} while (slash);
	sdb_gh_free (str);
	return s;
}

static void ns_sync(Sdb *s, SdbList *list) {
	SdbNs *ns;
	SdbListIter *it;
	ls_foreach_cast (s->ns, it, SdbNs*, ns) {
		if (in_list (list, ns)) {
			continue;
		}
		ls_append (list, ns);
		ns_sync (ns->sdb, list);
		sdb_sync (ns->sdb);
	}
	sdb_sync (s);
}

SDB_API void sdb_ns_sync(Sdb *s) {
	SdbList *list = ls_new ();
	ns_sync (s, list);
	list->free = NULL;
	ls_free (list);
}
