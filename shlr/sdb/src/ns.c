/* sdb - LGPLv3 - Copyright 2011-2014 - pancake */

#include "sdb.h"

SDB_API void sdb_ns_free(Sdb *s) {
	SdbListIter next;
	SdbListIter *it;
	SdbNs *ns;
	// TODO: Implement and use ls_foreach_safe
	ls_foreach (s->ns, it, ns) {
		next.n = it->n;
		sdb_ns_free (ns->sdb);
		sdb_free (ns->sdb);
		free (ns->name);
		ns->name = NULL;
		ls_del (s->ns, it); // free (it)
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
		memcpy (dir+dir_len+1, name, name_len);
	}
	ns = malloc (sizeof (SdbNs));
	ns->hash = hash;
	ns->name = strdup (name);
	ns->sdb = sdb_new (dir, name, 0);
	return ns;
}

SDB_API int sdb_ns_set (Sdb *s, const char *name, Sdb *r) {
	SdbNs *ns;
	SdbListIter *it;
	ut32 hash = sdb_hashstr (name);
	ls_foreach (s->ns, it, ns) {
		if (ns->hash == hash) {
			ns->sdb = r;
			return 0;
		}
	}
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
	ut32 hash = sdb_hashstr (name);
	ls_foreach (s->ns, it, ns) {
		if (ns->hash == hash)
			return ns->sdb;
	}
	ns = sdb_ns_new (s, name, hash);
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
