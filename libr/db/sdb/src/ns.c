/* Copyleft 2012-2013 - sdb (aka SimpleDB) - pancake<nopcode.org> */

#include "sdb.h"

void sdb_ns_free(Sdb *s) {
	SdbNs *ns;
	SdbListIter *it;
	ls_foreach (s->ns, it, ns) {
		sdb_ns_free (ns->sdb);
		sdb_free (ns->sdb);
		ls_delete (s->ns, it);
	}
}

SdbNs *sdb_ns_new (const char *name, ut32 hash) {
	SdbNs *ns = malloc (sizeof (SdbNs));
	ns->hash = hash;
	ns->sdb = sdb_new (name, 0);
	return ns;
}

Sdb *sdb_ns(Sdb *s, const char *name) {
	SdbNs *ns;
	SdbListIter *it;
	ut32 hash = sdb_hashstr (name);
	ls_foreach (s->ns, it, ns) {
		if (ns->hash == hash)
			return ns->sdb;
	}
	ns = sdb_ns_new (name, hash);
	ls_append (s->ns, ns);
	return ns->sdb;
}

void sdb_ns_sync (Sdb *s) {
	SdbNs *ns;
	SdbListIter *it;
	ls_foreach (s->ns, it, ns) {
		sdb_ns_sync (ns->sdb);
		sdb_sync (ns->sdb);
	}
	sdb_sync (s);
}
