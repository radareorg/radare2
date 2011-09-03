/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#include <r_db.h>
#include <r_util.h>
//#undef UT32_MAX
//#undef UT64_MAX
#include "sdb/src/sdb.h"

/*
var p = new Pair ();
p.set ("foo", "bar")
var out = p.get ("foo")
*/


R_API RPair *r_pair_new () {
	RPair *p = R_NEW0 (RPair);
	p->dbs = r_list_new ();
	p->dbs->free = (RListFree)sdb_free;
	return p;
}

R_API void r_pair_free (RPair *p) {
	r_hashtable_free (p->ht);
	r_list_destroy (p->dbs);
	free (p->dir);
	free (p);
}

R_API void r_pair_delete (RPair *p, const char *name) {
	Sdb *sdb;
	ut32 hdom;
	char *dom, *key = strdup (name);

	dom = r_str_lchr (key, '.');
	if (dom) {
		key = dom+1;
		*dom = 0;
		dom = 0;
	} else dom = "";
	hdom = r_str_hash (dom);
	sdb = r_hashtable_lookup (p->ht, hdom);
	if (sdb)
		sdb_delete (sdb, key);
}

R_API char *r_pair_get (RPair *p, const char *name) {
	Sdb *sdb;
	ut32 hdom;
	char *dom, *key = strdup (name);

	dom = r_str_lchr (key, '.');
	if (dom) {
		key = dom+1;
		*dom = 0;
		dom = 0;
	} else dom = "";
	hdom = r_str_hash (dom);
	sdb = r_hashtable_lookup (p->ht, hdom);
	if (sdb)
		return sdb_get (sdb, key);
	return strdup ("");
}

R_API void r_pair_set (RPair *p, const char *name, const char *value) {
	Sdb *sdb;
	ut32 hdom;
	char *dom, *key = strdup (name);

	dom = r_str_lchr (key, '.');
	if (dom) {
		key = dom+1;
		*dom = 0;
		dom = 0;
	} else dom = "";
	hdom = r_str_hash (dom);
	sdb = r_hashtable_lookup (p->ht, hdom);
	if (!sdb) {
		sdb = sdb_new (dom, 0);
		r_hashtable_insert (p->ht, hdom, sdb);
	}
	sdb_set (sdb, key, value);
}

R_API RList *r_pair_list (RPair *p, const char *domain) {
	return NULL;
}

R_API void r_pair_set_sync_dir (RPair *p, const char *dir) {
	free (p->dir);
	p->dir = strdup (dir);
}

// use sync dir
R_API void r_pair_load (RPair *p) {
	// TODO
}

R_API void r_pair_sync (RPair *p) {
	Sdb *s;
	RListIter *iter;
	// chdir
	r_list_foreach (p->dbs, iter, s) {
		sdb_sync (s);
	}
}
