/* radare - LGPL - Copyright 2019 - nibble, pancake */

#include <stdio.h>
#include <string.h>
#include <r_core.h>

static bool matchBytes(RSignItem *a, RSignItem *b) {
	if (a->bytes && b->bytes) {
		if (a->bytes->size == b->bytes->size) {
			return !memcmp (a->bytes->bytes, b->bytes->bytes, b->bytes->size);
		}
	}
	return false;
}

static bool matchGraph(RSignItem *a, RSignItem *b) {
	if (a->graph && b->graph) {
		if (a->graph->cc != b->graph->cc) {
			return false;
		}
		if (a->graph->nbbs != b->graph->nbbs) {
			return false;
		}
		if (a->graph->ebbs != b->graph->ebbs) {
			return false;
		}
		if (a->graph->edges != b->graph->edges) {
			return false;
		}
		if (a->graph->bbsum!= b->graph->bbsum) {
			return false;
		}
		return true;
	}
	return false;
}

R_API int r_core_zdiff(RCore *c, RCore *c2) {
	if (!c || !c2) {
		return false;
	}
	////////// moove this into anal/sign
	SdbList *a = sdb_foreach_list (c->anal->sdb_zigns, false);
	SdbList *b = sdb_foreach_list (c2->anal->sdb_zigns, false);

	eprintf ("Diff %d %d\n", (int)ls_length (a), (int)ls_length (b));
	SdbListIter *iter;
	SdbKv *kv;
	RList *la = r_list_new ();
	ls_foreach (a, iter, kv) {
		RSignItem *it = r_sign_item_new ();
		if (r_sign_deserialize (c->anal, it, kv->base.key, kv->base.value)) {
			r_list_append (la, it);
		} else {
			r_sign_item_free (it);
		}
	}
	RList *lb = r_list_new ();
	ls_foreach (b, iter, kv) {
		RSignItem *it = r_sign_item_new ();
		if (r_sign_deserialize (c2->anal, it, kv->base.key, kv->base.value)) {
			r_list_append (lb, it);
		} else {
			r_sign_item_free (it);
		}
	}
	//////////
	RListIter *itr;
	RListIter *itr2;
	RSignItem *si;
	RSignItem *si2;

	// do the sign diff here
	r_list_foreach (la, itr, si) {
		//eprintf ("-- %s\n", si->name);
		if (strstr (si->name, "imp.")) {
			continue;
		}
		r_list_foreach (lb, itr2, si2) {
			if (strstr (si2->name, "imp.")) {
				continue;
			}
			if (matchBytes (si, si2)) {
				eprintf ("0x%08"PFMT64x" 0x%08"PFMT64x" B %s\n", si->addr, si2->addr, si->name);
			}
			if (matchGraph (si, si2)) {
				eprintf ("0x%08"PFMT64x" 0x%08"PFMT64x" G %s\n", si->addr, si2->addr, si->name);
			}
		}
	}
	
	/* Diff functions */
	// r_anal_diff_fcn (cores[0]->anal, cores[0]->anal->fcns, cores[1]->anal->fcns);

	return true;
}
