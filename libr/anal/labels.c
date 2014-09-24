/* radare - LGPL - Copyright 2014 - pancake */

#include <r_anal.h>

#define DB anal->sdb_fcns

// list of all the labels for a specific function
#define LABELS sdb_fmt (0, "fcn.%"PFMT64x".labels", fcn->addr)
// value of each element in the labels list
#define ADDRLABEL(x,y) sdb_fmt (1, "0x%"PFMT64x"/%s", x,y)
// resolve by name
#define LABEL(x) sdb_fmt (2, "fcn.%"PFMT64x".label.%s", fcn->addr, x)
// resolve by addr
#define ADDR(x) sdb_fmt (3, "fcn.%"PFMT64x".label.0x%"PFMT64x, fcn->addr,x)
// SDB looks like fcn.0x80480408.labels=0x8048480/patata,0x0405850/potro

R_API ut64 r_anal_fcn_label_get (RAnal *anal, RAnalFunction *fcn, const char *name) {
	if (!anal || !fcn)
		return UT64_MAX;
	return sdb_num_get (DB, LABEL(name), NULL);
}

R_API const char *r_anal_fcn_label_at (RAnal *anal, RAnalFunction *fcn, ut64 addr) {
	if (!anal || !fcn)
		return NULL;
	return sdb_const_get (DB, ADDR(addr), NULL);
}

R_API int r_anal_fcn_label_set (RAnal *anal, RAnalFunction *fcn, const char *name, ut64 addr) {
	if (!anal || !fcn)
		return R_FALSE;
	if (sdb_add (DB, ADDR(addr), name, 0)) {
		if (sdb_num_add (DB, LABEL(name), addr, 0)) {
			sdb_array_add (DB, LABELS, ADDRLABEL (addr, name), 0);
			return R_TRUE;
		} else {
			sdb_unset (DB, ADDR(addr), 0);
		}
	}
	return R_FALSE;
}

R_API int r_anal_fcn_label_del (RAnal *anal, RAnalFunction *fcn, const char *name, ut64 addr) {
	if (!anal || !fcn || !name)
		return R_FALSE;
	sdb_array_remove (DB, LABELS, ADDRLABEL (addr, name), 0);
	sdb_unset (DB, LABEL(name), 0);
	sdb_unset (DB, ADDR(addr), 0);
	return R_TRUE;
}

R_API int r_anal_fcn_labels (RAnal *anal, RAnalFunction *fcn, int rad) {
	if (!anal || !fcn)
		return 0;
	
	if (fcn) {
		char *cur, *token;
		char *str = sdb_get (DB, LABELS, 0);
		sdb_aforeach (cur, str) {
			struct {
				ut64 addr;
				char *name;
			} loc;
			token = strchr (cur, '/');
			if (!token)
				break;
			*token = ',';
			sdb_fmt_tobin (cur, "qz", &loc);
			switch (rad) {
			case '*':
			case 1:
				anal->printf ("f.%s@0x%08"PFMT64x"\n",
					loc.name, loc.addr);
				break;
			case 'j':
				eprintf ("TODO\n");
				break;
			default:
				anal->printf ("0x%08"PFMT64x" %s   [%s + %"PFMT64d"]\n",
					loc.addr,
					loc.name, fcn->name,
					loc.addr - fcn->addr, loc.addr);
			}
			*token = '/';
			sdb_fmt_free (&loc, "qz");
			sdb_aforeach_next (cur);
		}
		free (str);
	} else {
		RAnalFunction *f;
		RListIter *iter;
		r_list_foreach (anal->fcns, iter, f) {
			r_anal_fcn_labels (anal, f, rad);
		}
	}
	return R_TRUE;
}
