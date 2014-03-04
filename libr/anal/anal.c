/* radare - LGPL - Copyright 2009-2014 - pancake, nibble */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>
#include <r_io.h>
#include "../config.h"

R_LIB_VERSION(r_anal);

static RAnalPlugin *anal_static_plugins[] =
	{ R_ANAL_STATIC_PLUGINS };

/*
static RAnalVarType anal_default_vartypes[] =
	{{ "char",  "c",  1 },
	 { "byte",  "b",  1 },
	 { "int",   "i",  4 },
	 { "int32", "d",  4 },
	 { "int64", "q",  8 },
	 { "dword", "x",  4 },
	 { "float", "f",  4 },
	 { NULL,    NULL, 0 }};
*/

static void r_anal_type_init(RAnal *anal) {
	Sdb *D = anal->sdb_types;
	sdb_set (D, "unsigned int", "type", 0);
	sdb_set (D, "int", "type", 0);
	sdb_set (D, "long", "type", 0);
	sdb_set (D, "void *", "type", 0);
	sdb_set (D, "char", "type", 0);
	sdb_set (D, "char*", "type", 0);
	sdb_set (D, "const char*", "type", 0);
	sdb_set (D, "type.unsigned int", "i", 0);
	sdb_set (D, "type.int", "d", 0);
	sdb_set (D, "type.long", "x", 0);
	sdb_set (D, "type.void *", "p", 0);
	sdb_set (D, "type.char", "x", 0);
	sdb_set (D, "type.char*", "*z", 0);
	sdb_set (D, "type.const char*", "*z", 0);
}

R_API RAnal *r_anal_new() {
	int i;
	RAnalPlugin *static_plugin;
	RAnal *anal = R_NEW0 (RAnal);
	if (!anal) return NULL;
	anal->cpu = NULL;
	anal->decode = R_TRUE; // slow slow if not used
	anal->sdb_vars = sdb_new (NULL, NULL, 0);
	anal->sdb_refs = sdb_new (NULL, NULL, 0);
	anal->sdb_args = sdb_new (NULL, NULL, 0);
	anal->sdb_ret = sdb_new (NULL, NULL, 0);
	anal->sdb_locals = sdb_new (NULL, NULL, 0);
	anal->sdb_xrefs = NULL;
	anal->sdb_types = sdb_new (NULL, NULL, 0);
	anal->sdb_meta = sdb_new (NULL, NULL, 0);
	r_meta_init (anal);
	anal->printf = (PrintfCallback) printf;
	r_anal_type_init (anal);
	r_anal_xrefs_init (anal);
	anal->diff_ops = 0;
	anal->diff_thbb = R_ANAL_THRESHOLDBB;
	anal->diff_thfcn = R_ANAL_THRESHOLDFCN;
	anal->split = R_TRUE; // used from core
	anal->queued = NULL;
	anal->syscall = r_syscall_new ();
	r_io_bind_init (anal->iob);
	anal->reg = r_reg_new ();
	anal->lineswidth = 0;
	anal->fcns = r_anal_fcn_list_new ();
#if USE_NEW_FCN_STORE
	anal->fcnstore = r_listrange_new ();
#endif
	anal->hints = r_list_new ();
	anal->refs = r_anal_ref_list_new ();
	anal->types = r_anal_type_list_new ();
	r_anal_set_bits (anal, 32);
	r_anal_set_big_endian (anal, R_FALSE);
	INIT_LIST_HEAD (&anal->anals); // TODO: use RList here
	for (i=0; anal_static_plugins[i]; i++) {
		static_plugin = R_NEW (RAnalPlugin);
		memcpy (static_plugin, anal_static_plugins[i], sizeof (RAnalPlugin));
		r_anal_add (anal, static_plugin);
	}
/*
	for (i=0; anal_default_vartypes[i].name; i++)
		r_anal_var_type_add (anal, anal_default_vartypes[i].name,
				anal_default_vartypes[i].size, anal_default_vartypes[i].fmt);
*/
	return anal;
}

R_API void r_anal_free(RAnal *a) {
	if (!a) return;
	/* TODO: Free anals here */
	free (a->cpu);
	a->cpu = NULL;
	a->fcns->free = r_anal_fcn_free;
	r_list_free (a->fcns);
	// r_listrange_free (anal->fcnstore); // might provoke double frees since this is used in r_anal_fcn_insert()
	r_list_free (a->refs);
	r_list_free (a->types);
	r_list_free (a->hints);
	r_meta_fini (a);
	r_reg_free(a->reg);
	r_syscall_free (a->syscall);
	r_anal_op_free (a->queued);

	sdb_free (a->sdb_vars);
	sdb_free (a->sdb_refs);
	sdb_free (a->sdb_args);
	sdb_free (a->sdb_locals);
	// r_io_free(anal->iob.io); // need r_core (but recursive problem to fix)
	free (a);
}

R_API void r_anal_set_user_ptr(RAnal *anal, void *user) {
	anal->user = user;
}

R_API int r_anal_add(RAnal *anal, RAnalPlugin *foo) {
	if (foo->init)
		foo->init (anal->user);
	list_add_tail (&(foo->list), &(anal->anals));
	return R_TRUE;
}

// TODO: Must be deprecated
R_API int r_anal_list(RAnal *anal) {
	struct list_head *pos;
	list_for_each_prev(pos, &anal->anals) {
		RAnalPlugin *h = list_entry(pos, RAnalPlugin, list);
		anal->printf ("anal %-10s %s\n", h->name, h->desc);
	}
	return R_FALSE;
}

R_API int r_anal_use(RAnal *anal, const char *name) {
	struct list_head *pos;
	list_for_each (pos, &anal->anals) { // XXX: must be _prevmust be _prev
		RAnalPlugin *h = list_entry(pos, RAnalPlugin, list);
		if (!strcmp (h->name, name)) {
			anal->cur = h;
			r_anal_set_reg_profile (anal);
			return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API int r_anal_set_reg_profile(RAnal *anal) {
	if (anal && anal->cur && anal->cur->set_reg_profile)
		return anal->cur->set_reg_profile (anal);
	return R_FALSE;
}

R_API int r_anal_set_bits(RAnal *anal, int bits) {
	switch (bits) {
	case 8:
	case 16:
	case 32:
	case 64:
		anal->bits = bits;
		r_anal_set_reg_profile (anal);
		return R_TRUE;
	}
	return R_FALSE;
}

R_API void r_anal_set_cpu(RAnal *anal, const char *cpu) {
	free (anal->cpu);
	anal->cpu = cpu ? strdup (cpu) : NULL;
}

R_API int r_anal_set_big_endian(RAnal *anal, int bigend) {
	anal->big_endian = bigend;
	return R_TRUE;
}

R_API char *r_anal_strmask (RAnal *anal, const char *data) {
	RAnalOp *op;
	ut8 *buf;
	char *ret = NULL;
	int oplen, len, idx = 0;

	ret = strdup (data);
	buf = malloc (1+strlen (data));
	op = r_anal_op_new ();
	if (op == NULL || ret == NULL || buf == NULL) {
		free (op);
		free (buf);
		free (ret);
		return NULL;
	}
	len = r_hex_str2bin (data, buf);
	while (idx < len) {
		if ((oplen = r_anal_op (anal, op, 0, buf+idx, len-idx)) == 0)
			break;
		switch (op->type) {
		case R_ANAL_OP_TYPE_CALL:
		case R_ANAL_OP_TYPE_UCALL:
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_UJMP:
			if (op->nopcode != 0)
				memset (ret+(idx+op->nopcode)*2, '.', (oplen-op->nopcode)*2);
		}
		idx += oplen;
	}
	free (op);
	free (buf);
	return ret;
}

R_API void r_anal_trace_bb(RAnal *anal, ut64 addr) {
	RAnalBlock *bbi;
	RAnalFunction *fcni;
	RListIter *iter, *iter2;
	VERBOSE_ANAL eprintf ("bbtraced\n"); // XXX Debug msg
	r_list_foreach (anal->fcns, iter, fcni) {
		r_list_foreach (fcni->bbs, iter2, bbi) {
			if (addr>=bbi->addr && addr<(bbi->addr+bbi->size)) {
				bbi->traced = R_TRUE;
				break;
			}
		}
	}
}

R_API RList* r_anal_get_fcns (RAnal *anal) { return anal->fcns; }

R_API int r_anal_project_load(RAnal *anal, const char *prjfile) {
	if (!prjfile || !*prjfile)
		return R_FALSE;
	r_anal_xrefs_load (anal, prjfile);
	return R_TRUE;
}

R_API int r_anal_project_save(RAnal *anal, const char *prjfile) {
	if (!prjfile || !*prjfile)
		return R_FALSE;
	r_anal_xrefs_save (anal, prjfile);
	return R_TRUE;
}

R_API RAnalOp *r_anal_op_hexstr(RAnal *anal, ut64 addr, const char *str) {
	int len;
	ut8 *buf;
	RAnalOp *op = R_NEW0 (RAnalOp);
	buf = malloc (strlen (str)+1);
	len = r_hex_str2bin (str, buf);
	r_anal_op (anal, op, addr, buf, len);
	return op;
}
