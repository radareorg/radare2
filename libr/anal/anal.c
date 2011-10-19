/* radare - LGPL - Copyright 2009-2011 */
/* - nibble<.ds@gmail.com> + pancake<nopcode.org> */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>
#include "../config.h"

static RAnalPlugin *anal_static_plugins[] = 
	{ R_ANAL_STATIC_PLUGINS };

static RAnalVarType anal_default_vartypes[] =
	{{ "char",  "c",  1 },
	 { "byte",  "b",  1 },
	 { "int",   "i",  4 },
	 { "int32", "d",  4 },
	 { "int64", "q",  8 },
	 { "dword", "x",  4 },
	 { "float", "f",  4 },
	 { NULL,    NULL, 0 }};

R_API RAnal *r_anal_new() {
	int i;
	RAnalPlugin *static_plugin;
	RAnal *anal = R_NEW (RAnal);
	if (!anal)
		return NULL;
	memset (anal, 0, sizeof (RAnal));
	anal->diff_ops = 0;
	anal->diff_thbb = R_ANAL_THRESHOLDBB;
	anal->diff_thfcn = R_ANAL_THRESHOLDFCN;
	anal->split = R_TRUE; // used from core
	anal->queued = NULL;
	anal->meta = r_meta_new ();
	anal->syscall = r_syscall_new ();
	r_io_bind_init (anal->iob);
	anal->reg = r_reg_new ();
	anal->lineswidth = 0;
	anal->fcns = r_anal_fcn_list_new ();
	anal->fcnstore = r_listrange_new ();
	anal->refs = r_anal_ref_list_new ();
	anal->vartypes = r_anal_var_type_list_new ();
	r_anal_set_bits (anal, 32);
	r_anal_set_big_endian (anal, R_FALSE);
	INIT_LIST_HEAD (&anal->anals); // TODO: use RList here
	for (i=0; anal_static_plugins[i]; i++) {
		static_plugin = R_NEW (RAnalPlugin);
		memcpy (static_plugin, anal_static_plugins[i], sizeof (RAnalPlugin));
		r_anal_add (anal, static_plugin);
	}
	for (i=0; anal_default_vartypes[i].name; i++)
		r_anal_var_type_add (anal, anal_default_vartypes[i].name,
				anal_default_vartypes[i].size, anal_default_vartypes[i].fmt);
	return anal;
}

R_API RAnal *r_anal_free(RAnal *anal) {
	if (anal) {
		/* TODO: Free anals here */
		r_listrange_free (anal->fcnstore);
		r_list_free (anal->fcns);
		r_list_free (anal->vartypes);
	}
	free (anal);
	return NULL;
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
		printf ("anal %-10s %s\n", h->name, h->desc);
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

R_API RList *r_anal_get_fcns(RAnal *anal) {
	return anal->fcns;
}

/* XXX: Move this function into fcn.c !!! */
R_API RAnalFcn *r_anal_get_fcn_at(RAnal *anal, ut64 addr) {
	RAnalFcn *fcni;
	RListIter *iter;
eprintf ("DEPRECATED: get-at\n");
	r_list_foreach (anal->fcns, iter, fcni)
		if (fcni->addr == addr)
			return fcni;
	return NULL;
}

R_API void r_anal_trace_bb(RAnal *anal, ut64 addr) {
	RAnalBlock *bbi;
	RAnalFcn *fcni;
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
