/* radare - LGPL - Copyright 2009-2010 */
/*   nibble<.ds@gmail.com> */
/*   pancake<nopcode.org> */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>
#include "../config.h"

static RAnalPlugin *anal_static_plugins[] = 
	{ R_ANAL_STATIC_PLUGINS };

static RAnalVarType anal_default_vartypes[] =
	{{ "char",  "b",  1 },
	 { "byte",  "b",  1 },
	 { "int",   "d",  4 },
	 { "int32", "d",  4 },
	 { "dword", "x",  4 },
	 { "float", "f",  4 },
	 { NULL,    NULL, 0 }};

R_API RAnal *r_anal_new() {
	int i;
	RAnalPlugin *static_plugin;
	RAnal *anal = R_NEW (RAnal);
	if (anal) {
		memset (anal, 0, sizeof (RAnal));
		anal->syscall = r_syscall_new ();
		anal->reg = NULL;
		anal->bbs = r_anal_bb_list_new ();
		anal->fcns = r_anal_fcn_list_new ();
		anal->refs = r_anal_ref_list_new ();
		anal->vartypes = r_anal_var_type_list_new ();
		r_anal_set_bits (anal, 32);
		r_anal_set_big_endian (anal, R_FALSE);
		INIT_LIST_HEAD (&anal->anals);
		for (i=0; anal_static_plugins[i]; i++) {
			static_plugin = R_NEW (RAnalPlugin);
			memcpy (static_plugin, anal_static_plugins[i], sizeof (RAnalPlugin));
			r_anal_add (anal, static_plugin);
		}
		for (i=0; anal_default_vartypes[i].name; i++)
			r_anal_var_type_add (anal, anal_default_vartypes[i].name,
					anal_default_vartypes[i].size, anal_default_vartypes[i].fmt);
	}
	return anal;
}

R_API RAnal *r_anal_free(RAnal *anal) {
	if (anal) {
		/* TODO: Free a->anals here */
		if (anal->bbs)
			r_list_free (anal->bbs);
		if (anal->fcns)
			r_list_free (anal->fcns);
		if (anal->vartypes)
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
			return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API int r_anal_set_bits(RAnal *anal, int bits) {
	switch (bits) {
	case 8:
	case 16:
	case 32:
	case 64:
		anal->bits = bits;
		return R_TRUE;
	}
	return R_FALSE;
}

R_API int r_anal_set_big_endian(RAnal *anal, int bigend) {
	anal->big_endian = bigend;
	return R_TRUE;
}

R_API char *r_anal_strmask (RAnal *anal, const char *data) {
	RAnalOp *aop;
	ut8 *buf;
	char *ret = NULL;
	int oplen, len, idx = 0;

	ret = strdup (data);
	buf = malloc (strlen (data));
	aop = r_anal_aop_new ();
	if (aop == NULL || ret == NULL || buf == NULL) {
		free (aop);
		free (buf);
		free (ret);
		return NULL;
	}
	len = r_hex_str2bin (data, buf);
	while (idx < len) {
		if ((oplen = r_anal_aop (anal, aop, 0, buf+idx, len-idx)) == 0)
			break;
		switch (aop->type) {
		case R_ANAL_OP_TYPE_CALL:
		case R_ANAL_OP_TYPE_UCALL:
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_UJMP:
			if (aop->nopcode != 0)
				memset (ret+(idx+aop->nopcode)*2, '.', (oplen-aop->nopcode)*2);
		}
		idx += oplen;
	}
	free (aop);
	free (buf);
	return ret;
}

R_API RList *r_anal_get_fcns (RAnal *anal) {
	if (anal)
		return anal->fcns;
	return NULL;
}
