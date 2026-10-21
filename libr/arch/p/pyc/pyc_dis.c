/* radare - LGPL3 - Copyright 2016-2025 - c0riolis, x0urc3, pancake, bemodtwz */

#include "pyc_dis.h"

#define CMP_OP_SIZE 12
static const char *cmp_op[CMP_OP_SIZE] = { "<", "<=", "==", "!=", ">", ">=", "in", "not in", "is", "is not", "exception match", "BAD" };

static char *parse_arg(pyc_opcode_object *op, ut32 oparg, pyc_code_object *cobj, RList *interned_table, RList *opcode_arg_fmt);

bool r_pyc_disasm(RAnalOp *opstruct, pyc_code_object *func, RList *interned_table, pyc_opcodes *ops, py_simple_op *so) {
	pyc_opcode_object *op_obj = &ops->opcodes[so->opcode];
	char *name = strdup (op_obj->op_name);
	if (!name) {
		free (name);
		return false;
	}
	r_str_case (name, false);
	opstruct->mnemonic = name;

	/* TODO: adding line number and offset */
	if (so->opcode >= so->have_arg) {
		char *arg = parse_arg (op_obj, so->arg, func, interned_table, ops->opcode_arg_fmt);
		if (arg) {
			char *nm = r_str_newf ("%s %s", opstruct->mnemonic, arg);
			free (opstruct->mnemonic);
			opstruct->mnemonic = nm;
			free (arg);
		}
	}
	return true;
}

static RList *list_from_pycobj(pyc_object *obj) {
	if (obj) {
		switch (obj->type) {
		case TYPE_DICT:
		case TYPE_FROZENSET:
		case TYPE_SET:
		case TYPE_LIST:
		case TYPE_TUPLE:
		case TYPE_SMALL_TUPLE:
			return obj->data;
		// TYPE_REF = 'r', // not sure????
		default:
			break;
		}
	}
	return NULL;
}

// names are string objects, any other type keeps no C string in data
static const char *str_from_pycobj(pyc_object *obj) {
	if (obj) {
		switch (obj->type) {
		case TYPE_ASCII:
		case TYPE_INTERNED:
		case TYPE_STRING:
		case TYPE_STRINGREF:
		case TYPE_UNICODE:
			return obj->data;
		default:
			break;
		}
	}
	return NULL;
}

static char *obj_tostring(pyc_object *obj);

static char *generic_array_obj_tostring(RList *l) {
	RListIter *iter;
	pyc_object *e;
	RStrBuf *sb = r_strbuf_new ("(");
	r_list_foreach (l, iter, e) {
		char *s = obj_tostring (e);
		r_strbuf_appendf (sb, "%s%s", iter == l->head? "": ",", r_str_get (s));
		free (s);
	}
	r_strbuf_append (sb, ")");
	return r_strbuf_drain (sb);
}

static char *obj_tostring(pyc_object *obj) {
	if (!obj) {
		return NULL;
	}
	switch (obj->type) {
	case TYPE_CODE_v0:
	case TYPE_CODE_v1: {
		pyc_code_object *co = obj->data;
		return r_str_newf ("CodeObject(%s) from %s",
			r_str_get (str_from_pycobj (co->name)),
			r_str_get (str_from_pycobj (co->filename)));
	}
	case TYPE_DICT:
	case TYPE_TUPLE:
	case TYPE_SET:
	case TYPE_FROZENSET:
	case TYPE_LIST:
	case TYPE_SMALL_TUPLE:
		return generic_array_obj_tostring (obj->data);
	case TYPE_STRING:
	case TYPE_INTERNED:
	case TYPE_STRINGREF:
		return r_str_newf ("'%s'", (char *)obj->data);
	case TYPE_ELLIPSIS:
		return strdup ("Ellipsis");
	case TYPE_STOPITER:
		return strdup ("StopIteration");
	default:
		// the remaining scalar types keep their text in data
		return r_str_new (obj->data);
	}
}

static char *parse_arg(pyc_opcode_object *op, ut32 oparg, pyc_code_object *cobj, RList *interned_table, RList *opcode_arg_fmt) {
	pyc_object *t = NULL;
	char *arg = NULL;
	pyc_arg_fmt *fmt;
	RListIter *i = NULL;

	// TODO: don't traverse if you are not going to use
	// Also, this should probably be more stringent on the allowed types
	RList *varnames = list_from_pycobj (R_UNWRAP2 (cobj, varnames));
	RList *consts = list_from_pycobj (R_UNWRAP2 (cobj, consts));
	RList *names = list_from_pycobj (R_UNWRAP2 (cobj, names));
	RList *freevars = list_from_pycobj (R_UNWRAP2 (cobj, freevars));
	RList *cellvars = list_from_pycobj (R_UNWRAP2 (cobj, cellvars));

	// version-specific formatter for certain opcodes
	r_list_foreach (opcode_arg_fmt, i, fmt)
		if (!strcmp (fmt->op_name, op->op_name)) {
			return fmt->formatter (oparg);
		}

	if (op->type & HASCONST) {
		if (!consts) {
			return NULL;
		}
		arg = obj_tostring (r_list_get_n (consts, oparg));
	}
	if (op->type & HASNAME) {
		if (names) {
			return r_str_new (str_from_pycobj (r_list_get_n (names, oparg)));
		}
		return NULL;
	}
	if ((op->type & HASJREL) || (op->type & HASJABS)) {
		arg = r_str_newf ("%u", oparg);
	}
	if (op->type & HASLOCAL) {
		if (varnames) {
			return r_str_new (str_from_pycobj (r_list_get_n (varnames, oparg)));
		}
		return NULL;
	}
	if (op->type & HASCOMPARE) {
		if (oparg < 0 || oparg >= CMP_OP_SIZE) {
			return NULL;
		}
		arg = strdup (cmp_op[oparg]);
	}
	if (op->type & HASFREE) {
		if (!cellvars || !freevars) {
			arg = r_str_newf ("%u", oparg);
			return arg;
		}
		if (oparg < r_list_length (cellvars)) {
			t = (pyc_object *)r_list_get_n (cellvars, oparg);
		} else if ((oparg - r_list_length (cellvars)) < r_list_length (freevars)) {
			t = (pyc_object *)r_list_get_n (freevars, oparg);
		} else {
			return r_str_newf ("%u", oparg);
		}
		arg = r_str_new (str_from_pycobj (t));
	}
	if (op->type & (HASVARGS | HASNARGS)) {
		arg = r_str_newf ("%u", oparg);
	}
	return arg;
}
