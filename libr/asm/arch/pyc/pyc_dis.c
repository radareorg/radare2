/* radare - LGPL3 - Copyright 2016-2021 - c0riolis, x0urc3, pancake */

#include "pyc_dis.h"

static const char *cmp_op[] = { "<", "<=", "==", "!=", ">", ">=", "in", "not in", "is", "is not", "exception match", "BAD" };

static char *parse_arg(pyc_opcode_object *op, ut32 oparg, RList *names, RList *consts, RList *varnames, RList *interned_table, RList *freevars, RList *cellvars, RList *opcode_arg_fmt);

int r_pyc_disasm(RAnalOp *opstruct, const ut8 *code, RList *cobjs, RList *interned_table, ut64 pc, pyc_opcodes *ops) {
	pyc_code_object *cobj = NULL, *t = NULL;
	ut32 extended_arg = 0, i = 0, oparg;
	st64 start_offset, end_offset;
	RListIter *iter = NULL;

	if (cobjs) {
		r_list_foreach (cobjs, iter, t) {
			start_offset = t->start_offset;
			end_offset = t->end_offset;
			// pc in [start_offset, end_offset)
			if (start_offset <= pc && pc < end_offset) {
				cobj = t;
				break;
			}
		}
	}

	/* TODO: adding line number and offset */
	RList *varnames = cobj? cobj->varnames->data: NULL;
	RList *consts = cobj?cobj->consts->data: NULL;
	RList *names = cobj?cobj->names->data: NULL;
	RList *freevars = cobj?cobj->freevars->data: NULL;
	RList *cellvars = cobj? cobj->cellvars->data: NULL;

	ut8 op = code[i];
	i++;
	char *name = strdup (ops->opcodes[op].op_name);
	if (!name) {
		return 0;
	}
	r_str_case (name, 0);
	opstruct->mnemonic = strdup (name);
	free (name);
	if (op >= ops->have_argument) {
		if (ops->bits == 16) {
			oparg = code[i] + code[i + 1] * 256 + extended_arg;
			i += 2;
		} else {
			oparg = code[i] + extended_arg;
			i += 1;
		}
		extended_arg = 0;
		if (op == ops->extended_arg) {
			if (ops->bits == 16) {
				extended_arg = oparg * 65536;
			} else {
				extended_arg = oparg << 8;
			}
		}
		char *arg = parse_arg (&ops->opcodes[op], oparg, names,
			consts, varnames, interned_table, freevars, cellvars,
			ops->opcode_arg_fmt);
		if (arg) {
			char *nm = r_str_newf ("%s %s", opstruct->mnemonic, arg);
			free (opstruct->mnemonic);
			opstruct->mnemonic = nm;
			free ((char *)arg);
		}
	} else if (ops->bits == 8) {
		i += 1;
	}

	return i;
}

static char *generic_array_obj_tostring(RList *l);

static char *parse_arg(pyc_opcode_object *op, ut32 oparg, RList *names, RList *consts, RList *varnames, RList *interned_table, RList *freevars, RList *cellvars, RList *opcode_arg_fmt) {
	pyc_object *t = NULL;
	char *arg = NULL;
	pyc_code_object *tmp_cobj;
	pyc_arg_fmt *fmt;
	RListIter *i = NULL;

	// version-specific formatter for certain opcodes
	r_list_foreach (opcode_arg_fmt, i, fmt)
		if (!strcmp (fmt->op_name, op->op_name)) {
			return fmt->formatter (oparg);
		}

	if (op->type & HASCONST) {
		if (!consts) {
			return NULL;
		}
		t = (pyc_object *)r_list_get_n (consts, oparg);
		if (!t) {
			return NULL;
		}
		switch (t->type) {
		case TYPE_CODE_v0:
		case TYPE_CODE_v1:
			tmp_cobj = t->data;
			arg = r_str_newf ("CodeObject(%s) from %s", (char *)tmp_cobj->name->data, (char *)tmp_cobj->filename->data);
			break;
		case TYPE_TUPLE:
		case TYPE_SET:
		case TYPE_FROZENSET:
		case TYPE_LIST:
		case TYPE_SMALL_TUPLE:
			arg = generic_array_obj_tostring (t->data);
			break;
		case TYPE_STRING:
		case TYPE_INTERNED:
		case TYPE_STRINGREF:
			arg = r_str_newf ("'%s'", (char *)t->data);
			break;
		default:
			arg = r_str_new (t->data);
		}
	}
	if (op->type & HASNAME) {
		if (names) {
			t = (pyc_object *)r_list_get_n (names, oparg);
			if (t) {
				return r_str_new (t->data);
			}
		}
		return NULL;
	}
	if ((op->type & HASJREL) || (op->type & HASJABS)) {
		arg = r_str_newf ("%u", oparg);
	}
	if (op->type & HASLOCAL) {
		if (varnames) {
			t = (pyc_object *)r_list_get_n (varnames, oparg);
			if (t) {
				return strdup (t->data);
			}
		}
		return NULL;
	}
	if (op->type & HASCOMPARE) {
		arg = r_str_new (cmp_op[oparg]);
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
		if (!t) {
			return NULL;
		}

		arg = r_str_new (t->data);
	}
	if (op->type & HASNARGS) {
		arg = r_str_newf ("%u", oparg);
	}
	if (op->type & HASVARGS) {
		arg = r_str_newf ("%u", oparg);
	}

	return arg;
}

static char *generic_array_obj_tostring(RList *l) {
	RListIter *iter = NULL;
	pyc_object *e = NULL;

	RStrBuf *rbuf = r_strbuf_new (NULL);

	r_list_foreach (l, iter, e) {
		r_strbuf_append (rbuf, e->data);
		r_strbuf_append (rbuf, ",");
	}

	char *buf = r_strbuf_get (rbuf);

	/* remove last , */
	buf[strlen (buf) - 1] = '\0';
	char *r = r_str_newf ("(%s)", buf);

	r_strbuf_free (rbuf);
	return r;
}
