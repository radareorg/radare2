/* radare - LGPL3 - Copyright 2016-2020 - c0riolis, x0urc3 */

#include "pyc_dis.h"

static const char *cmp_op[] = { "<", "<=", "==", "!=", ">", ">=", "in", "not in", "is", "is not", "exception match", "BAD" };

static const char *parse_arg(pyc_opcode_object *op, ut32 oparg, RList *names, RList *consts, RList *varnames, RList *interned_table, RList *freevars, RList *cellvars, RList *opcode_arg_fmt);

int r_pyc_disasm(RAsmOp *opstruct, const ut8 *code, RList *cobjs, RList *interned_table, ut64 pc, pyc_opcodes *ops) {
	pyc_code_object *cobj = NULL, *t = NULL;
	ut32 extended_arg = 0, i = 0, oparg;
	st64 start_offset, end_offset;
	RListIter *iter = NULL;

	r_list_foreach (cobjs, iter, t) {
		start_offset = t->start_offset;
		end_offset = t->end_offset;
		if (start_offset <= pc && pc < end_offset) { // pc in [start_offset, end_offset)
			cobj = t;
			break;
		}
	}

	if (cobj) {
		/* TODO: adding line number and offset */
		RList *varnames = cobj->varnames->data;
		RList *consts = cobj->consts->data;
		RList *names = cobj->names->data;
		RList *freevars = cobj->freevars->data;
		RList *cellvars = cobj->cellvars->data;

		ut8 op = code[i];
		i++;
		char *name = ops->opcodes[op].op_name;
		r_strbuf_set (&opstruct->buf_asm, name);
		if (!name) {
			return 0;
		}
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
			const char *arg = parse_arg (&ops->opcodes[op], oparg, names, consts, varnames, interned_table, freevars, cellvars, ops->opcode_arg_fmt);
			if (arg != NULL) {
				r_strbuf_appendf (&opstruct->buf_asm, "%20s", arg);
				free ((char *)arg);
			}
		} else if (ops->bits == 8) {
			i += 1;
		}

		return i;
	}
	return 0;
}

static char *generic_array_obj_to_string(RList *l);

static const char *parse_arg(pyc_opcode_object *op, ut32 oparg, RList *names, RList *consts, RList *varnames, RList *interned_table, RList *freevars, RList *cellvars, RList *opcode_arg_fmt) {
	pyc_object *t = NULL;
	const char *arg = NULL;
	pyc_code_object *tmp_cobj;
	pyc_arg_fmt *fmt;
	RListIter *i = NULL;

	// version-specific formatter for certain opcodes
	r_list_foreach (opcode_arg_fmt, i, fmt)
		if (!strcmp (fmt->op_name, op->op_name)) {
			return fmt->formatter (oparg);
		}

	if (op->type & HASCONST) {
		t = (pyc_object *)r_list_get_n (consts, oparg);
		if (t == NULL) {
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
			arg = generic_array_obj_to_string (t->data);
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
		t = (pyc_object *)r_list_get_n (names, oparg);
		if (t == NULL) {
			return NULL;
		}
		arg = r_str_new (t->data);
	}
	if ((op->type & HASJREL) || (op->type & HASJABS)) {
		arg = r_str_newf ("%u", oparg);
	}
	if (op->type & HASLOCAL) {
		t = (pyc_object *)r_list_get_n (varnames, oparg);
		if (!t)
			return NULL;
		arg = r_str_new (t->data);
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
			arg = r_str_newf ("%u", oparg);
			return arg;
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

static char *generic_array_obj_to_string(RList *l) {
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
