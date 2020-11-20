#include "opcode.h"

static version_opcode version_op[] = {
	{ "1.0.1", opcode_10 },
	{ "1.1", opcode_11 },
	{ "1.2", opcode_12 },
	{ "1.3b1", opcode_13 },
	{ "1.4", opcode_14 },
	{ "1.4b1", opcode_14 },
	{ "1.5a1", opcode_15 },
	{ "1.6a2", opcode_16 },
	{ "2.0b1", opcode_20 },
	{ "2.1a1", opcode_21 },
	{ "2.1a2", opcode_21 },
	{ "2.2a0", opcode_22 },
	{ "2.2a1", opcode_22 },
	{ "2.3a0", opcode_23 },
	{ "2.4a0", opcode_24 },
	{ "2.4a2", opcode_24 },
	{ "2.4a3", opcode_24 },
	{ "2.5a0", opcode_25 },
	{ "2.5b2", opcode_25 },
	{ "2.5c3", opcode_25 },
	{ "2.6a0", opcode_26 },
	{ "2.6a1+", opcode_26 },
	{ "2.7a0", opcode_27 },
	{ "2.7a2+", opcode_27 },
	{ "3.0a1", opcode_30 },
	{ "3.0a1+", opcode_30 },
	{ "3.0a2", opcode_30 },
	{ "3.0a2+", opcode_30 },
	{ "3.0a3+", opcode_30 },
	{ "3.0a5+", opcode_30 },
	{ "3.0x", opcode_30 },
	{ "3.1a0", opcode_31 },
	{ "3.2a0", opcode_32 },
	{ "3.2a1+", opcode_32 },
	{ "3.2a2+", opcode_33 },
	{ "3.3.0a0", opcode_33 },
	{ "3.3.0a1+", opcode_33 },
	{ "3.3.0a3+", opcode_33 },
	{ "3.3a0", opcode_33 },
	{ "3.4.0a0", opcode_34 },
	{ "3.4.0a3+", opcode_34 },
	{ "3.4.0rc1+", opcode_34 },
	{ "3.5.0a0", opcode_35 },
	{ "3.5.0a4+", opcode_35 },
	{ "3.5.0b1+", opcode_35 },
	{ "3.5.0b2+", opcode_35 },
	{ "3.6.0a0", opcode_36 },
	{ "v3.6.0", opcode_36 },
	{ "v3.6.0a2", opcode_36 },
	{ "v3.6.0a3", opcode_36 },
	{ "v3.6.0a4", opcode_36 },
	{ "v3.6.0b1", opcode_36 },
	{ "v3.6.0b2", opcode_36 },
	{ "v3.6.0b3", opcode_36 },
	{ "v3.6.0b4", opcode_36 },
	{ "v3.6.0rc1", opcode_36 },
	{ "v3.6.0rc2", opcode_36 },
	{ "v3.6.1", opcode_36 },
	{ "v3.6.10", opcode_36 },
	{ "v3.6.10rc", opcode_36 },
	{ "v3.6.1rc1", opcode_36 },
	{ "v3.6.2", opcode_36 },
	{ "v3.6.2rc1", opcode_36 },
	{ "v3.6.2rc2", opcode_36 },
	{ "v3.6.3", opcode_36 },
	{ "v3.6.3rc1", opcode_36 },
	{ "v3.6.4", opcode_36 },
	{ "v3.6.4rc1", opcode_36 },
	{ "v3.6.5", opcode_36 },
	{ "v3.6.5rc1", opcode_36 },
	{ "v3.6.6", opcode_36 },
	{ "v3.6.6rc1", opcode_36 },
	{ "v3.6.7", opcode_36 },
	{ "v3.6.7rc1", opcode_36 },
	{ "v3.6.7rc2", opcode_36 },
	{ "v3.6.8", opcode_36 },
	{ "v3.6.8rc1", opcode_36 },
	{ "v3.6.9", opcode_36 },
	{ "v3.6.9rc1", opcode_36 },
	{ "v3.7.0", opcode_37 },
	{ "v3.7.0a1", opcode_37 },
	{ "v3.7.0a2", opcode_37 },
	{ "v3.7.0a3", opcode_37 },
	{ "v3.7.0a4", opcode_37 },
	{ "v3.7.0b1", opcode_37 },
	{ "v3.7.0b2", opcode_37 },
	{ "v3.7.0b3", opcode_37 },
	{ "v3.7.0b4", opcode_37 },
	{ "v3.7.0b5", opcode_37 },
	{ "v3.7.0rc1", opcode_37 },
	{ "v3.7.1", opcode_37 },
	{ "v3.7.1rc1", opcode_37 },
	{ "v3.7.1rc2", opcode_37 },
	{ "v3.7.2", opcode_37 },
	{ "v3.7.2rc1", opcode_37 },
	{ "v3.7.3", opcode_37 },
	{ "v3.7.3rc1", opcode_37 },
	{ "v3.7.4", opcode_37 },
	{ "v3.7.4rc1", opcode_37 },
	{ "v3.7.4rc2", opcode_37 },
	{ "v3.7.5", opcode_37 },
	{ "v3.7.5rc1", opcode_37 },
	{ "v3.7.6", opcode_37 },
	{ "v3.7.6rc1", opcode_37 },
	{ "v3.8.0", opcode_38 },
	{ "v3.8.0a1", opcode_38 },
	{ "v3.8.0a2", opcode_38 },
	{ "v3.8.0a3", opcode_38 },
	{ "v3.8.0a4", opcode_38 },
	{ "v3.8.0b1", opcode_38 },
	{ "v3.8.0b2", opcode_38 },
	{ "v3.8.0b3", opcode_38 },
	{ "v3.8.0b4", opcode_38 },
	{ "v3.8.0rc1", opcode_38 },
	{ "v3.8.1", opcode_38 },
	{ "v3.8.1rc1", opcode_38 },
	{ "v3.9.0a1", opcode_39 },
	{ "v3.9.0a2", opcode_39 },
	{ "v3.9.0a3", opcode_39 },
	{ NULL, NULL },
};

bool pyc_opcodes_equal(pyc_opcodes *op, const char *version) {
	version_opcode *vop = version_op;

	while (vop->version) {
		if (!strcmp (vop->version, version)) {
			if (vop->opcode_func == (pyc_opcodes * (*)()) (op->version_sig)) {
				return true;
			}
		}
		vop++;
	}

	return false;
}

pyc_opcodes *get_opcode_by_version(char *version) {
	version_opcode *vop = version_op;

	while (vop->version) {
		if (!strcmp (vop->version, version)) {
			return vop->opcode_func ();
		}
		vop++;
	}

	return NULL; // No match version
}

pyc_opcodes *new_pyc_opcodes() {
	size_t i, j;
	pyc_opcodes *ret = R_NEW0 (pyc_opcodes);
	if (!ret) {
		return NULL;
	}
	ret->have_argument = 90;
	ret->opcodes = malloc (sizeof (pyc_opcode_object) * 256);
	if (!ret->opcodes) {
		free (ret);
		return NULL;
	}
	for (i = 0; i < 256; i++) {
		ret->opcodes[i].op_name = r_str_newf ("<%zu>", i);
		if (!ret->opcodes[i].op_name) {
			for (j = 0; j < i; j++) {
				free (ret->opcodes[j].op_name);
			}
			free (ret->opcodes);
			R_FREE (ret);
			return NULL;
		}
		ret->opcodes[i].type = 0;
		ret->opcodes[i].op_code = i;
		ret->opcodes[i].op_push = 0;
		ret->opcodes[i].op_pop = 0;
	}

	ret->opcode_arg_fmt = r_list_newf ((RListFree)free);
	return ret;
}

void free_opcode(pyc_opcodes *opcodes) {
	size_t i;
	for (i = 0; i < 256; i++) {
		free (opcodes->opcodes[i].op_name);
	}
	free (opcodes->opcodes);
	r_list_free (opcodes->opcode_arg_fmt);
	free (opcodes);
}

void add_arg_fmt(pyc_opcodes *ret, char *op_name, const char *(*formatter) (ut32 oparg)) {
	pyc_arg_fmt *fmt = R_NEW0 (pyc_arg_fmt);
	if (!fmt) {
		return;
	}
	fmt->op_name = op_name;
	fmt->formatter = formatter;
	r_list_append (ret->opcode_arg_fmt, fmt);
}

void (def_opN)(struct op_parameter par) {
	free (par.op_obj[par.op_code].op_name);
	par.op_obj[par.op_code].op_name = strdup (par.op_name);
	par.op_obj[par.op_code].op_code = par.op_code;
	par.op_obj[par.op_code].op_pop = par.pop;
	par.op_obj[par.op_code].op_push = par.push;
	if (!par.fallthrough) {
		par.op_obj[par.op_code].type |= NOFOLLOW;
	}
}

void (name_opN)(struct op_parameter par) {
	def_op (.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push);
	par.op_obj[par.op_code].type |= HASNAME;
}

void (local_opN)(struct op_parameter par) {
	def_op (.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push);
	par.op_obj[par.op_code].type |= HASLOCAL;
}

void (free_opN)(struct op_parameter par) {
	def_op (.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push);
	par.op_obj[par.op_code].type |= HASFREE;
}

void (store_opN)(struct op_parameter par) {
	switch (par.func) {
	case NAME_OP:
		name_op (.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push);
		break;
	case LOCAL_OP:
		local_op (.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push);
		break;
	case FREE_OP:
		free_op (.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push);
		break;
	case DEF_OP:
		def_op (.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push);
		break;
	default:
		eprintf ("Error in store_op in opcode.c, call function %u.\n", par.func);
		return;
	}
	par.op_obj[par.op_code].type |= HASSTORE;
}

void (varargs_op)(struct op_parameter par) {
	def_op (.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push);
	par.op_obj[par.op_code].type |= HASVARGS;
}

void (const_opN)(struct op_parameter par) {
	def_op (.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push);
	par.op_obj[par.op_code].type |= HASCONST;
}

void (compare_op)(struct op_parameter par) {
	def_op (.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push);
	par.op_obj[par.op_code].type |= HASCOMPARE;
}

void (jabs_opN)(struct op_parameter par) {
	def_op00 (.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push, .fallthrough = par.fallthrough);
	par.op_obj[par.op_code].type |= HASJABS;
	if (par.conditional) {
		par.op_obj[par.op_code].type |= HASCONDITION;
	}
}

void (jrel_opN)(struct op_parameter par) {
	def_op00 (.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push, .fallthrough = par.fallthrough);
	par.op_obj[par.op_code].type |= HASJREL;
	if (par.conditional) {
		par.op_obj[par.op_code].type |= HASCONDITION;
	}
}

void (nargs_op)(struct op_parameter par) {
	def_op (.op_obj = par.op_obj, .op_name = par.op_name, .op_code = par.op_code, .pop = par.pop, .push = par.push);
	par.op_obj[par.op_code].type |= HASNARGS;
}

void (rm_op)(struct op_parameter par) {
	pyc_opcode_object *op_obj = &par.op_obj[par.op_code];
	if (op_obj->op_code == par.op_code && !strcmp (op_obj->op_name, par.op_name)) {
		free (op_obj->op_name);
		op_obj->op_name = r_str_newf ("<%u>", par.op_code);
		op_obj->type = op_obj->op_pop = op_obj->op_push = 0;
	} else {
		eprintf ("Error in rm_op() while constructing opcodes for .pyc file: \n .op_code = %u, .op_name = %s", par.op_code, par.op_name);
	}
}
