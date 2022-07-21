/* radare2 - LGPL - Copyright 2022 - bemodtwz */

#include <r_anal.h>
#include <r_lib.h>

#define MAXSTRLEN 128

enum opcode {
	OP_MARK = '(',
	OP_STOP = '.',
	OP_POP = '0',
	OP_POP_MARK = '1',
	OP_DUP = '2',
	OP_FLOAT = 'F',
	OP_INT = 'I',
	OP_BININT = 'J',
	OP_BININT1 = 'K',
	OP_LONG = 'L',
	OP_BININT2 = 'M',
	OP_NONE = 'N',
	OP_PERSID = 'P',
	OP_BINPERSID = 'Q',
	OP_REDUCE = 'R',
	OP_STRING = 'S',
	OP_BINSTRING = 'T',
	OP_SHORT_BINSTRING = 'U',
	OP_UNICODE = 'V',
	OP_BINUNICODE = 'X',
	OP_APPEND = 'a',
	OP_BUILD = 'b',
	OP_GLOBAL = 'c',
	OP_DICT = 'd',
	OP_EMPTY_DICT = '}',
	OP_APPENDS = 'e',
	OP_GET = 'g',
	OP_BINGET = 'h',
	OP_INST = 'i',
	OP_LONG_BINGET = 'j',
	OP_LIST = 'l',
	OP_EMPTY_LIST = ']',
	OP_OBJ = 'o',
	OP_PUT = 'p',
	OP_BINPUT = 'q',
	OP_LONG_BINPUT = 'r',
	OP_SETITEM = 's',
	OP_TUPLE = 't',
	OP_EMPTY_TUPLE = ')',
	OP_SETITEMS = 'u',
	OP_BINFLOAT = 'G',

	// Protocol 2.
	OP_PROTO = '\x80',
	OP_NEWOBJ = '\x81',
	OP_EXT1 = '\x82',
	OP_EXT2 = '\x83',
	OP_EXT4 = '\x84',
	OP_TUPLE1 = '\x85',
	OP_TUPLE2 = '\x86',
	OP_TUPLE3 = '\x87',
	OP_NEWTRUE = '\x88',
	OP_NEWFALSE = '\x89',
	OP_LONG1 = '\x8a',
	OP_LONG4 = '\x8b',

	// Protocol 3 (Python 3.x)
	OP_BINBYTES = 'B',
	OP_SHORT_BINBYTES = 'C',

	// Protocol 4
	OP_SHORT_BINUNICODE = '\x8c',
	OP_BINUNICODE8 = '\x8d',
	OP_BINBYTES8 = '\x8e',
	OP_EMPTY_SET = '\x8f',
	OP_ADDITEMS = '\x90',
	OP_FROZENSET = '\x91',
	OP_NEWOBJ_EX = '\x92',
	OP_STACK_GLOBAL = '\x93',
	OP_MEMOIZE = '\x94',
	OP_FRAME = '\x95',

	// Protocol 5
	OP_BYTEARRAY8 = '\x96',
	OP_NEXT_BUFFER = '\x97',
	OP_READONLY_BUFFER = '\x98'
};

static inline int handle_int(RAnalOp *op, const char *name, int sz, const ut8 *buf, int buflen) {
	if (sz <= buflen && sz <= sizeof (op->val)) {
		op->size += sz;
		op->val = r_mem_get_num (buf, sz);
		op->mnemonic = r_str_newf ("%s 0x%" PFMT64x, name, op->val);
		return op->size;
	}
	return -1;
}

static inline int handle_float(RAnalOp *op, const char *name, int sz, const ut8 *buf, int buflen) {
	if (sz <= buflen && sz <= sizeof (op->val)) {
		op->family = R_ANAL_OP_FAMILY_FPU;
		op->size += sz;
		double d;
		memcpy (&d, buf, sz);
		r_mem_swap ((ut8 *)&d, sizeof (d));
		op->ptr = op->addr + op->nopcode;
		op->ptrsize = sz;
		op->mnemonic = r_str_newf ("%s %lf", name, d);
		return op->size;
	}
	return -1;
}

static inline char *get_line(const ut8 *buf, int len) {
	// TODO: find end of large strings through RAnal->iob
	char *str = r_str_ndup (buf, len);
	if (str) {
		char *n = strchr (str, '\n');
		if (n) {
			*n = 0;
			if (r_str_is_ascii (str)) {
				return str;
			}
		}
	}
	free (str);
	return NULL;
}

static inline char *get_two_lines(const ut8 *buf, int len) {
	char *out = malloc (len);
	char *rep = " \x00";
	int i, cnt = 0;
	if (out) {
		for (i = 0; i < len; i++) {
			char c = buf[i];
			if (c == '\n') {
				out[i] = rep[cnt++];
				if (cnt >= 2) {
					return out;
				}
			} else if (!IS_PRINTABLE (c) || c == ' ') {
				break;
			} else {
				out[i] = c;
			}
		}
		free (out);
	}
	return NULL;
}

static inline int handle_n_lines(RAnalOp *op, const char *name, int n, const ut8 *buf, int buflen) {
	r_return_val_if_fail (buflen >= 0 && name && n < 3 && n > 0, -1);

	// TODO: use an alternative func for INT, FLOAT, LONG ops that gets the
	// value from arg str
	char *str = n == 2? get_two_lines (buf, buflen): get_line (buf, buflen);
	if (str) {
		op->ptr = op->addr + op->nopcode;
		op->ptrsize = strlen (str) + 1;
		op->size += op->ptrsize;
		op->mnemonic = r_str_newf ("%s \"%s\"", name, str);
		free (str);
	} else {
		op->type = R_ANAL_OP_TYPE_ILL;
	}
	return op->size;
}

static inline void set_mnemonic_str(RAnalOp *op, const char *n, const ut8 *buf, size_t max) {
	char *dots = "";
	size_t readlen = op->ptrsize;
	if (op->ptrsize > max) {
		dots = "...";
		readlen = max;
	}
	char *str = r_str_escape_raw ((ut8 *)buf, readlen);
	if (str) {
		op->mnemonic = r_str_newf ("%s \"%s%s\"", n, str, dots);
		free (str);
	} else {
		op->mnemonic = r_str_newf ("%s <failed to decode str>", n);
	}
}

static inline int cnt_str(RAnal *a, RAnalOp *op, const char *name, int sz, const ut8 *buf, int buflen) {
	if (sz <= buflen && sz <= sizeof (op->val)) {
		op->ptrsize = r_mem_get_num (buf, sz);
		op->size = op->nopcode + sz + op->ptrsize;
		op->ptr = op->addr + sz + op->nopcode;
		if (!a->iob.is_valid_offset (a->iob.io, op->addr + op->size - 1, 0)) {
			// end of string is in bad area, probably this is invalid offset for op
			op->size = 1;
			op->type = R_ANAL_OP_TYPE_ILL;
		} else {
			// handle string
			buflen -= sz;
			buf += sz;
			set_mnemonic_str (op, name, buf, R_MIN (buflen, MAXSTRLEN));
		}
	}
	return op->size;
}

#define trivial_op(x) \
	op->mnemonic = strdup (x); \
	return op->size;

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	r_return_val_if_fail (a && op && buf && len > 0, -1);
	// all opcodes are 1 byte, some have arbitrarily large strings as args
	op->nopcode = 1;
	op->size = 1;
	op->addr = addr;
	op->family = R_ANAL_OP_FAMILY_CPU;

	char opcode = *buf;
	buf++;
	len--;
	switch (opcode) {
	case OP_MARK:
		trivial_op ("MARK");
	case OP_STOP:
		trivial_op ("STOP");
	case OP_POP:
		trivial_op ("POP");
	case OP_POP_MARK:
		trivial_op ("POP_MARK");
	case OP_DUP:
		trivial_op ("DUP");
	case OP_FLOAT:
		return handle_n_lines (op, "FLOAT", 1, buf, len);
	case OP_INT:
		return handle_n_lines (op, "INT", 1, buf, len);
	case OP_BININT:
		op->sign = true;
		return handle_int (op, "BININT", 4, buf, len);
	case OP_BININT1:
		return handle_int (op, "BININT1", 1, buf, len);
	case OP_LONG:
		return handle_n_lines (op, "LONG", 1, buf, len);
	case OP_BININT2:
		return handle_int (op, "BININT2", 2, buf, len);
	case OP_NONE:
		trivial_op ("NONE");
	case OP_PERSID:
		// TODO: validate
		return handle_n_lines (op, "PERSID", 1, buf, len);
	case OP_BINPERSID:
		trivial_op ("BINPERSID");
	case OP_REDUCE:
		trivial_op ("REDUCE");
	case OP_STRING:
		return handle_n_lines (op, "STRING", 1, buf, len);
	case OP_BINSTRING:
		return cnt_str (a, op, "BINSTRING", 4, buf, len);
	case OP_SHORT_BINSTRING:
		return cnt_str (a, op, "SHORT_BINSTRING", 1, buf, len);
	case OP_UNICODE:
		return handle_n_lines (op, "UNICODE", 1, buf, len);
	case OP_BINUNICODE:
		return cnt_str (a, op, "BINUNICODE", 4, buf, len);
	case OP_APPEND:
		trivial_op ("APPEND");
	case OP_BUILD:
		trivial_op ("BUILD");
	case OP_GLOBAL:
		return handle_n_lines (op, "GLOBAL", 2, buf, len);
	case OP_DICT:
		trivial_op ("DICT");
	case OP_EMPTY_DICT:
		trivial_op ("EMPTY_DICT");
	case OP_APPENDS:
		trivial_op ("APPENDS");
	case OP_GET:
		return handle_n_lines (op, "GET", 1, buf, len);
	case OP_BINGET:
		op->sign = true; // I think
		return handle_int (op, "BINGET", 1, buf, len);
	case OP_INST:
		return handle_n_lines (op, "INST", 2, buf, len);
	case OP_LONG_BINGET:
		return handle_int (op, "LONG_BINGET", 4, buf, len);
	case OP_LIST:
		trivial_op ("LIST");
	case OP_EMPTY_LIST:
		trivial_op ("EMPTY_LIST");
	case OP_OBJ:
		trivial_op ("OBJ");
	case OP_PUT:
		return handle_n_lines (op, "PUT", 1, buf, len);
	case OP_BINPUT:
		return handle_int (op, "BINPUT", 1, buf, len);
	case OP_LONG_BINPUT:
		return handle_int (op, "LONG_BINPUT", 4, buf, len);
	case OP_SETITEM:
		trivial_op ("SETITEM");
	case OP_TUPLE:
		trivial_op ("TUPLE");
	case OP_EMPTY_TUPLE:
		trivial_op ("EMPTY_TUPLE");
	case OP_SETITEMS:
		trivial_op ("SETITEMS");
	case OP_BINFLOAT:
		return handle_float (op, "BINFLOAT", 8, buf, len);
	case OP_PROTO:
		return handle_int (op, "PROTO", 1, buf, len);
	case OP_NEWOBJ:
		trivial_op ("NEWOBJ");
	case OP_EXT1:
		// I don't *think* it's signed
		return handle_int (op, "EXT1", 1, buf, len);
	case OP_EXT2:
		return handle_int (op, "EXT2", 2, buf, len);
	case OP_EXT4:
		return handle_int (op, "EXT4", 4, buf, len);
	case OP_TUPLE1:
		trivial_op ("TUPLE1");
	case OP_TUPLE2:
		trivial_op ("TUPLE2");
	case OP_TUPLE3:
		trivial_op ("TUPLE3");
	case OP_NEWTRUE:
		trivial_op ("NEWTRUE");
	case OP_NEWFALSE:
		trivial_op ("NEWFALSE");
	case OP_LONG1:
		return handle_int (op, "LONG1", 1, buf, len);
	case OP_LONG4:
		return handle_int (op, "LONG4", 4, buf, len);
	case OP_BINBYTES:
		return cnt_str (a, op, "BINBYTES", 4, buf, len);
	case OP_SHORT_BINBYTES:
		return cnt_str (a, op, "SHORT_BINBYTES", 1, buf, len);
	case OP_SHORT_BINUNICODE:
		return cnt_str (a, op, "SHORT_BINUNICODE", 1, buf, len);
	case OP_BINUNICODE8:
		return cnt_str (a, op, "BINUNICODE8", 8, buf, len);
	case OP_BINBYTES8:
		return cnt_str (a, op, "BINBYTES8", 8, buf, len);
	case OP_EMPTY_SET:
		trivial_op ("EMPTY_SET");
	case OP_ADDITEMS:
		trivial_op ("ADDITEMS");
	case OP_FROZENSET:
		trivial_op ("FROZENSET");
	case OP_NEWOBJ_EX:
		trivial_op ("NEWOBJ_EX");
	case OP_STACK_GLOBAL:
		trivial_op ("STACK_GLOBAL");
	case OP_MEMOIZE:
		trivial_op ("MEMOIZE");
	case OP_FRAME:
		return handle_int (op, "FRAME", 8, buf, len);
	case OP_BYTEARRAY8:
		return cnt_str (a, op, "BYTEARRAY8", 8, buf, len);
	case OP_NEXT_BUFFER:
		trivial_op ("NEXT_BUFFER");
	case OP_READONLY_BUFFER:
		trivial_op ("READONLY_BUFFER");
	}

	// bad opcode, must be at bad addr
	op->type = R_ANAL_OP_TYPE_ILL;
	return op->size;
}

static int archinfo(RAnal *anal, int q) {
	switch (q) {
	case R_ANAL_ARCHINFO_ALIGN:
		return 0;
	case R_ANAL_ARCHINFO_MAX_OP_SIZE:
		// some ops accept newline terminated strings of arbitrary len...
		return MAXSTRLEN + 1;
	case R_ANAL_ARCHINFO_INV_OP_SIZE:
		return 1;
	case R_ANAL_ARCHINFO_MIN_OP_SIZE:
		return 1;
	}
	return 0;
}

RAnalPlugin r_anal_plugin_pickle = {
	.name = "pickle",
	.desc = "Python Pickle Machine Disassembler",
	.esil = false,
	.license = "BSD",
	.arch = "pickle",
	.bits = 8, // not real sure
	.op = &analop,
	// .preludes = anal_preludes,
	.archinfo = archinfo,
	// .get_reg_profile = &get_reg_profile,
	// .mnemonics = cs_mnemonics,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_pickle,
	.version = R2_VERSION
};
#endif
