/* radare2 - LGPL - Copyright 2022 - bemodtwz */

#include <r_anal.h>
#include <r_lib.h>

#define MAXSTRLEN 128

struct opmap {
	const char *name;
	char op;
};

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

static const struct opmap op_name_map[] = {
	{ "mark", '(' },
	{ "stop", '.' },
	{ "pop", '0' },
	{ "pop_mark", '1' },
	{ "dup", '2' },
	{ "float", 'F' },
	{ "int", 'I' },
	{ "binint", 'J' },
	{ "binint1", 'K' },
	{ "long", 'L' },
	{ "binint2", 'M' },
	{ "none", 'N' },
	{ "persid", 'P' },
	{ "binpersid", 'Q' },
	{ "reduce", 'R' },
	{ "string", 'S' },
	{ "binstring", 'T' },
	{ "short_binstring", 'U' },
	{ "unicode", 'V' },
	{ "binunicode", 'X' },
	{ "append", 'a' },
	{ "build", 'b' },
	{ "global", 'c' },
	{ "dict", 'd' },
	{ "empty_dict", '}' },
	{ "appends", 'e' },
	{ "get", 'g' },
	{ "binget", 'h' },
	{ "inst", 'i' },
	{ "long_binget", 'j' },
	{ "list", 'l' },
	{ "empty_list", ']' },
	{ "obj", 'o' },
	{ "put", 'p' },
	{ "binput", 'q' },
	{ "long_binput", 'r' },
	{ "setitem", 's' },
	{ "tuple", 't' },
	{ "empty_tuple", ')' },
	{ "setitems", 'u' },
	{ "binfloat", 'G' },
	{ "proto", '\x80' },
	{ "newobj", '\x81' },
	{ "ext1", '\x82' },
	{ "ext2", '\x83' },
	{ "ext4", '\x84' },
	{ "tuple1", '\x85' },
	{ "tuple2", '\x86' },
	{ "tuple3", '\x87' },
	{ "newtrue", '\x88' },
	{ "newfalse", '\x89' },
	{ "long1", '\x8a' },
	{ "long4", '\x8b' },
	{ "binbytes", 'B' },
	{ "short_binbytes", 'C' },
	{ "short_binunicode", '\x8c' },
	{ "binunicode8", '\x8d' },
	{ "binbytes8", '\x8e' },
	{ "empty_set", '\x8f' },
	{ "additems", '\x90' },
	{ "frozenset", '\x91' },
	{ "newobj_ex", '\x92' },
	{ "stack_global", '\x93' },
	{ "memoize", '\x94' },
	{ "frame", '\x95' },
	{ "bytearray8", '\x96' },
	{ "next_buffer", '\x97' },
	{ "readonly_buffer", '\x98' }
};

static inline bool valid_offset(RAnal *a, ut64 addr) {
	RIOIsValidOff validoff = a->iob.io? a->iob.is_valid_offset: NULL;
	if (validoff && !validoff (a->iob.io, addr, 0)) {
		return false;
	}
	return true;
}

static inline int handle_int(RAnalOp *op, const char *name, int sz, const ut8 *buf, int buflen) {
	if (sz <= buflen && sz <= sizeof (op->val)) {
		op->size += sz;
		op->val = r_mem_get_num (buf, sz);
		op->mnemonic = r_str_newf ("%s 0x%" PFMT64x, name, op->val);
		return op->size;
	}
	return -1;
}

static inline int handle_long(RAnal *a, RAnalOp *op, const char *name, int sz, const ut8 *buf, int buflen) {
	r_return_val_if_fail (sz == 1 || sz == 4, -1);
	op->sign = true;

	// process how long the numer is is
	if (sz > buflen) {
		return -1;
	}
	ut64 longlen = r_mem_get_num (buf, sz);
	buf += sz;
	buflen -= sz;
	op->size += sz + longlen;

	if (longlen <= sizeof (op->val) && longlen <= buflen) {
		op->val = 0;
		if (longlen) {
			st64 i, out = 0;
			bool neg = buf[longlen - 1] & 0x80? true: false;
			for (i = 0; i < longlen; i++) {
				ut8 v = neg? ~buf[i]: buf[i]; // force positive
				out += (ut64)v << (8 * i);
			}
			if (neg) {
				out = -out - 1;
			}
			op->val = out;
		}
		op->mnemonic = r_str_newf ("long%d %" PFMT64d, sz, op->val);
	} else {
		if (!valid_offset (a, op->addr + op->size - 1)) {
			op->size = 1;
			return -1;
		}
		op->mnemonic = r_str_newf ("long%d <%" PFMT64d " bytes long int too big>", sz, longlen);
		op->val = UT8_MAX;
	}
	return op->size;
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
	char *str = r_str_ndup ((char *)buf, len);
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
	const char * const rep = " \x00";
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

static inline int handle_opstring(RAnalOp *op, const ut8 *buf, int buflen) {
	if (buf[0] != '\'') {
		op->type = R_ANAL_OP_TYPE_ILL;
		return -1;
	}
	buf++;
	buflen --; // remove starting quote
	char *str = get_line (buf, buflen);
	if (str) {
		size_t len = strlen (str);
		if (len > 0 && str[len - 1] == '\'') {
			str[len - 1] = '\0';
			op->mnemonic = r_str_newf ("string \"%s\"", str);
			op->ptr = op->addr + 2; // skip op and first '
			op->ptrsize = len - 1; // remove last ' from len
			op->size = 2 + op->ptrsize + 2; // (S') + str + ('\n)
			free (str);
			return op->size;
		}
		free (str);
	}
	return -1;
}

static inline void set_mnemonic_str(RAnalOp *op, const char *n, const ut8 *buf, size_t max) {
	char *trunc = "";
	size_t readlen = op->ptrsize;
	if (op->ptrsize > max) {
		trunc = "<truncated>";
		readlen = max;
	}
	char *str = r_str_escape_raw ((ut8 *)buf, readlen);
	if (str) {
		op->mnemonic = r_str_newf ("%s \"%s\"%s", n, str, trunc);
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
		if (valid_offset (a, op->addr + op->size - 1)) {
			buflen -= sz;
			buf += sz;
			set_mnemonic_str (op, name, buf, R_MIN (buflen, MAXSTRLEN));
		} else {
			op->size = 1;
			op->type = R_ANAL_OP_TYPE_ILL;
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
		trivial_op ("mark");
	case OP_STOP:
		trivial_op ("stop");
	case OP_POP:
		trivial_op ("pop");
	case OP_POP_MARK:
		trivial_op ("pop_mark");
	case OP_DUP:
		trivial_op ("dup");
	case OP_FLOAT:
		return handle_n_lines (op, "float", 1, buf, len);
	case OP_INT:
		return handle_n_lines (op, "int", 1, buf, len);
	case OP_BININT:
		op->sign = true;
		return handle_int (op, "binint", 4, buf, len);
	case OP_BININT1:
		return handle_int (op, "binint1", 1, buf, len);
	case OP_LONG:
		return handle_n_lines (op, "long", 1, buf, len);
	case OP_BININT2:
		return handle_int (op, "binint2", 2, buf, len);
	case OP_NONE:
		trivial_op ("none");
	case OP_PERSID:
		// TODO: validate
		return handle_n_lines (op, "persid", 1, buf, len);
	case OP_BINPERSID:
		trivial_op ("binpersid");
	case OP_REDUCE:
		trivial_op ("reduce");
	case OP_STRING:
		return handle_opstring (op, buf, len);
	case OP_BINSTRING:
		return cnt_str (a, op, "binstring", 4, buf, len);
	case OP_SHORT_BINSTRING:
		return cnt_str (a, op, "short_binstring", 1, buf, len);
	case OP_UNICODE:
		return handle_n_lines (op, "unicode", 1, buf, len);
	case OP_BINUNICODE:
		return cnt_str (a, op, "binunicode", 4, buf, len);
	case OP_APPEND:
		trivial_op ("append");
	case OP_BUILD:
		trivial_op ("build");
	case OP_GLOBAL:
		return handle_n_lines (op, "global", 2, buf, len);
	case OP_DICT:
		trivial_op ("dict");
	case OP_EMPTY_DICT:
		trivial_op ("empty_dict");
	case OP_APPENDS:
		trivial_op ("appends");
	case OP_GET:
		return handle_n_lines (op, "get", 1, buf, len);
	case OP_BINGET:
		op->sign = true; // I think
		return handle_int (op, "binget", 1, buf, len);
	case OP_INST:
		return handle_n_lines (op, "inst", 2, buf, len);
	case OP_LONG_BINGET:
		return handle_int (op, "long_binget", 4, buf, len);
	case OP_LIST:
		trivial_op ("list");
	case OP_EMPTY_LIST:
		trivial_op ("empty_list");
	case OP_OBJ:
		trivial_op ("obj");
	case OP_PUT:
		return handle_n_lines (op, "put", 1, buf, len);
	case OP_BINPUT:
		return handle_int (op, "binput", 1, buf, len);
	case OP_LONG_BINPUT:
		return handle_int (op, "long_binput", 4, buf, len);
	case OP_SETITEM:
		trivial_op ("setitem");
	case OP_TUPLE:
		trivial_op ("tuple");
	case OP_EMPTY_TUPLE:
		trivial_op ("empty_tuple");
	case OP_SETITEMS:
		trivial_op ("setitems");
	case OP_BINFLOAT:
		return handle_float (op, "binfloat", 8, buf, len);
	case OP_PROTO:
		return handle_int (op, "proto", 1, buf, len);
	case OP_NEWOBJ:
		trivial_op ("newobj");
	case OP_EXT1:
		// I don't *think* it's signed
		return handle_int (op, "ext1", 1, buf, len);
	case OP_EXT2:
		return handle_int (op, "ext2", 2, buf, len);
	case OP_EXT4:
		return handle_int (op, "ext4", 4, buf, len);
	case OP_TUPLE1:
		trivial_op ("tuple1");
	case OP_TUPLE2:
		trivial_op ("tuple2");
	case OP_TUPLE3:
		trivial_op ("tuple3");
	case OP_NEWTRUE:
		trivial_op ("newtrue");
	case OP_NEWFALSE:
		trivial_op ("newfalse");
	case OP_LONG1:
		return handle_long (a, op, "long1", 1, buf, len);
	case OP_LONG4:
		return handle_long (a, op, "long1", 4, buf, len);
	case OP_BINBYTES:
		return cnt_str (a, op, "binbytes", 4, buf, len);
	case OP_SHORT_BINBYTES:
		return cnt_str (a, op, "short_binbytes", 1, buf, len);
	case OP_SHORT_BINUNICODE:
		return cnt_str (a, op, "short_binunicode", 1, buf, len);
	case OP_BINUNICODE8:
		return cnt_str (a, op, "binunicode8", 8, buf, len);
	case OP_BINBYTES8:
		return cnt_str (a, op, "binbytes8", 8, buf, len);
	case OP_EMPTY_SET:
		trivial_op ("empty_set");
	case OP_ADDITEMS:
		trivial_op ("additems");
	case OP_FROZENSET:
		trivial_op ("frozenset");
	case OP_NEWOBJ_EX:
		trivial_op ("newobj_ex");
	case OP_STACK_GLOBAL:
		trivial_op ("stack_global");
	case OP_MEMOIZE:
		trivial_op ("memoize");
	case OP_FRAME:
		return handle_int (op, "frame", 8, buf, len);
	case OP_BYTEARRAY8:
		return cnt_str (a, op, "bytearray8", 8, buf, len);
	case OP_NEXT_BUFFER:
		trivial_op ("next_buffer");
	case OP_READONLY_BUFFER:
		trivial_op ("readonly_buffer");
	}

	// bad opcode, must be at bad addr
	op->type = R_ANAL_OP_TYPE_ILL;
	return op->size;
}

static inline bool write_num_sz(ut64 n, int byte_sz, ut8 *outbuf, int outsz) {
	if (byte_sz > outsz) {
		return false;
	}
	int bits = r_num_to_bits (NULL, n);
	if (n && bits > byte_sz * 8) {
		R_LOG_ERROR ("Arg 0x%" PFMT64x " is more than %d bytes", n, byte_sz);
		return false;
	}
	switch (byte_sz) {
	case 1:
		r_write_ble8 (outbuf, (ut8)(n & UT8_MAX));
		break;
	case 2:
		r_write_ble16 (outbuf, (ut16)(n & UT16_MAX), false);
		break;
	case 4:
		r_write_ble32 (outbuf, (ut32)(n & UT32_MAX), false);
		break;
	case 8:
		r_write_ble64 (outbuf, n, false);
		break;
	default:
		return false;
	}
	return true;
}

static inline bool get_asmembled_num(const char *str, ut64 *out) {
	RNum *num = r_num_new (NULL, NULL, NULL);
	if (num) {
		*out = r_num_math (num, str);
		r_num_free (num);
		return true;
	}
	return false;
}

static inline int assemble_int(const char *str, int byte_sz, ut8 *outbuf, int outsz) {
	ut64 n;
	if (outsz < byte_sz || !get_asmembled_num (str, &n)) {
		return -2;
	}
	if (write_num_sz (n, byte_sz, outbuf, outsz)) {
		return byte_sz;
	}
	return 0;
}

static inline int l_num_to_bytes(ut64 n, bool sign) {
	bool flip = false;
	st64 test = n;
	int ret = 0;
	if (sign && test < 0) {
		test = -test;
		flip = true;
	}
	st64 last = 0;
	while (test) {
		last = test;
		test = test >> 8;
		ret++;
	}
	if (!flip && last & 0x80) {
		ret++; // extra null byte needed to indicate positive
	}
	return ret;
}

static inline int assemble_longint(const char *str, int byte_sz, ut8 *outbuf, int outsz) {
	// long1 is followed by a single byte indicating size of the encoded long,
	// so up to 255 byte numbers, long4 uses 4 bytes to encode size
	ut64 n;
	if (get_asmembled_num (str, &n)) {
		if (!n && write_num_sz (n, byte_sz, outbuf, outsz)) { // special, can be smaller
			return byte_sz;
		}
		int bytes = l_num_to_bytes (n, true);
		if (bytes > sizeof (ut64)) {
			R_LOG_ERROR ("Can't assemble longs larger then 64 bits yet");
			return -2;
		}
		int writesize = bytes + byte_sz;
		if (writesize < outsz && write_num_sz (bytes, byte_sz, outbuf, outsz)) {
			outbuf += byte_sz;
			outsz -= byte_sz;
			size_t i;
			for (i = 0; i < bytes; i++) {
				outbuf[i] = 0xff & (n >> (i * 8));
			}
			return writesize;
		}
	}
	return -2;
}

static inline int assemble_float(const char *str, ut8 *outbuf, int outsz) {
	if (outsz < sizeof (double)) {
		return -2;
	}
	RNum *num = r_num_new (NULL, NULL, NULL);
	if (num) {
		*((double *)outbuf) = r_num_get_float (num, str);
		r_mem_swap (outbuf, sizeof (double));
		r_num_free (num);
		return sizeof (double);
	}
	return 0;
}

static inline st64 str_valid_arg(const char *str) {
	size_t len = strlen (str);
	if (len < 2 || str[0] != '\"' || str[len - 1] != '\"') {
		R_LOG_ERROR ("String arg must be quoted");
		return -2;
	}
	return len;
}

static inline int assemble_cnt_str(char *str, int byte_sz, ut8 *outbuf, int outsz) {
	st64 len = str_valid_arg (str);
	if (len < 0) {
		return len;
	}
	// remove quotes from string
	str[len - 1] = '\0';
	str++;
	int wlen = -2;
	len = r_str_unescape (str);
	if (len > 0 && len + byte_sz <= outsz && write_num_sz (len, byte_sz, outbuf, outsz)) {
		wlen = len + byte_sz;
		memcpy (outbuf + byte_sz, str, len);
	}
	return wlen;
}

static inline int assemble_n_str(char *str, ut32 cnt, ut8 *outbuf, int outsz, bool q) {
	r_return_val_if_fail (cnt <= 2, -2);
	st64 len = str_valid_arg (str);
	if (len < 0) {
		return len;
	}
	if (outsz > 0 && len > outsz - 1) { // str must be be \n terminated in outbuf
		R_LOG_ERROR ("String to large for assembler to handle");
		return -2;
	}
	if (strchr (str, '\n')) {
		R_LOG_ERROR ("Shouldn't be newlines in argument");
		return -2;
	}

	if (q) { // string is rpr bracket quoted
		str[0] = '\'';
		str[len - 1] = '\'';
	} else {
		// don't include quotes in output
		str = str + 1;
		len -= 2;
	}

	if (cnt == 2) {
		char *space = strchr (str, ' ');
		if (!space) {
			R_LOG_ERROR ("Need space between args");
			return -2;
		}
		*space = '\n';
	}
	memcpy (outbuf, str, len);
	outbuf[len] = '\n';
	return len + 1;
}

static inline int write_op(char *opstr, ut8 *outbuf) {
	bool ret = false;
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (op_name_map); i++) {
		if (!r_str_casecmp (opstr, op_name_map[i].name)) {
			*outbuf = (ut8)op_name_map[i].op;
			ret = true;
			break;
		}
	}
	return ret;
}

static int pickle_opasm(RAnal *a, ut64 addr, const char *str, ut8 *outbuf, int outsz) {
	r_return_val_if_fail (str && *str && outsz > 0 && outbuf, -1);
	int wlen = 0;
	char *opstr = strdup (str); // get a non-const str to manipulate
	if (!opstr) {
		return -1;
	}

	// get arg w/o whitespace
	char *arg = strchr (opstr, ' ');
	if (arg && *arg == ' ') {
		*arg = '\0';
		arg++;
		arg = r_str_ichr (arg, ' ');
	} else {
		arg = "";
	}

	if (write_op (opstr, outbuf)) {
		char op = (char)*outbuf;
		wlen++;
		outbuf++;
		outsz--;
		switch (op) {
		// single byte
		case OP_MARK:
		case OP_STOP:
		case OP_POP:
		case OP_POP_MARK:
		case OP_DUP:
		case OP_NONE:
		case OP_BINPERSID:
		case OP_REDUCE:
		case OP_APPEND:
		case OP_BUILD:
		case OP_DICT:
		case OP_EMPTY_DICT:
		case OP_APPENDS:
		case OP_LIST:
		case OP_EMPTY_LIST:
		case OP_OBJ:
		case OP_SETITEM:
		case OP_TUPLE:
		case OP_EMPTY_TUPLE:
		case OP_SETITEMS:
		case OP_NEWOBJ:
		case OP_TUPLE1:
		case OP_TUPLE2:
		case OP_TUPLE3:
		case OP_NEWTRUE:
		case OP_NEWFALSE:
		case OP_EMPTY_SET:
		case OP_ADDITEMS:
		case OP_FROZENSET:
		case OP_NEWOBJ_EX:
		case OP_STACK_GLOBAL:
		case OP_MEMOIZE:
		case OP_NEXT_BUFFER:
		case OP_READONLY_BUFFER:
			if (arg && *arg) {
				wlen = -1;
			}
			break;
		// ints
		case OP_FRAME:
			wlen += assemble_int (arg, 8, outbuf, outsz);
			break;
		case OP_BININT:
		case OP_LONG_BINPUT:
		case OP_LONG_BINGET:
		case OP_EXT4:
			wlen += assemble_int (arg, 4, outbuf, outsz);
			break;
		case OP_BININT2:
		case OP_EXT2:
			wlen += assemble_int (arg, 2, outbuf, outsz);
			break;
		case OP_BININT1:
		case OP_BINGET:
		case OP_BINPUT:
		case OP_PROTO:
		case OP_EXT1:
			wlen += assemble_int (arg, 1, outbuf, outsz);
			break;
		case OP_LONG4:
			wlen += assemble_longint (arg, 4, outbuf, outsz);
			break;
		case OP_LONG1:
			wlen += assemble_longint (arg, 1, outbuf, outsz);
			break;
		// float
		case OP_BINFLOAT:
			wlen += assemble_float (arg, outbuf, outsz);
			break;
		// counted strings
		case OP_BINUNICODE8:
		case OP_BINBYTES8:
		case OP_BYTEARRAY8:
			wlen += assemble_cnt_str (arg, 8, outbuf, outsz);
			break;
		case OP_BINSTRING:
		case OP_BINUNICODE:
		case OP_BINBYTES:
			wlen += assemble_cnt_str (arg, 4, outbuf, outsz);
			break;
		case OP_SHORT_BINBYTES:
		case OP_SHORT_BINSTRING:
		case OP_SHORT_BINUNICODE:
			wlen += assemble_cnt_str (arg, 1, outbuf, outsz);
			break;
		// two lines
		case OP_INST:
		case OP_GLOBAL:
			wlen += assemble_n_str (arg, 2, outbuf, outsz, false);
			break;
		// one line
		case OP_FLOAT:
		case OP_INT:
		case OP_LONG:
		case OP_PERSID:
		case OP_UNICODE:
		case OP_GET:
		case OP_PUT:
			wlen += assemble_n_str (arg, 1, outbuf, outsz, false);
			break;
		// one like rpr style
		case OP_STRING:
			wlen += assemble_n_str (arg, 1, outbuf, outsz, true);
			break;
		default:
			r_warn_if_reached ();
			wlen = -1;
		}
	}
	free (opstr);
	return wlen;
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

static inline char *pickle_json_mnemonic(int id) {
	PJ *pj = pj_new ();
	if (pj) {
		pj_a (pj);
		if (id >= 0 && id < R_ARRAY_SIZE (op_name_map)) {
			pj_s (pj, op_name_map[id].name);
		} else if (id == -1) {
			size_t i;
			RStrBuf *buf = buf = r_strbuf_new ("");
			for (i = 0; i < R_ARRAY_SIZE (op_name_map); i++) {
				pj_s (pj, op_name_map[i].name);
			}
		}
		pj_end (pj);
		return pj_drain (pj);
	}
	return NULL;
}

static char *pickle_mnemonics(RAnal *a, int id, bool json) {
	if (json) {
		return pickle_json_mnemonic (id);
	}
	if (id >= 0 && id < R_ARRAY_SIZE (op_name_map)) {
		return strdup (op_name_map[id].name);
	}
	if (id == -1) {
		size_t i;
		RStrBuf *buf = buf = r_strbuf_new ("");
		for (i = 0; i < R_ARRAY_SIZE (op_name_map); i++) {
			r_strbuf_append (buf, op_name_map[i].name);
			r_strbuf_append (buf, "\n");
		}
		return r_strbuf_drain (buf);
	}

	return NULL;
}

RAnalPlugin r_anal_plugin_pickle = {
	.name = "pickle",
	.desc = "Python Pickle Machine Disassembler",
	.esil = false,
	.license = "BSD",
	.arch = "pickle",
	.bits = 8, // not real sure
	.op = &analop,
	.opasm = &pickle_opasm,
	// .preludes = anal_preludes,
	.archinfo = archinfo,
	.mnemonics = pickle_mnemonics,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_pickle,
	.version = R2_VERSION
};
#endif
