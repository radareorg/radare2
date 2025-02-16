/* radare2 - LGPL - Copyright 2022-2024 - bemodtwz */

#include <r_anal.h>
#include "dis_helper.inc"

#define MAXSTRLEN 128

static inline bool valid_offset(RArch *a, ut64 addr) {
	RBin *bin = R_UNWRAP2 (a, binb.bin);
	if (bin) {
		RIOIsValidOff validoff = bin->iob.is_valid_offset;
		if (validoff && !validoff (bin->iob.io, addr, 0)) {
			return false;
		}
	}
	return true;
}

static inline bool handle_int(RAnalOp *op, const char *name, int sz) {
	int buflen = op->size - 1;
	if (sz <= buflen && sz <= sizeof (op->val)) {
		op->size = sz + 1;
		op->val = r_mem_get_num (op->bytes + 1, sz);
		free (op->mnemonic);
		op->mnemonic = r_str_newf ("%s 0x%" PFMT64x, name, op->val);
		return true;
	}
	return false;
}

static inline int handle_long(RArch *a, RAnalOp *op, int sz) {
	R_RETURN_VAL_IF_FAIL (sz == 1 || sz == 4, -1);
	op->sign = true;

	// process how long the numer is is
	if (sz >= op->size) {
		return -1;
	}
	const ut8 *buf = op->bytes + 1;
	ut64 longlen = r_mem_get_num (buf, sz);
	buf += sz;
	int buflen = op->size - sz + 1;
	op->size = sz + longlen + 1;

	if (longlen <= sizeof (op->val) && longlen <= buflen) {
		op->val = 0;
		if (longlen) {
			st64 i, out = 0;
			bool neg = (buf[longlen - 1] & 0x80) != 0;
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

static inline int handle_float(RAnalOp *op, const char *name, int sz) {
	int buflen = op->size - 1;
	if (sz <= buflen && sz <= sizeof (op->val)) {
		op->family = R_ANAL_OP_FAMILY_FPU;
		op->size = sz + 1;
		double d;
		memcpy (&d, op->bytes + 1, sz);
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
	const char * const rep = " \x00"; // XXX this x00 is implicit in "" as terminator
	int i, cnt = 0;
	char *out = malloc (len);
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

static inline void max_oplen_set(RArchSession *s, RAnalOp *op) {
	// update max opsise
	if (op->size > MAXSTRLEN && s->data) {
		int *x = (int *)s->data;
		if (*x < op->size) {
			*x = op->size;
		}
	}
}

static inline bool handle_n_lines(RArchSession *s, RAnalOp *op, const char *name, int n) {
	R_RETURN_VAL_IF_FAIL (op->size >= 2 && name && n < 3 && n > 0, -1);
	// TODO: use an alternative func for INT, FLOAT, LONG ops that gets the
	// value from arg str
	const ut8 *buf = op->bytes + 1;
	int buflen = op->size - 1;
	char *str = (n == 2)? get_two_lines (buf, buflen): get_line (buf, buflen);
	if (str) {
		op->ptr = op->addr + op->nopcode;
		op->ptrsize = strlen (str) + 1;
		op->size = op->ptrsize + 1;
		op->mnemonic = r_str_newf ("%s \"%s\"", name, str);
		free (str);
		max_oplen_set (s, op);
		return true;
	}
	op->type = R_ANAL_OP_TYPE_ILL;
	op->size = 1;
	return false;
}

static inline int handle_opstring(RArchSession *s, RAnalOp *op) {
	const ut8 *buf = op->bytes + 1;
	int buflen = op->size - 1;
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
			max_oplen_set (s, op);
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
		trunc = "truncated";
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

static bool cnt_str(RArchSession *s, RAnalOp *op, const char *name, int sz) {
	const ut8 *buf = op->bytes + 1;
	int buflen = op->size - 1;
	if (sz <= buflen && sz <= sizeof (op->val)) {
		op->ptrsize = r_mem_get_num (buf, sz);
		op->size = op->nopcode + sz + op->ptrsize;
		op->ptr = op->addr + sz + op->nopcode;
		if (valid_offset (s->arch, op->addr + op->size - 1)) {
			buflen -= sz;
			buf += sz;
			set_mnemonic_str (op, name, buf, R_MIN (buflen, MAXSTRLEN));
			max_oplen_set (s, op);
			return true;
		} else {
			op->size = 1;
			op->type = R_ANAL_OP_TYPE_ILL;
		}
	}
	return false;
}

static bool pickle_decode(RArchSession *s, RAnalOp *op, RAnalOpMask mask) {
	R_RETURN_VAL_IF_FAIL (s && op, false);
	if (op->size < 1 || !op->bytes) {
		return false;
	}
	// all opcodes are 1 byte, some have arbitrarily large strings as args
	op->nopcode = 1;
	op->family = R_ANAL_OP_FAMILY_CPU;
	op->type = R_ANAL_OP_TYPE_MOV;

	const char *opstr = NULL;
	switch ((char)*op->bytes) {
	case OP_MARK:
		opstr = "mark";
		break;
	case OP_STOP:
		opstr = "stop";
		break;
	case OP_POP:
		opstr = "pop";
		break;
	case OP_POP_MARK:
		opstr = "pop_mark";
		break;
	case OP_DUP:
		opstr = "dup";
		break;
	case OP_FLOAT:
		return handle_n_lines (s, op, "float", 1);
	case OP_INT:
		return handle_n_lines (s, op, "int", 1);
	case OP_BININT:
		op->sign = true;
		return handle_int (op, "binint", 4);
	case OP_BININT1:
		return handle_int (op, "binint1", 1);
	case OP_LONG:
		return handle_n_lines (s, op, "long", 1);
	case OP_BININT2:
		return handle_int (op, "binint2", 2);
	case OP_NONE:
		opstr = "none";
		break;
	case OP_PERSID:
		// TODO: validate
		return handle_n_lines (s, op, "persid", 1);
	case OP_BINPERSID:
		opstr = "binpersid";
		break;
	case OP_REDUCE:
		opstr = "reduce";
		break;
	case OP_STRING:
		return handle_opstring (s, op);
	case OP_BINSTRING:
		return cnt_str (s, op, "binstring", 4);
	case OP_SHORT_BINSTRING:
		return cnt_str (s, op, "short_binstring", 1);
	case OP_UNICODE:
		return handle_n_lines (s, op, "unicode", 1);
	case OP_BINUNICODE:
		return cnt_str (s, op, "binunicode", 4);
	case OP_APPEND:
		opstr = "append";
		break;
	case OP_BUILD:
		opstr = "build";
		break;
	case OP_GLOBAL:
		return handle_n_lines (s, op, "global", 2);
	case OP_DICT:
		opstr = "dict";
		break;
	case OP_EMPTY_DICT:
		opstr = "empty_dict";
		break;
	case OP_APPENDS:
		opstr = "appends";
		break;
	case OP_GET:
		return handle_n_lines (s, op, "get", 1);
	case OP_BINGET:
		op->sign = true; // I think
		return handle_int (op, "binget", 1);
	case OP_INST:
		return handle_n_lines (s, op, "inst", 2);
	case OP_LONG_BINGET:
		return handle_int (op, "long_binget", 4);
	case OP_LIST:
		opstr = "list";
		break;
	case OP_EMPTY_LIST:
		opstr = "empty_list";
		break;
	case OP_OBJ:
		opstr = "obj";
		break;
	case OP_PUT:
		return handle_n_lines (s, op, "put", 1);
	case OP_BINPUT:
		return handle_int (op, "binput", 1);
	case OP_LONG_BINPUT:
		return handle_int (op, "long_binput", 4);
	case OP_SETITEM:
		opstr = "setitem";
		break;
	case OP_TUPLE:
		opstr = "tuple";
		break;
	case OP_EMPTY_TUPLE:
		opstr = "empty_tuple";
		break;
	case OP_SETITEMS:
		opstr = "setitems";
		break;
	case OP_BINFLOAT:
		return handle_float (op, "binfloat", 8);
	case OP_PROTO:
		return handle_int (op, "proto", 1);
	case OP_NEWOBJ:
		opstr = "newobj";
		break;
	case OP_EXT1:
		// I don't *think* it's signed
		return handle_int (op, "ext1", 1);
	case OP_EXT2:
		return handle_int (op, "ext2", 2);
	case OP_EXT4:
		return handle_int (op, "ext4", 4);
	case OP_TUPLE1:
		opstr = "tuple1";
		break;
	case OP_TUPLE2:
		opstr = "tuple2";
		break;
	case OP_TUPLE3:
		opstr = "tuple3";
		break;
	case OP_NEWTRUE:
		opstr = "newtrue";
		break;
	case OP_NEWFALSE:
		opstr = "newfalse";
		break;
	case OP_LONG1:
		return handle_long (s->arch, op, 1);
	case OP_LONG4:
		return handle_long (s->arch, op, 4);
	case OP_BINBYTES:
		return cnt_str (s, op, "binbytes", 4);
	case OP_SHORT_BINBYTES:
		return cnt_str (s, op, "short_binbytes", 1);
	case OP_SHORT_BINUNICODE:
		return cnt_str (s, op, "short_binunicode", 1);
	case OP_BINUNICODE8:
		return cnt_str (s, op, "binunicode8", 8);
	case OP_BINBYTES8:
		return cnt_str (s, op, "binbytes8", 8);
	case OP_EMPTY_SET:
		opstr = "empty_set";
		break;
	case OP_ADDITEMS:
		opstr = "additems";
		break;
	case OP_FROZENSET:
		opstr = "frozenset";
		break;
	case OP_NEWOBJ_EX:
		opstr = "newobj_ex";
		break;
	case OP_STACK_GLOBAL:
		opstr = "stack_global";
		break;
	case OP_MEMOIZE:
		opstr = "memoize";
		break;
	case OP_FRAME:
		return handle_int (op, "frame", 8);
	case OP_BYTEARRAY8:
		return cnt_str (s, op, "bytearray8", 8);
	case OP_NEXT_BUFFER:
		opstr = "next_buffer";
		break;
	case OP_READONLY_BUFFER:
		opstr = "readonly_buffer";
		break;
	}
	if (opstr) {
		op->mnemonic = strdup (opstr);
		op->size = 1;
	} else {
		op->mnemonic = strdup ("invalid");
		// bad opcode, must be at bad addr
		op->type = R_ANAL_OP_TYPE_ILL;
		return false;
	}

	return true;
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
		*((double *)outbuf) = r_num_get_double (num, str);
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

static int assemble_cnt_str(char *str, int byte_sz, ut8 *outbuf, int outsz) {
	st64 len = str_valid_arg (str);
	if (len < 0) {
		return 0;
	}
	// remove quotes from string
	str[len - 1] = '\0';
	str++;
	int wlen = -2;
	len = r_str_unescape (str);
	if (len >= 0 && len + byte_sz <= outsz && write_num_sz (len, byte_sz, outbuf, outsz)) {
		wlen = len + byte_sz;
		memcpy (outbuf + byte_sz, str, len);
	}
	return wlen;
}

static inline int assemble_n_str(char *str, ut32 cnt, ut8 *outbuf, int outsz, bool q) {
	R_RETURN_VAL_IF_FAIL (cnt <= 2, -2);
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

static bool pickle_encode(RArchSession *s, RAnalOp *op, RArchEncodeMask mask) {
	const char *str = op->mnemonic;
	// some ops can be huge, but they should always be smaller then the mnemonics
	int outsz = strlen (str);

	// _outbuf is kept for free'ing while outbuff will get ++
	ut8 *_outbuf = malloc (outsz);
	if (!_outbuf) {
		return false;
	}
	ut8 *outbuf = _outbuf;

	R_RETURN_VAL_IF_FAIL (str && *str && outsz > 0 && outbuf, -1);
	int wlen = 0;
	char *opstr = strdup (str); // get a non-const str to manipulate
	if (!opstr) {
		return false;
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

	char ob = name_to_op (opstr);
	if (ob == OP_FAILURE) {
		R_LOG_ERROR ("Unknown pickle verb: %s", opstr);
		wlen = -1;
	} else {
		*outbuf = (ut8)ob;
		wlen++;
		outbuf++;
		outsz--;
		switch (ob) {
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
			R_WARN_IF_REACHED ();
			wlen = -1;
		}
	}
	free (opstr);

	if (wlen > 0) {
		R_RETURN_VAL_IF_FAIL (wlen <= outsz, false);
		free (op->bytes);
		op->bytes = realloc (_outbuf, wlen);
		if (op->bytes) {
			op->size = wlen;
			return true;
		}
	}
	op->size = 1;
	free (_outbuf);
	return false;
}

static int pickle_info(RArchSession *s, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_CODE_ALIGN:
		return 0;
	case R_ARCH_INFO_MAXOP_SIZE:
		// some ops accept newline terminated strings of arbitrary len...
		if (s->data) {
			return *(int *)s->data;
		}
		return MAXSTRLEN;
	case R_ARCH_INFO_INVOP_SIZE:
		return 1;
	case R_ARCH_INFO_MINOP_SIZE:
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
			for (i = 0; i < R_ARRAY_SIZE (op_name_map); i++) {
				pj_s (pj, op_name_map[i].name);
			}
		}
		pj_end (pj);
		return pj_drain (pj);
	}
	return NULL;
}

static char *pickle_mnemonics(RArchSession *s, int id, bool json) {
	if (json) {
		return pickle_json_mnemonic (id);
	}
	if (id >= 0 && id < R_ARRAY_SIZE (op_name_map)) {
		return strdup (op_name_map[id].name);
	}
	if (id == -1) {
		size_t i;
		RStrBuf *buf = r_strbuf_new ("");
		for (i = 0; i < R_ARRAY_SIZE (op_name_map); i++) {
			r_strbuf_append (buf, op_name_map[i].name);
			r_strbuf_append (buf, "\n");
		}
		return r_strbuf_drain (buf);
	}
	return NULL;
}

static bool pickle_init(RArchSession *s) {
	R_RETURN_VAL_IF_FAIL (s, false);
	s->data = R_NEW (int);
	if (s->data) {
		*((int *)s->data) = MAXSTRLEN;
		return true;
	}
	return false;
}

static bool pickle_fini(RArchSession *s) {
	R_RETURN_VAL_IF_FAIL (s, false);
	free (s->data);
	s->data = NULL;
	return true;
}

const RArchPlugin r_arch_plugin_pickle = {
	.meta = {
		.name = "pickle",
		.author = "bemodtwz",
		.desc = "Python Pickle Machine Disassembler",
		.license = "BSD-3-Clause",
	},
	.arch = "pickle",
	.bits = R_SYS_BITS_PACK1 (8), // not sure
	.decode = &pickle_decode,
	.encode = &pickle_encode,
	.info = pickle_info,
	.mnemonics = pickle_mnemonics,
	.init = pickle_init,
	.fini = pickle_fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_pickle,
	.version = R2_VERSION
};
#endif
