/* radare - LGPL - Copyright 2014-2022 - dso, condret, pancake */

#include <r_util.h>

enum {
	WS_OP_UNK = 0,
	WS_OP_NOP,
	WS_OP_PREF,
	WS_OP_STACK,
	WS_OP_ARITH,
	WS_OP_HEAP,
	WS_OP_FLOW,
	WS_OP_IO
};

static int get_ws_pref_optype(const ut8 *buf, int len) {
	if (len < 1) {
		return WS_OP_UNK;
	}
	switch (buf[0]) {
	case ' ': return WS_OP_STACK;
	case '\t': return WS_OP_PREF;
	case 10: return WS_OP_FLOW;
	default: return WS_OP_NOP;
	}
}

static int get_ws_suf_optype(const ut8 *buf, int len) {
	if (len < 1) {
		return WS_OP_UNK;
	}
	switch (buf[0]) {
	case ' ': return WS_OP_ARITH;
	case '\t': return WS_OP_HEAP;
	case 10: return WS_OP_IO;
	default: return WS_OP_NOP;
	}
}

static int get_ws_optype(const ut8 *buf, int len) {
	const ut8 *ptr;
	if (get_ws_pref_optype (buf, len) == WS_OP_PREF) {
		ptr = buf + 1;
		while (get_ws_suf_optype (ptr, len - (ptr - buf)) == WS_OP_NOP) {
			ptr++;
		}
		return get_ws_suf_optype (ptr, len - (ptr - buf));
	}
	return get_ws_pref_optype (buf, len);
}

static const ut8 *get_ws_next_token(const ut8 *buf, int len) {
	const ut8 *ret;
	ret = buf;
	while (len - (ret - buf)) {
		switch (*ret) {
		case ' ':
		case '\t':
		case 10:
			return ret;
		}
		ret++;
	}
	return NULL;
}

static st32 get_ws_val(const ut8 *buf, int len) {
	ut8 sig;
	int i, ret = 0;
	const ut8 *tok = get_ws_next_token (buf, len);
	sig = (*tok == '\t');
	len -= (tok - buf) + 1;
	for (i = 0; i < 30; i++) { // XXX : conceptually wrong
		tok++;
		tok = get_ws_next_token (tok, len);
		if (!tok || *tok == 10) {
			if (sig) {
				return ret * (-1);
			}
			return ret;
		}
		ret = (ret << 1);
		ret = ret + (*tok == '\t');
		len = len - (tok - buf) - 1;
	}
	return sig? ret * (-1): ret;
}

static int test_ws_token_exist(const ut8 *buf, ut8 token, int len) {
	const ut8 *ptr = get_ws_next_token (buf, len);
	int size = 1;
	while (ptr && *ptr != token && (len > 0)) {
		len = len - (ptr - buf);
		ptr = get_ws_next_token (ptr + 1, len - 1);
		size++;
	}
	return size;
}

static int wsdis(RStrBuf *mn, const ut8 *buf, int len) {
	const char *buf_asm = NULL;
	const ut8 *ptr = buf;
	switch (get_ws_optype (buf, len)) {
	case WS_OP_UNK:
		return 0;
	case WS_OP_NOP:
		r_strbuf_set (mn, "nop");
		return 1;
	case WS_OP_STACK:
		ptr++;
		if (!get_ws_next_token (ptr, len - 1)) {
			return 0;
		}
		switch (*get_ws_next_token (ptr, len - 1)) {
		case ' ':
			if (test_ws_token_exist (get_ws_next_token (ptr, len - 1), 10, len - 1) == -1) {
				return 0;
			}
			int n = test_ws_token_exist (ptr - 1, 10, len);
			r_strbuf_setf (mn, "push %d", n);
			return n;
		case 10:
			ptr = get_ws_next_token (ptr, len - 1) + 1;
			ptr = get_ws_next_token (ptr, len - (ptr - buf));
			if (!ptr) {
				return 0;
			}
			switch (*ptr) {
			case ' ':
				r_strbuf_set (mn, "dup");
				break;
			case '\t':
				r_strbuf_set (mn, "swap");
				break;
			case 10:
				r_strbuf_set (mn, "pop");
				break;
			}
			return ptr - buf + 1;
		case '\t':
			ptr = get_ws_next_token (ptr, len - 1) + 1;
			ptr = get_ws_next_token (ptr, len - (ptr - buf));
			if (!ptr) {
				return 0;
			}
			switch (*ptr) {
			case ' ':
				r_strbuf_set (mn, "copy");
				break;
			case 10:
				r_strbuf_set (mn, "slide");
				break;
			case '\t':
				r_strbuf_set (mn, "illegal_stack_t");
				return ptr - buf + 1;
			}
			ptr++;
			if (-1 == test_ws_token_exist (ptr, 10, len - (ptr - buf) - 1)) {
				r_strbuf_set (mn, "");
				return 0;
			}
			if (r_strbuf_length (mn) < 6) {
				r_strbuf_appendf (mn, " %d", get_ws_val (ptr, len - (ptr - buf) - 1));
			}
			return test_ws_token_exist (ptr, 10, len - (ptr - buf) - 1) + ptr - buf + 1; // +1?
		}
	case WS_OP_HEAP:
		ptr = get_ws_next_token (ptr + 1, len - 1) + 1;
		ptr = get_ws_next_token (ptr, len - (ptr - buf));
		if (!ptr) {
			return 0;
		}
		switch (*ptr) {
		case ' ':
			r_strbuf_set (mn, "store");
			break;
		case '\t':
			r_strbuf_set (mn, "load");
			break;
		case 10:
			r_strbuf_set (mn, "illegal_heap");
			break;
		}
		return ptr - buf + 1;
	case WS_OP_IO:
		ptr = get_ws_next_token (ptr + 1, len - 1) + 1;
		ptr = get_ws_next_token (ptr, len - (ptr - buf));
		if (!ptr) {
			return 0;
		}
		switch (*ptr) {
		case ' ':
			ptr++;
			ptr = get_ws_next_token (ptr, len - (ptr - buf));
			if (!ptr) {
				return 0;
			}
			switch (*ptr) {
			case ' ':
				r_strbuf_set (mn, "putc");
				return ptr - buf + 1;
			case '\t':
				r_strbuf_set (mn, "puti");
				return ptr - buf + 1;
			}
			break;
		case '\t':
			ptr++;
			ptr = get_ws_next_token (ptr, len - (ptr - buf));
			if (!ptr) {
				return 0;
			}
			switch (*ptr) {
			case ' ':
				r_strbuf_set (mn, "getc");
				return ptr - buf + 1;
			case '\t':
				r_strbuf_set (mn, "geti");
				return ptr - buf + 1;
			}
		}
		r_strbuf_set (mn, "illegal_io");
		return ptr - buf + 1;
		break;
	case WS_OP_ARITH:
		ptr = get_ws_next_token (ptr + 1, len - 1) + 1;
		ptr = get_ws_next_token (ptr, len - (ptr - buf));
		if (!ptr) {
			return 0;
		}
		switch (*ptr) {
		case ' ':
			ptr++;
			ptr = get_ws_next_token (ptr, len - (ptr - buf));
			if (!ptr) {
				return 0;
			}
			switch (*ptr) {
			case ' ': buf_asm = "add"; break;
			case '\t': buf_asm = "sub"; break;
			case 10: buf_asm = "mul"; break;
			}
			break;
		case '\t':
			ptr++;
			ptr = get_ws_next_token (ptr, len - (ptr - buf));
			if (!ptr) {
				return 0;
			}
			switch (*ptr) {
			case ' ': buf_asm = "div"; break;
			case '\t': buf_asm = "mod"; break;
			case 10: buf_asm = "illegal_ar_t"; break;
			}
			break;
		case 10:
			buf_asm = "illegal_ar";
			break;
		}
		if (buf_asm) {
			r_strbuf_set (mn, buf_asm);
		}
		return ptr - buf + 1;
	case WS_OP_FLOW:
		ptr = get_ws_next_token (ptr + 1, len - 1);
		if (!ptr) {											// evil
			return 0;
		}
		switch (*ptr) {
		case 10:
			ptr++;
			ptr = get_ws_next_token (ptr, len - (ptr - buf));
			if (!ptr) {
				return 0;
			}
			if (*ptr == 10) {
				r_strbuf_set (mn, "exit");
			} else {
				r_strbuf_set (mn, "illegal_fl_lf");
			}
			return ptr - buf + 1;
		case '\t':
			ptr++;
			ptr = get_ws_next_token (ptr, len - (ptr - buf));
			if (!ptr) {
				return 0;
			}
			switch (*ptr) {
			case 10:
				r_strbuf_set (mn, "ret");
				return ptr - buf + 1;
			case '\t':
				r_strbuf_set (mn, "jn");
				break;
			case ' ':
				r_strbuf_set (mn, "jz");
				break;
			}
			ptr++;
			if (-1 == test_ws_token_exist (ptr, 10, len - (ptr - buf))) {
				r_strbuf_set (mn, "");
				return 0;
			}
			if (r_strbuf_length (mn) == 2) {
				r_strbuf_appendf (mn, " %d", get_ws_val (ptr, len - (ptr - buf) - 1));
			}
			return ptr - buf + test_ws_token_exist (ptr, 10, len - (ptr - buf)) + 1;
		case ' ':
			ptr++;
			ptr = get_ws_next_token (ptr, len - (ptr - buf));
			if (!ptr) {
				return 0;
			}
			switch (*ptr) {
			case 10: buf_asm = "jmp"; break;
			case '\t': buf_asm = "call"; break;
			case ' ': buf_asm = "mark"; break;
			}
			ptr++;
			if (-1 == test_ws_token_exist (ptr, 10, len - (ptr - buf))) {
				r_strbuf_set (mn, "invalid");
				return 0;
			}
			if (buf_asm) {
				r_strbuf_set (mn, buf_asm);
			}
			r_strbuf_appendf (mn, " %d", get_ws_val (ptr, len - (ptr - buf) - 1));
			return ptr - buf + test_ws_token_exist (ptr, 10, len - (ptr - buf)) + 1;
		}
	}
	return 0;
}
