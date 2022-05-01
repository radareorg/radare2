/* radare - LGPL - Copyright 2014-2018 - dso, condret, pancake */

#include <r_types.h>
#include <r_asm.h>
#include <string.h>

#ifndef WS_API
#define WS_API
#endif

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

WS_API int get_ws_optype(const ut8 *buf, int len) {
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

WS_API const ut8 *get_ws_next_token(const ut8 *buf, int len) {
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

WS_API int test_ws_token_exist(const ut8 *buf, ut8 token, int len) {
	const ut8 *ptr = get_ws_next_token (buf, len);
	int size = 1;
	while (ptr && *ptr != token && (len > 0)) {
		len = len - (ptr - buf);
		ptr = get_ws_next_token (ptr + 1, len - 1);
		size++;
	}
	return size;
}

#if 0
WS_API int wsdis(RAsmOp *op, const ut8 *buf, int len) {
	r_strf_buffer (64);
	const char *buf_asm = NULL;
	const ut8 *ptr = buf;
	switch (get_ws_optype (buf, len)) {
	case WS_OP_UNK:
		return op->size = 0;
	case WS_OP_NOP:
		r_strbuf_set (sb, "nop");
		return op->size = 1;
	case WS_OP_STACK:
		ptr++;
		if (!get_ws_next_token (ptr, len - 1)) {
			return op->size = 0;
		}
		switch (*get_ws_next_token (ptr, len - 1)) {
		case ' ':
			if (test_ws_token_exist (get_ws_next_token (ptr, len - 1), 10, len - 1) == -1) {
				return op->size = 0;
			}
			int n = test_ws_token_exist (ptr - 1, 10, len);
			r_strbuf_set (sb, r_strf ("push %d", n));
			return op->size = n;
		case 10:
			ptr = get_ws_next_token (ptr, len - 1) + 1;
			ptr = get_ws_next_token (ptr, len - (ptr - buf));
			if (!ptr) {
				return op->size = 0;
			}
			switch (*ptr) {
			case ' ':
				r_strbuf_set (sb, "dup");
				break;
			case '\t':
				r_strbuf_set (sb, "swap");
				break;
			case 10:
				r_strbuf_set (sb, "pop");
				break;
			}
			return op->size = ptr - buf + 1;
		case '\t':
			ptr = get_ws_next_token (ptr, len - 1) + 1;
			ptr = get_ws_next_token (ptr, len - (ptr - buf));
			if (!ptr) {
				return op->size = 0;
			}
			switch (*ptr) {
			case ' ':
				r_strbuf_set (sb, "copy");
				break;
			case 10:
				r_strbuf_set (sb, "slide");
				break;
			case '\t':
				r_strbuf_set (sb, "illegal_stack_t");
				return op->size = ptr - buf + 1;
			}
			ptr++;
			if (-1 == test_ws_token_exist (ptr, 10, len - (ptr - buf) - 1)) {
				r_strbuf_set (sb, "");
				return op->size = 0;
			}
			if (r_strbuf_length (sb) < 6) {
				r_strbuf_append (sb, r_strf (" %d", get_ws_val (ptr, len - (ptr - buf) - 1)));
			}
			return op->size = test_ws_token_exist (ptr, 10, len - (ptr - buf) - 1) + ptr - buf + 1; // +1?
		}
	case WS_OP_HEAP:
		ptr = get_ws_next_token (ptr + 1, len - 1) + 1;
		ptr = get_ws_next_token (ptr, len - (ptr - buf));
		if (!ptr) {
			return op->size = 0;
		}
		switch (*ptr) {
		case ' ':
			r_strbuf_set (sb, "store");
			break;
		case '\t':
			r_strbuf_set (sb, "load");
			break;
		case 10:
			r_strbuf_set (sb, "illegal_heap");
			break;
		}
		return op->size = ptr - buf + 1;
	case WS_OP_IO:
		ptr = get_ws_next_token (ptr + 1, len - 1) + 1;
		ptr = get_ws_next_token (ptr, len - (ptr - buf));
		if (!ptr) {
			return op->size = 0;
		}
		switch (*ptr) {
		case ' ':
			ptr++;
			ptr = get_ws_next_token (ptr, len - (ptr - buf));
			if (!ptr) {
				return op->size = 0;
			}
			switch (*ptr) {
			case ' ':
				r_strbuf_set (sb, "putc");
				return op->size = ptr - buf + 1;
			case '\t':
				r_strbuf_set (sb, "puti");
				return op->size = ptr - buf + 1;
			}
			break;
		case '\t':
			ptr++;
			ptr = get_ws_next_token (ptr, len - (ptr - buf));
			if (!ptr) {
				return op->size = 0;
			}
			switch (*ptr) {
			case ' ':
				r_strbuf_set (sb, "getc");
				return op->size = ptr - buf + 1;
			case '\t':
				r_strbuf_set (sb, "geti");
				return op->size = ptr - buf + 1;
			}
		}
		r_strbuf_set (sb, "illegal_io");
		return op->size = ptr - buf + 1;
		break;
	case WS_OP_ARITH:
		ptr = get_ws_next_token (ptr + 1, len - 1) + 1;
		ptr = get_ws_next_token (ptr, len - (ptr - buf));
		if (!ptr) {
			return op->size = 0;
		}
		switch (*ptr) {
		case ' ':
			ptr++;
			ptr = get_ws_next_token (ptr, len - (ptr - buf));
			if (!ptr) {
				return op->size = 0;
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
				return op->size = 0;
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
			r_strbuf_set (sb, buf_asm);
		}
		return op->size = ptr - buf + 1;
	case WS_OP_FLOW:
		ptr = get_ws_next_token (ptr + 1, len - 1);
		if (!ptr) {											// evil
			return op->size = 0;
		}
		switch (*ptr) {
		case 10:
			ptr++;
			ptr = get_ws_next_token (ptr, len - (ptr - buf));
			if (!ptr) {
				return op->size = 0;
			}
			if (*ptr == 10) {
				r_strbuf_set (sb, "exit");
			} else {
				r_strbuf_set (sb, "illegal_fl_lf");
			}
			return op->size = ptr - buf + 1;
		case '\t':
			ptr++;
			ptr = get_ws_next_token (ptr, len - (ptr - buf));
			if (!ptr) {
				return op->size = 0;
			}
			switch (*ptr) {
			case 10:
				r_strbuf_set (sb, "ret");
				return op->size = ptr - buf + 1;
			case '\t':
				r_strbuf_set (sb, "jn");
				break;
			case ' ':
				r_strbuf_set (sb, "jz");
				break;
			}
			ptr++;
			if (-1 == test_ws_token_exist (ptr, 10, len - (ptr - buf))) {
				r_strbuf_set (sb, "");
				return op->size = 0;
			}
			if (r_strbuf_length (sb) == 2) {
				r_strbuf_append (sb, r_strf (" %d", get_ws_val (ptr, len - (ptr - buf) - 1)));
			}
			return op->size = ptr - buf + test_ws_token_exist (ptr, 10, len - (ptr - buf)) + 1;
		case ' ':
			ptr++;
			ptr = get_ws_next_token (ptr, len - (ptr - buf));
			if (!ptr) {
				return op->size = 0;
			}
			switch (*ptr) {
			case 10: buf_asm = "jmp"; break;
			case '\t': buf_asm = "call"; break;
			case ' ': buf_asm = "mark"; break;
			}
			ptr++;
			if (-1 == test_ws_token_exist (ptr, 10, len - (ptr - buf))) {
				r_strbuf_set (sb, "invalid");
				return op->size = 0;
			}
			if (buf_asm) {
				r_strbuf_set (sb, buf_asm);
			}
			r_strbuf_append (sb, r_strf (" %d", get_ws_val (ptr, len - (ptr - buf) - 1)));
			return op->size = ptr - buf + test_ws_token_exist (ptr, 10, len - (ptr - buf)) + 1;
		}
	}
	r_strbuf_set (sb, "wtf");
	return op->size = 0;
}
#endif

WS_API char *wsdisasm(const ut8 *buf, int len, int *size) {
	r_strf_buffer (64);
	int sz = 0;
	const char *buf_asm = NULL;
	RStrBuf *sb = r_strbuf_new ("");
	const ut8 *ptr = buf;
	switch (get_ws_optype (buf, len)) {
	case WS_OP_UNK:
		break;
	case WS_OP_NOP:
		r_strbuf_set (sb, "nop");
		sz = 1;
		break;
	case WS_OP_STACK:
		ptr++;
		if (!get_ws_next_token (ptr, len - 1)) {
			sz = 0;
			break;
		}
		switch (*get_ws_next_token (ptr, len - 1)) {
		case ' ':
			if (test_ws_token_exist (get_ws_next_token (ptr, len - 1), 10, len - 1) == -1) {
				sz = 0;
				break;
			}
			int n = test_ws_token_exist (ptr - 1, 10, len);
			r_strbuf_setf (sb, "push %d", n);
			sz = n;
			break;
		case 10:
			ptr = get_ws_next_token (ptr, len - 1) + 1;
			ptr = get_ws_next_token (ptr, len - (ptr - buf));
			if (!ptr) {
				break;
			}
			switch (*ptr) {
			case ' ':
				r_strbuf_set (sb, "dup");
				break;
			case '\t':
				r_strbuf_set (sb, "swap");
				break;
			case 10:
				r_strbuf_set (sb, "pop");
				break;
			}
			sz = ptr - buf + 1;
			break;
		case '\t':
			ptr = get_ws_next_token (ptr, len - 1) + 1;
			ptr = get_ws_next_token (ptr, len - (ptr - buf));
			if (!ptr) {
				break;
			}
			switch (*ptr) {
			case ' ':
				r_strbuf_set (sb, "copy");
				break;
			case 10:
				r_strbuf_set (sb, "slide");
				break;
			case '\t':
				r_strbuf_set (sb, "illegal_stack_t");
				sz = ptr - buf + 1;
				break;
			}
			if (sz) {
				break;
			}
			ptr++;
			if (-1 == test_ws_token_exist (ptr, 10, len - (ptr - buf) - 1)) {
				r_strbuf_set (sb, "");
				break;
			}
			if (r_strbuf_length (sb) < 6) {
				r_strbuf_append (sb, r_strf (" %d", get_ws_val (ptr, len - (ptr - buf) - 1)));
			}
			sz = test_ws_token_exist (ptr, 10, len - (ptr - buf) - 1) + ptr - buf + 1; // +1?
			break;
		}
		break;
	case WS_OP_HEAP:
		ptr = get_ws_next_token (ptr + 1, len - 1) + 1;
		ptr = get_ws_next_token (ptr, len - (ptr - buf));
		if (!ptr) {
			sz = 0;
			break;
		}
		switch (*ptr) {
		case ' ':
			r_strbuf_set (sb, "store");
			break;
		case '\t':
			r_strbuf_set (sb, "load");
			break;
		case 10:
			r_strbuf_set (sb, "illegal_heap");
			break;
		}
		sz = ptr - buf + 1;
		break;
	case WS_OP_IO:
		ptr = get_ws_next_token (ptr + 1, len - 1) + 1;
		ptr = get_ws_next_token (ptr, len - (ptr - buf));
		if (!ptr) {
			break;
		}
		switch (*ptr) {
		case ' ':
			ptr++;
			ptr = get_ws_next_token (ptr, len - (ptr - buf));
			if (!ptr) {
				break;
			}
			switch (*ptr) {
			case ' ':
				r_strbuf_set (sb, "putc");
				sz = ptr - buf + 1;
				break;
			case '\t':
				r_strbuf_set (sb, "puti");
				sz = ptr - buf + 1;
				break;
			}
			break;
		case '\t':
			ptr++;
			ptr = get_ws_next_token (ptr, len - (ptr - buf));
			if (!ptr) {
				break;
			}
			switch (*ptr) {
			case ' ':
				r_strbuf_set (sb, "getc");
				*size = ptr - buf + 1;
				return r_strbuf_drain (sb);
			case '\t':
				r_strbuf_set (sb, "geti");
				*size = ptr - buf + 1;
				return r_strbuf_drain (sb);
			}
			break;
		}
		r_strbuf_set (sb, "illegal_io");
		sz = ptr - buf + 1;
		break;
	case WS_OP_ARITH:
		ptr = get_ws_next_token (ptr + 1, len - 1) + 1;
		ptr = get_ws_next_token (ptr, len - (ptr - buf));
		if (!ptr) {
			break;
		}
		switch (*ptr) {
		case ' ':
			ptr++;
			ptr = get_ws_next_token (ptr, len - (ptr - buf));
			if (!ptr) {
				break;
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
				break;
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
			r_strbuf_set (sb, buf_asm);
		}
		sz = ptr - buf + 1;
		break;
	case WS_OP_FLOW:
		ptr = get_ws_next_token (ptr + 1, len - 1);
		if (!ptr) {											// evil
			sz = 0;
			break;
		}
		switch (*ptr) {
		case 10:
			ptr++;
			ptr = get_ws_next_token (ptr, len - (ptr - buf));
			if (!ptr) {
				sz = 0;
				break;
			}
			if (*ptr == 10) {
				r_strbuf_set (sb, "exit");
			} else {
				r_strbuf_set (sb, "illegal_fl_lf");
			}
			sz = ptr - buf + 1;
			break;
		case '\t':
			ptr++;
			ptr = get_ws_next_token (ptr, len - (ptr - buf));
			if (!ptr) {
				sz = 0;
				break;
			}
			switch (*ptr) {
			case 10:
				r_strbuf_set (sb, "ret");
				sz = ptr - buf + 1;
				break;
			case '\t':
				r_strbuf_set (sb, "jn");
				break;
			case ' ':
				r_strbuf_set (sb, "jz");
				break;
			}
			ptr++;
			if (-1 == test_ws_token_exist (ptr, 10, len - (ptr - buf))) {
				r_strbuf_set (sb, "");
				break;
			}
			if (r_strbuf_length (sb) == 2) {
				r_strbuf_append (sb, r_strf (" %d", get_ws_val (ptr, len - (ptr - buf) - 1)));
			}
			sz = ptr - buf + test_ws_token_exist (ptr, 10, len - (ptr - buf)) + 1;
			break;
		case ' ':
			ptr++;
			ptr = get_ws_next_token (ptr, len - (ptr - buf));
			if (!ptr) {
				break;
			}
			switch (*ptr) {
			case 10: buf_asm = "jmp"; break;
			case '\t': buf_asm = "call"; break;
			case ' ': buf_asm = "mark"; break;
			}
			ptr++;
			if (-1 == test_ws_token_exist (ptr, 10, len - (ptr - buf))) {
				r_strbuf_set (sb, "invalid");
				sz = 0;
			} else {
				if (buf_asm) {
					r_strbuf_set (sb, buf_asm);
				}
				r_strbuf_append (sb, r_strf (" %d", get_ws_val (ptr, len - (ptr - buf) - 1)));
				sz = ptr - buf + test_ws_token_exist (ptr, 10, len - (ptr - buf)) + 1;
			}
			break;
		}
	}
	*size = sz;
	return r_strbuf_drain (sb);
}
