/* radare - LGPL - Copyright 2015-2024 - pancake */

#include <r_asm.h>

static char *replace(int argc, const char *argv[]) {
#define MAXPSEUDOOPS 10
	int i, j, d;
	char ch;
	struct {
		int narg;
		const char *op;
		const char *str;
		int args[MAXPSEUDOOPS];
	} ops[] = {
		{ 2, "uxtb", "# = #", { 1, 2 } },
		{ 0, "abs", "# = abs(#)", { 1, 1 } },
		{ 0, "adc", "# = # + #", { 1, 2, 3 } },
		{ 3, "add", "# = # + #", { 1, 2, 3 } },
		{ 0, "fcvtzs", "# = #", { 1, 2 } },
		{ 0, "scvtf", "# = #", { 1, 2 } },
		{ 2, "add", "# += #", { 1, 2 } },
		{ 2, "adds", "# += #", { 1, 2 } },
		{ 4, "madd", "# = (# * #) + #", { 1, 2, 3, 4 } },
		{ 4, "msub", "# = (# * #) - #", { 1, 2, 3, 4 } },
		{ 3, "mneg ", "# = -(# * #)", { 1, 2, 3 } },
		{ 3, "adds", "# = # + #", { 1, 2, 3 } },
		{ 3, "addw", "# = # + #", { 1, 2, 3 } },
		{ 3, "add.w", "# = # + #", { 1, 2, 3 } },
		{ 0, "adf", "# = # + #", { 1, 2, 3 } },
		{ 0, "adrp", "# = #", { 1, 2 } },
		{ 0, "adr", "# = #", { 1, 2 } },
		{ 0, "and", "# = # & #", { 1, 2, 3 } },
		{ 0, "ands", "# &= #", { 1, 2 } },
		{ 0, "asls", "# = # << #", { 1, 2, 3 } },
		{ 0, "asl", "# = # << #", { 1, 2, 3 } },
		{ 0, "asrs", "# = # >> #", { 1, 2, 3 } },
		{ 0, "asr", "# = # >> #", { 1, 2, 3 } },
		{ 0, "b", "goto #", { 1 } },
		{ 0, "cbz", "if (!#) goto #", { 1, 2 } },
		{ 0, "cbnz", "if (#) goto #", { 1, 2 } },
		{ 0, "b.w", "goto #", { 1 } },
		{ 0, "b.gt", "if (a > b) goto #", { 1 } },
		{ 0, "b.le", "if (a <= b) goto #", { 1 } },
		{ 0, "b.lt", "if (a < b) goto #", { 1 } },
		{ 0, "b.ls", "if (a < b) goto #", { 1 } },
		{ 0, "b.ge", "if (a >= b) goto #", { 1 } },
		{ 0, "beq lr", "ifeq ret", {0} },
		{ 0, "beq", "je #", { 1 } },
		{ 0, "call", "# ()", { 1 } },
		{ 0, "bl", "# ()", { 1 } },
		{ 0, "blx", "# ()", { 1 } },
		{ 0, "bx lr", "ret", {0} },
		{ 1, "br", "switch #", { 1 } },
		{ 0, "bxeq", "je #", { 1 } },
		{ 0, "b.eq", "if (eq) goto #", { 1 } },
		{ 0, "b.ne", "if (eq) goto #", { 1 } },
		{ 0, "b.hi", "goto ifgt #", { 1 } },
		{ 0, "b.lo", "goto iflt #", { 1 } },
		{ 0, "cmf", "if (# == #)", { 1, 2 } },
		{ 0, "cmn", "if (# != #)", { 1, 2 } },
		{ 0, "cmp", "(a, b) = compare (#, #)", { 1, 2 } },
		{ 0, "fcmp", "(a, b) = compare (#, #)", { 1, 2 } },
		{ 0, "tst", "(a, b) = compare (#, #)", { 1, 2 } },
		// { 0, "cmp", "if (# == #)", { 1, 2 } },
		// { 0, "fcmp", "if (# == #)", { 1, 2 } },
		//{ 0, "tst", "if ((# & #) == 0)", { 1, 2 } },
		{ 4, "csel", "# = (#)? # : #", { 1, 4, 2, 3 } },
		{ 2, "cset", "# = (#)? 1 : 0", { 1, 2 } },
		{ 0, "dvf", "# = # / #", { 1, 2, 3 } },
		{ 0, "eor", "# = # ^ #", { 1, 2, 3 } },
		{ 3, "tbnz", "if (# != #) goto #", { 1, 2, 3 } },
		{ 3, "tbz", "if (# == #) goto #", { 1, 2, 3 } },
		{ 1, "bkpt", "breakpoint #", { 1 } },
		{ 1, "udf", "undefined #", { 1 } },
		{ 2, "sxtb", "# = (char) #", { 1, 2 } },
		{ 2, "sxth", "# = (short) #", { 1, 2 } },
		{ 0, "fdv", "# = # / #", { 1, 2, 3 } },
		{ 0, "fml", "# = # * #", { 1, 2, 3 } },
		{ 3, "ldurb", "# = (byte) # #", { 1, 2, 3 } },
		{ 3, "ldur", "# = # #", { 1, 2, 3 } },
		{ 3, "ldursw", "# = # #", { 1, 2, 3 } },
		{ 2, "ldr", "# = #", { 1, 2 } },
		{ 2, "ldxr", "# = #", { 1, 2 } },
		{ 2, "ldaxr", "# = #", { 1, 2 } },
		{ 2, "ldrh", "# = (word) #", { 1, 2 } },
		{ 3, "ldrh", "# = (word) # + #", { 1, 2, 3 } },
		{ 3, "ldruh", "# = (uword) # + #", { 1, 2, 3 } },
		{ 2, "ldrb", "# = (byte) #", { 1, 2 } },
		{ 3, "ldrb", "# = (byte) # + #", { 1, 2, 3 } },
		{ 2, "ldr.w", "# = #", { 1, 2 } },
		{ 4, "ldrsb", "# = (byte) # + #", { 1, 2, 3 } },
		{ 3, "ldrsb", "# = (byte) # + #", { 1, 2, 3 } },
		{ 2, "ldrsb", "# = (byte) #", { 1, 2 } },
		{ 2, "ldrsw", "# = #", { 1, 2 } },
		{ 4, "ldrsw", "# = # + # #", { 1, 2, 3, 4 } },
		{ 3, "ldrsw", "# = # + #", { 1, 2, 3 } },
		{ 3, "ldr", "# = # + #", { 1, 2, 3 } },
		{ 3, "ldrb", "# = (byte) # + #", { 1, 2, 3 } },
		{ 3, "ldr.w", "# = # + #", { 1, 2, 3 } },
		{ 0, "mov", "# = #", { 1, 2 } },
		{ 0, "fmov", "# = #", { 1, 2 } },
		{ 0, "mvn", "# = ~#", { 1, 2 } },
		{ 0, "movz", "# = #", { 1, 2 } },
		// { 4, "movk", "# = # # #", { 1, 2, 3, 4 } },
		{ 3, "movk", "# = # #", { 1, 2, 3 } },
		{ 0, "movn", "# = ~#", { 1, 2 } },
		{ 0, "neg", "# = -#", { 1, 2 } },
		{ 0, "sxtw", "# = #", { 1, 2 } },
		{ 0, "stur", "# # = #", { 2, 3, 1 } },
		{ 4, "stp", "# + # = (#, 2)", { 3, 4, 1 } },
		{ 0, "ldp", "(#, 2) = 3", { 1 } },
		{ 0, "vmov.i32", "# = #", { 1, 2 } },
		{ 0, "muf", "# = # * #", { 1, 2, 3 } },
		{ 0, "mul", "# = # * #", { 1, 2, 3 } },
		{ 0, "fmul", "# = # * #", { 1, 2, 3 } },
		{ 0, "smul", "# = # * #", { 1, 2, 3 } },
		{ 0, "muls", "# = # * #", { 1, 2, 3 } },
		{ 0, "div", "# = # / #", { 1, 2, 3 } },
		{ 0, "sdiv", "# = # / #", { 1, 2, 3 } },
		{ 0, "fdiv", "# = # / #", { 1, 2, 3 } },
		{ 0, "udiv", "# = (unsigned) # / #", { 1, 2, 3 } },
		{ 0, "orr", "# = # | #", { 1, 2, 3 } },
		{ 0, "rmf", "# = # % #", { 1, 2, 3 } },
		{ 0, "bge", "(>=) goto #", { 1 } },
		{ 0, "sbc", "# = # - #", { 1, 2, 3 } },
		{ 0, "sqt", "# = sqrt(#)", { 1, 2 } },
		{ 0, "lsrs", "# = # >> #", { 1, 2, 3 } },
		{ 0, "lsls", "# = # << #", { 1, 2, 3 } },
		{ 1, "blr", "callreg #", { 1 } },
		{ 0, "lsr", "# = # >> #", { 1, 2, 3 } },
		{ 0, "lsl", "# = # << #", { 1, 2, 3 } },
		{ 0, "lsr.w", "# = # >> #", { 1, 2, 3 } },
		{ 0, "lsl.w", "# = # << #", { 1, 2, 3 } },
		{ 3, "stxr", "# = #", { 3, 2 } }, // stxr w10, x9, [x8] (w10 is 0 or 1 if exclusively locked)
		{ 3, "stlxr", "# = #", { 3, 2 } },
		{ 2, "str", "# = #", { 2, 1 } },
		{ 2, "strb", "# = (byte) #", { 2, 1 } },
		{ 2, "strh", "# = (half) #", { 2, 1 } },
		{ 2, "strh.w", "# = (half) #", { 2, 1 } },
		{ 3, "str", "# + # = #", { 2, 3, 1 } },
		{ 3, "strb", "# + # = (byte) #", { 2, 3, 1 } },
		{ 3, "strh", "# + # = (half) #", { 2, 3, 1 } },
		{ 3, "strh.w", "# + # = (half) #", { 2, 3, 1 } },
		{ 3, "sub", "# = # - #", { 1, 2, 3 } },
		{ 3, "subs", "# = # - #", { 1, 2, 3 } },
		{ 3, "fsub", "# = # - #", { 1, 2, 3 } },
		{ 2, "sub", "# -= #", { 1, 2 } }, // THUMB
		{ 2, "subs", "# -= #", { 1, 2 } }, // THUMB
		{ 0, "swp", "swap(#, 2)", { 1 } },
		/* arm thumb */
		{ 0, "movs", "# = #", { 1, 2 } },
		{ 0, "movw", "# = #", { 1, 2 } },
		{ 0, "movt", "# |= # << 16", { 1, 2 } },
		{ 0, "vmov", "# = (float) # . #", { 1, 2, 3 } },
		{ 0, "vdiv.f64", "# = (float) # / #", { 1, 2, 3 } },
		{ 0, "addw", "# = # + #", { 1, 2, 3 } },
		{ 0, "sub.w", "# = # - #", { 1, 2, 3 } },
		{ 0, "tst.w", "if ((# & #) == 0)", { 1, 2 } },
		{ 0, "pop.w", "pop #", { 1 } },
		{ 0, "vpop", "pop #", { 1 } },
		{ 0, "paciza", "", { 1 } },
		{ 0, "vpush", "push #", { 1 } },
		{ 0, "push.w", "push #", { 1 } },
		{ 0, NULL }
	};
	RStrBuf *sb = r_strbuf_new ("");
	for (i = 0; ops[i].op; i++) {
		if (ops[i].narg) {
			if (argc - 1 != ops[i].narg) {
				continue;
			}
		}
		if (!strcmp (ops[i].op, argv[0])) {
			d = 0;
			j = 0;
			ch = ops[i].str[j];
			for (j = 0; ch != '\0'; j++) {
				ch = ops[i].str[j];
				if (ch == '#') {
					if (d >= MAXPSEUDOOPS) {
						// XXX Shouldn't ever happen...
						continue;
					}
					int idx = ops[i].args[d];
					d++;
					if (idx <= 0) {
						// XXX Shouldn't ever happen...
						continue;
					}
					const char *w = argv[idx];
					if (w) {
						r_strbuf_append (sb, w);
					}
				} else {
					r_strbuf_append_n (sb, &ch, 1);
				}
			}
			goto fin;
		}
	}

	/* TODO: this is slow */
	for (i = 0; i < argc; i++) {
		r_strbuf_append (sb, argv[i]);
		r_strbuf_append (sb, (!i || i == argc - 1)? " " : ",");
	}
fin:;
	char *newstr = r_strbuf_drain (sb);
	r_str_replace_char (newstr, '{', '(');
	r_str_replace_char (newstr, '}', ')');
	return newstr;
}

static char *parse(RAsmPluginSession *aps, const char *data) {
	char w0[256], w1[256], w2[256], w3[256], w4[256];
	char *ptr, *optr;
	int i;

	if (strlen (data) >= sizeof (w0)) {
		return NULL;
	}
	char *buf = strdup (data);
	char *s = NULL;
	if (*buf) {
		*w0 = *w1 = *w2 = *w3 = *w4 = '\0';
		ptr = strchr (buf, ' ');
		if (!ptr) {
			ptr = strchr (buf, '\t');
		}
		if (ptr) {
			*ptr = '\0';
			ptr = (char *)r_str_trim_head_ro (ptr + 1);
			strncpy (w0, buf, sizeof (w0) - 1);
			strncpy (w1, ptr, sizeof (w1) - 1);
			optr = ptr;
			if (*ptr == '(') {
				ptr = strchr (ptr + 1, ')');
			}
			if (ptr && *ptr == '[') {
				ptr = strchr (ptr + 1, ']');
			}
			if (ptr && *ptr == '{') {
				ptr = strchr (ptr + 1, '}');
			}
			if (!ptr) {
				R_LOG_ERROR ("Unbalanced bracket");
				free (buf);
				return NULL;
			}
			ptr = strchr (ptr, ',');
			if (ptr) {
				*ptr = '\0';
				ptr = (char *)r_str_trim_head_ro (ptr + 1);
				strncpy (w1, optr, sizeof (w1) - 1);
				strncpy (w2, ptr, sizeof (w2) - 1);
				optr = ptr;
				ptr = strchr (ptr, ',');
				if (ptr) {
					*ptr = '\0';
					ptr = (char *)r_str_trim_head_ro (ptr + 1);
					strncpy (w2, optr, sizeof (w2) - 1);
					strncpy (w3, ptr, sizeof (w3) - 1);
					optr = ptr;
					ptr = strchr (ptr, ',');
					if (ptr) {
						*ptr = '\0';
						ptr = (char *)r_str_trim_head_ro (ptr + 1);
						strncpy (w3, optr, sizeof (w3) - 1);
						strncpy (w4, ptr, sizeof (w4) - 1);
					}
				}
			}
		}
		{
			const char *wa[] = { w0, w1, w2, w3, w4 };
			int nw = 0;
			for (i = 0; i < 5; i++) {
				if (wa[i][0]) {
					nw++;
				}
			}
			s = replace (nw, wa);
		}
	}
	if (s) {
		s = r_str_replace (s, "xzr", "0", 1);
		s = r_str_replace (s, "wzr", "0", 1);
		s = r_str_replace (s, " lsl ", " << ", 1);
		s = r_str_replace (s, " lsr ", " >> ", 1);
		s = r_str_replace (s, "+ -", "- ", 1);
		s = r_str_replace (s, "- -", "+ ", 1);
		s = r_str_fixspaces (s);
	}
	free (buf);
	return s;
}

static char *subs_var_string(RParse *p, RAnalVarField *var, char *tstr, const char *oldstr, const char *reg, int delta) {
	char *newstr = p->localvar_only
		? r_str_newf ("%s", var->name)
		: r_str_newf ("%s %c %s", reg, delta > 0 ? '+' : '-', var->name);
	if (isupper (*tstr)) {
		char *space = (char *)r_str_rchr (newstr, NULL, ' ');
		if (space) {
			*space = 0;
			r_str_case (newstr, true);
			*space = ' ';
		}
	}
	char *ret = r_str_replace (tstr, oldstr, newstr, 1);
	free (newstr);
	return ret;
}

static char *mount_oldstr(RParse* p, const char *reg, st64 delta, bool ucase) {
	const char *tmplt;
	char *oldstr;
	if (delta > -10 && delta < 10) {
		if (p->pseudo) {
			char sign = '+';
			if (delta < 0) {
				sign = '-';
			}
			oldstr = r_str_newf ("%s %c %" PFMT64d, reg, sign, R_ABS (delta));
		} else {
			oldstr = r_str_newf ("%s, %" PFMT64d, reg, delta);
		}
	} else if (delta > 0) {
		tmplt = p->pseudo ? "%s + 0x%x" : (ucase ? "%s, 0x%X" : "%s, 0x%x");
		oldstr = r_str_newf (tmplt, reg, delta);
	} else {
		tmplt = p->pseudo ? "%s - 0x%x" : (ucase ? "%s, -0x%X" : "%s, -0x%x");
		oldstr = r_str_newf (tmplt, reg, -delta);
	}
	if (ucase) {
		char *comma = strchr (oldstr, ',');
		if (comma) {
			*comma = 0;
			r_str_case (oldstr, true);
			*comma = ',';
		}
	}
	return oldstr;
}

static char *r_core_hack_arm64(RAsmPluginSession *s, RAnalOp *aop, const char *op) {
	const char *cmd = NULL;
	if (!strcmp (op, "nop")) {
		cmd = "wx 1f2003d5";
	} else if (!strcmp (op, "ret")) {
		cmd = "wx c0035fd6t";
	} else if (!strcmp (op, "trap")) {
		cmd = "wx 000020d4";
	} else if (!strcmp (op, "jz") || !strcmp (op, "je")) {
		R_LOG_ERROR ("ARM jz hack not supported");
	} else if (!strcmp (op, "jinf")) {
		cmd = "wx 00000014";
	} else if (!strcmp (op, "jnz") || !strcmp (op, "jne")) {
		R_LOG_ERROR ("ARM jnz hack not supported");
	} else if (!strcmp (op, "nocj")) {
		R_LOG_ERROR ("ARM jnz hack not supported");
	} else if (!strcmp (op, "recj")) {
		if (aop->size < 4) {
			R_LOG_ERROR ("can't fit 4 bytes in here");
			return NULL;
		}
		const ut8 *buf = aop->bytes;
		if (!buf) {
			buf = aop->bytes_buf;
			if (!buf) {
				R_LOG_DEBUG ("aop->bytes[0] == 0");
				return NULL;
			}
		}
		if (!*buf) {
			R_LOG_DEBUG ("aop->bytes[0] == 0");
		}
		switch (*buf) {
		case 0x4c: // bgt -> ble
			cmd = "wx 4d";
			break;
		case 0x4d: // ble -> bgt
			cmd = "wx 4c";
			break;
		default:
			switch (buf[3]) {
			case 0x36: // tbz
				cmd = "wx 37 @ $$+3";
				break;
			case 0x37: // tbnz
				cmd = "wx 36 @ $$+3";
				break;
			case 0x34: // cbz
			case 0xb4: // cbz
				cmd = "wx 35 @ $$+3";
				break;
			case 0x35: // cbnz
				cmd = "wx b4 @ $$+3";
				break;
			}
			break;
		}
	} else if (!strcmp (op, "ret1")) {
		cmd = "'wa mov x0, 1,,ret";
	} else if (!strcmp (op, "ret0")) {
		cmd = "'wa mov x0, 0,,ret";
	} else if (!strcmp (op, "retn")) {
		cmd = "'wa mov x0, -1,,ret";
	}
	if (cmd) {
		return strdup (cmd);
	}
	return NULL;
}

static char *r_core_hack_arm(RAsmPluginSession *s, RAnalOp *aop, const char *op) {
	const int bits = s->rasm->config->bits;
	const ut8 *b = aop->bytes;
	char *hcmd = NULL;
	const char *cmd = NULL;

	if (!strcmp (op, "nop")) {
		const int nopsize = (bits == 16)? 2: 4;
		const char *nopcode = (bits == 16)? "00bf":"0000a0e1";
		const int len = aop->size;
		int i;

		if (len % nopsize) {
			R_LOG_ERROR ("Invalid nopcode size");
			return false;
		}
		hcmd = calloc (len + 8, 2);
		if (R_LIKELY (hcmd)) {
			strcpy (hcmd, "wx ");
			int n = 3;
			for (i = 0; i < len; i += nopsize) {
				memcpy (hcmd + n + i * 2, nopcode, nopsize * 2);
			}
			hcmd[n + (len * 2)] = '\0';
			cmd = hcmd;
		}
	} else if (!strcmp (op, "jinf")) {
		hcmd = r_str_newf ("wx %s", (bits==16)? "fee7": "feffffea");
		cmd = hcmd;
	} else if (!strcmp (op, "trap")) {
		const char* trapcode = (bits==16)? "bebe": "fedeffe7";
		hcmd = r_str_newf ("wx %s", trapcode);
		cmd = hcmd;
	} else if (!strcmp (op, "jz") || !strcmp (op, "je")) {
		if (bits == 16) {
			switch (b[1]) {
			case 0xb9: // CBNZ
				cmd = "wx b1 @ $$+1"; //CBZ
				break;
			case 0xbb: // CBNZ
				cmd = "wx b3 @ $$+1"; //CBZ
				break;
			case 0xd1: // BNE
				cmd = "wx d0 @ $$+1"; //BEQ
				break;
			default:
				R_LOG_ERROR ("Current opcode is not conditional");
				return NULL;
			}
		} else {
			R_LOG_ERROR ("ARM jz hack not supported");
			return NULL;
		}
	} else if (!strcmp (op, "jnz") || !strcmp (op, "jne")) {
		if (bits == 16) {
			switch (b[1]) {
			case 0xb1: // CBZ
				cmd = "wx b9 @ $$+1"; //CBNZ
				break;
			case 0xb3: // CBZ
				cmd = "wx bb @ $$+1"; //CBNZ
				break;
			case 0xd0: // BEQ
				cmd = "wx d1 @ $$+1"; //BNE
				break;
			default:
				R_LOG_ERROR ("Current opcode is not conditional");
				return NULL;
			}
		} else {
			R_LOG_ERROR ("ARM jnz hack not supported");
			return NULL;
		}
	} else if (!strcmp (op, "nocj")) {
		// TODO: drop conditional bit instead of that hack
		if (bits == 16) {
			switch (b[1]) {
			case 0xb1: // CBZ
			case 0xb3: // CBZ
			case 0xd0: // BEQ
			case 0xb9: // CBNZ
			case 0xbb: // CBNZ
			case 0xd1: // BNE
				cmd = "wx e0 @ $$+1"; //BEQ
				break;
			default:
				R_LOG_ERROR ("Current opcode is not conditional");
				return NULL;
			}
		} else {
			R_LOG_ERROR ("ARM un-cjmp hack not supported");
			return NULL;
		}
	} else if (!strcmp (op, "recj")) {
		R_LOG_ERROR ("TODO: use jnz or jz");
		return false;
	} else if (!strcmp (op, "ret1")) {
		if (bits == 16) {
			cmd = "wx 01207047"; // mov r0, 1; bx lr
		} else {
			cmd = "wx 0100b0e31eff2fe1"; // movs r0, 1; bx lr
		}
	} else if (!strcmp (op, "ret0")) {
		if (bits == 16) {
			cmd = "wx 00207047"; // mov r0, 0; bx lr
		} else {
			cmd = "wx 0000a0e31eff2fe1"; // movs r0, 0; bx lr
		}
	} else if (!strcmp (op, "retn")) {
		if (bits == 16) {
			cmd = "wx ff207047"; // mov r0, -1; bx lr
		} else {
			cmd = "wx ff00a0e31eff2fe1"; // movs r0, -1; bx lr
		}
	} else {
		R_LOG_ERROR ("Invalid operation");
		return NULL;
	}
	if (hcmd) {
		return hcmd;
	}
	if (cmd) {
		return strdup (cmd);
	}
	free (hcmd);
	return NULL;
}

static char *patch(RAsmPluginSession *s, RAnalOp *aop, const char *op) {
	if (s->rasm->config->bits == 64) {
		return r_core_hack_arm64 (s, aop, op);
	}
	return r_core_hack_arm (s, aop, op);
}

static char *subvar(RAsmPluginSession *s, RAnalFunction *f, ut64 addr, int oplen, const char *data) {
	R_RETURN_VAL_IF_FAIL (s, false);
	RAsm *a = s->rasm;
	RParse *p = a->parse;
	RList *spargs = NULL;
	RList *bpargs = NULL;
	RListIter *iter;
	RAnal *anal = a->analb.anal;
	char *oldstr;
	bool newstack = anal->opt.var_newstack;
	char *tstr = strdup (data);
	if (!tstr) {
		return false;
	}

	if (p->subrel) {
		char *rip;
		if (p->pseudo) {
			rip = (char *)r_str_casestr (tstr, "[pc +");
			if (!rip) {
				rip = (char *)r_str_casestr (tstr, "[pc -");
			}
		} else {
			rip = (char *)r_str_casestr (tstr, "[pc, ");
		}

		if (rip && !strchr (rip + 4, ',')) {
			rip += 4;
			char *tstr_new, *ripend = strchr (rip, ']');
			const char *neg = strchr (rip, '-');
			ut64 off = (oplen == 2 || strstr (tstr, ".w") || strstr(tstr, ".W")) ? 4 : 8;
			ut64 repl_num = (addr + off) & ~3;
			if (!ripend) {
				ripend = "]";
			}
			if (neg) {
				repl_num -= r_num_get (NULL, neg + 1);
			} else {
				repl_num += r_num_get (NULL, rip);
			}
			rip -= 3;
			*rip = 0;
			tstr_new = r_str_newf ("%s0x%08"PFMT64x"%s", tstr, repl_num, ripend);
			free (tstr);
			tstr = tstr_new;
		}
	}
	if (f && p->varlist) {
		bpargs = p->varlist (f, 'b');
		spargs = p->varlist (f, 's');
		bool ucase = isupper (*tstr);
		RAnalVarField *var;
		bool is64 = f->bits == 64;
		// NOTE: on arm32 bp is fp
		if ((is64 && strstr (tstr, "[bp")) || !is64) {
			r_list_foreach (bpargs, iter, var) {
				st64 delta = p->get_ptr_at
					? p->get_ptr_at (f, var->delta, addr)
					: ST64_MAX;
				if (delta == ST64_MAX && var->field) {
					delta = var->delta + f->bp_off;
				} else if (delta == ST64_MAX) {
					continue;
				}
				const char *reg = NULL;
				if (p->get_reg_at) {
					reg = p->get_reg_at (f, var->delta, addr);
				}
				if (!reg) {
					reg = anal->reg->alias[R_REG_ALIAS_BP];
				}
				oldstr = mount_oldstr (p, reg, delta, ucase);
				if (strstr (tstr, oldstr)) {
					tstr = subs_var_string (p, var, tstr, oldstr, reg, delta);
					free (oldstr);
					break;
				}
				free (oldstr);
			}
		}
		if ((is64 && strstr (tstr, "[sp")) || !is64) {
			r_list_foreach (spargs, iter, var) {
				st64 delta;
				if (is64) {
					const int maxstack = f->maxstack;
					// st64 delta = -var->delta + 8;
					delta = maxstack - R_ABS (var->delta);
				} else {
					delta = var->delta;
					if (!newstack) {
						delta = p->get_ptr_at
							? p->get_ptr_at (f, var->delta, addr)
							: ST64_MAX;
						if (delta == ST64_MAX && var->field) {
							delta = var->delta;
						} else if (delta == ST64_MAX) {
							// delta = -var->delta + 8;
							continue;
						}
					}
				}
				const char *reg = NULL;
				if (p->get_reg_at) {
					reg = p->get_reg_at (f, delta, addr);
				}
				if (!reg) {
					reg = anal->reg->alias[R_REG_ALIAS_SP];
				}
				oldstr = mount_oldstr (p, reg, delta, ucase);
				if (strstr (tstr, oldstr)) {
					tstr = subs_var_string (p, var, tstr, oldstr, reg, delta);
					free (oldstr);
					break;
				}
				free (oldstr);
			}
		}
		r_list_free (bpargs);
		r_list_free (spargs);
	}
	return tstr;
}

RAsmPlugin r_asm_plugin_arm = {
	.meta = {
		.name = "arm",
		.desc = "ARM/ARM64 pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
	.subvar = subvar,
	.patch = patch
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_arm,
	.version = R2_VERSION
};
#endif
