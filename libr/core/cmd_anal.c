/* radare - LGPL - Copyright 2009-2015 - pancake */

#include "r_util.h"

static void find_refs(RCore *core, const char *glob) {
	char cmd[128];
	ut64 curseek = core->offset;
	while (*glob==' ') glob++;
	if (!*glob)
		glob = "str.";
	if (*glob == '?') {
		eprintf ("Usage: arf [flag-str-filter]\n");
		return;
	}
	eprintf ("Finding references of flags matching '%s'...\n", glob);
	snprintf (cmd, sizeof (cmd)-1, ".(findstref) @@= `f~%s[0]`", glob);
	r_core_cmd0 (core, "(findstref,f here=$$,s entry0,/r here,f-here)");
	r_core_cmd0 (core, cmd);
	r_core_cmd0 (core, "(-findstref)");
	r_core_seek (core, curseek, 1);
}

static void var_help(RCore *core, char ch) {
	 const char* help_msg[] = {
		 "Usage:", "af[aAv]", " [idx] [type] [name]",
		 "afa", "", "list function arguments",
		 "afa*", "", "list function arguments in commands",
		 "afa", " [idx] [name] ([type])", "define argument N with name and type",
		 "afan", " [old_name] [new_name]", "rename function argument",
		 "afaj", "", "return list of function arguments in JSON format",
		 "afa-", " [idx]", "delete argument at the given index",
		 "afag", " [idx] [addr]", "define var get reference",
		 "afas", " [idx] [addr]", "define var set reference",
		 "afv", "", "list function local variables",
		 "afv", " [idx] [name] ([type])", "define variable N with name and type",
		 "afvn", " [old_name] [new_name]", "rename local variable",
		 "afvj", "", "return list of function local variables in JSON format",
		 "afv-", " [idx]", "delete variable at the given index",
		 "afvg", " [idx] [addr]", "define var get reference",
		 "afvs", " [idx] [addr]", "define var set reference",
		 NULL};
	if (ch=='a' || ch=='A' || ch=='v') {
		r_core_cmd_help (core, help_msg);
	} else {
		eprintf ("See afv? and afa?\n");
	}
}

static int var_cmd(RCore *core, const char *str) {
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, -1);
	char *p, *ostr;
	int delta, type = *str;

	ostr = p = strdup (str);
	str = (const char *)ostr;

	switch (type) {
	case 'V': // show vars in human readable format
		r_anal_var_list_show (core->anal, fcn, 'v', 0);
		r_anal_var_list_show (core->anal, fcn, 'a', 0);
		break;
	case '?':
		var_help (core, 0);
		break;
	case 'v': // frame variable
	case 'a': // stack arg
	case 'A': // fastcall arg
		// XXX nested dup
		/* Variable access CFvs = set fun var */
		switch (str[1]) {
		case '\0':
		case '*':
		case 'j':
			r_anal_var_list_show (core->anal, fcn, type, str[1]);
			goto end;
		case '?':
			var_help (core, *str);
			goto end;
		case '.':
			r_anal_var_list_show (core->anal, fcn, core->offset, 0);
			goto end;
		case '-':
			if (fcn) {
				r_anal_var_delete (core->anal, fcn->addr,
					type, 1, (int)
					r_num_math (core->num, str+1));
			} else {
				eprintf ("Cnnot find function here\n");
			}
			goto end;
		case 'n':
			str++;
			for (str++;*str==' ';) str++;
			char *new_name = strchr (str, ' ');
			if (!new_name) {
				var_help (core, type);
				break;
			}
			*new_name++ = 0;
			char *old_name = strdup (str);
			r_str_split(old_name, ' ');
			r_anal_var_rename (core->anal, fcn->addr,
				R_ANAL_VAR_SCOPE_LOCAL, (char)type,
				old_name, new_name);
			free (old_name);
			goto end;
		case 's':
		case 'g':
			if (str[2]!='\0') {
				if (fcn != NULL) {
					int rw = 0; // 0 = read, 1 = write
					RAnalVar *var = r_anal_var_get (core->anal, fcn->addr,
						(char)type, atoi (str+2), R_ANAL_VAR_SCOPE_LOCAL);
					if (var != NULL) {
						int scope = (str[1]=='g')?0: 1;
						r_anal_var_access (core->anal, fcn->addr, (char)type,
							scope, atoi (str+2), rw, core->offset);
						r_anal_var_free (var);
						goto end;
					}
					eprintf ("Can not find variable in: '%s'\n", str);
				} else eprintf ("Unknown variable in: '%s'\n", str);
				free (ostr);
				return R_FALSE;
			} else eprintf ("Missing argument\n");
			break;
		case ' ':
			for (str++;*str==' ';) str++;
			p = strchr (str, ' ');
			if (!p) {
				var_help (core, type);
				break;
			}
			*p++ = 0;
			delta = r_num_math (core->num, str);
			 {
				int size = 4;
				int scope = 1; // 0 = global, 1 = LOCAL;
				const char *name = p;
				char *vartype = strchr (name, ' ');
				if (vartype) {
					*vartype++ = 0;
				}
				if (fcn) {
					r_anal_var_add (core->anal, fcn->addr,
						scope, delta, type,
						vartype, size, name);
				} else eprintf ("Cannot find function\n");
			 }
			break;
		default:
			var_help (core, *str);
			break;
		}
	}
	end:
	free (ostr);
	return R_TRUE;
}

static void print_trampolines(RCore *core, ut64 a, ut64 b, size_t element_size) {
	int i;
	for (i=0; i<core->blocksize; i+=element_size) {
		ut32 n;
		memcpy (&n, core->block+i, sizeof(ut32));
		if (n>=a && n<=b) {
			if (element_size == 4)
				r_cons_printf ("f trampoline.%x @ 0x%"PFMT64x"\n", n, core->offset+i);
			else
				r_cons_printf ("f trampoline.%"PFMT64x" @ 0x%"PFMT64x"\n", n, core->offset+i);

			r_cons_printf ("Cd %u @ 0x%"PFMT64x":%u\n", element_size, core->offset+i, element_size);
			// TODO: add data xrefs
		}
	}
}

static void cmd_anal_trampoline (RCore *core, const char *input) {
	int bits = r_config_get_i (core->config, "asm.bits");
	char *p, *inp = strdup (input);
	p = strchr (inp, ' ');
	if (p) *p=0;
	ut64 a = r_num_math (core->num, inp);
	ut64 b = p?r_num_math (core->num, p+1):0;
	free (inp);

	switch (bits) {
	case 32:
		print_trampolines(core, a, b, 4);
		break;
	case 64:
		print_trampolines(core, a, b, 8);
		break;
	}
}

static void cmd_syscall_do(RCore *core, int num) {
	int i;
	char str[64];
	RSyscallItem *item = r_syscall_get (core->anal->syscall, num, -1);
	if (item == NULL) {
		r_cons_printf ("%d = unknown ()", num);
		return;
	}
	r_cons_printf ("%d = %s (", item->num, item->name);
	// TODO: move this to r_syscall
	for (i=0; i<item->args; i++) {
		ut64 arg = r_debug_arg_get (core->dbg, R_TRUE, i+1);
		if (item->sargs==NULL)
			r_cons_printf ("0x%08"PFMT64x"", arg);
		else
			switch (item->sargs[i]) {
			case 'p': // pointer
				r_cons_printf ("0x%08"PFMT64x"", arg);
				break;
			case 'i':
				r_cons_printf ("%"PFMT64d"", arg);
				break;
			case 'z':
				r_io_read_at (core->io, arg, (ut8*)str, sizeof (str));
				// TODO: filter zero terminated string
				str[63] = '\0';
				r_str_filter (str, strlen (str));
				r_cons_printf ("\"%s\"", str);
				break;
			default:
				r_cons_printf ("0x%08"PFMT64x"", arg);
				break;
			}
		if (i+1<item->args)
			r_cons_printf (", ");
	}
	r_cons_printf (")\n");
}

static void core_anal_bytes (RCore *core, const ut8 *buf, int len, int nops, int fmt) {
	int ret, i, j, idx, size;
	RAsmOp asmop;
	RAnalOp op;
	ut64 addr;
	RAnalHint *hint;
	int use_color = core->print->flags & R_PRINT_FLAGS_COLOR;
	const char *color = "";
	if (use_color)
		color = core->cons->pal.label;
	if (fmt=='j')
		r_cons_printf ("[");
	for (i=idx=ret=0; idx<len && (!nops|| (nops&&i<nops)); i++, idx+=ret) {
		addr = core->offset+idx;
		// TODO: use more anal hints
		hint = r_anal_hint_get (core->anal, addr);
		r_asm_set_pc (core->assembler, addr);
		ret = r_asm_disassemble (core->assembler, &asmop, buf+idx, len-idx);
		ret = r_anal_op (core->anal, &op, core->offset+idx, buf + idx, len-idx);
		if (ret<1 && fmt!='d') {
			eprintf ("Oops at 0x%08"PFMT64x" (%02x %02x %02x ...)\n",
				core->offset+idx, buf[idx],
				buf[idx+1], buf[idx+2]);
			break;
		}
		size = (hint&&hint->size)? hint->size: op.size;
		if (fmt=='d') {
			char *opname = strdup (asmop.buf_asm);
			r_str_split (opname, ' ');
			char *d = r_asm_describe (core->assembler, opname);
			if (d && *d) {
				r_cons_printf ("%s: %s\n", opname, d);
				free (d);
			} else r_cons_printf ("Unknown opcode\n");
			free(opname);
		} else if (fmt=='j') {
			r_cons_printf ("{\"opcode\": \"%s\",", asmop.buf_asm);
			if (hint && hint->opcode)
				r_cons_printf ("\"ophint\": \"%s\",", hint->opcode);
			r_cons_printf ("\"prefix\": %"PFMT64d",", op.prefix);
			r_cons_printf ("\"addr\": %"PFMT64d",", core->offset+idx);
			r_cons_printf ("\"bytes\": \"");
			for (j=0; j<size; j++)
				r_cons_printf ("%02x", buf[j]);
			r_cons_printf("\",");
			if (op.val != UT64_MAX)
				r_cons_printf ("\"val\": %"PFMT64d",", op.val);
			if (op.ptr != UT64_MAX)
				r_cons_printf ("\"ptr\": %"PFMT64d",", op.ptr);
			r_cons_printf ("\"size\": %d,", size);
			r_cons_printf ("\"type\": \"%s\",",
				r_anal_optype_to_string (op.type));
			if (*R_STRBUF_SAFEGET (&op.esil))
				r_cons_printf ("\"esil\": \"%s\",",
					R_STRBUF_SAFEGET (&op.esil));
			if (hint && hint->jump != UT64_MAX)
				op.jump = hint->jump;
			if (op.jump != UT64_MAX)
				r_cons_printf ("\"jump\":%"PFMT64d",", op.jump);
			if (hint && hint->fail != UT64_MAX)
				op.fail = hint->fail;
			if (op.refptr != -1)
				r_cons_printf ("\"refptr\":%d,", op.refptr);
			if (op.fail != UT64_MAX)
				r_cons_printf ("\"fail\":%"PFMT64d",", op.fail);

			r_cons_printf ("\"cycles\":%d,", op.cycles);
			if (op.failcycles)
				r_cons_printf ("failcycles: %d\n", op.failcycles);
			r_cons_printf ("\"stack\":\"%s\",", r_anal_stackop_tostring (op.stackop));
			r_cons_printf ("\"cond\":%d,",
				(op.type &R_ANAL_OP_TYPE_COND)?1: op.cond);
			r_cons_printf ("\"family\":\"%s\"}", r_anal_op_family_to_string (op.family));
		} else {
#define printline(k,fmt,arg) {\
	if (use_color) r_cons_printf ("%s%s: "Color_RESET, color, k); \
	else r_cons_printf ("%s: ", k); \
	if (fmt) r_cons_printf (fmt, arg); \
}
			printline ("opcode", "%s\n", asmop.buf_asm);
			if (hint) {
				if (hint->opcode)
					printline ("ophint", "%s\n", hint->opcode);
				printline ("addr", "0x%08"PFMT64x"\n", (hint->addr+idx));
			}
			printline ("prefix", "%"PFMT64d"\n", op.prefix);
			printline ("bytes", NULL, 0);
			for (j=0; j<size; j++)
				r_cons_printf ("%02x", buf[j]);
			r_cons_newline ();
			if (op.val != UT64_MAX)
				printline ("val","0x%08"PFMT64x"\n", op.val);
			if (op.ptr != UT64_MAX)
				printline ("ptr","0x%08"PFMT64x"\n", op.ptr);
			if (op.refptr != -1)
				printline ("refptr","%d\n", op.refptr);
			printline ("size", "%d\n", size);
			printline ("type","%s\n", r_anal_optype_to_string (op.type));
			if (*R_STRBUF_SAFEGET (&op.esil))
				printline ("esil", "%s\n", R_STRBUF_SAFEGET (&op.esil));
			if (hint && hint->jump != UT64_MAX)
				op.jump = hint->jump;
			if (op.jump != UT64_MAX)
				printline ("jump","0x%08"PFMT64x"\n", op.jump);

			if (hint && hint->fail != UT64_MAX)
				op.fail = hint->fail;
			if (op.fail != UT64_MAX)
				printline ("fail","0x%08"PFMT64x"\n", op.fail);

			printline ("stack","%s\n", r_anal_stackop_tostring (op.stackop));
			printline ("cond","%d\n", (op.type &R_ANAL_OP_TYPE_COND)?1: op.cond);
			printline ("family","%s\n", r_anal_op_family_to_string (op.family));
		}
		//r_cons_printf ("false: 0x%08"PFMT64x"\n", core->offset+idx);
		//free (hint);
		r_anal_hint_free (hint);
		if (((idx+ret)<len) && (!nops||(i+1)<nops))
			r_cons_printf (",");
	}

	if (fmt=='j') {
		r_cons_printf ("]");
		r_cons_newline ();
	}
}

static int bb_cmp(void *a, void *b) {
	RAnalBlock *ba = a;
	RAnalBlock *bb = b;
	return ba->addr - bb->addr;
}

static int anal_fcn_list_bb (RCore *core, const char *input) {
	RDebugTracepoint *tp = NULL;
	RAnalFunction *fcn;
	RListIter *iter;
	RAnalBlock *b;
	int mode = 0;
	ut64 addr;

	if (*input && (input[1]==' ' || !input[1])) {
		if (*input == 'r')
			mode = '*';
		else	mode = *input;
		input++;
	}
	if (input && *input) {
		addr = r_num_math (core->num, input);
	} else {
		addr = core->offset;
	}
	fcn = r_anal_get_fcn_in (core->anal, addr, 0);
	if (!fcn)
		return R_FALSE;
	switch (mode) {
	case 'j':
		r_cons_printf ("[");
		break;
	case '*':
		r_cons_printf ("fs blocks\n");
		break;
	}
	r_list_sort (fcn->bbs, bb_cmp);
	r_list_foreach (fcn->bbs, iter, b) {
		switch (mode) {
		case '*':
			r_cons_printf ("f bb.%05"PFMT64x" = 0x%08"PFMT64x"\n",
				b->addr & 0xFFFFF, b->addr);
			break;
		case 'q':
			r_cons_printf ("0x%08"PFMT64x"\n", b->addr);
			break;
		case 'j':
			r_cons_printf ("%"PFMT64d"%s", b->addr, iter->n?",":"");
			break;
		default:
			tp = r_debug_trace_get (core->dbg, b->addr);
			r_cons_printf ("0x%08"PFMT64x" 0x%08"PFMT64x" %02X:%04X %d",
				b->addr, b->addr + b->size,
				tp?tp->times:0, tp?tp->count:0,
				b->size);
			if (b->jump != UT64_MAX) {
				r_cons_printf (" j 0x%08"PFMT64x, b->jump);
			}
			if (b->fail != UT64_MAX) {
				r_cons_printf (" f 0x%08"PFMT64x, b->fail);
			}
			r_cons_newline ();
			break;
		}
	}
	if (mode=='j') {
		r_cons_printf ("]");
	}
	return R_TRUE;
}

static int anal_fcn_add_bb (RCore *core, const char *input) {
	// fcn_addr bb_addr bb_size [jump] [fail]
	char *ptr;
	const char *ptr2 = NULL;
	ut64 fcnaddr = -1LL, addr = -1LL;
	ut64 size = 0LL;
	ut64 jump = UT64_MAX;
	ut64 fail = UT64_MAX;
	int type = R_ANAL_BB_TYPE_NULL;
	RAnalFunction *fcn = NULL;
	RAnalDiff *diff = NULL;

	while (*input==' ') input++;
	ptr = strdup (input);

	switch (r_str_word_set0 (ptr)) {
	case 7:
		ptr2 = r_str_word_get0 (ptr, 6);
		if (!(diff = r_anal_diff_new ())) {
			eprintf ("error: Cannot init RAnalDiff\n");
			free (ptr);
			return R_FALSE;
		}
		if (ptr2[0] == 'm')
			diff->type = R_ANAL_DIFF_TYPE_MATCH;
		else if (ptr2[0] == 'u')
			diff->type = R_ANAL_DIFF_TYPE_UNMATCH;
	case 6:
		ptr2 = r_str_word_get0 (ptr, 5);
		if (strchr (ptr2, 'h'))
			type |= R_ANAL_BB_TYPE_HEAD;
		if (strchr (ptr2, 'b'))
			type |= R_ANAL_BB_TYPE_BODY;
		if (strchr (ptr2, 'l'))
			type |= R_ANAL_BB_TYPE_LAST;
		if (strchr (ptr2, 'f'))
			type |= R_ANAL_BB_TYPE_FOOT;
	case 5: // get fail
		fail = r_num_math (core->num, r_str_word_get0 (ptr, 4));
	case 4: // get jump
		jump = r_num_math (core->num, r_str_word_get0 (ptr, 3));
	case 3: // get size
		size = r_num_math (core->num, r_str_word_get0 (ptr, 2));
	case 2: // get addr
		addr = r_num_math (core->num, r_str_word_get0 (ptr, 1));
	case 1: // get fcnaddr
		fcnaddr = r_num_math (core->num, r_str_word_get0 (ptr, 0));
	}
	fcn = r_anal_get_fcn_in (core->anal, fcnaddr, 0);
	if (fcn) {
		int ret = r_anal_fcn_add_bb (core->anal, fcn, addr,
			size, jump, fail, type, diff);
		if (!ret) {
			eprintf ("Cannot add basic block\n");
		}
	} else {
		eprintf ("Cannot find function at 0x%"PFMT64x"\n", fcnaddr);
	}
	r_anal_diff_free (diff);
	free (ptr);
	return R_TRUE;
}

static int setFunctionName(RCore *core, ut64 off, const char *name) {
	char *oname;
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, off,
		R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM|R_ANAL_FCN_TYPE_LOC);
	if (!fcn)
		return 0;
	//r_cons_printf ("fr %s %s@ 0x%"PFMT64x"\n",
	//	 fcn->name, name, off);
	r_core_cmdf (core, "fr %s %s@ 0x%"PFMT64x,
		fcn->name, name, off);
	oname = fcn->name;
	fcn->name = strdup (name);
	if (core->anal->cb.on_fcn_rename) {
		core->anal->cb.on_fcn_rename (core->anal, core->anal->user, fcn, oname);
	}
	free (oname);
	return 1;
}

static int cmd_anal_fcn(RCore *core, const char *input) {
	switch (input[1]) {
	case 'f':
		r_anal_fcn_fit_overlaps (core->anal, NULL);
		break;
	case '-':
		 {
			ut64 addr = input[2]?
			r_num_math (core->num, input+2): core->offset;
			r_anal_fcn_del_locs (core->anal, addr);
			r_anal_fcn_del (core->anal, addr);
		 }
		break;
	case 'u':
		{
		ut64 addr = core->offset;
		ut64 addr_end = r_num_math (core->num, input+2);
		if (addr_end < addr) {
			eprintf ("Invalid address ranges\n");
		} else {
			int depth = 1;
			ut64 a, b;
			const char *c;
			a = r_config_get_i (core->config, "anal.from");
			b = r_config_get_i (core->config, "anal.to");
			c = r_config_get (core->config, "anal.limits");
			r_config_set_i (core->config, "anal.from", addr);
			r_config_set_i (core->config, "anal.to", addr_end);
			r_config_set (core->config, "anal.limits", "true");

			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, 0);
			if (fcn) r_anal_fcn_resize (fcn, addr_end-addr);
			r_core_anal_fcn (core, addr, UT64_MAX,
					R_ANAL_REF_TYPE_NULL, depth);
			fcn = r_anal_get_fcn_in (core->anal, addr, 0);
			if (fcn) r_anal_fcn_resize (fcn, addr_end-addr);

			r_config_set_i (core->config, "anal.from", a);
			r_config_set_i (core->config, "anal.to", b);
			r_config_set (core->config, "anal.limits", c?c:"");
		}
		}
		break;
	case '+':
		 {
			char *ptr = strdup (input+3);
			const char *ptr2;
			int n = r_str_word_set0 (ptr);
			const char *name = NULL;
			ut64 addr = -1LL;
			ut64 size = 0LL;
			RAnalDiff *diff = NULL;
			int type = R_ANAL_FCN_TYPE_FCN;
			if (n > 2) {
				switch(n) {
				case 5:
					ptr2 = r_str_word_get0 (ptr, 4);
					if (!(diff = r_anal_diff_new ())) {
						eprintf ("error: Cannot init RAnalDiff\n");
						free (ptr);
						return R_FALSE;
					}
					if (ptr2[0] == 'm')
						diff->type = R_ANAL_DIFF_TYPE_MATCH;
					else if (ptr2[0] == 'u')
						diff->type = R_ANAL_DIFF_TYPE_UNMATCH;
				case 4:
					ptr2 = r_str_word_get0 (ptr, 3);
					if (strchr (ptr2, 'l'))
						type = R_ANAL_FCN_TYPE_LOC;
					else if (strchr (ptr2, 'i'))
						type = R_ANAL_FCN_TYPE_IMP;
					else if (strchr (ptr2, 's'))
						type = R_ANAL_FCN_TYPE_SYM;
					else type = R_ANAL_FCN_TYPE_FCN;
				case 3:
					name = r_str_word_get0 (ptr, 2);
				case 2:
					size = r_num_math (core->num, r_str_word_get0 (ptr, 1));
				case 1:
					addr = r_num_math (core->num, r_str_word_get0 (ptr, 0));
				}
				if (!r_anal_fcn_add (core->anal, addr, size, name, type, diff))
					eprintf ("Cannot add function (duplicated)\n");
			}
			r_anal_diff_free (diff);
			free (ptr);
		 }
		break;
	case 'o': // "afo"
		 {
			RAnalFunction *fcn;
			ut64 addr = core->offset;
			if (input[2]==' ')
				addr = r_num_math (core->num, input+3);
			if (addr == 0LL) {
				fcn = r_anal_fcn_find_name (core->anal, input+3);
			} else {
				fcn = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
			}
			if (fcn) r_cons_printf ("0x%08"PFMT64x"\n", fcn->addr);
		 }
		break;
	case 'i': // "afi"
		switch (input[2]) {
		case '?': eprintf ("Usage: afi[j*] <addr>\n"); break;
		case 'j': r_core_anal_fcn_list (core, input+3, 'j'); break; // "afij"
		case '*': r_core_anal_fcn_list (core, input+3, 1); break; // "afi*"
		default: r_core_anal_fcn_list (core, input+2, 0); break;
		}
		break;
	case 'l': // "afl"
		switch (input[2]) {
		case '?':
			eprintf ("Usage: afl[ajq*] <addr>\n");
			eprintf ("List all functions in quiet, commands or json format\n");
			break;
		case 'a':
		case '*':
		case 'j':
		case 'q':
			r_core_anal_fcn_list (core, NULL, input[2]);
			break;
		default:
			r_core_anal_fcn_list (core, NULL, 'q');
			break;
		}
		break;
	case 's': { // "afs"
			  ut64 addr;
			  RAnalFunction *f;
			  const char *arg = input+3;
			  if (input[2] && (addr = r_num_math (core->num, arg))) {
				  arg = strchr (arg, ' ');
				  if (arg) arg++;
			  } else addr = core->offset;
			  if ((f = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL))) {
				  if (arg && *arg) {
					  r_anal_str_to_fcn (core->anal, f, arg);
				  } else {
					  char *str = r_anal_fcn_to_string (core->anal, f);
					  r_cons_printf ("%s\n", str);
					  free (str);
				  }
			  } else eprintf("No function defined at 0x%08"PFMT64x"\n", addr);
		  }
		 break;
	case 'm': // "afm" - merge two functions
		r_core_anal_fcn_merge (core,
			core->offset, r_num_math (core->num, input+2));
		break;
	case 'a': // "afa"
	case 'A': // "afA"
	case 'v': // "afv"
		 var_cmd (core, input+1);
		 break;
	case 'c': // "afc"
		  {
			 RAnalFunction *fcn;
			 if ((fcn = r_anal_get_fcn_in (core->anal, core->offset, 0)) != NULL) {
				 r_cons_printf ("%i\n", r_anal_fcn_cc (fcn));
			 } else eprintf ("Error: Cannot find function at 0x08%"PFMT64x"\n", core->offset);
		  }
		 break;
	case 'C': // "afC"
		if (input[2]=='?') {
			int i;
			for (i=0; ; i++) {
				const char *s = r_anal_cc_type2str (i);
				if (!s) break;
				r_cons_printf ("%s\n", s);
			}
		} else {
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			if (fcn) {
				if (input[2]=='a') {
					eprintf ("TODO: analyze function to guess its calling convention\n");
				} else
					if (input[2]==' ') {
						int type = r_anal_cc_str2type (input+3);
						if (type == -1) {
							eprintf ("Unknown calling convention '%s'\n", input+3);
						} else {
							// set calling convention for current function
							fcn->call = type;
						}
					} else {
						const char *type = r_anal_cc_type2str (fcn->call);
						if (type) {
							r_cons_printf ("%s\n", type);
						} else {
							eprintf ("Unknown calling convention\n");
						}
					}
			} else {
				eprintf ("Cannot find function\n");
			}
		}
		break;
	case 'B': // "afB" // set function bits
		if (input[2] == ' ') {
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset,
				R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
			if (fcn) fcn->bits = atoi (input+3);
			else eprintf ("Cannot find function to set bits\n");
		} else {
			eprintf ("Usage: afB [bits]\n");
		}
		break;
	case 'b': // "afb"
		switch (input[2]) {
		case 0:
		case ' ':
		case 'q':
		case 'r':
		case '*':
		case 'j':
			anal_fcn_list_bb (core, input+2);
			break;
		case '+': // "afb+"
			anal_fcn_add_bb (core, input+3);
			break;
		default:
		case '?':
			eprintf ("Usage: afb+ or afbb or afb\n"
			" afB [bits]  - define asm.bits for given function\n"
			" afb [addr]  - list basic blocks of function (see afbq, afbj, afb*)\n"
			" afb+ fcn_at bbat bbsz [jump] [fail] ([type] ([diff]))  add bb to function @ fcnaddr\n");
			break;
		}
		break;
	case 'n': // "afn"
		if (input[2]=='a') { // afna autoname
			char *name = r_core_anal_fcn_autoname (core, core->offset);
			if (name) {
				r_cons_printf ("afn %s 0x%08"PFMT64x"\n",
					name, core->offset);
				free (name);
			}
		} else {
			 ut64 off = core->offset;
			 char *p, *name = strdup (input+3);
			 if ((p=strchr (name, ' '))) {
				 *p++ = 0;
				 off = r_num_math (core->num, p);
			 }
			 if (*name) {
				 if (!setFunctionName (core, off, name))
					 eprintf ("Cannot find function '%s' at 0x%08"PFMT64x"\n", name, off);
				 free (name);
			 } else {
				 eprintf ("Usage: afn newname [off]   # set new name to given function\n");
				 free (name);
			 }
		 }
		 break;
#if FCN_OLD
/* this is undocumented and probably have no uses. plz discuss */
	case 'e': // "afe"
		  {
			 RAnalFunction *fcn;
			 ut64 off = core->offset;
			 char *p, *name = strdup (input+3);
			 if ((p=strchr (name, ' '))) {
				 *p = 0;
				 off = r_num_math (core->num, p+1);
			 }
			 fcn = r_anal_get_fcn_in (core->anal, off,
				 R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
			 if (fcn) {
				 RAnalBlock *b;
				 RListIter *iter;
				 RAnalRef *r;
				 r_list_foreach (fcn->refs, iter, r) {
					 r_cons_printf ("0x%08"PFMT64x" -%c 0x%08"PFMT64x"\n", r->at, r->type, r->addr);
				 }
				 r_list_foreach (fcn->bbs, iter, b) {
					 int ok = 0;
					 if (b->type == R_ANAL_BB_TYPE_LAST) ok = 1;
					 if (b->type == R_ANAL_BB_TYPE_FOOT) ok = 1;
					 if (b->jump == UT64_MAX && b->fail == UT64_MAX) ok=1;
					 if (ok) {
						 r_cons_printf ("0x%08"PFMT64x" -r\n", b->addr);
						 // TODO: check if destination is outside the function boundaries
					 }
				 }
			 } else eprintf ("Cannot find function at 0x%08"PFMT64x"\n", core->offset);
			free (name);
		  }
		 break;
#endif
	case 'x':
		 switch (input[2]) {
		 case '\0':
		 case ' ':
#if FCN_OLD
			 // TODO: sdbize!
			 // list xrefs from current address
			  {
				 ut64 addr = input[2]?  r_num_math (core->num, input+2): core->offset;
				 RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
				 if (fcn) {
					 RAnalRef *ref;
					 RListIter *iter;
					 r_list_foreach (fcn->refs, iter, ref) {
						 r_cons_printf ("%c 0x%08"PFMT64x" -> 0x%08"PFMT64x"\n",
							 ref->type, ref->at, ref->addr);
					 }
				 } else eprintf ("Cant find function\n");
			  }
#else
#warning TODO_ FCNOLD sdbize xrefs here
			eprintf ("TODO\n");
#endif
			 break;
		 case 'c': // add meta xref
		 case 'd':
		 case 's':
		 case 'C': {
				   char *p;
				   ut64 a, b;
				   RAnalFunction *fcn;
				   char *mi = strdup (input);
				   if (mi && mi[3]==' ' && (p=strchr (mi+4, ' '))) {
					   *p = 0;
					   a = r_num_math (core->num, mi+3);
					   b = r_num_math (core->num, p+1);
					   fcn = r_anal_get_fcn_in (core->anal, a, R_ANAL_FCN_TYPE_ROOT);
					   if (fcn) {
						   r_anal_fcn_xref_add (core->anal, fcn, a, b, input[2]);
					   } else eprintf ("Cannot add reference to non-function\n");
				   } else eprintf ("Usage: afx[cCd?] [src] [dst]\n");
				   free (mi);
			   }
			  break;
		 case '-': {
				   char *p;
				   ut64 a, b;
				   RAnalFunction *fcn;
				   char *mi = strdup (input+2);
				   if (mi && *mi==' ' && (p=strchr (mi+1, ' '))) {
					   *p = 0;
					   a = r_num_math (core->num, mi);
					   b = r_num_math (core->num, p+1);
					   fcn = r_anal_get_fcn_in (core->anal, a, R_ANAL_FCN_TYPE_ROOT);
					   if (fcn) {
						   r_anal_fcn_xref_del (core->anal, fcn, a, b, -1);
					   } else eprintf ("Cannot del reference to non-function\n");
				   } else eprintf ("Usage: afx- [src] [dst]\n");
				   free (mi);
			   }
			  break;
		 default:
		 case '?':{
			   const char* help_msg[] = {
			       "Usage:", "afx[-cCd?] [src] [dst]", "# manage function references (see also ar?)",
				   "afxc", " sym.main+0x38 sym.printf", "add code ref",
				   "afxC", " sym.main sym.puts", "add call ref",
				   "afxd", " sym.main str.helloworld", "add data ref",
				   "afx-", " sym.main str.helloworld", "remove reference",
				   NULL
			   };
			   r_core_cmd_help (core, help_msg);
			   }
			   break;
		 }
		 break;
	case '?':{ // "af?"
		 const char* help_msg[] = {
		 "Usage:", "af", "",
		 "af", " [name] ([addr]) (@ [addr])", "analyze functions (start at addr)",
		 "af+", " addr size name [type] [diff]", "add function",
		 "af-", " [addr]", "clean all function analysis data (or function at addr)",
		 "afa", "[?] [idx] [type] [name]", "add function argument",
		 "af[aAv?]", "[arg]", "manipulate args, fastargs and variables in function",
		 "afb+", " fa a sz [j] [f] ([t]( [d]))","add bb to function @ fcnaddr",
		 "afb", " [addr]", "List basic blocks of given function",
		 "afB", " 16", "set current function as thumb (change asm.bits)",
		 "afc", "@[addr]", "calculate the Cyclomatic Complexity (starting at addr)",
		 "afC[a]", " type @[addr]", "set calling convention for function (afC?=list cc types)",
		 "aff", "", "re-adjust function boundaries to fit",
		 "afi", " [addr|fcn.name]", "show function(s) information (verbose afl)",
		 "afl", "[*] [fcn name]", "list functions (addr, size, bbs, name)",
		 "afo", " [fcn.name]", "show address for the function named like this",
		 "afn", " name [addr]", "rename name for function at address (change flag too)",
		 "afna", "", "suggest automatic name for current offset",
		 "afs", " [addr] [fcnsign]", "get/set function signature at current address",
		 "afx", "[cCd-] src dst", "add/remove code/Call/data/string reference",
		 "afv", "[?] [idx] [type] [name]", "add local var on current function",
		 NULL};
		 r_core_cmd_help (core, help_msg);
		}
		 break;
	default:
		{
			char *uaddr = NULL, *name = NULL;
			int depth = r_config_get_i (core->config, "anal.depth");
			RAnalFunction *fcn;
			ut64 addr = core->offset;

			// first undefine
			if (input[1]==' ') {
				name = strdup (input+2);
				uaddr = strchr (name+1, ' ');
				if (uaddr) {
					*uaddr++ = 0;
					addr = r_num_math (core->num, uaddr);
				}
				//depth = 1; // or 1?
				// disable hasnext
			}
			//r_core_anal_undefine (core, core->offset);
			/* resize function if overlaps */
			fcn = r_anal_get_fcn_in (core->anal, addr, 0);
			if (fcn) r_anal_fcn_resize (fcn, addr - fcn->addr);
			r_core_anal_fcn (core, addr, UT64_MAX,
				R_ANAL_REF_TYPE_NULL, depth);
			if (name && *name) {
				if (!setFunctionName (core, addr, name))
					eprintf ("Cannot find function '%s' at 0x%08"PFMT64x"\n", name, addr);
			}
			free (name);
		}
	}
	return R_TRUE;
}

static void __anal_reg_list (RCore *core, int type, int size, char mode) {
	RReg *hack = core->dbg->reg;
	int bits;
	if (size > 0)			//TODO: ar all
		bits = size;
	else	bits = core->anal->bits;
	const char *use_color;
	int use_colors = r_config_get_i(core->config, "scr.color");
	if (use_colors) {
#undef ConsP
#define ConsP(x) (core->cons && core->cons->pal.x)? core->cons->pal.x
		use_color = ConsP(creg): Color_BWHITE;
	} else {
		use_color = NULL;
	}
	core->dbg->reg = core->anal->reg;
	/* workaround for thumb */
	if (core->anal->cur->arch == R_SYS_ARCH_ARM && bits==16) {
		bits = 32;
	}
	r_debug_reg_list (core->dbg, type, bits, mode, use_color);
	core->dbg->reg = hack;
}

static void ar_show_help(RCore *core) {
	const char * help_message[] = {
		"Usage: ar", "", "# Analysis Registers",
		"ar", "", "Show 'gpr' registers",
		"ar0", "", "Reset register arenas to 0",
		"ar", " 16", "Show 16 bit registers",
		"ar", " 32", "Show 32 bit registers",
		"ar", " all", "Show all bit registers",
		"ar", " <type>", "Show all registers of given type",
		"ar=", "", "Show register values in columns",
		"ar?"," <reg>", "Show register value",
		"arb"," <type>", "Display hexdump of the given arena",
		"arc"," <name>", "Conditional flag registers",
		"ard"," <name>", "Show only different registers",
		"arn"," <regalias>", "Get regname for pc,sp,bp,a0-3,zf,cf,of,sg",
		"aro", "", "Show old (previous) register values",
		"arp"," <file>", "Load register profile from file",
		"ars", "", "Stack register state",
		"art","","List all register types",
		".ar*","", "Import register values as flags",
		".ar-","", "Unflag all registers",
		NULL
	};
	r_core_cmd_help (core, help_message);
}

void cmd_anal_reg(RCore *core, const char *str) {
	int size = 0, i, type = R_REG_TYPE_GPR;
	int bits = (core->anal->bits & R_SYS_BITS_64)? 64: 32;
	int use_colors = r_config_get_i(core->config, "scr.color");
	struct r_reg_item_t *r;
	const char *use_color;
	const char *name;
	char *arg;

	if (use_colors) {
#define ConsP(x) (core->cons && core->cons->pal.x)? core->cons->pal.x
		use_color = ConsP(creg): Color_BWHITE;
	} else {
		use_color = NULL;
	}
	switch (str[0]) {
	case 'l':
		{
			RRegSet *rs = r_reg_regset_get (core->anal->reg, R_REG_TYPE_GPR);
			if (rs) {
				RRegItem *r;
				RListIter *iter;
				r_list_foreach (rs->regs, iter, r) {
					r_cons_printf ("%s\n", r->name);
				}
			}
		}
		break;
	case '0':
		r_reg_arena_zero (core->anal->reg);
		break;
	case '?':
		if (str[1]) {
			ut64 off = r_reg_getv (core->anal->reg, str+1);
			r_cons_printf ("0x%08"PFMT64x"\n", off);
		} else ar_show_help (core);
		break;
	case 'S':
		 {
			int sz;
			ut8 *buf = r_reg_get_bytes (
				core->anal->reg, R_REG_TYPE_GPR, &sz);
			r_cons_printf ("%d\n", sz);
			free (buf);
		 }
		break;
	case 'b':
		 { // WORK IN PROGRESS // DEBUG COMMAND
			int len;
			const ut8 *buf = r_reg_get_bytes (core->dbg->reg, R_REG_TYPE_GPR, &len);
			//r_print_hexdump (core->print, 0LL, buf, len, 16, 16);
			r_print_hexdump (core->print, 0LL, buf, len, 32, 4);
		 }
		break;
	case 'c':
		// TODO: set flag values with drc zf=1
		 {
			RRegItem *r;
			const char *name = str+1;
			while (*name==' ') name++;
			if (*name && name[1]) {
				r = r_reg_cond_get (core->dbg->reg, name);
				if (r) {
					r_cons_printf ("%s\n", r->name);
				} else {
					int id = r_reg_cond_from_string (name);
					RRegFlags* rf = r_reg_cond_retrieve (core->dbg->reg, NULL);
					if (rf) {
						int o = r_reg_cond_bits (core->dbg->reg, id, rf);
						core->num->value = o;
						// ORLY?
						r_cons_printf ("%d\n", o);
						free (rf);
					} else eprintf ("unknown conditional or flag register\n");
				}
			} else {
				RRegFlags *rf = r_reg_cond_retrieve (core->dbg->reg, NULL);
				if (rf) {
					r_cons_printf ("| s:%d z:%d c:%d o:%d p:%d\n",
						rf->s, rf->z, rf->c, rf->o, rf->p);
					if (*name=='=') {
						for (i=0; i<R_REG_COND_LAST; i++) {
							r_cons_printf ("%s:%d ",
								r_reg_cond_to_string (i),
								r_reg_cond_bits (core->dbg->reg, i, rf));
						}
						r_cons_newline ();
					} else {
						for (i=0; i<R_REG_COND_LAST; i++) {
							r_cons_printf ("%d %s\n",
								r_reg_cond_bits (core->dbg->reg, i, rf),
								r_reg_cond_to_string (i));
						}
					}
					free (rf);
				}
			}
		 }
		break;
	case 's': // "drs"
		switch (str[1]) {
		case '-':
			r_reg_arena_pop (core->dbg->reg);
			// restore debug registers if in debugger mode
			r_debug_reg_sync (core->dbg, 0, 1);
			break;
		case '+':
			r_reg_arena_push (core->dbg->reg);
			break;
		case '?':{
			const char* help_msg[] = {
				"Usage:", "drs", " # Register states commands",
				"drs", "", "List register stack",
				"drs+", "", "Push register state",
				"drs-", "", "Pop register state",
				NULL};
			r_core_cmd_help (core, help_msg);
			}
			break;
		default:
			r_cons_printf ("%d\n", r_list_length (
					core->dbg->reg->regset[0].pool));
			break;
		}
		break;
	case 'p':
		if (!str[1]) {
			if (core->dbg->reg->reg_profile_str) {
				//core->anal->reg = core->dbg->reg;
				r_cons_printf ("%s\n", core->dbg->reg->reg_profile_str);
				//r_cons_printf ("%s\n", core->anal->reg->reg_profile);
			} else eprintf ("No register profile defined. Try 'dr.'\n");
		} else r_reg_set_profile (core->dbg->reg, str+2);
		break;
	case 't': // "drt"
		for (i=0; (name=r_reg_get_type (i)); i++)
			r_cons_printf ("%s\n", name);
		break;
	case 'n': // "drn"
		name = r_reg_get_name (core->dbg->reg, r_reg_get_name_idx (str+2));
		if (name && *name)
			r_cons_printf ("%s\n", name);
		else eprintf ("Oops. try drn [pc|sp|bp|a0|a1|a2|a3|zf|sf|nf|of]\n");
		break;
	case 'd': // "drd"
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, 3, use_color); // XXX detect which one is current usage
		break;
	case 'o': // "dro"
		r_reg_arena_swap (core->dbg->reg, R_FALSE);
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, 0, use_color); // XXX detect which one is current usage
		r_reg_arena_swap (core->dbg->reg, R_FALSE);
		break;
	case '=': // "dr="
		__anal_reg_list (core, type, size, 2);
		break;
	case '-':
	case '*':
	case 'j':
	case '\0':
		__anal_reg_list (core, type, size, str[0]);
		break;
	case ' ':
		arg = strchr (str+1, '=');
		if (arg) {
			char *ostr, *regname;
			*arg = 0;
			ostr = r_str_chop (strdup (str+1));
			regname = r_str_clean (ostr);
			r = r_reg_get (core->dbg->reg, regname, -1); //R_REG_TYPE_GPR);
			if (r) {
				eprintf ("%s 0x%08"PFMT64x" -> ", str,
					r_reg_get_value (core->dbg->reg, r));
				r_reg_set_value (core->dbg->reg, r,
					r_num_math (core->num, arg+1));
				r_debug_reg_sync (core->dbg, -1, R_TRUE);
				eprintf ("0x%08"PFMT64x"\n",
					r_reg_get_value (core->dbg->reg, r));
			} else {
				eprintf ("ar: Unknown register '%s'\n", regname);
			}
			free (ostr);
			return;
		}
		size = atoi (str+1);
		if (size==0) {
			r = r_reg_get (core->dbg->reg, str+1, -1);
			if (r) {
				r_cons_printf ("0x%08"PFMT64x"\n",
					r_reg_get_value (core->dbg->reg, r));
				return;
			}
			arg = strchr (str+1, ' ');
			if (arg && size==0) {
				*arg='\0';
				size = atoi (arg);
			} else size = bits;
			type = r_reg_type_by_name (str+1);
		}
		if (type != R_REG_TYPE_LAST) {
			__anal_reg_list (core, type, size, str[0]);
		} else eprintf ("cmd_debug_reg: Unknown type\n");
	}
}

static void esil_step(RCore *core, ut64 until_addr, const char *until_expr) {
	// Stepping
	int ret;
	ut8 code[256];
	RAnalOp op;
	const char *name = r_reg_get_name (core->anal->reg, r_reg_get_name_idx ("pc"));
	ut64 addr = r_reg_getv (core->anal->reg, name);
	repeat:
	if (r_cons_singleton()->breaked) {
		eprintf ("[+] ESIL emulation interrupted at 0x%08"PFMT64x"\n", addr);
		return;
	}
	if (!core->anal->esil) {
		int romem = r_config_get_i (core->config, "esil.romem");
		int stats = r_config_get_i (core->config, "esil.stats");
		core->anal->esil = r_anal_esil_new ();
		r_anal_esil_setup (core->anal->esil, core->anal, romem, stats); // setup io
		RList *entries = r_bin_get_entries (core->bin);
		RBinAddr *entry = NULL;
		RBinInfo *info = NULL;
		if (entries && r_list_length(entries)) {
			entry = (RBinAddr *) r_list_pop (entries);
			info = r_bin_get_info (core->bin);
			if (info->has_va)
				addr = entry->vaddr;
			else	addr = entry->paddr;
			eprintf ("PC=entry0\n");
			r_list_push (entries, entry);
		} else {
			addr = core->offset;
			eprintf ("PC=OFF\n");
		}
		r_reg_setv (core->anal->reg, name, addr);
		// set memory read only
	} else {
		addr = r_reg_getv (core->anal->reg, name);
		//eprintf ("PC=0x%llx\n", (ut64)addr);
	}
	if (core->anal->esil->delay)
		addr = core->anal->esil->delay_addr;
	r_io_read_at (core->io, addr, code, sizeof (code));
	r_asm_set_pc (core->assembler, addr);
	ret = r_anal_op (core->anal, &op, addr, code, sizeof (code));
	core->anal->esil->delay = op.delay;
	if (core->anal->esil->delay)
		core->anal->esil->delay_addr = addr+op.size;
#if 0
eprintf ("RET %d\n", ret);
eprintf ("ADDR 0x%llx\n", addr);
eprintf ("DATA %x %x %x %x\n", code[0], code[1], code[2], code[3]);
eprintf ("ESIL %s\n", op.esil);
eprintf ("EMULATE %s\n", R_STRBUF_SAFEGET (&op.esil));
sleep (1);
#endif
	if (ret) {
		//r_anal_esil_eval (core->anal, input+2);
		RAnalEsil *esil = core->anal->esil;
		r_anal_esil_set_offset (esil, addr);
		r_anal_esil_parse (esil, R_STRBUF_SAFEGET (&op.esil));
		if (core->anal->cur && core->anal->cur->esil_post_loop)
			core->anal->cur->esil_post_loop (esil, &op);
		r_anal_esil_dumpstack (esil);
		r_anal_esil_stack_free (esil);
	}
	ut64 newaddr = r_reg_getv (core->anal->reg, name);

	ut64 follow = r_config_get_i (core->config, "dbg.follow");
	if (follow>0) {
		ut64 pc = r_debug_reg_get (core->dbg, "pc");
		if ((pc<core->offset) || (pc > (core->offset+follow)))
			r_core_cmd0 (core, "sr pc");
	}
	if (addr == newaddr) {
		if (op.size<1)
			op.size = 1; // avoid inverted stepping
		r_reg_setv (core->anal->reg, name, addr + op.size);
	}
	if (core->dbg->trace->enabled) {
		RReg *reg = core->dbg->reg;
		core->dbg->reg = core->anal->reg;
		r_debug_trace_pc (core->dbg);
		core->dbg->reg = reg;
	}
	// check addr
	if (until_addr != UT64_MAX) {
		if (r_reg_getv (core->anal->reg, name) == until_addr) {
			eprintf ("ADDR BREAK\n");
		} else goto repeat;
	}
	// check esil
	if (until_expr) {
		if (r_anal_esil_condition (core->anal->esil, until_expr)) {
			eprintf ("ESIL BREAK!\n");
		} else goto repeat;
	}
}

static void cmd_address_info(RCore *core, const char *addrstr, int fmt) {
	ut64 addr, type;
	if (!addrstr || !*addrstr) {
		addr = core->offset;
	} else {
		addr = r_num_math (core->num, addrstr);
	}
	type = r_core_anal_address (core, addr);
	int isp = 0;
	switch(fmt) {
	case 'j':
#define COMMA isp++?",":""
		r_cons_printf ("{");
		if (type & R_ANAL_ADDR_TYPE_PROGRAM)
			r_cons_printf ("%s\"program\":true", COMMA);
		if (type & R_ANAL_ADDR_TYPE_LIBRARY)
			r_cons_printf ("%s\"library\":true", COMMA);
		if (type & R_ANAL_ADDR_TYPE_EXEC)
			r_cons_printf ("%s\"exec\":true", COMMA);
		if (type & R_ANAL_ADDR_TYPE_READ)
			r_cons_printf ("%s\"read\":true", COMMA);
		if (type & R_ANAL_ADDR_TYPE_WRITE)
			r_cons_printf ("%s\"write\":true", COMMA);
		if (type & R_ANAL_ADDR_TYPE_FLAG)
			r_cons_printf ("%s\"flag\":true", COMMA);
		if (type & R_ANAL_ADDR_TYPE_FUNC)
			r_cons_printf ("%s\"func\":true", COMMA);
		if (type & R_ANAL_ADDR_TYPE_STACK)
			r_cons_printf ("%s\"stack\":true", COMMA);
		if (type & R_ANAL_ADDR_TYPE_HEAP)
			r_cons_printf ("%s\"heap\":true", COMMA);
		if (type & R_ANAL_ADDR_TYPE_REG)
			r_cons_printf ("%s\"reg\":true", COMMA);
		if (type & R_ANAL_ADDR_TYPE_ASCII)
			r_cons_printf ("%s\"ascii\":true", COMMA);
		if (type & R_ANAL_ADDR_TYPE_SEQUENCE)
			r_cons_printf ("%s\"sequence\":true", COMMA);
		r_cons_printf ("}");
		break;
	default:
		if (type & R_ANAL_ADDR_TYPE_PROGRAM)
			r_cons_printf ("program\n");
		if (type & R_ANAL_ADDR_TYPE_LIBRARY)
			r_cons_printf ("library\n");
		if (type & R_ANAL_ADDR_TYPE_EXEC)
			r_cons_printf ("exec\n");
		if (type & R_ANAL_ADDR_TYPE_READ)
			r_cons_printf ("read\n");
		if (type & R_ANAL_ADDR_TYPE_WRITE)
			r_cons_printf ("write\n");
		if (type & R_ANAL_ADDR_TYPE_FLAG)
			r_cons_printf ("flag\n");
		if (type & R_ANAL_ADDR_TYPE_FUNC)
			r_cons_printf ("func\n");
		if (type & R_ANAL_ADDR_TYPE_STACK)
			r_cons_printf ("stack\n");
		if (type & R_ANAL_ADDR_TYPE_HEAP)
			r_cons_printf ("heap\n");
		if (type & R_ANAL_ADDR_TYPE_REG)
			r_cons_printf ("reg\n");
		if (type & R_ANAL_ADDR_TYPE_ASCII)
			r_cons_printf ("ascii\n");
		if (type & R_ANAL_ADDR_TYPE_SEQUENCE)
			r_cons_printf ("sequence\n");
	}
}

static void cmd_anal_info(RCore *core, const char *input) {
	switch (input[0]) {
	case '?':
		eprintf ("Usage: ai @ rsp\n");
		break;
	case ' ':
		cmd_address_info (core, input, 0);
		break;
	case 'j': // "aij"
		cmd_address_info (core, input+1, 'j');
		break;
	default:
		cmd_address_info (core, NULL, 0);
		break;
	}
}

static void cmd_esil_mem (RCore *core, const char *input) {
	ut64 curoff = core->offset;
	ut64 addr = 0x100000;
	ut32 size = 0xf0000;
	char name[128];
	RCoreFile *cf;
	RFlagItem *fi;
	char uri[32];
	char nomalloc[256];
	char *p;
	if (*input=='?') {
		eprintf ("Usage: [addr] [size] [name]\n");
		eprintf ("Default: 0x100000 0xf0000\n");
		return;
	}

	p = strncpy (nomalloc, input, 255);
	if ((p = strchr (p, ' '))) {
		while (*p == ' ') p++;
		addr = r_num_math (core->num, p);
		if ((p = strchr (p, ' '))) {
			while (*p == ' ') p++;
			size = (ut32)r_num_math (core->num, p);
			if (size<1)
				size = 0xf0000;
			if ((p = strchr (p, ' '))) {
				while (*p == ' ') p++;
				snprintf (name, 128, "mem.%s", p);
			} else	snprintf (name, 128, "mem.0x%"PFMT64x"_0x%x", addr, size);
		} else	snprintf (name, 128, "mem.0x%"PFMT64x"_0x%x", addr, size);
	} else	snprintf (name, 128, "mem.0x%"PFMT64x"_0x%x", addr, size);

	fi = r_flag_get (core->flags, name);
	if (fi) {
		if (*input=='-') {
			cf = r_core_file_get_by_fd (core, fi->offset);
			r_core_file_close (core, cf);
			r_flag_unset (core->flags, name, NULL);
			eprintf ("Deinitialized %s\n", name);
			return;
		}
		eprintf ("Cannot create mem here, mem allready lives here");
		return;
	}
	if (*input=='-') {
		eprintf ("Cannot deinitialize %s\n", name);
		return;
	}
	snprintf (uri, sizeof (uri), "malloc://%d", (int)size);
	cf = r_core_file_open (core, uri, R_IO_RW, addr);
	if (cf)
		r_flag_set (core->flags, name, addr, size, 0);
	//r_core_cmdf (core, "f stack_fd=`on malloc://%d 0x%08"
	//	PFMT64x"`", stack_size, stack_addr);
	//r_core_cmdf (core, "f stack=0x%08"PFMT64x, stack_addr);
	//r_core_cmdf (core, "dr %s=0x%08"PFMT64x, sp, stack_ptr);
	//r_debug_reg_set (core->dbg, sp, stack_ptr);
	//r_core_cmdf (core, "ar %s=0x%08"PFMT64x, sp, stack_ptr);
	//r_core_cmdf (core, "f %s=%s", sp, sp);
	r_core_seek (core, curoff, 0);
}

static void cmd_anal_esil(RCore *core, const char *input) {
	RAnalEsil *esil = core->anal->esil;
	ut64 addr = core->offset;
	int romem = r_config_get_i (core->config, "esil.romem");
	int stats = r_config_get_i (core->config, "esil.stats");
	ut64 until_addr = UT64_MAX;
	const char *until_expr = NULL;
	RAnalOp *op;

	switch (input[0]) {
	case 'r':
		// 'aer' is an alias for 'ar'
		cmd_anal_reg (core, input+1);
		break;
	case ' ':
		//r_anal_esil_eval (core->anal, input+1);
		if (!esil) {
			core->anal->esil = esil = r_anal_esil_new ();
		}
		r_anal_esil_setup (esil, core->anal, romem, stats); // setup io
		r_anal_esil_set_offset (esil, core->offset);
		r_anal_esil_parse (esil, input+1);
		r_anal_esil_dumpstack (esil);
		r_anal_esil_stack_free (esil);
		break;
	case 's':
		// "aes" "aeso" "aesu" "aesue"
		// aes -> single step
		// aeso -> single step over
		// aesu -> until address
		// aesue -> until esil expression
		switch (input[1]) {
		case 'u':
			if (input[2] == 'e') {
				until_expr = input + 3;
			} else {
				until_addr = r_num_math (core->num, input + 2);
			}
			esil_step (core, until_addr, until_expr);
			break;
		case 'o':
			// step over
			op = r_core_anal_op (core, addr);
			if (op && op->type == R_ANAL_OP_TYPE_CALL) {
				until_addr = addr + op->size;
			}
			esil_step (core, until_addr, until_expr);
			r_anal_op_free (op);
			break;
		default:
			esil_step (core, until_addr, until_expr);
			break;
		}
		break;
	case 'c':
		// aec  -> continue until ^C
		// aecu -> until address
		// aecue -> until esil expression
		if (input[1] == 'u' && input[2] == 'e')
			until_expr = input + 3;
		else if (input[1] == 'u')
			until_addr = r_num_math (core->num, input + 2);
		else until_expr = "0";
		esil_step (core, until_addr, until_expr);
		break;
	case 'd': // "aed"
		r_anal_esil_free (esil);
		core->anal->esil = NULL;
		break;
	case 'i': // "aei"
		switch (input [1]) {
		case 'm':
			cmd_esil_mem (core, input+2);
			break;
		case '?':
			cmd_esil_mem (core, "?");
			break;
		case 0:
			r_anal_esil_free (esil);
			// reinitialize
			esil = core->anal->esil = r_anal_esil_new ();
			romem = r_config_get_i (core->config, "esil.romem");
			stats = r_config_get_i (core->config, "esil.stats");
			r_anal_esil_setup (esil, core->anal, romem, stats); // setup io
			esil->debug = (int)r_config_get_i (core->config, "esil.debug");
			break;
		}
		break;
	case 'k':
		switch (input[1]) {
		case '\0':
			input = "123*";
		case ' ':
			if (esil && esil->stats) {
				char *out = sdb_querys (esil->stats, NULL, 0, input+2);
				if (out) {
					r_cons_printf ("%s\n", out);
					free (out);
				}
			} else eprintf ("esil.stats is empty. Run 'aei'\n");
			break;
		case '-':
			if (esil) {
				sdb_reset (esil->stats);
			}
			break;
		}
		break;
	case 'f':
		{
			RListIter *iter;
			RAnalBlock *bb;
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal,
					core->offset, R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
			if (fcn) {
				// emulate every instruction in the function recursively across all the basic blocks
				r_list_foreach (fcn->bbs, iter, bb) {
					ut64 pc = bb->addr;
					ut64 end = bb->addr +bb->size;
					RAnalOp op;
					ut8 *buf;
					int ret, bbs = end-pc;
					if (bbs<1 || bbs > 0xfffff) {
						eprintf ("Invalid block size\n");
					}
					eprintf ("Emulate basic block 0x%08"PFMT64x" - 0x%08"PFMT64x"\n",pc, end);
					buf = malloc (bbs+1);
					r_io_read_at (core->io, pc, buf, bbs);
					while (pc<end) {
						r_asm_set_pc (core->assembler, pc);
						ret = r_anal_op (core->anal, &op, addr, buf, 32); // read overflow
						if (ret) {
							r_reg_setv (core->anal->reg, "pc", pc);
							r_anal_esil_parse (esil, R_STRBUF_SAFEGET (&op.esil));
							r_anal_esil_dumpstack (esil);
							r_anal_esil_stack_free (esil);
							pc += op.size;
						} else {
							pc += 4; // XXX
						}
					}
				}
			} else eprintf ("Cannot find function at 0x%08"PFMT64x"\n", core->offset);
		}
		break;
	case 't': // "aet"
		switch (input[1]) {
			case 'r': // "aetr"
				{
					// anal ESIL to REIL.
					int romem = r_config_get_i (core->config, "esil.romem");
					int stats = r_config_get_i (core->config, "esil.stats");
					RAnalEsil *esil = r_anal_esil_new ();
					r_anal_esil_to_reil_setup (esil, core->anal, romem, stats);
					r_anal_esil_set_offset (esil, core->offset);
					r_anal_esil_parse (esil, input+2);
					r_anal_esil_dumpstack (esil);
					r_anal_esil_stack_free (esil);
					break;
				}
        }
        break;
	case '?':
		if (input[1]=='?') {
			const char* help_msg[] = {
				"Examples:", "ESIL", " examples and documentation",
				"+", "=", "A+=B => B,A,+=",
				"+", "", "A=A+B => B,A,+,A,=",
				"*", "=", "A*=B => B,A,*=",
				"/", "=", "A/=B => B,A,/=",
				"&", "=", "and ax, bx => bx,ax,&=",
				"|", "", "or r0, r1, r2 => r2,r1,|,r0,=",
				"^", "=", "xor ax, bx => bx,ax,^=",
				">>", "=", "shr ax, bx => bx,ax,>>=  # shift right",
				"<<", "=", "shr ax, bx => bx,ax,<<=  # shift left",
				"", "[]", "mov eax,[eax] => eax,[],eax,=",
				"=", "[]", "mov [eax+3], 1 => 1,3,eax,+,=[]",
				"=", "[1]", "mov byte[eax],1 => 1,eax,=[1]",
				"=", "[8]", "mov [rax],1 => 1,rax,=[8]",
				"$", "", "int 0x80 => 0x80,$",
				"$$", "", "simulate a hardware trap",
				"==", "", "pops twice, compare and update esil flags",
				"<", "", "compare for smaller",
				"<", "=", "compare for smaller or equal",
				">", "", "compare for bigger",
				">", "=", "compare bigger for or equal",
				"?{", "", "if poped value != 0 run the block until }",
				"POP", "", "drops last element in the esil stack",
				"TODO", "", "the instruction is not yet esilized",
				"STACK", "", "show contents of stack",
				"CLEAR", "", "clears the esil stack",
				"BREAK", "", "terminates the string parsing",
				"GOTO", "", "jump to the Nth word poped from the stack",
				NULL};
			r_core_cmd_help (core, help_msg);
			break;
		}
		/* fall through */
	default:
		{
			const char* help_msg[] = {
				"Usage:", "ae[idesr?] [arg]", "ESIL code emulation",
				"ae?", "", "show this help",
				"ae??", "", "show ESIL help",
				"aei", "", "initialize ESIL VM state",
				"aeis", "", "initialize ESIL VM stack (aeis- remove)",
				"aed", "", "deinitialize ESIL VM state",
				"ae", " [expr]", "evaluate ESIL expression",
				"aef", " [addr]", "emulate function",
				"aek", " [query]", "perform sdb query on ESIL.info",
				"aek-", "", "resets the ESIL.info sdb instance",
				"aec", "", "continue until ^C",
				"aecu", " [addr]", "continue until address",
				"aecue", " [esil]", "continue until esil expression match",
				"aetr", "[esil]", "Convert an ESIL Expression to REIL",
				"aes", "", "perform emulated debugger step",
				"aesu", " [addr]", "step until given address",
				"aesue", " [esil]", "step until esil expression match",
				"aer", " [..]", "handle ESIL registers like 'ar' or 'dr' does",
				NULL};
			r_core_cmd_help (core, help_msg);
		}
		break;
	}
}

static void cmd_anal_opcode(RCore *core, const char *input) {
	int l, len = core->blocksize;
	ut32 tbs = core->blocksize;

	switch (input[0]) {
	case '?':
		{
			const char* help_msg[] = {
				"Usage:", "ao[e?] [len]", "Analyze Opcodes",
				"aoj", "", "display opcode analysis information in JSON",
				"aoe", "", "emulate opcode at current offset",
				"aos", " [esil]", "show sdb representation of esil expression (TODO)",
				"aoe", " 4", "emulate 4 opcodes starting at current offset",
				"ao", " 5", "display opcode analysis of 5 opcodes",
				"ao*", "", "display opcode in r commands",
				NULL};
			r_core_cmd_help (core, help_msg);
		}
		break;
	case 'j':
		{
			int count = 1;
			if (input[1] && input[2]) {
				l = (int) r_num_get (core->num, input+1);
				if (l>0) count = l;
				if (l>tbs) {
					r_core_block_size (core, l*4);
					//len = l;
				}
			} else {
				len = l = core->blocksize;
				count = 1;
			}
			core_anal_bytes (core, core->block, len, count, 'j');
		}
		break;
	case 'e':
		eprintf ("TODO: See 'ae' command\n");
		break;
	case '*':
		r_core_anal_hint_list (core->anal, input[0]);
		break;
	default:
		{
			int count = 0;
			if (input[0]) {
				l = (int) r_num_get (core->num, input+1);
				if (l>0) count = l;
				if (l>tbs) {
					r_core_block_size (core, l*4);
					//len = l;
				}
			} else {
				len = l = core->blocksize;
				count = 1;
			}
			core_anal_bytes (core, core->block, len, count, 0);
		}
	}
}

static void cmd_anal_calls(RCore *core, const char *input) {
	int minop = 1; // 4
	ut8 buf[32];
	RBinFile *binfile;
	RAnalOp op;
	ut64 addr, addr_end;
	ut64 len = r_num_math (core->num, input);
	if (len > 0xffffff) {
		eprintf ("Too big\n");
		return;
	}
	if (len<1) {
		len = r_num_math (core->num, "$SS-($$-$S)"); // section size
	}
	binfile = r_core_bin_cur (core);
	if (!binfile){
		eprintf ("cur binfile null\n");
		return;
	}
	if (len > binfile->size){
		eprintf ("section size greater than file size\n");
		return;
	}
	addr = core->offset;
	addr_end = addr + len;
	while (addr < addr_end) {
		r_io_read_at (core->io, addr, buf, sizeof (buf));
		if (r_anal_op (core->anal, &op, addr, buf, sizeof (buf))) {
			if (op.size<1)
				op.size = minop; // XXX must be +4 on arm/mips/.. like we do in disasm.c
			if (op.type == R_ANAL_OP_TYPE_CALL) {
	//			eprintf ("af @ 0x%08"PFMT64x"\n", op.jump);
				r_core_cmdf (core, "af@0x%08"PFMT64x, op.jump);
			}
		} else {
			op.size = minop;
		}
		addr += op.size;
	}
}

static void cmd_anal_syscall(RCore *core, const char *input) {
	RSyscallItem *si;
	RListIter *iter;
	RList *list;
	char *out;
	int n;
	const char* help_msg[] = {
		"Usage: as[ljk?]", "", "syscall name <-> number utility",
		"as", "", "show current syscall and arguments",
		"as", " 4", "show syscall 4 based on asm.os and current regs/mem",
		"asj", "", "list of syscalls in JSON",
		"asl", "", "list of syscalls by asm.os and asm.arch",
		"asl", " close", "returns the syscall number for close",
		"asl", " 4", "returns the name of the syscall number 4",
		"ask", " [query]", "perform syscall/ queries",
		NULL};

	switch (input[0]) {
	case 'l': // "asl"
		if (input[1] == ' ') {
			if ((n = atoi (input+2))>0) {
				si = r_syscall_get (core->anal->syscall, n, -1);
				if (si) r_cons_printf ("%s\n", si->name);
				else eprintf ("Unknown syscall number\n");
			} else {
				n = r_syscall_get_num (core->anal->syscall, input+2);
				if (n != -1) r_cons_printf ("%d\n", n);
				else eprintf ("Unknown syscall name\n");
			}
		} else {
			list = r_syscall_list (core->anal->syscall);
			r_list_foreach (list, iter, si) {
				r_cons_printf ("%s = 0x%02x.%d\n",
						si->name, si->swi, si->num);
			}
			r_list_free (list);
		}
		break;
	case 'j': // "asj"
		list = r_syscall_list (core->anal->syscall);
		r_cons_printf ("[");
		r_list_foreach (list, iter, si) {
			r_cons_printf ("{\"name\":\"%s\","
					"\"swi\":\"%d\",\"num\":\"%d\"}",
					si->name, si->swi, si->num);
			if (iter->n) r_cons_printf (",");
		}
		r_cons_printf ("]\n");
		r_list_free (list);
		// JSON support
		break;
	case '\0':
		n = (int)r_debug_reg_get (core->dbg, "oeax"); //XXX
		cmd_syscall_do (core, n);
		break;
	case ' ':
		cmd_syscall_do (core, (int)r_num_get (core->num, input+1));
		break;
	case 'k': // "ask"
		out = sdb_querys (core->anal->syscall->db, NULL, 0, input+2);
		if (out) {
			r_cons_printf ("%s\n", out);
			free (out);
		}
		break;
	default:
	case '?':
		r_core_cmd_help (core, help_msg);
		break;
	}
}

static boolt cmd_anal_refs(RCore *core, const char *input) {
	ut64 addr = core->offset;
	const char* help_msg[] = {
		"Usage:", "ax[?d-l*]", " # see also 'afx?'",
		"ax", " addr [at]", "add code ref pointing to addr (from curseek)",
		"axc", " addr [at]", "add code jmp ref // unused?",
		"axC", " addr [at]", "add code call ref",
		"axd", " addr [at]", "add data ref",
		"axj", "", "list refs in json format",
		"axF", " [flg-glob]", "find data/code references of flags",
		"axt", " [addr]", "find data/code references to this address",
		"axf", " [addr]", "find data/code references from this address",
		"ax-", " [at]", "clean all refs (or refs from addr)",
		"ax", "", "list refs",
		"axk", " [query]", "perform sdb query",
		"ax*", "", "output radare commands",
		NULL };
	switch (input[0]) {
	case '-':
		r_anal_ref_del (core->anal, r_num_math (core->num, input+1), core->offset);
		break;
	case 'k':
		if (input[1]==' ') {
			sdb_query (core->anal->sdb_xrefs, input+2);
		} else eprintf ("|ERROR| Usage: axk [query]\n");
		break;
	case '\0':
	case 'j':
	case '*':
		r_core_anal_ref_list (core, input[0]);
		break;
	case 't':
		{
			RList *list;
			RAnalRef *ref;
			RListIter *iter;
			ut8 buf[12];
			RAsmOp asmop;
			char* buf_asm = NULL;
			char *space = strchr (input, ' ');

			if (space) {
				addr = r_num_math (core->num, space+1);
			} else {
				addr = core->offset;
			}
			list = r_anal_xrefs_get (core->anal, addr);
			if (list) {
				if (input[1] == 'q') { // "axtq"
					r_list_foreach (list, iter, ref)
						r_cons_printf ("0x%"PFMT64x"\n", ref->addr);
				} else if (input[1] == 'j') { // "axtj"
					r_cons_printf("[");
					r_list_foreach (list, iter, ref) {
						r_core_read_at (core, ref->addr, buf, 12);
						r_asm_set_pc (core->assembler, ref->addr);
						r_asm_disassemble (core->assembler, &asmop, buf, 12);
						char str[512];
						r_parse_filter (core->parser, core->flags,
								asmop.buf_asm, str, sizeof (str));
						r_cons_printf ("{\"from\":0x%"PFMT64x",\"type\":\"%c\",\"opcode\":\"%s\"}%s",
								ref->addr, ref->type, str, iter->n?",":"");
					}
					r_cons_printf("]");
					r_cons_newline();
				} else if (input[1] == '*') { // axt*
					// TODO: implement multi-line comments
					r_list_foreach (list, iter, ref)
						r_cons_printf ("CCa 0x%"PFMT64x" \"XREF from 0x%"PFMT64x"\n",
								ref->addr, ref->type, asmop.buf_asm, iter->n?",":"");
				} else { // axt
					int has_color = core->print->flags & R_PRINT_FLAGS_COLOR;
					char str[512];
					r_list_foreach (list, iter, ref) {
						r_core_read_at (core, ref->addr, buf, 12);
						r_asm_set_pc (core->assembler, ref->addr);
						r_asm_disassemble (core->assembler, &asmop, buf, 12);
						r_parse_filter (core->parser, core->flags,
								asmop.buf_asm, str, sizeof (str));
						if (has_color) {
							buf_asm = r_print_colorize_opcode (str, core->cons->pal.reg,
									core->cons->pal.num);
							r_cons_printf ("%c 0x%"PFMT64x" %s\n", ref->type, ref->addr, buf_asm);
							free (buf_asm);
						} else {
							r_cons_printf ("%c 0x%"PFMT64x" %s\n", ref->type, ref->addr, str);
						}
					}
				}
				r_list_free (list);
			}
		}
		break;
	case 'f':
		{
			ut8 buf[12];
			RAsmOp asmop;
			char* buf_asm = NULL;
			RList *list;
			RAnalRef *ref;
			RListIter *iter;
			char *space = strchr (input, ' ');

			if (space) {
				addr = r_num_math (core->num, space+1);
			} else {
				addr = core->offset;
			}
			list = r_anal_xrefs_get_from (core->anal, addr);
			if (list) {
				if (input[1] == 'q') { // axfq
					r_list_foreach (list, iter, ref)
						r_cons_printf ("0x%"PFMT64x"\n", ref->at);
				} else if (input[1] == 'j') { // axfj
					r_cons_printf("[");
					r_list_foreach (list, iter, ref) {
						r_core_read_at (core, ref->at, buf, 12);
						r_asm_set_pc (core->assembler, ref->at);
						r_asm_disassemble (core->assembler, &asmop, buf, 12);
						r_cons_printf ("{\"from\":0x%"PFMT64x",\"type\":\"%c\",\"opcode\":\"%s\"}%s",
								ref->at, ref->type, asmop.buf_asm, iter->n?",":"");
					}
					r_cons_printf ("]\n");
				} else if (input[1] == '*') { // axf*
					// TODO: implement multi-line comments
					r_list_foreach (list, iter, ref)
						r_cons_printf ("CCa 0x%"PFMT64x" \"XREF from 0x%"PFMT64x"\n",
								ref->at, ref->type, asmop.buf_asm, iter->n?",":"");
				} else { // axf
					char str[512];
					r_list_foreach (list, iter, ref) {
						r_core_read_at (core, ref->at, buf, 12);
						r_asm_set_pc (core->assembler, ref->at);
						r_asm_disassemble (core->assembler, &asmop, buf, 12);
						r_parse_filter (core->parser, core->flags,
								asmop.buf_asm, str, sizeof (str));
						buf_asm = r_print_colorize_opcode (str, core->cons->pal.reg,
								core->cons->pal.num);
						r_cons_printf ("%c 0x%"PFMT64x" %s\n",
								ref->type, ref->at, buf_asm);
						free (buf_asm);
					}
				}
				r_list_free (list);
			}
		}
		break;
	case 'F':
		find_refs (core, input+1);
		break;
	case 'C':
	case 'c':
	case 'd':
	case ' ':
		{
			char *ptr = strdup (r_str_trim_head ((char*)input+1));
			int n = r_str_word_set0 (ptr);
			ut64 at = core->offset;
			ut64 addr = UT64_MAX;
			switch (n) {
				case 2: // get at
					at = r_num_math (core->num, r_str_word_get0 (ptr, 1));
				case 1: // get addr
					addr = r_num_math (core->num, r_str_word_get0 (ptr, 0));
					break;
				default:
					free (ptr);
					return R_FALSE;
			}
			r_anal_ref_add (core->anal, addr, at, input[0]);
			free (ptr);
		}
		break;
	default:
	case '?':
		r_core_cmd_help (core, help_msg);
		break;
	}

	return R_TRUE;
}
/*
   in core/disasm we call
   R_API int r_core_hint(RCore *core, ut64 addr) {
	   static int hint_bits = 0;
	   RAnalHint *hint = r_anal_hint_get (core->anal, addr);
	   if (hint->bits) {
		   if (!hint_bits)
		   hint_bits = core->assembler->bits;
		   r_config_set_i (core->config, "asm.bits", hint->bits);
	   } else if (hint_bits) {
		   r_config_set_i (core->config, "asm.bits", hint_bits);
		   hint_bits = 0;
	   }
	   if (hint->arch)
		   r_config_set (core->config, "asm.arch", hint->arch);
	   if (hint->length)
		   force_instruction_length = hint->length;
	   r_anal_hint_free (hint);
  }
 */

static void cmd_anal_hint(RCore *core, const char *input) {
	const char* help_msg[] = {
		"Usage:", "ah[lba-]", "Analysis Hints",
		"ah?", "", "show this help",
		"ah?", " offset", "show hint of given offset",
		"ah", "", "list hints in human-readable format",
		"ah-", "", "remove all hints",
		"ah-", " offset [size]", "remove hints at given offset",
		"ah*", " offset", "list hints in radare commands format",
		"aha", " ppc 51", "set arch for a range of N bytes",
		"ahb", " 16 @ $$",  "force 16bit for current instruction",
		"ahc", " 0x804804", "override call/jump address",
		"ahf", " 0x804840", "override fallback address for call",
		"ahs", " 4", "set opcode size=4",
		"ahS", " jz", "set asm.syntax=jz for this opcode",
		"aho", " foo a0,33", "replace opcode string",
		"ahe", " eax+=3", "set vm analysis string",
		NULL };
	switch (input[0]) {
	case '?':
		if (input[1]) {
			//ut64 addr = r_num_math (core->num, input+1);
			eprintf ("TODO: show hint\n");
		} else r_core_cmd_help (core, help_msg);
		break;
	case 'a': // set arch
		if (input[1]) {
			int i;
			char *ptr = strdup (input+2);
			i = r_str_word_set0 (ptr);
			if (i==2)
				r_num_math (core->num, r_str_word_get0 (ptr, 1));
			r_anal_hint_set_arch (core->anal, core->offset,
					r_str_word_get0 (ptr, 0));
			free (ptr);
		} else eprintf("Missing argument\n");
		break;
	case 'b': // set bits
		if (input[1]) {
			char *ptr = strdup (input+2);
			int bits;
			int i = r_str_word_set0 (ptr);
			if (i==2)
				r_num_math (core->num, r_str_word_get0 (ptr, 1));
			bits = r_num_math (core->num, r_str_word_get0 (ptr, 0));
			r_anal_hint_set_bits (core->anal, core->offset, bits);
			free (ptr);
		} else eprintf("Missing argument\n");
		break;
	case 'c':
		r_anal_hint_set_jump (core->anal, core->offset,
				r_num_math (core->num, input+1));
		break;
	case 'f':
		r_anal_hint_set_fail (core->anal, core->offset,
				r_num_math (core->num, input+1));
		break;
	case 's': // set size (opcode length)
		if (input[1]) {
			r_anal_hint_set_size (core->anal, core->offset, atoi (input+1));
		} else eprintf ("Usage: ahs 16\n");
		break;
	case 'S': // set size (opcode length)
		if (input[1]==' ') {
			r_anal_hint_set_syntax (core->anal, core->offset, input+2);
		} else eprintf ("Usage: ahS att\n");
		break;
	case 'o': // set opcode string
		if (input[1]==' ') {
			r_anal_hint_set_opcode (core->anal, core->offset, input+2);
		} else eprintf ("Usage: aho popall\n");
		break;
	case 'e': // set ESIL string
		if (input[1]==' ') {
			r_anal_hint_set_esil (core->anal, core->offset, input+2);
		} else eprintf ("Usage: ahe r0,pc,=\n");
		break;
#if TODO
	case 'e': // set endian
		r_anal_hint_set_opcode (core->anal, core->offset, atoi (input+1));
		break;
#endif
	case 'p':
		r_anal_hint_set_pointer (core->anal, core->offset, r_num_math (core->num, input+1));
		break;
	case '*':
	case 'j':
	case '\0':
		r_core_anal_hint_list (core->anal, input[0]);
		break;
	case '-':
		if (input[1]) {
			int i;
			char *ptr = strdup (input+1);
			ut64 addr;
			int size = 1;
			i = r_str_word_set0 (ptr);
			if (i==2)
				size = r_num_math (core->num, r_str_word_get0 (ptr, 1));
			addr = r_num_math (core->num, r_str_word_get0 (ptr, 0));
			r_anal_hint_del (core->anal, addr, size);
			free (ptr);
		} else r_anal_hint_clear (core->anal);
		break;
	}
}

static void cmd_anal_graph(RCore *core, const char *input) {
	RList *list;
	const char *arg;
	const char* help_msg[] = {
		"Usage:", "ag[?f]", "Graphiz Code",
		"ag", " [addr]", "output graphviz code (bb at addr and children)",
		"agj", " [addr]", "idem, but in JSON format",
		"agk", " [addr]", "idem, but in SDB key-value format",
		"aga", " [addr]", "idem, but only addresses",
		"agc", " [addr]", "output graphviz call graph of function",
		"agd", " [fcn name]", "output graphviz code of diffed function",
		"agl", " [fcn name]",  "output graphviz code using meta-data",
		"agt", " [addr]", "find paths from current offset to given address",
		"agfl", " [fcn name]", "output graphviz code of function using meta-data",
		"agv", "[acdltfl] [a]", "view function using graphviz",
		NULL};

	switch (input[0]) {
	case 't':
		list = r_core_anal_graph_to (core, r_num_math (core->num, input+1), 0);
		if (list) {
			RListIter *iter, *iter2;
			RList *list2;
			RAnalBlock *bb;
			r_list_foreach (list, iter, list2) {
				r_list_foreach (list2, iter2, bb) {
					r_cons_printf ("-> 0x%08"PFMT64x"\n", bb->addr);
				}
			}
			r_list_purge (list);
			free (list);
		}
		break;
	case 'c':
		r_core_anal_refs (core, r_num_math (core->num, input+1), input[1]=='j'? 2: 1);
		break;
	case 'j':
		r_core_anal_graph (core, r_num_math (core->num, input+1), R_CORE_ANAL_JSON);
		break;
	case 'k':
		r_core_anal_graph (core, r_num_math (core->num, input+1), R_CORE_ANAL_KEYVALUE);
		break;
	case 'l':
		r_core_anal_graph (core, r_num_math (core->num, input+1), R_CORE_ANAL_GRAPHLINES);
		break;
	case 'a':
		r_core_anal_graph (core, r_num_math (core->num, input+1), 0);
		break;
	case 'd':
		r_core_anal_graph (core, r_num_math (core->num, input+1),
				R_CORE_ANAL_GRAPHBODY|R_CORE_ANAL_GRAPHDIFF);
		break;
	case 'v':
		r_core_cmd0 (core, "=H /graph/");
#if 0
		{
			int is_html = (r_config_get_i (core->config, "scr.html"));
			const char *cmd = r_config_get (core->config, "cmd.graph");
			//char *tmp = r_file_temp ("/tmp/a.dot");
			char *tmp = strdup ("a.dot"); // XXX

			if (!is_html && strstr (cmd, "htmlgraph")) {
				is_html = 2;
				r_config_set (core->config, "scr.html", "true");
			}
			r_cons_flush ();
			int fd = r_cons_pipe_open (tmp, 0);
			r_core_cmdf (core, "ag%s", input+1);
			if (is_html==2)
				r_config_set (core->config, "scr.html", "false");
			r_cons_flush ();
			r_cons_pipe_close (fd);
			r_sys_setenv ("DOTFILE", tmp);
			r_core_cmdf (core, "%s", cmd);
			free (tmp);
		}
#endif
		break;
	case '?':
		r_core_cmd_help (core, help_msg);
		break;
	default:
		arg = strchr (input, ' ');
		if (arg) arg++;
		r_core_anal_graph (core, r_num_math (core->num, arg),
				R_CORE_ANAL_GRAPHBODY);
		break;
	}
}

static void cmd_anal_trace(RCore *core, const char *input)  {
	RDebugTracepoint *t;
	const char *ptr;
	ut64 addr = core->offset;
	const char* help_msg[] = {
		"Usage:", "at", "[*] [addr]",
		"at", "", "list all traced opcode ranges",
		"at-", "", "reset the tracing information",
		"at*", "", "list all traced opcode offsets",
		"at+", " [addr] [times]", "add trace for address N times",
		"at", " [addr]", "show trace info at address",
		"ate", "", "show esil trace logs (anal.trace)",
		"ate", " [idx]", "show commands to restore to this trace index",
		"ate", "-", "clear esil trace logs",
		"att", " [tag]", "select trace tag (no arg unsets)",
		"at%", "", "TODO",
		"ata", " 0x804020 ...", "only trace given addresses",
		"atr", "", "show traces as range commands (ar+)",
		"atd", "", "show disassembly trace",
		"atD", "", "show dwarf trace (at*|rsc dwarf-traces $FILE)",
		NULL
	};

	switch (input[0]) {
	case 'e': // "ate"
		if (!core->anal->esil) {
			int romem = r_config_get_i (core->config, "esil.romem");
			int stats = r_config_get_i (core->config, "esil.stats");
			core->anal->esil = r_anal_esil_new ();
			r_anal_esil_setup (core->anal->esil,	
				core->anal, romem, stats);
		}
		switch (input[1]) {
		case 0:
			r_anal_esil_trace_list (core->anal->esil);
			break;
		case 'i':
			{
				RAnalOp *op;
				ut64 addr = r_num_math (core->num, input +2);
				if (!addr)
					addr = core->offset;
				op = r_core_anal_op (core, addr);
				if (op)
					r_anal_esil_trace (core->anal->esil, op);
				r_anal_op_free (op);
			}
			break;
		case '-':
			if (!strcmp (input+2, "*")) {
				if (core->anal->esil) {
					sdb_free (core->anal->esil->db_trace);
					core->anal->esil->db_trace = sdb_new0 ();
				}
			} else {
				eprintf ("TODO: ate- cant delete specific logs. Use ate-*\n");
			}
			break;
		case ' ':
			{
				int idx = atoi (input+2);	
				r_anal_esil_trace_show (
					core->anal->esil, idx);
			}
			break;
		case 'k':
			if (input[2]== ' ') {
				char *s = sdb_querys (core->anal->esil->db_trace,
					NULL, 0, input+3);
				r_cons_printf ("%s\n", s);
				free (s);
			} else {
				eprintf ("Usage: atek [query]\n");
			}
			break;
		default:
			eprintf ("|Usage: ate[ilk] [-arg]\n"
			"| ate           esil trace log single instruction\n"
			"| ate idx       show commands for that index log\n"
			"| ate-*         delete all esil traces\n"
			"| atei          esil trace log single instruction\n"
			"| atek  [sdbq]  esil trace log single instruction\n");
		}
		break;
	case '?':
		r_core_cmd_help (core, help_msg);
		eprintf ("Current Tag: %d\n", core->dbg->trace->tag);
		break;
	case 'a':
		eprintf ("NOTE: Ensure given addresses are in 0x%%08"PFMT64x" format\n");
		r_debug_trace_at (core->dbg, input+1);
		break;
	case 't':
		r_debug_trace_tag (core->dbg, atoi (input+1));
		break;
	case 'd':
		//trace_show (2, trace_tag_get());
		eprintf ("TODO\n");
		break;
	case 'D':
		// XXX: not yet tested..and rsc dwarf-traces comes from r1
		r_core_cmd (core, "at*|rsc dwarf-traces $FILE", 0);
		break;
	case 'r':
		eprintf ("TODO\n");
		//trace_show(-1, trace_tag_get());
		break;
	case '+':
		ptr = input+2;
		addr = r_num_math (core->num, ptr);
		ptr = strchr (ptr, ' ');
		if (ptr != NULL) {
			RAnalOp *op = r_core_op_anal (core, addr);
			if (op != NULL) {
				RDebugTracepoint *tp = r_debug_trace_add (core->dbg, addr, op->size);
				tp->count = atoi (ptr+1);
				r_anal_trace_bb (core->anal, addr);
				r_anal_op_free (op);
			} else eprintf ("Cannot analyze opcode at 0x%"PFMT64x"\n", addr);
		}
		break;
	case '-':
		r_debug_trace_free (core->dbg);
		core->dbg->trace = r_debug_trace_new ();
		break;
	case ' ':
		if ((t = r_debug_trace_get (core->dbg,
				r_num_math (core->num, input)))) {
			r_cons_printf ("offset = 0x%"PFMT64x"\n", t->addr);
			r_cons_printf ("opsize = %d\n", t->size);
			r_cons_printf ("times = %d\n", t->times);
			r_cons_printf ("count = %d\n", t->count);
			//TODO cons_printf("time = %d\n", t->tm);
		}
		break;
	case '*':
		r_debug_trace_list (core->dbg, 1);
		break;
	default:
		r_debug_trace_list (core->dbg, 0);
	}
}

static int cmd_anal(void *data, const char *input) {
	const char *r;
	RCore *core = (RCore *)data;
	ut32 tbs = core->blocksize;
	const char* help_msg_ad[] = {
		"Usage:",  "ad", "[kt] [...]",
		"ad", " [N] [D]","analyze N data words at D depth",
		"adt", "", "analyze data trampolines (wip)",
		"adk", "", "analyze data kind (code, text, data, invalid, ...)",
		NULL
	};
	const char* help_msg_aa[] = {
		"Usage:", "aa[0*?]", " # see also 'af' and 'afna'",
		"aa", " ", "alias for 'af@@ sym.*;af@entry0'", //;.afna @@ fcn.*'",
		"aa*", "", "analyze all flags starting with sym. (af @@ sym.*)",
		"aaa", "", "autoname functions after aa (see afna)",
		"aac", " [len]", "analyze function calls (af @@ `pi len~call[1]`)",
		"aas", " [len]", "analyze symbols (af @@= `isq~[0]`)",
		"aap", "", "find and analyze function preludes",
		NULL};
	const char* help_msg[] = {
		"Usage:", "a", "[8adefFghoprxstc] [...]",
		"a8", " [hexpairs]", "analyze bytes",
		"aa", "", "analyze all (fcns + bbs) (aa0 to avoid sub renaming)",
		"ac", " [cycles]", "analyze which op could be executed in [cycles]",
		"ad", "", "analyze data trampoline (wip)",
		"ad", " [from] [to]", "analyze data pointers to (from-to)",
		"ae", " [expr]", "analyze opcode eval expression (see ao)",
		"af", "[rnbcsl?+-*]", "analyze Functions",
		"aF", "", "same as above, but using anal.depth=1",
		"ag", "[?acgdlf]", "output Graphviz code",
		"ah", "[?lba-]", "analysis hints (force opcode size, ...)",
		"ai", " [addr]", "address information (show perms, stack, heap, ...)",
		"ao", "[e?] [len]", "analyze Opcodes (or emulate it)",
		"ar", "", "like 'dr' but for the esil vm. (registers)",
		"ax", "[?ld-*]", "manage refs/xrefs (see also afx?)",
		"as", " [num]", "analyze syscall using dbg.reg",
		"at", "[trd+-%*?] [.]", "analyze execution traces",
		//"ax", " [-cCd] [f] [t]", "manage code/call/data xrefs",
		NULL
	};

	r_cons_break (NULL, NULL);

	switch (input[0]) {
	case '8': // TODO: rename to 'ab'?
		if (input[1]==' ') {
			int len;
			ut8 *buf = malloc (strlen (input)+1);
			len = r_hex_str2bin (input+2, buf);
			if (len>0)
				core_anal_bytes (core, buf, len, 0, 0);
			free (buf);
		} else eprintf ("Usage: a8 [hexpair-bytes]\n");
		break;
	case 'i': cmd_anal_info (core, input+1); break; // "ai"
	case 'r': cmd_anal_reg (core, input+1); break; // "ar"
	case 'e': cmd_anal_esil (core, input+1); break; // "ae"
	case 'o': cmd_anal_opcode (core, input+1); break;
	case 'F':
		r_core_anal_fcn (core, core->offset, UT64_MAX, R_ANAL_REF_TYPE_NULL, 1);
		break;
	case 'f':
		if (!cmd_anal_fcn (core, input)) {
			r_cons_break_end ();
			return R_FALSE;
		}
		break;
	case 'g':
		cmd_anal_graph (core, input+1);
		break;
	case 't':
		cmd_anal_trace (core, input+1);
		break;
	case 's': // "as"
		cmd_anal_syscall(core, input+1);
		break;
	case 'x':
		if (!cmd_anal_refs (core, input+1)) {
			r_cons_break_end ();
			return R_FALSE;
		}
		break;
	case 'a':
		switch (input[1]) {
		case '?': r_core_cmd_help (core, help_msg_aa); break;
		case 'c': cmd_anal_calls (core, input + 2) ; break; // "aac"
		//case '*': r_cons_printf ("af @@ sym.* ; af @ entry0\n"); break; // ; .afna @@ fcn.*\n");
		case '*':
			r_core_cmd0 (core, "af @@ sym.*");
			r_core_cmd0 (core, "af @ entry0");
			break;
		case 's':
			r_core_cmd0 (core, "af @@= `isq~[0]`");
			r_core_cmd0 (core, "af @ entry0");
			break;
		case 'p':
			if (input[1]=='?') {
				// TODO: accept parameters for ranges
				r_cons_printf ("Usage: /aap   ; find in memory for function preludes");
			} else r_core_search_preludes (core);
			break;
		case '\0': // "aa"
		case 'a': 
			r_cons_break (NULL, NULL);
			r_core_anal_all (core);
			if (core->cons->breaked)
				eprintf ("Interrupted\n");
			r_cons_clear_line (1);
			r_cons_break_end ();
			if (input[1] == 'a') // "aaa"
				r_core_cmd0 (core, ".afna @@ fcn.*"); break; // "aaa"
			break;
		default: r_core_cmd_help (core, help_msg_aa); break;
		}
		break;
	case 'c':
		if (input[1]=='?') {
			eprintf ("Usage: ac [cycles]   # analyze instructions that fit in N cycles\n");
		} else {
			RList *hooks ;
			RListIter *iter;
			RAnalCycleHook *hook;
			char *instr_tmp = NULL;
			int ccl = input[1]? r_num_math (core->num, &input[2]):0; //get cycles to look for
			int cr = r_config_get_i (core->config, "asm.cmtright");
			int fun = r_config_get_i (core->config, "asm.functions");
			int li = r_config_get_i (core->config, "asm.lines");
			int xr = r_config_get_i (core->config, "asm.xrefs");

			r_config_set_i (core->config, "asm.cmtright", R_TRUE);
			r_config_set_i (core->config, "asm.functions", R_FALSE);
			r_config_set_i (core->config, "asm.lines", R_FALSE);
			r_config_set_i (core->config, "asm.xrefs", R_FALSE);

			r_cons_break (NULL, NULL);
			hooks = r_core_anal_cycles (core, ccl); //analyse
			r_cons_break_end ();
			r_cons_clear_line (1);
			r_list_foreach (hooks, iter, hook) {
				instr_tmp = r_core_disassemble_instr (core, hook->addr, 1);
				r_cons_printf ("After %4i cycles:\t%s", (ccl - hook->cycles), instr_tmp);
				r_cons_flush ();
				free (instr_tmp);
			}
			r_list_free (hooks);

			r_config_set_i (core->config, "asm.cmtright", cr); //reset settings
			r_config_set_i (core->config, "asm.functions", fun);
			r_config_set_i (core->config, "asm.lines", li);
			r_config_set_i (core->config, "asm.xrefs", xr);
		}
		break;
	case 'd':
		switch (input[1]) {
		case 't':
			cmd_anal_trampoline (core, input+2);
			break;
		case ' ':
			{
				const int default_depth = 1;
				const char *p;
				int a, b;
				a = r_num_math (core->num, input+2);
				p = strchr (input+2, ' ');
				b = p? r_num_math (core->num, p+1): default_depth;
				if (a<1) a = 1;
				if (b<1) b = 1;
				r_core_anal_data (core, core->offset, a, b);
			}
			break;
		case 'k':
			r = r_anal_data_kind (core->anal,
					core->offset, core->block, core->blocksize);
			r_cons_printf ("%s\n", r);
			break;
		case '\0':
			r_core_anal_data (core, core->offset, 2+(core->blocksize/4), 1);
			break;
		default:
			r_core_cmd_help (core, help_msg_ad);
			break;
		}
		break;
	case 'h':
		cmd_anal_hint(core, input+1);
		break;
	case '!':
		if (core->anal && core->anal->cur && core->anal->cur->cmd_ext)
			return core->anal->cur->cmd_ext (core->anal, input+1);
		else r_cons_printf ("No plugins for this analysis plugin\n");
		break;
	default:
		r_core_cmd_help (core, help_msg);
		r_cons_printf ("Examples:\n"
				" f ts @ `S*~text:0[3]`; f t @ section..text\n"
				" f ds @ `S*~data:0[3]`; f d @ section..data\n"
				" .ad t t+ts @ d:ds\n",
				NULL);
		break;
	}
	if (tbs != core->blocksize)
		r_core_block_size (core, tbs);
	if (core->cons->breaked) {
		r_cons_clear_line (1);
		eprintf ("Interrupted\n");
	}
	r_cons_break_end();
	return 0;
}
