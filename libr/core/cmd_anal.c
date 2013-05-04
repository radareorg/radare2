/* radare - LGPL - Copyright 2009-2013 - pancake */

#if 1
/* TODO: Move into cmd_anal() */
static void var_help() {
	eprintf("Try afv?\n"
	" afv 12 int buffer[3]\n"
	" afv 12 byte buffer[1024]\n"
	"Try af[aAv][gs] [delta] [[addr]]\n"
	" afag 0  = arg0 get\n"
	" afvs 12 = var12 set\n"
	"a = arg, A = fastarg, v = var\n"
	"TODO: [[addr]] is not yet implemented. use @\n");
}

static int var_cmd(RCore *core, const char *str) {
	RAnalFunction *fcn = r_anal_fcn_find (core->anal, core->offset,
			R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
	char *p, *p2, *p3, *ostr;
	int scope, delta;

	ostr = p = strdup (str);
	str = (const char *)ostr;

	switch (*str) {
	case 'V': // show vars in human readable format
		r_anal_var_list_show (core->anal, fcn, core->offset);
		break;
	case '?':
		var_help ();
		break;
	case 'v': // frame variable
	case 'a': // stack arg
	case 'A': // fastcall arg
		// XXX nested dup
		switch (*str) {
		case 'v': scope = R_ANAL_VAR_SCOPE_LOCAL|R_ANAL_VAR_DIR_NONE; break;
		case 'a': scope = R_ANAL_VAR_SCOPE_ARG|R_ANAL_VAR_DIR_IN; break;
		case 'A': scope = R_ANAL_VAR_SCOPE_ARGREG|R_ANAL_VAR_DIR_IN; break;
		default:
			eprintf ("Unknown type\n");
			return 0;
		}

		/* Variable access CFvs = set fun var */
		switch (str[1]) {
		case '\0': r_anal_var_list (core->anal, fcn, 0, 0); return 0;
		case '?': var_help(); return 0;
		case '.': r_anal_var_list (core->anal, fcn, core->offset, 0); return 0;
		case 's':
		case 'g':
			if (str[2]!='\0') {
				if (fcn != NULL) {
					RAnalVar *var = r_anal_var_get (core->anal, fcn, atoi (str+2), R_ANAL_VAR_SCOPE_LOCAL);
					if (var != NULL)
						return r_anal_var_access_add (core->anal, var, atoi (str+2), (str[1]=='g')?0:1);
					eprintf ("Can not find variable in: '%s'\n", str);
				} else eprintf ("Unknown variable in: '%s'\n", str);
				return R_FALSE;
			} else eprintf ("Missing argument\n");
			break;
		}
		str++;
		if (str[0]==' ') str++;
		delta = atoi (str);
		p = strchr (str, ' ');
		if (p==NULL) {
			var_help();
			break;
		}
		// TODO: Improve parsing error handling
		p[0]='\0'; p++;
		p2 = strchr (p, ' ');
		if (p2) {
			p2[0]='\0'; p2 = p2+1;
			p3 = strchr (p2,'[');
			if (p3 != NULL) {
				p3[0]='\0';
				p3=p3+1;
			}
			// p2 - name of variable
			r_anal_var_add (core->anal, fcn, core->offset, delta, scope,
				r_anal_str_to_type (core->anal, p), p2, p3? atoi (p3): 0);
		} else var_help ();
		break;
	default:
		var_help ();
		break;
	}
	free (ostr);
	return 0;
}
#endif

static void cmd_anal_trampoline (RCore *core, const char *input) {
	int i, bits = r_config_get_i (core->config, "asm.bits");
	char *p, *inp = strdup (input);
	p = strchr (inp, ' ');
	if (p) *p=0;
	ut64 a = r_num_math (core->num, inp);
	ut64 b = p?r_num_math (core->num, p+1):0;
	free (inp);
	switch (bits) {
	case 32:
		for (i=0; i<core->blocksize; i+=4) {
			ut32 n;
			memcpy (&n, core->block+i, sizeof(ut32));
			if (n>=a && n<=b) {
				r_cons_printf ("f trampoline.%x @ 0x%"PFMT64x"\n", n, core->offset+i);
				r_cons_printf ("Cd 4 @ 0x%"PFMT64x":4\n", core->offset+i);
				// TODO: add data xrefs
			}
		}
		break;
	case 64:
		for (i=0; i<core->blocksize; i+=8) {
			ut32 n;
			memcpy (&n, core->block+i, sizeof(ut32));
			if (n>=a && n<=b) {
				r_cons_printf ("f trampoline.%"PFMT64x" @ 0x%"PFMT64x"\n", n, core->offset+i);
				r_cons_printf ("Cd 8 @ 0x%"PFMT64x":8\n", core->offset+i);
				// TODO: add data xrefs
			}
		}
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

static const char *optypestr(int type) {
	switch (type) {
	case R_ANAL_OP_TYPE_NULL  : return "null";
	case R_ANAL_OP_TYPE_JMP   : return "jmp";
	case R_ANAL_OP_TYPE_UJMP  : return "ujmp";
	case R_ANAL_OP_TYPE_CJMP  : return "cjmp";
	case R_ANAL_OP_TYPE_CALL  : return "call";
	case R_ANAL_OP_TYPE_UCALL : return "ucall";
	case R_ANAL_OP_TYPE_REP   : return "rep";
	case R_ANAL_OP_TYPE_RET   : return "ret";
	case R_ANAL_OP_TYPE_ILL   : return "ill";
	case R_ANAL_OP_TYPE_UNK   : return "unk";
	case R_ANAL_OP_TYPE_NOP   : return "nop";
	case R_ANAL_OP_TYPE_MOV   : return "mov";
	case R_ANAL_OP_TYPE_TRAP  : return "trap";
	case R_ANAL_OP_TYPE_SWI   : return "swi";
	case R_ANAL_OP_TYPE_UPUSH : return "upush";
	case R_ANAL_OP_TYPE_PUSH  : return "push";
	case R_ANAL_OP_TYPE_POP   : return "pop";
	case R_ANAL_OP_TYPE_CMP   : return "cmp";
	case R_ANAL_OP_TYPE_ADD   : return "add";
	case R_ANAL_OP_TYPE_SUB   : return "sub";
	case R_ANAL_OP_TYPE_MUL   : return "mul";
	case R_ANAL_OP_TYPE_DIV   : return "div";
	case R_ANAL_OP_TYPE_SHR   : return "shr";
	case R_ANAL_OP_TYPE_SHL   : return "shl";
	case R_ANAL_OP_TYPE_OR    : return "or";
	case R_ANAL_OP_TYPE_AND   : return "andr";
	case R_ANAL_OP_TYPE_XOR   : return "xor";
	case R_ANAL_OP_TYPE_NOT   : return "not";
	case R_ANAL_OP_TYPE_STORE : return "store";
	case R_ANAL_OP_TYPE_LOAD  : return "load";
	case R_ANAL_OP_TYPE_LEA   : return "lea";
	case R_ANAL_OP_TYPE_LEAVE : return "leave";
	}
	return "err";
}

static void r_core_anal_bytes (RCore *core, const ut8 *buf, int len, int nops) {
	int ret, i, idx;
	RAsmOp asmop;
	RAnalOp op;

	for (i=idx=ret=0; idx<len && (!nops|| (nops&&i<nops)); i++, idx+=ret) {
		r_asm_set_pc (core->assembler, core->offset+idx);
		ret = r_asm_disassemble (core->assembler, &asmop, buf+idx, len-idx);
		ret = r_anal_op (core->anal, &op, core->offset+idx, buf + idx, len-idx);
		if (ret<1) {
			eprintf ("Oops at 0x%08"PFMT64x" (%02x %02x %02x ...)\n",
					core->offset+idx, buf[idx], buf[idx+1], buf[idx+2]);
			break;
		}

		r_cons_printf ("opcode: %s\n", asmop.buf_asm);
		r_cons_printf ("addr: 0x%08"PFMT64x"\n", core->offset+idx);
		r_cons_printf ("size: %d\n", op.length);
		r_cons_printf ("type: %d (%s)\n", op.type, optypestr (op.type)); // TODO: string
		if (op.code)
			r_cons_printf ("code: %s\n", op.code);
		r_cons_printf ("eob: %d\n", op.eob);
		if (op.jump != UT64_MAX)
			r_cons_printf ("jump: 0x%08"PFMT64x"\n", op.jump);
		if (op.fail != UT64_MAX)
			r_cons_printf ("fail: 0x%08"PFMT64x"\n", op.fail);
		r_cons_printf ("stack: %d\n", op.stackop); // TODO: string
		r_cons_printf ("cond: %d\n", op.cond); // TODO: string
		r_cons_printf ("family: %d\n", op.family);
		r_cons_printf ("\n");
		//r_cons_printf ("false: 0x%08"PFMT64x"\n", core->offset+idx);
	}
}

static int cmd_anal(void *data, const char *input) {
	const char *ptr;
	RCore *core = (RCore *)data;
	int l, len = core->blocksize;
	ut64 addr = core->offset;
	ut32 tbs = core->blocksize;

	r_cons_break (NULL, NULL);

	switch (input[0]) {
	case '8': // TODO: rename to 'ab'?
		if (input[1]==' ') {
			int len;
			ut8 *buf = malloc (strlen (input));
			len = r_hex_str2bin (input+2, buf);
			if (len>0)
				r_core_anal_bytes (core, buf, len, 0);
			free (buf);
		} else eprintf ("Usage: ab [hexpair-bytes]\n");
		break;
	case 'x':
		switch (input[1]) {
		case '\0':
		case ' ':
			// list xrefs from current address
			{
				ut64 addr = input[1]?  r_num_math (core->num, input+1): core->offset;
				RAnalFunction *fcn = r_anal_fcn_find (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
				if (fcn) {
					RAnalRef *ref;
					RListIter *iter;
					r_list_foreach (fcn->refs, iter, ref) {
						r_cons_printf ("%c 0x%08"PFMT64x" -> 0x%08"PFMT64x"\n",
							ref->type, ref->at, ref->addr);
					}
				} else eprintf ("Cant find function\n");
			}
			break;
		case 'c': // add meta xref
		case 'd':
		case 'C': {
				char *p;
				ut64 a, b;
				RAnalFunction *fcn;
				char *mi = strdup (input);
				if (mi && mi[2]==' ' && (p=strchr (mi+3, ' '))) {
					*p = 0;
					a = r_num_math (core->num, mi+2);
					b = r_num_math (core->num, p+1);
					fcn = r_anal_fcn_find (core->anal, a, R_ANAL_FCN_TYPE_ROOT);
					if (fcn) {
						r_anal_fcn_xref_add (core->anal, fcn, a, b, input[1]);
					} else eprintf ("Cannot add reference to non-function\n");
				} else eprintf ("Usage: ax[cCd?] [src] [dst]\n");
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
					fcn = r_anal_fcn_find (core->anal, a, R_ANAL_FCN_TYPE_ROOT);
					if (fcn) {
						r_anal_fcn_xref_del (core->anal, fcn, a, b, -1);
					} else eprintf ("Cannot del reference to non-function\n");
				} else eprintf ("Usage: ax- [src] [dst]\n");
				free (mi);
			}
			break;
		default:
		case '?':
			r_cons_printf (
			"Usage: ax[-cCd?] [src] [dst]\n"
			" axc sym.main+0x38 sym.printf   ; add code ref\n"
			" axC sym.main sym.puts          ; add call ref\n"
			" axd sym.main str.helloworld    ; add data ref\n"
			" ax- sym.main str.helloworld    ; remove reference\n");
			break;
		}
		break;
	case 'e':
		if (input[1] == ' ') {
			r_anal_code_eval (core->anal, input+2);
		} else eprintf ("Usage: ae [expression]  # wip\n");
		break;
	case 'o':
		if (input[1] == '?') {
			r_cons_printf (
			"Usage: ao[e?] [len]\n"
			" aoe      ; emulate opcode at current offset\n"
			" aoe 4    ; emulate 4 opcodes starting at current offset\n"
			" ao 5     ; display opcode analysis of 5 opcodes\n");
		} else
		if (input[1] == 'e') {
			eprintf ("TODO: r_anal_op_execute\n");
		} else {
			int count = 0;
			if (input[0] && input[1]) {
				l = (int) r_num_get (core->num, input+2);
				if (l>0) count = l;
				if (l>tbs) {
					r_core_block_size (core, l*4);
					//len = l;
				}
			} else len = l = core->blocksize;
			r_core_anal_bytes (core, core->block, len, count);
		}
		break;
	case 'F':
		r_core_anal_fcn (core, core->offset, -1, R_ANAL_REF_TYPE_NULL, 1);
		break;
	case 'f':
		switch (input[1]) {
		case '-':
			{
			ut64 addr = input[2]?
				r_num_math (core->num, input+2): core->offset;
			r_anal_fcn_del_locs (core->anal, addr);
			r_anal_fcn_del (core->anal, addr);
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
		case 'i':
			r_core_anal_fcn_list (core, input+2, 0);
			break;
		case 'l':
			r_core_anal_fcn_list (core, input, 2);
			break;
		case '*':
			r_core_anal_fcn_list (core, input+2, 1);
			break;
		case 's': {
			ut64 addr;
			RAnalFunction *f;
			const char *arg = input+3;
			if (input[2] && (addr = r_num_math (core->num, arg))) {
				arg = strchr (arg, ' ');
				if (arg) arg++;
			} else addr = core->offset;
			if ((f = r_anal_fcn_find (core->anal, addr, R_ANAL_FCN_TYPE_NULL))) {
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
		case 'a':
		case 'A':
		case 'v':
			var_cmd (core, input+1);
			break;
		case 'c':
			{
			RAnalFunction *fcn;
			int cc;
			if ((fcn = r_anal_get_fcn_at (core->anal, core->offset)) != NULL) {
				cc = r_anal_fcn_cc (fcn);
				r_cons_printf ("CyclomaticComplexity 0x%08"PFMT64x" = %i\n",
						fcn->addr, cc);
			} else eprintf ("Error: function not found\n");
			}
			break;
		case 'b':
			{
			char *ptr = strdup(input+3);
			const char *ptr2 = NULL;
			ut64 fcnaddr = -1LL, addr = -1LL;
			ut64 size = 0LL;
			ut64 jump = -1LL;
			ut64 fail = -1LL;
			int type = R_ANAL_BB_TYPE_NULL;
			RAnalFunction *fcn = NULL;
			RAnalDiff *diff = NULL;

			switch(r_str_word_set0 (ptr)) {
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
			if ((fcn = r_anal_get_fcn_at (core->anal, fcnaddr)) == NULL ||
					!r_anal_fcn_add_bb (fcn, addr, size, jump, fail, type, diff)) {
				//eprintf ("Error: Cannot add bb\n");
			}
			r_anal_diff_free (diff);
			free (ptr);
			}
			break;
		case 'r':
			if (1) { //input[2]==' ' && input[3]) {
				RAnalFunction *fcn;
				ut64 off = core->offset;
				char *p, *name = strdup (input+3);
				if ((p=strchr (name, ' '))) {
					*p++ = 0;
					off = r_num_math (core->num, p);
				}
				if (*name) {
					fcn = r_anal_fcn_find (core->anal, off,
							R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
					if (fcn) {
						eprintf ("fr %s %s@ 0x%"PFMT64x"\n",
							fcn->name, name, off);
						r_core_cmdf (core, "fr %s %s@ 0x%"PFMT64x,
							fcn->name, name, off);
						free (fcn->name);
						fcn->name = strdup (name);
					} else eprintf ("Cannot find function '%s' at 0x%08llx\n", name, off);
				} else eprintf ("Usage: afr [newname] [off]\n");
			}
			break;
		case 'e':
			{
				RAnalFunction *fcn;
				ut64 off = core->offset;
				char *p, *name = strdup (input+3);
				if ((p=strchr (name, ' '))) {
					*p = 0;
					off = r_num_math (core->num, p+1);
				}
				fcn = r_anal_fcn_find (core->anal, off,
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
				} else eprintf ("Cannot find function at 0x%08llx\n", core->offset);
			}
			break;
		case '?':
			r_cons_printf (
			"Usage: af[?+-l*]\n"
			" af @ [addr]               ; Analyze functions (start at addr)\n"
			" af+ addr size name [type] [diff] ; Add function\n"
			" af- [addr]                ; Clean all function analysis data (or function at addr)\n"
			" afb fcnaddr addr size name [type] [diff] ; Add bb to function @ fcnaddr\n"
			" afl[*] [fcn name]         ; List functions (addr, size, bbs, name)\n"
			" afi [fcn name]            ; Show function(s) information (verbose afl)\n"
			" afr name [addr]           ; Rename name for function at address (change flag too)\n"
			" afs [addr] [fcnsign]      ; Get/set function signature at current address\n"
			" af[aAv][?] [arg]          ; Manipulate args, fastargs and variables in function\n"
			" afc @ [addr]              ; Calculate the Cyclomatic Complexity (starting at addr)\n"
			" af*                       ; Output radare commands\n");
			break;
		default:
			r_core_anal_fcn (core, core->offset, -1, R_ANAL_REF_TYPE_NULL,
					r_config_get_i (core->config, "anal.depth"));
		}
		break;
	case 'g':
		switch (input[1]) {
		case 't':
			{
			int n = 0;
			RList *list = r_core_anal_graph_to (core,
				r_num_math (core->num, input+2), n);
			if (list) {
				RListIter *iter, *iter2;
				RList *list2;
				RAnalBlock *bb;
				r_list_foreach (list, iter, list2) {
					r_list_foreach (list2, iter2, bb) {
						r_cons_printf ("-> 0x%08"PFMT64x"\n", bb->addr);
					}
				}
			}
			}
			break;
		case 'c':
			r_core_anal_refs (core, r_num_math (core->num, input+2), input[2]=='j'? 2: 1);
			break;
		case 'j':
			r_core_anal_graph (core, r_num_math (core->num, input+2), R_CORE_ANAL_JSON);
			break;
		case 'l':
			r_core_anal_graph (core, r_num_math (core->num, input+2), R_CORE_ANAL_GRAPHLINES);
			break;
		case 'a':
			r_core_anal_graph (core, r_num_math (core->num, input+2), 0);
			break;
		case 'd':
			r_core_anal_graph (core, r_num_math (core->num, input+2),
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
				r_core_cmdf (core, "ag%s", input+2);
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
			r_cons_printf (
			"Usage: ag[?f]\n"
			" ag [addr]       ; Output graphviz code (bb at addr and children)\n"
			" aga [addr]      ; Idem, but only addresses\n"
			" agc [addr]      ; Output graphviz call graph of function\n"
			" agd [fcn name]  ; Output graphviz code of diffed function\n"
			" agl [fcn name]  ; Output graphviz code using meta-data\n"
			" agt [addr]      ; find paths from current offset to given address\n"
			" agfl [fcn name] ; Output graphviz code of function using meta-data\n"
			" agv[acdltfl] [a]; View function using graphviz\n");
			break;
		default:
			r_core_anal_graph (core, r_num_math (core->num, input+1),
				R_CORE_ANAL_GRAPHBODY);
		}
		break;
	case 't':
		switch (input[1]) {
		case '?':
			r_cons_strcat ("Usage: at[*] [addr]\n"
			" at?                ; show help message\n"
			" at                 ; list all traced opcode ranges\n"
			" at-                ; reset the tracing information\n"
			" at*                ; list all traced opcode offsets\n"
			" at+ [addr] [times] ; add trace for address N times\n"
			" at [addr]          ; show trace info at address\n"
			" att [tag]          ; select trace tag (no arg unsets)\n"
			" at%                ; TODO\n"
			" ata 0x804020 ...   ; only trace given addresses\n"
			" atr                ; show traces as range commands (ar+)\n"
			" atd                ; show disassembly trace\n"
			" atD                ; show dwarf trace (at*|rsc dwarf-traces $FILE)\n");
			eprintf ("Current Tag: %d\n", core->dbg->trace->tag);
			break;
		case 'a':
			eprintf ("NOTE: Ensure given addresses are in 0x%%08"PFMT64x" format\n");
			r_debug_trace_at (core->dbg, input+2);
			break;
		case 't':
			r_debug_trace_tag (core->dbg, atoi (input+2));
			break;
		case 'd':
			//trace_show (2, trace_tag_get());
			eprintf ("TODO\n");
			break;
		case 'D':
			// XXX: not yet tested..and rsc dwarf-traces comes from r1
			r_core_cmd (core, "at*|rsc dwarf-traces $FILE", 0);
			break;
		case '+':
			ptr = input+3;
			addr = r_num_math (core->num, ptr);
			ptr = strchr (ptr, ' ');
			if (ptr != NULL) {
				RAnalOp *op = r_core_op_anal (core, addr);
				if (op != NULL) {
					//eprintf("at(0x%08"PFMT64x")=%d (%s)\n", addr, atoi(ptr+1), ptr+1);
					//trace_set_times(addr, atoi(ptr+1));
					RDebugTracepoint *tp = r_debug_trace_add (core->dbg, addr, op->length);
					tp->count = atoi (ptr+1);
					r_anal_trace_bb (core->anal, addr);
					r_anal_op_free (op);
				} else eprintf ("Cannot analyze opcode at 0x%"PFMT64x"\n", addr);
			}
			break;
		case '-':
			r_debug_trace_free (core->dbg);
			core->dbg->trace = r_debug_trace_new (core->dbg);
			break;
		case ' ': {
			RDebugTracepoint *t = r_debug_trace_get (core->dbg,
				r_num_math (core->num, input+1));
			if (t != NULL) {
				r_cons_printf ("offset = 0x%"PFMT64x"\n", t->addr);
				r_cons_printf ("opsize = %d\n", t->size);
				r_cons_printf ("times = %d\n", t->times);
				r_cons_printf ("count = %d\n", t->count);
				//TODO cons_printf("time = %d\n", t->tm);
			} }
			break;
		case '*':
			r_debug_trace_list (core->dbg, 1);
			break;
		case 'r':
			eprintf ("TODO\n");
			//trace_show(-1, trace_tag_get());
			break;
		default:
			r_debug_trace_list (core->dbg, 0);
		}
		break;
	case 's':
		switch (input[1]) {
		case 'l':
			if (input[2] == ' ') {
				int n = atoi (input+3);
				if (n>0) {
					RSyscallItem *si = r_syscall_get (core->anal->syscall, n, -1);
					if (si) r_cons_printf ("%s\n", si->name);
					else eprintf ("Unknown syscall number\n");
				} else {
					int n = r_syscall_get_num (core->anal->syscall, input+3);
					if (n != -1) r_cons_printf ("%d\n", n);
					else eprintf ("Unknown syscall name\n");
				}
			} else {
				RSyscallItem *si;
				RListIter *iter;
				RList *list = r_syscall_list (core->anal->syscall);
				r_list_foreach (list, iter, si) {
					r_cons_printf ("%s = 0x%02x.%d\n", si->name, si->swi, si->num);
				}
				r_list_free (list);
			}
			break;
		case '\0': {
			int a0 = (int)r_debug_reg_get (core->dbg, "oeax"); //XXX
			cmd_syscall_do (core, a0);
			} break;
		case ' ':
			cmd_syscall_do (core, (int)r_num_get (core->num, input+2));
			break;
		default:
		case '?':
			r_cons_printf (
			"Usage: as[l?]\n"
			" as         Display syscall and arguments\n"
			" as 4       Show syscall 4 based on asm.os and current regs/mem\n"
			" asl        List of syscalls by asm.os and asm.arch\n"
			" asl close  Returns the syscall number for close\n"
			" asl 4      Returns the name of the syscall number 4\n");
			break;
		}
		break;
	case 'r':
		switch(input[1]) {
		case '?':
			r_cons_printf (
			"Usage: ar[?d-l*]\n"
			" ar addr [at]   ; Add code ref\n"
			" ard addr [at]  ; Add data ref\n"
			" ar- [at]       ; Clean all refs (or refs from addr)\n"
			" arl            ; List refs\n"
			" ar*            ; Output radare commands\n");
			break;
		case '-':
			r_anal_ref_del (core->anal, r_num_math (core->num, input+2));
			break;
		case 'l':
			r_core_anal_ref_list (core, R_FALSE);
			break;
		case '*':
			r_core_anal_ref_list (core, R_TRUE);
			break;
		default:
			{
			char *ptr = strdup (r_str_trim_head ((char*)input+2));
			int n = r_str_word_set0 (ptr);
			ut64 at = core->offset;
			ut64 addr = -1LL;
			switch (n) {
			case 2: // get at
				at = r_num_math (core->num, r_str_word_get0 (ptr, 1));
			case 1: // get addr
				addr = r_num_math (core->num, r_str_word_get0 (ptr, 0));
				break;
			default:
				return R_FALSE;
			}
			r_anal_ref_add (core->anal, addr, at,
					input[1]=='d'?R_ANAL_REF_TYPE_DATA:R_ANAL_REF_TYPE_CODE);
			free (ptr);
			}
		}
		break;
	case 'a':
		r_cons_break (NULL, NULL);
		r_core_anal_all (core);
		if (core->cons->breaked)
			eprintf ("Interrupted\n");
		r_cons_break_end();
		break;
	case 'p':
		if (input[1]=='?') {
			// TODO: accept parameters for ranges
			r_cons_printf ("Usage: ap   ; find in memory for function preludes");
		} else r_core_search_preludes (core);
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
			{ 
				const char *r = r_anal_data_kind (core->anal,
					core->offset, core->block, core->blocksize);
				r_cons_printf ("%s\n", r);
			}
			break;
		case '\0':
			{
				//int word = core->assembler->bits / 8;
				r_core_anal_data (core, core->offset, core->blocksize, 1);
			}
			break;
		default:
			eprintf ("Usage: ad[kt] [...]\n"
			"  ad [N] [D]  analyze N data words at D depth\n"
			"  adt         analyze data trampolines (wip)\n"
			"  adk         analyze data kind (code, text, data, invalid, ...)\n");
			break;
		}
		break;
	case 'h':
		switch (input[1]) {
		case '?':
			if (input[2]) {
				//ut64 addr = r_num_math (core->num, input+2);
				eprintf ("TODO: show hint\n");
			} else
			r_cons_printf (
				"Usage: ah[lba-]\n"
				" ah?           # show this help\n"
				" ah? offset    # show hint of given offset\n"
				" ah            # list hints in human-readable format\n"
				" ah-           # remove all hints\n"
				" ah- offset    # remove hints at given offset\n"
				" ah* offset    # list hints in radare commands format\n"
				" aha ppc 51    # set arch for a range of N bytes\n"
				" ahb 16 @ $$   # force 16bit for current instruction\n"
				" ahl 4 32      # set opcode size=4 for range of 32 bytes\n"
				" aho foo a0,33 # replace opcode string\n"
				" ahs eax+=3    # set vm analysis string\n"
			);
			break;
#if 0
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
#endif
		case 'a': // set arch
			r_anal_hint_set_arch (core->anal, core->offset,
				1, input+2);
			break;
		case 'b': // set bits
			r_anal_hint_set_bits (core->anal, core->offset,
				1, atoi (input+2));
			//r_anal_hint_bits (op, 1);
			break;
		case 'l': // set size (opcode length)
			r_anal_hint_set_length (core->anal, core->offset,
				1, atoi (input+2));
			break;
		case 'o': // set opcode string
			r_anal_hint_set_opcode (core->anal, core->offset,
				1, input+2);
			break;
		case 's': // set analysis string
			r_anal_hint_set_analstr (core->anal, core->offset,
				1, input+2);
			break;
#if TODO
		case 'e': // set endian
			r_anal_hint_set_opcode (core->anal, core->offset,
				1, atoi (input+2));
			break;
#endif
		case '*':
		case 'j':
		case '\0':
			r_core_anal_hint_list (core->anal, input[1]);
			break;
		case '-':
			if (input[2]) {
				r_anal_hint_del (core->anal,
					r_num_math (core->num, input+2));
			} else r_anal_hint_clear (core->anal);
			break;
		}
		break;
	default:
		r_cons_printf (
		"Usage: a[?adfFghoprsx]\n"
		" a8 [hexpairs]    ; analyze bytes\n" 
		" aa               ; analyze all (fcns + bbs)\n"
		" ad               ; analyze data trampoline (wip)\n"
		" ad [from] [to]   ; analyze data pointers to (from-to)\n"
		" ae [expr]        ; analyze opcode eval expression (see ao)\n"
		" af[bcsl?+-*]     ; analyze Functions\n"
		" aF               ; same as above, but using graph.depth=1\n"
		" ag[?acgdlf]      ; output Graphviz code\n"
		" ah[?lba-]        ; analysis hints (force opcode size, ...)\n"
		" ao[e?] [len]     ; analyze Opcodes (or emulate it)\n"
		" ap               ; find and analyze function preludes\n"
		" ar[?ld-*]        ; manage refs/xrefs\n"
		" as [num]         ; analyze syscall using dbg.reg\n"
		" at[trd+-*?] [.]  ; analyze execution Traces\n"
		" ax[-cCd] [f] [t] ; manage code/call/data xrefs\n"
		"Examples:\n"
		" f ts @ `S*~text:0[3]`; f t @ section..text\n"
		" f ds @ `S*~data:0[3]`; f d @ section..data\n"
		" .ad t t+ts @ d:ds\n");
		break;
	}
	if (tbs != core->blocksize)
		r_core_block_size (core, tbs);
	if (core->cons->breaked)
		eprintf ("Interrupted\n");
	r_cons_break_end();
	return 0;
}

