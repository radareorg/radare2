/* radare - LGPL - Copyright 2009-2025 - pancake */

#include <r_core.h>

#define MAX_FORMAT 3

enum {
	R_BYTE_DATA  = 1,
	R_WORD_DATA  = 2,
	R_DWORD_DATA = 4,
	R_QWORD_DATA = 8
};

enum {
	SORT_NONE,
	SORT_NAME,
	SORT_ADDR
};

typedef struct {
	RCore *core;
	int t_idx;
	int t_ctr;
	const char *type;
	char *curname;
	char *curfmt;
	const char *optword;
} RCoreVisualTypes;

static int copyuntilch(char *dst, char *src, int ch) {
	size_t i;
	for (i = 0; src[i] && src[i] != ch; i++) {
		dst[i] = src[i];
	}
	dst[i] = '\0';
	return i;
}

R_IPI void visual_add_comment(RCore *core, ut64 at) {
	char buf[1024];
	r_cons_enable_mouse (core->cons, false);
	r_cons_gotoxy (core->cons, 0, 0);
	r_cons_printf (core->cons, "Enter a comment: ('-' to remove, '!' to use cfg.editor)\n");
	r_core_visual_showcursor (core, true);
	r_cons_flush (core->cons);
	r_cons_set_raw (core->cons, false);
	const ut64 orig = core->addr;
	if (at == UT64_MAX) {
		at = core->addr;
		if (core->print->cur_enabled) {
			at += core->print->cur;
		}
	}
	if (at != orig) {
		r_core_seek (core, at, false);
	}
	const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, at);
	bool use_editor = comment != NULL;
	r_line_set_prompt (core->cons->line, "comment: ");
	bool do_sthg = true;
	if (use_editor) {
		strcpy (buf, "!");
	} else {
		do_sthg = r_cons_fgets (core->cons, buf, sizeof (buf), 0, NULL) > 0;
	}
	if (do_sthg) {
		const char *command = "CC ";
		const char *argument = NULL;
		switch (buf[0]) {
		case '-':
			command = "CC-";
			argument = r_str_trim_head_ro (buf + 1);
			break;
		case '!':
			command = "CC!";
			argument = r_str_trim_head_ro (buf + 1);
			break;
		default:
			command = "CC ";
			argument = r_str_trim_head_ro (buf);
			break;
		}
		r_core_cmdf (core, "'%s%s", command, argument);
	}
	if (core->print->cur_enabled) {
		r_core_seek (core, orig, true);
	}
	r_cons_set_raw (core->cons, true);
	r_core_visual_showcursor (core, false);
}

// TODO: move this helper into r_cons
static char *prompt(RCore *core, const char *str, const char *txt) {
	char cmd[1024];
	char *res = NULL;
	RCons *cons = core->cons;
	char *oprompt = strdup (cons->line->prompt);
	r_cons_show_cursor (cons, true);
	if (txt && *txt) {
		free (cons->line->contents);
		cons->line->contents = strdup (txt);
	} else {
		R_FREE (cons->line->contents);
	}
	*cmd = '\0';
	r_line_set_prompt (cons->line, str);
	if (r_cons_fgets (cons, cmd, sizeof (cmd), 0, NULL) < 0) {
		*cmd = '\0';
	}
	//line[strlen(line)-1]='\0';
	if (*cmd) {
		res = strdup (cmd);
	}
	r_line_set_prompt (cons->line, oprompt);
	free (oprompt);
	R_FREE (cons->line->contents);
	return res;
}

static inline char *getformat(RCoreVisualTypes *vt, const char *k) {
	r_strf_var (key, 64, "type.%s", k);
	return sdb_get (vt->core->anal->sdb_types, key, 0);
}

static char *colorize_asm_string(RCore *core, const char *buf_asm, int optype, ut64 addr) {
	if (!buf_asm) {
		return NULL;
	}
	char *tmp, *spacer = NULL;
	char *source = (char*)buf_asm;
	bool use_color = core->print->flags & R_PRINT_FLAGS_COLOR;
	const char *color_num = core->cons->context->pal.num;
	const char *color_reg = core->cons->context->pal.reg;
	RAnalFunction* fcn = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL);

	if (!use_color) {
		return strdup (source);
	}
	// workaround dummy colorizer in case of paired commands (tms320 & friends)
	spacer = strstr (source, "||");
	if (spacer) {
		char *s1 = r_str_ndup (source, spacer - source);
		char *s2 = strdup (spacer + 2);
		char *scol1 = r_print_colorize_opcode (core->print, s1, color_reg, color_num, false, fcn ? fcn->addr : 0);
		char *scol2 = r_print_colorize_opcode (core->print, s2, color_reg, color_num, false, fcn ? fcn->addr : 0);
		char *source = r_str_newf ("%s||%s", r_str_get (scol1), r_str_get (scol2));
		free (scol1);
		free (scol2);
		free (s1);
		free (s2);
		return source;
	}
	char *res = strdup ("");
	res = r_str_append (res, r_print_color_op_type (core->print, optype));
	tmp = r_print_colorize_opcode (core->print, source, color_reg, color_num, false, fcn ? fcn->addr : 0);
	res = r_str_append (res, tmp);
	free (tmp);
	return res;
}

static int rotate_nibble(const ut8 b, int dir) {
	if (dir > 0) {
		bool high = b >> 7;
		return (b << 1) | high;
	}
	bool lower = b & 1;
	return (b >> 1) | (lower << 7);
}

static int wordpos(const char *esil, int n) {
	const char *w = esil;
	if (n < 1) {
		n = 0;
	}
	while (w && *w && n--) {
		const char *nw = strchr (w + 1, ',');
		if (!nw) {
			return strlen (esil);
		}
		w = nw;
	}
	if (!w && n > 0) {
		return strlen (esil);
	}
	return (size_t)(w - esil);
}

static void showreg(RCore *core, const char *rn, const char *desc) {
#define FLG(x) R_ESIL_FLAG_##x
	// r_esil_reg_read (esil, rn, &nm, NULL); // R_BIT_CHK (&esil->flags, FLG (ZERO)));
#if 1
	char *res = r_core_cmd_strf (core, "ae %s", rn);
#else
	// this code clears the esil stack :?
	REsil *esil = core->anal->esil;
	r_esil_runword (esil, rn);
	char *res = r_esil_pop (esil);
#endif
	ut64 nm = r_num_get (NULL, res);
	int sz = (*rn == '$') ? (rn[1] == '$')? 8: 1: 8;
	RCons *cons = core->cons;
	if (sz == 1) {
		r_cons_printf (cons, "%s = %d ; %s\n", rn, (int)nm, desc);
	} else {
		r_cons_printf (cons, "%s 0x%08"PFMT64x" (%d) ; %s\n", rn, nm, sz, desc);
	}
	free (res);
}

R_API bool r_core_visual_esil(RCore *core, const char *input) {
	const int nbits = sizeof (ut64) * 8;
	int analopType;
	char *word = NULL;
	int x = 0;
	char *ginput = NULL;
	RAnalOp analop;
	ut8 buf[sizeof (ut64)];
	unsigned int addrsize = r_config_get_i (core->config, "esil.addr.size");
	static RCoreHelpMessage help_msg_aev = {
		"Usage:", "aev [esil]", "Visual esil debugger (VdE)",
		"aev", " [esil]", "visual esil debugger for the given expression or current instruction",
		NULL
	};
	if (input && !*input) {
		input = NULL;
	}
	if (input && *input == '?') {
		r_core_cmd_help (core, help_msg_aev);
		return false;
	}
	if (!r_config_get_b (core->config, "scr.interactive")) {
		return false;
	}

	if (core->blocksize < sizeof (ut64)) {
		return false;
	}
	RCons *cons = core->cons;
	r_reg_arena_push (core->anal->reg);
	REsil *esil = r_esil_new (20, 0, addrsize);
	r_esil_setup (esil, core->anal, false, false, false);
	// esil->anal = core->anal;
	r_esil_set_pc (esil, core->addr);
	char *expr = NULL;
	bool refresh = false;
	for (;;) {
		R_FREE (expr);
		r_cons_clear00 (cons);
		if (refresh) {
			x = 0;
			refresh = false;
		}
		if (input) {
			expr = strdup (input);
		} else {
			RAnalOp asmop;
			memcpy (buf, core->block, sizeof (ut64));
			// bool use_color = core->print->flags & R_PRINT_FLAGS_COLOR;
			(void) r_asm_disassemble (core->rasm, &asmop, buf, sizeof (ut64));
			analop.type = -1;
			(void)r_anal_op (core->anal, &analop, core->addr, buf, sizeof (ut64), R_ARCH_OP_MASK_ESIL);
			analopType = analop.type & R_ANAL_OP_TYPE_MASK;
			r_cons_printf (cons, "r2's esil debugger:\n\n");
			const char *vi = r_config_get (core->config, "cmd.vprompt");
			if (R_STR_ISNOTEMPTY (vi)) {
				r_core_cmd0 (core, vi);
			}
			r_cons_printf (cons, "addr: 0x%08"PFMT64x"\n", core->addr);
			r_cons_printf (cons, "pos: %d\n", x);
			{
				char *op_hex = r_asm_op_get_hex (&asmop);
				char *res = r_print_hexpair (core->print, op_hex, -1);
				r_cons_printf (cons, "hex: %s\n"Color_RESET, res);
				free (res);
				free (op_hex);
			}
			char *op = colorize_asm_string (core, asmop.mnemonic, analopType, core->addr);
			r_cons_printf (cons, Color_RESET"asm: %s\n"Color_RESET, op);
			free (op);
			expr = strdup (r_strbuf_get (&analop.esil));
			r_asm_op_fini (&asmop);
		}
		{
			r_cons_printf (cons, Color_RESET"esil: %s\n"Color_RESET, expr);
			int wp = wordpos (expr, x);
			char *pas = strdup (r_str_pad (' ', wp ? wp + 1: 0));
			int wp2 = wordpos (expr, x + 1);
			free (word);
			word = r_str_ndup (expr + (wp?(wp+1):0), (wp2 - wp) - (wp?1:0));
			if (wp == wp2) {
				refresh = true;
			}
			const char *pad = r_str_pad ('-', wp2 - ((wp > 0)? wp + 1: 0));
			r_cons_printf (cons, Color_RESET"      %s%s\n"Color_RESET, pas, pad);
			free (pas);
			// free (pad);
		}
		r_cons_printf (cons, "esil stack: ");
		if (!r_esil_dumpstack (esil)) {
			r_cons_newline (cons);
		}
		r_cons_printf (cons, "esil regs:\n");
		showreg (core, "$$", "address");
		showreg (core, "$z", "zero");
		showreg (core, "$b", "borrow");
		showreg (core, "$c", "carry");
		showreg (core, "$o", "overflow");
		showreg (core, "$p", "parity");
		showreg (core, "$r", "regsize");
		showreg (core, "$s", "sign");
		showreg (core, "$d", "delay");
		showreg (core, "$j", "jump");

		r_cons_printf (cons, "regs:\n");
		char *r = r_core_cmd_str (core, "dr=");
		if (r) {
			r_cons_printf (cons, "%s", r);
			free (r);
		}
		if (!input) {
			r_anal_op_fini (&analop);
		}
		r_cons_newline (cons);
		r_cons_visual_flush (cons);

		int ch = r_cons_readchar (cons);
		if (ch == -1 || ch == 4) {
			break;
		}
		ch = r_cons_arrow_to_hjkl (cons, ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 'Q':
		case 'q':
			goto beach;
		case 'n':
		case 'P':
			x = 0;
			r_esil_free (esil);
			esil = r_esil_new (20, 0, addrsize);
			esil->anal = core->anal;
			r_core_cmd0 (core, "so+1");
			r_esil_set_pc (esil, core->addr);
			break;
		case 'N':
		case 'p':
			x = 0;
			r_esil_free (esil);
			esil = r_esil_new (20, 0, addrsize);
			esil->anal = core->anal;
			r_core_cmd0 (core, "so-1");
			r_esil_set_pc (esil, core->addr);
			break;
		case '=':
		{ // TODO: edit
			r_core_visual_showcursor (core, true);
			const char *buf = NULL;
			#define I core->cons
			const char *cmd = r_config_get (core->config, "cmd.vprompt");
			r_line_set_prompt (core->cons->line, "cmd.vprompt> ");
			I->line->contents = strdup (cmd);
			buf = r_line_readline (core->cons);
			I->line->contents = NULL;
			(void)r_config_set (core->config, "cmd.vprompt", buf);
			r_core_visual_showcursor (core, false);
		}
		break;
		case '!':
			r_esil_parse (esil, "CLEAR");
		//	r_esil_clear (esil);
			break;
		case 'e':
			{
				char *s = r_cons_input (cons, "esil: ");
				free (ginput);
				if (*s) {
					input = s;
					ginput = s;
				} else {
					ginput = NULL;
					input = NULL;
					free (s);
				}
			}
			break;
		case 'o':
			{
				char *s = r_cons_input (cons, "offset: ");
				r_core_cmd_callf (core, "s %s", s);
				free (s);
			}
			break;
		case 'j':
			r_core_cmd_call (core, "so");
			break;
		case 'k':
			r_core_cmd_call (core, "so -1");
			break;
		case 's':
			// eprintf ("step ((%s))\n", word);
			// r_sys_usleep (500);
			x = R_MIN (x + 1, nbits - 1);
			r_esil_runword (esil, word);
			break;
		case '$':
			r_core_cmd_call (core, "ar PC=$$");
			break;
		case 'S':
			r_core_cmd_call (core, "aeso");
			break;
		case 'h':
			if (x > 0) {
				x--;
			}
			break;
		case 'H':
			x = 0;
			break;
		case 'l':
			if (wordpos (expr, x + 1) != strlen (expr)) {
				x++;
			}
			break;
		case 'L':
			while (wordpos (expr, x + 1) != strlen (expr)) {
				x++;
			}
			break;
		case '?':
			r_cons_clear00 (cons);
			r_cons_printf (core->cons,
			"VdE?: Visual Esil Debugger Help (aev):\n\n"
			" q     - quit the esil debugger\n"
			" h/r   - reset / go back (reinitialize esil state)\n"
			" s     - esil step in\n"
			" S     - esil step over\n"
			" o     - specify offset to seek\n"
			" e     - type a new esil expression to debug\n"
			" j/k   - next/prev instruction\n"
			" n/p   - go next/prev instruction\n"
			" =     - enter cmd.vprompt command\n"
			" !     - toggle all bits\n"
			" :     - enter command\n");
			r_cons_flush (cons);
			r_cons_any_key (cons, NULL);
			break;
		case ':': // TODO: move this into a separate helper function
			r_cons_show_cursor (core->cons, true);
			r_cons_set_raw (core->cons, 0);
			while (1) {
				char cmd[1024];
				*cmd = 0;
				r_line_set_prompt (core->cons->line, ":> ");
				if (r_cons_fgets (cons, cmd, sizeof (cmd), 0, NULL) < 0) {
					cmd[0] = '\0';
				}
				r_core_cmd0 (core, cmd);
				if (!*cmd) {
					break;
				}
				r_cons_flush (cons);
			}
			r_cons_show_cursor (cons, false);
			r_cons_set_raw (cons, 1);
			r_cons_clear (cons);
			break;
		}
	}
beach:
	free (expr);
	r_reg_arena_pop (core->anal->reg);
	r_esil_free (esil);
	free (word);
	free (ginput);
	return true;
}

R_API bool r_core_visual_bit_editor(RCore *core) {
	const int nbits = sizeof (ut64) * 8;
	bool colorBits = false;
	int analopType;
	ut8 yankBuffer[8] = {0};
	int yankSize = 0;
	int i, j, x = 0;
	RAnalOp analop;
	ut8 buf[sizeof (ut64)];
	bool bitsInLine = false;

	if (core->blocksize < sizeof (ut64)) {
		return false;
	}
	int cur = 0;
	if (core->print->cur != -1) {
		cur = core->print->cur;
	}
	int wordsize = 1;
	RCons *cons = core->cons;
	memcpy (buf, core->block + cur, sizeof (ut64));
	for (;;) {
		r_anal_op_init (&analop);
		r_cons_clear00 (cons);
		bool use_color = core->print->flags & R_PRINT_FLAGS_COLOR;
		r_anal_op_set_bytes (&analop, core->addr + cur, buf, sizeof (ut64));
		(void)r_anal_op (core->anal, &analop, core->addr, buf, sizeof (buf), R_ARCH_OP_MASK_ESIL | R_ARCH_OP_MASK_DISASM);
		analopType = analop.type & R_ANAL_OP_TYPE_MASK;
		{
			ut8 *o = core->block;
			int bs = core->blocksize;
			core->block = buf;
			int stride = r_config_get_i (core->config, "hex.stride");
			r_config_set_i (core->config, "hex.stride", 1);
			core->blocksize = sizeof (buf);
			char *s = r_core_cmd_str (core, "pri1");
			core->block = o;
			r_config_set_i (core->config, "hex.stride", stride);
			core->blocksize = bs;
			r_cons_print_at (cons, s, 60, 1, 20, 12);
			free (s);
		}
		r_cons_printf (cons, "[0x%08"PFMT64x"]> Vd1 # r2's sprite / bit editor\n\n", (ut64)(core->addr + cur));
		if (analop.bytes) {
			char *op_hex = r_hex_bin2strdup (analop.bytes, analop.size);
			char *res = r_print_hexpair (core->print, op_hex, -1);
			r_cons_printf (cons, "hex: %s\n"Color_RESET, res);
			free (res);
			free (op_hex);
		}
		{
			if (analop.size <= 4) {
				r_cons_printf (cons, "nle: %d\n", r_read_le32 (buf));
				r_cons_printf (cons, "nbe: %d\n", r_read_be32 (buf));
			} else {
				r_cons_printf (cons, "nle: %"PFMT64d"\n", r_read_le64 (buf));
				r_cons_printf (cons, "nbe: %"PFMT64d"\n", r_read_be64 (buf));
			}
		}
		r_cons_printf (cons, "len: %d\n", analop.size);
		{
			ut32 word = (x % 32);
			r_cons_printf (cons, "shf: >> %d << %d\n", word, (analop.size * 8) - word - 1);
		}
		{
			char *op = colorize_asm_string (core, analop.mnemonic, analopType, core->addr);
			if (op) {
				r_cons_printf (cons, Color_RESET"asm: %s\n"Color_RESET, op);
				free (op);
			} else {
				r_cons_printf (cons, Color_RED"asm: unknown\n"Color_RESET);
				free (op);
			}
		}
		r_cons_printf (cons, Color_RESET"esl: %s\n"Color_RESET, r_strbuf_get (&analop.esil));
		r_cons_printf (cons, "[w]:");
		int nbyte = (x / 8);
		char first = '/';
		for (i = 0; i < 8; i++) {
			if (i == 4) {
				if (i < nbyte + 1) {
					r_cons_printf (cons, "  ");
				} else if (i < nbyte + wordsize) {
					r_cons_printf (cons, "==");
				}
			}
			if (i < nbyte) {
				r_cons_printf (cons, "         ");
			} else if (i < nbyte + wordsize) {
				r_cons_printf (cons, "%c========", first);
				first = '=';
			}
		}
		r_cons_printf (cons, "\\ word=%d\nchr:", wordsize);
		for (i = 0; i < 8; i++) {
			const ut8 *byte = buf + i;
			char ch = IS_PRINTABLE (*byte)? *byte: '?';
			if (i == 4) {
				r_cons_print (cons, " |");
			}
			if (use_color) {
				r_cons_printf (cons, " %5s'%s%c"Color_RESET"'", " ", core->cons->context->pal.btext, ch);
			} else {
				r_cons_printf (cons, " %5s'%c'", " ", ch);
			}
		}
		r_cons_printf (cons, "\ndec:");
		for (i = 0; i < 8; i++) {
			const ut8 *byte = buf + i;
			if (i == 4) {
				r_cons_print (cons, " |");
			}
			r_cons_printf (cons, " %8d", *byte);
		}
		r_cons_printf (cons, "\nhex:");
		for (i = 0; i < 8; i++) {
			const ut8 *byte = buf + i;
			if (i == 4) {
				r_cons_print (cons, " |");
			}
			r_cons_printf (cons, "     0x%02x", *byte);
		}
		if (bitsInLine) {
			r_cons_printf (cons, "\nbit: ");
			for (i = 0; i < 8; i++) {
				ut8 *byte = buf + i;
				if (i == 4) {
					r_cons_print (cons, "| ");
				}
				if (colorBits && i >= analop.size) {
					r_cons_print (cons, Color_RESET);
					colorBits = false;
				}
				for (j = 0; j < 8; j++) {
					bool bit = R_BIT_CHK (byte, 7 - j);
					r_cons_printf (cons, "%d", bit? 1: 0);
				}
				r_cons_print (cons, " ");
			}
		} else {
			int set;
			const char *ws = r_config_get_b (core->config, "scr.utf8")? "·": " ";
			for (set = 1; set >= 0; set--) {
				r_cons_printf (cons, "\nbit: ");
				for (i = 0; i < 8; i++) {
					ut8 *byte = buf + i;
					if (i == 4) {
						r_cons_print (cons, "| ");
					}
					if (colorBits && i >= analop.size) {
						r_cons_print (cons, Color_RESET);
						colorBits = false;
					}
					for (j = 0; j < 8; j++) {
						bool bit = R_BIT_CHK (byte, 7 - j);
						if (set && bit) {
							r_cons_print (cons, "1");
						} else if (!set && !bit) {
							r_cons_print (cons, "0");
						} else {
							r_cons_print (cons, ws);
						}
					}
					r_cons_print (cons, " ");
				}
			}
		}
		r_cons_newline (cons);
		{
			char str_pos[128];
			memset (str_pos, '-', nbits + 9);
			int pos = x;
			if (pos > 31) {
				pos += 2;
			}
			str_pos[pos + (x / 8)] = '^';
			str_pos[nbits + 9] = 0;
			str_pos[8] = ' ';
			str_pos[17] = ' ';
			str_pos[26] = ' ';
			str_pos[35] = ' ';
			str_pos[36] = ' ';
			str_pos[37] = ' ';
			str_pos[46] = ' ';
			str_pos[55] = ' ';
			str_pos[64] = ' ';
			r_cons_printf (cons, "cur: %s\n", str_pos);
		}
		// same output as "aob".. must reuse
		{
			// r_cons_printf (cons, "pos: ");
			// r_core_cmd0 (core, "aob");
			char *op_hex = r_hex_bin2strdup (buf, 8);
			char *r = r_core_cmd_strf (core, "'aobv %s", op_hex);
			free (op_hex);
			char *s = r_str_prefix_all (r, "    ");
			r_cons_printf (cons, "%s\n", s);
			free (r);
			free (s);
		}
		const char *vi = r_config_get (core->config, "cmd.vprompt");
		if (R_STR_ISNOTEMPTY (vi)) {
			memcpy (core->block, buf, 8);
			r_core_cmd0 (core, vi);
		}
		r_cons_newline (cons);
		//r_cons_visual_flush (core->cons);
		r_cons_flush (cons);

		int ch = r_cons_readchar (core->cons);
		if (ch == -1 || ch == 4) {
			break;
		}
		if (ch != 10) {
			ch = r_cons_arrow_to_hjkl (cons, ch); // get ESC+char, return 'hjkl' char
		}
		// input
		r_cons_newline (cons);
		switch (ch) {
		case 'w':
			wordsize += 1;
			if (wordsize > 8) {
				wordsize = 1;
			}
			break;
		case 'W':
			wordsize -= 1;
			if (wordsize < 1) {
				wordsize = 1;
			}
			break;
		case 'e': // swap endian
			{
				ut8 a[8];
				memcpy (a, buf, sizeof (a));
				const int nbyte = x / 8;
				const int last = R_MIN (nbyte + wordsize, 8);
				int i;
				for (i = nbyte; i < last; i++) {
					buf[i] = a[last - 1 - i + nbyte];
				}
			}
			break;
		case 'Q':
		case 'q':
			if (analop.bytes) {
				char *op_hex = r_hex_bin2strdup (analop.bytes, analop.size);
				char *res = r_print_hexpair (core->print, op_hex, -1);
				r_core_cmd_callf (core, "wx %02x%02x%02x%02x", buf[0], buf[1], buf[2], buf[3]);
				free (res);
				free (op_hex);
			}
			return false;
		case '!':
			{
				const int nbyte = x / 8;
				const int last = R_MIN (nbyte + wordsize, 8);
				int i;
				for (i = nbyte; i < last; i++) {
					*(buf + i) = ~*(buf + i);
				}
			}
			break;
		case 'H':
			{
				const int y = R_MAX (x - 8, 0);
				x = y - y % 8;
			}
			break;
		case 'Z':
			{
				const int y = R_MAX (x - 8, 0);
				x = y - y % 8;
			}
			break;
			break;
		case 'L':
		case 9: // TAB
			{
				const int y = R_MIN (x + 8, nbits - 8);
				x = y - y % 8;
			}
			break;
		case 'J':
			r_core_cmd_call (core, "so+1");
			memcpy (buf, core->block + cur, sizeof (ut64));
			break;
		case 'K':
			r_core_cmd_call (core, "so-1");
			memcpy (buf, core->block + cur, sizeof (ut64));
			break;
		case 'j':
		case 'k':
		case 10:
		case ' ':
			// togglebit();
			{
				const int nbyte = x / 8;
				const int nbit = 7 - (x - (nbyte * 8));
				ut8 *byte = buf + nbyte;
				bool bit = R_BIT_CHK (byte, nbit);
				if (bit) {
					R_BIT_UNSET (byte, nbit);
				} else {
					R_BIT_SET (byte, nbit);
				}
			}
			break;
		case '>':
			{
				// buf[x / 8] = rotate_nibble (buf [(x / 8)], -1);
				const int nbyte = x / 8;
				int last = R_MIN (nbyte + wordsize, 8);
				for (i = nbyte; i < last; i++) {
					buf[i] = rotate_nibble (buf [i], -1);
				}
			}
			break;
		case '<':
			// buf[x / 8] = rotate_nibble (buf [(x / 8)], 1);
			{
				// buf[x / 8] = rotate_nibble (buf [(x / 8)], -1);
				const int nbyte = x / 8;
				int last = R_MIN (nbyte + wordsize, 8);
				for (i = nbyte; i < last; i++) {
					buf[i] = rotate_nibble (buf [i], 1);
				}
			}
			break;
		case 'i':
			{
				r_line_set_prompt (core->cons->line, "> ");
				const char *line = r_line_readline (core->cons);
				ut64 num = r_num_math (core->num, line);
				if (num || (!num && *line == '0')) {
					buf[x / 8] = num;
				}
			}
			break;
		case 'R':
			if (r_config_get_i (core->config, "scr.randpal")) {
				r_core_cmd0 (core, "ecr");
			} else {
				r_core_cmd0 (core, "ecn");
			}
			break;
		case '=':
		{ // TODO: edit
			r_core_visual_showcursor (core, true);
			const char *buf = NULL;
			#define I core->cons
			const char *cmd = r_config_get (core->config, "cmd.vprompt");
			r_line_set_prompt (core->cons->line, "cmd.vprompt> ");
			I->line->contents = strdup (cmd);
			buf = r_line_readline (core->cons);
			I->line->contents = NULL;
			(void)r_config_set (core->config, "cmd.vprompt", buf);
			r_core_visual_showcursor (core, false);
		}
		break;
		case '+':
			{
				const int nbyte = x / 8;
				int last = R_MIN (nbyte + wordsize, 8);
				for (i = nbyte; i < last; i++) {
					buf[i]++;
				}
			}
			break;
		case '-':
			//buf[(x / 8)]--;
			{
				const int nbyte = x / 8;
				int last = R_MIN (nbyte + wordsize, 8);
				for (i = nbyte; i < last; i++) {
					buf[i]--;
				}
			}
			break;
		case 'h':
			x = R_MAX (x - 1, 0);
			break;
		case 'l':
			x = R_MIN (x + 1, nbits - 1);
			break;
		case 'b':
			bitsInLine = !bitsInLine;
			break;
		case 'y': // yank
			{
				const int nbyte = x / 8;
				const int last = R_MIN (nbyte + wordsize, 8);
				yankSize = last - nbyte + 1;
				int i;
				for (i = nbyte; i < last; i++) {
					yankBuffer[i - nbyte] = buf[i];
				}
			}
			break;
		case 'Y': // paste
			{
				const int nbyte = x / 8;
				const int last = R_MIN (nbyte + wordsize, yankSize + nbyte);
				int i;
				int j = 0;
				for (i = nbyte; i < last; i++) {
					buf[i] = yankBuffer[j++];
				}
			}
			break;
		case '?':
			r_cons_clear00 (cons);
			r_cons_printf (cons,
			"Vd1?: Visual Bit Editor Help:\n\n"
			" q     - quit the bit editor\n"
			" R     - randomize color palette\n"
			" b     - toggle bitsInLine\n"
			" e     - toggle endian of the selected word\n"
			" j/k   - toggle bit value (same as space key)\n"
			" J/K   - next/prev instruction (so+1,so-1)\n"
			" h/l   - select next/previous bit\n"
			" w/W   - increment 2 or 4 the wordsize\n"
			" y/Y   - yank/paste selected bits\n"
			" +/-   - increment or decrement byte value\n"
			" </>   - rotate left/right byte value\n"
			" i     - insert numeric value of byte\n"
			" =     - set cmd.vprompt command\n"
			" !     - toggle all the bits\n"
			" :     - run r2 command\n");
			r_cons_flush (cons);
			r_cons_any_key (cons, NULL);
			break;
		case ':': // TODO: move this into a separate helper function
			{
			char cmd[1024];
			r_cons_show_cursor (cons, true);
			r_cons_set_raw (cons, 0);
			cmd[0] = '\0';
			r_line_set_prompt (core->cons->line, ":> ");
			if (r_cons_fgets (core->cons, cmd, sizeof (cmd), 0, NULL) < 0) {
				cmd[0] = '\0';
			}
			r_core_cmd (core, cmd, 1);
			r_cons_set_raw (cons, 1);
			r_cons_show_cursor (cons, false);
			if (cmd[0]) {
				r_cons_any_key (cons, NULL);
			}
			r_cons_clear (cons);
			}
			break;
		}
		r_anal_op_fini (&analop);
	}
	return true;
}

// belongs to r_core_visual_types
static bool sdbforcb(void *p, const char *k, const char *v) {
	const char *pre = " ";
	RCoreVisualTypes *vt = (RCoreVisualTypes*)p;
	bool use_color = vt->core->print->flags & R_PRINT_FLAGS_COLOR;
	char *color_sel = vt->core->cons->context->pal.prompt;
	RCons *cons = vt->core->cons;
	if (vt->optword) {
		if (!strcmp (vt->type, "struct")) {
			char *s = r_str_newf ("struct.%s.", vt->optword);
			/* enum */
			if (!strncmp (s, k, strlen (s))) {
				if (vt->t_idx == vt->t_ctr) {
					free (vt->curname);
					vt->curname = strdup (k);
					free (vt->curfmt);
					vt->curfmt = strdup (v);
					pre = ">";
				}
				if (use_color && *pre == '>') {
					r_cons_printf (cons, "%s %s %s  %s %10s\n", color_sel,
						Color_RESET, pre, k+strlen (s), v);
				} else {
					r_cons_printf (cons, "   %s %s %10s\n",
						pre, k + strlen (s), v);
				}
				vt->t_ctr ++;
			}
			free (s);
		} else {
			char *s = r_str_newf ("%s.", vt->optword);
			/* enum */
			if (!strncmp (s, k, strlen (s))) {
				if (!strstr (k, ".0x")) {
					if (vt->t_idx == vt->t_ctr) {
						free (vt->curname);
						vt->curname = strdup (v);
						free (vt->curfmt);
						vt->curfmt = strdup (v);
						pre = ">";
					}
					if (use_color && *pre == '>') {
						r_cons_printf (cons, "%s"Color_RESET" %s %s  %s\n", color_sel,
							pre, k, v);
					} else {
						r_cons_printf (cons, " %s %s  %s\n",
							pre, k, v);
					}
					vt->t_ctr ++;
				}
			}
			free (s);
		}
	} else if (!strcmp (v, vt->type)) {
		if (!strcmp (vt->type, "type")) {
			char *fmt = getformat (vt, k);
			if (vt->t_idx == vt->t_ctr) {
				free (vt->curname);
				vt->curname = strdup (k);
				free (vt->curfmt);
				vt->curfmt = strdup (fmt);
				pre = ">";
			}
			if (use_color && *pre == '>') {
				r_cons_printf (cons, "%s %s pf %3s   %s\n"Color_RESET,
					color_sel, pre, fmt, k);
			} else {
				r_cons_printf (cons, " %s pf %3s   %s\n",
					pre, fmt, k);
			}
			free (fmt);
		} else {
			if (vt->t_idx == vt->t_ctr) {
				free (vt->curname);
				vt->curname = strdup (k);
				free (vt->curfmt);
				vt->curfmt = strdup (v);
				pre = ">";
			}
			if (use_color && *pre == '>') {
				r_cons_printf (cons, "%s %s %s\n"Color_RESET, color_sel,
					(vt->t_idx == vt->t_ctr)?  ">": " ", k);
			} else {
				r_cons_printf (cons, " %s %s\n", (vt->t_idx == vt->t_ctr)?  ">": " ", k);
			}
		}
		vt->t_ctr ++;
	}
	return true;
}

R_API int r_core_visual_types(RCore *core) {
	RCoreVisualTypes vt = {core, 0, 0};
	int i, ch;
	int _option = 0;
	int option = 0;
	char *txt;
	char cmd[1024];
	int menu = 0;
	int h_opt = 0;
	char *optword = NULL;
	const char *opts[] = {
		"type",
		"enum",
		"struct",
		"func",
		"union",
		"cc",
		NULL
	};
	RCons *cons = core->cons;
	bool use_color = core->print->flags & R_PRINT_FLAGS_COLOR;
	if (r_flag_space_is_empty (core->flags)) {
		menu = 1;
	}
	for (;;) {
		r_cons_clear00 (core->cons);
		for (i = 0; opts[i]; i++) {
			if (use_color) {
				if (h_opt == i) {
					r_cons_printf (cons, "%s[%s]%s ", core->cons->context->pal.call,
						opts[i], Color_RESET);
				} else {
					r_cons_printf (cons, "%s%s%s  ", core->cons->context->pal.other,
						opts[i], Color_RESET);
				}
			} else {
				r_cons_printf (cons, h_opt == i ? "[%s] " : " %s  ", opts[i]);
			}
		}
		r_cons_newline (core->cons);
		if (optword) {
			r_cons_printf (cons, ">> %s\n", optword);
		}
		if (!strcmp (opts[h_opt], "cc")) {
			// XXX TODO: make this work (select with cursor, to delete, or add a new one with 'i', etc)
			r_core_cmdf (core, "tfcl");
		} else {
			vt.t_idx = option;
			vt.t_ctr = 0;
			vt.type = opts[h_opt];
			vt.optword = optword;
			sdb_foreach (core->anal->sdb_types, sdbforcb, &vt);
		}

		r_cons_visual_flush (core->cons);
		ch = r_cons_readchar (core->cons);
		if (ch == -1 || ch == 4) {
			return false;
		}
		ch = r_cons_arrow_to_hjkl (core->cons, ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 'h':
			h_opt--;
			if (h_opt < 0) {
				h_opt = 0;
			}
			option = 0;
			R_FREE (optword);
			break;
		case 'l':
			h_opt++;
			option = 0;
			if (!opts[h_opt]) {
				h_opt--;
			}
			R_FREE (optword);
			break;
		case 'o':
			 {
				char *file = prompt (core, "Filename: ", NULL);
				if (file) {
					r_core_cmdf (core, "'to %s", file);
					free (file);
				}
			 }
			break;
		case 'j':
			if (++option >= vt.t_ctr) {
				option = vt.t_ctr - 1;
			}
			break;
		case 'J':
			option += 10;
			if (option >= vt.t_ctr) {
				option = vt.t_ctr-1;
			}
			break;
		case 'k':
			if (--option < 0) {
				option = 0;
			}
			break;
		case 'K':
			option -= 10;
			if (option < 0) {
				option = 0;
			}
			break;
		case 'b':
			r_core_cmdf (core, "tl %s", vt.curname);
			break;
		case -1: // EOF
		case 'Q':
		case 'q':
			if (optword) {
				R_FREE (optword);
				break;
			}
			if (menu <= 0) {
				return true;
			}
			menu--;
			option = _option;
			if (menu == 0) {
				// if no flagspaces, just quit
				if (r_flag_space_is_empty (core->flags)) {
					return true;
				}
			}
			break;
		case 'a':
			{
				txt = prompt (core, "add C type: ", NULL);
				if (txt) {
					r_core_cmdf (core, "'td %s", txt);
					free (txt);
				}
			}
		       break;
		case 'd':
			r_core_cmdf (core, "t- %s", vt.curname);
			break;
		case '-':
			r_core_cmd0 (core, "to -");
			break;
		case ' ':
		case '\r':
		case '\n':
		case 'e':
			if (optword) {
				/* TODO: edit field */
			} else {
				switch (h_opt) {
				case 0: { // type
					/* TODO: do something with this data */
					char *r = NULL;
					r = prompt (core, "name: ", vt.curname);
					free (r);
					r = prompt (core, "pf: ", vt.curfmt);
					free (r);
					break;
				}
				case 1: // enum
				case 2: // struct
					free (optword);
					if (vt.curname) {
						optword = strdup (vt.curname);
					} else {
						optword = NULL;
					}
					break;
				default:
					break;
				}
			}
			break;
		case '?':
			r_cons_clear00 (cons);
			r_cons_printf (cons,
			"Vt?: Visual Types Help:\n\n"
			" q     - quit menu\n"
			" j/k   - down/up keys\n"
			" h/l   - left-right\n"
			" a     - add new type (C syntax)\n"
			" b	- bind type to current offset\n"
			" d     - delete current type\n"
			" e     - edit current type\n"
			" o     - open .h include file\n"
			" -	- Open cfg.editor to load types\n"
			" :     - enter command\n");
			r_cons_flush (cons);
			r_cons_any_key (cons, NULL);
			break;
		case ':':
			r_cons_show_cursor (cons, true);
			r_cons_set_raw (cons, 0);
			cmd[0] = '\0';
			r_line_set_prompt (cons->line, ":> ");
			if (r_cons_fgets (cons, cmd, sizeof (cmd), 0, NULL) < 0) {
				cmd[0] = '\0';
			}
			r_core_cmd (core, cmd, 1);
			r_cons_set_raw (cons, 1);
			r_cons_show_cursor (cons, false);
			if (cmd[0]) {
				r_cons_any_key (cons, NULL);
			}
			r_cons_clear (cons);
			continue;
		}
	}
	return true;
}

R_API bool r_core_visual_hudclasses(RCore *core) {
	RListIter *iter, *iter2;
	RBinClass *c;
	RBinField *f;
	RBinSymbol *m;
	ut64 addr;
	char *res;
	RList *list = r_list_new ();
	if (!list) {
		return false;
	}
	const int pref = r_config_get_b (core->config, "asm.demangle")? 'd': 0;
	list->free = free;
	RList *classes = r_bin_get_classes (core->bin);
	r_list_foreach (classes, iter, c) {
		const char *cname = r_bin_name_tostring2 (c->name, pref);
		r_list_foreach (c->fields, iter2, f) {
			const char *fname = r_bin_name_tostring2 (f->name, pref);
			r_list_append (list, r_str_newf ("0x%08"PFMT64x"  %s %s",
				f->vaddr, cname, fname));
		}
		r_list_foreach (c->methods, iter2, m) {
			const char *name = r_bin_name_tostring2 (m->name, pref);
			r_list_append (list, r_str_newf ("0x%08"PFMT64x"  %s %s",
				m->vaddr, cname, name));
		}
	}
	res = r_cons_hud (core->cons, list, NULL);
	if (res) {
		char *p = strchr (res, ' ');
		if (p) {
			*p = 0;
		}
		addr = r_num_get (NULL, res);
		r_core_seek (core, addr, true);
		free (res);
	}
	r_list_free (list);
	return res;
}

static bool hudstuff_append(RFlagItem *fi, void *user) {
	RList *list = (RList *)user;
	char *s = r_str_newf ("0x%08"PFMT64x"  %s", fi->addr, fi->name);
	if (s) {
		r_list_append (list, s);
	}
	return true;
}

R_API bool r_core_visual_hudstuff(RCore *core) {
	ut64 addr;
	char *res;
	RList *list = r_list_new ();
	if (!list) {
		return false;
	}
	list->free = free;
	r_flag_foreach (core->flags, hudstuff_append, list);
	RIntervalTreeIter it;
	RAnalMetaItem *mi;
	r_interval_tree_foreach (&core->anal->meta, it, mi) {
		if (mi->type == R_META_TYPE_COMMENT) {
			char *s = r_str_newf ("0x%08"PFMT64x" %s", r_interval_tree_iter_get (&it)->start, mi->str);
			if (s) {
				r_list_push (list, s);
			}
		}
	}
	res = r_cons_hud (core->cons, list, NULL);
	if (res) {
		char *p = strchr (res, ' ');
		if (p) {
			*p = 0;
		}
		addr = r_num_get (NULL, res);
		r_io_sundo_push (core->io, core->addr, r_print_get_cursor (core->print));
		r_core_seek (core, addr, true);
		free (res);
	}
	r_list_free (list);
	return res;
}

static bool r_core_visual_config_hud(RCore *core) {
	RListIter *iter;
	RConfigNode *bt;
	RList *list = r_list_new ();
	if (!list) {
		return false;
	}
	list->free = free;
	r_list_foreach (core->config->nodes, iter, bt) {
		r_list_append (list, r_str_newf ("%s %s", bt->name, bt->value));
	}
	char *res = r_cons_hud (core->cons, list, NULL);
	if (res) {
		const char *oldvalue = NULL;
		char cmd[512];
		char *p = strchr (res, ' ');
		if (p) {
			*p = 0;
		}
		oldvalue = r_config_get (core->config, res);
		r_cons_show_cursor (core->cons, true);
		r_cons_set_raw (core->cons, false);
		cmd[0] = '\0';
		eprintf ("Set new value for %s (old=%s)\n", res, oldvalue);
		r_line_set_prompt (core->cons->line, ":> ");
		if (r_cons_fgets (core->cons, cmd, sizeof (cmd), 0, NULL) < 0) {
			cmd[0] = '\0';
		}
		r_config_set (core->config, res, cmd);
		r_cons_set_raw (core->cons, true);
		r_cons_show_cursor (core->cons, false);
	}
	r_list_free (list);
	return true;
}

// TODO: skip N first elements
// TODO: show only N elements of the list
// TODO: wrap index when out of boundaries
// TODO: Add support to show class fields too
// Segfaults - stack overflow, because of recursion
static void *show_class(RCore *core, int mode, int *idx, RBinClass *_c, const char *grep, RList *list) {
	const int pref = r_config_get_b (core->config, "asm.demangle")? 'd': 0;
	bool show_color = r_config_get_i (core->config, "scr.color");
	RListIter *iter;
	RBinClass *c, *cur = NULL;
	RBinSymbol *m, *mur = NULL;
	RBinField *f, *fur = NULL;
	int i = 0;
	int skip = *idx - 10;
	RCons *cons = core->cons;

	const char *_cname = _c? r_bin_name_tostring (_c->name): "";
	switch (mode) {
	case 'c':
		r_cons_printf (cons, "[hjkl_/Cfm]> classes:\n\n");
		r_list_foreach (list, iter, c) {
			const char *cname = r_bin_name_tostring (c->name);
			if (grep) {
				if (!r_str_casestr (cname, grep)) {
					i++;
					continue;
				}
			} else {
				if (*idx > 10) {
					skip--;
					if (skip > 0) {
						i++;
						continue;
					}
				}
			}
			if (show_color) {
				if (i == *idx) {
					const char *clr = Color_BLUE;
					r_cons_printf (cons, Color_GREEN ">>" Color_RESET " %02d %s0x%08"
							PFMT64x Color_YELLOW "  %s\n" Color_RESET,
						i, clr, c->addr, cname);
				} else {
					r_cons_printf (cons, "-  %02d %s0x%08"PFMT64x Color_RESET"  %s\n",
						i, core->cons->context->pal.addr, c->addr, cname);
				}
			} else {
				r_cons_printf (cons, "%s %02d 0x%08"PFMT64x"  %s\n",
					(i==*idx)?">>":"- ", i, c->addr, cname);
			}
			if (i++ == *idx) {
				cur = c;
			}
		}
		if (!cur) {
			*idx = i - 1;
		}
		return cur;
	case 'f':
		// show fields
		r_cons_printf (cons, "[hjkl_/cFm]> fields of %s:\n\n", _cname);
		if (_c)
		r_list_foreach (_c->fields, iter, f) {
			const char *name = r_bin_name_tostring2 (f->name, 'f');
			if (grep) {
				if (!r_str_casestr (name, grep)) {
					i++;
					continue;
				}
			} else {
				if (*idx > 10) {
					skip--;
					if (skip > 0) {
						i++;
						continue;
					}
				}
			}

			char *mflags = strdup ("");

			if (r_str_startswith (name, _cname)) {
				name += strlen (_cname);
			}
			if (show_color) {
				if (i == *idx) {
					const char *clr = Color_BLUE;
					r_cons_printf (cons, Color_GREEN ">>" Color_RESET " %02d %s0x%08"
							PFMT64x Color_YELLOW " %s %s\n" Color_RESET,
						i, clr, f->vaddr, mflags, name);
				} else {
					r_cons_printf (cons, "-  %02d %s0x%08"PFMT64x Color_RESET" %s %s\n",
						i, core->cons->context->pal.addr, f->vaddr, mflags, name);
				}
			} else {
				r_cons_printf (cons, "%s %02d 0x%08"PFMT64x" %s %s\n",
					(i==*idx)? ">>": "- ", i, f->vaddr, mflags, name);
			}

			R_FREE (mflags);

			if (i++ == *idx) {
				fur = f;
			}
		}
		if (!fur) {
			*idx = i - 1;
		}
		return fur;
		break;
	case 'm':
		// show methods
		if (!_c) {
			R_LOG_WARN ("No class selected");
			return mur;
		}
		r_cons_printf (cons, "[hjkl_/cfM]> methods of %s\n\n", _cname);
		r_list_foreach (_c->methods, iter, m) {
			const char *name = r_bin_name_tostring2 (m->name, pref);
			if (grep) {
				if (!r_str_casestr (name, grep)) {
					i++;
					continue;
				}
			} else {
				if (*idx > 10) {
					skip--;
					if (skip > 0) {
						i++;
						continue;
					}
				}
			}

			char *mflags = r_core_bin_attr_tostring (core, m->attr, false);
			if (show_color) {
				if (r_str_startswith (name, _cname)) {
					name += strlen (_cname);
				}
				if (i == *idx) {
					const char *clr = Color_BLUE;
					r_cons_printf (cons, Color_GREEN ">>" Color_RESET " %02d %s0x%08"
							PFMT64x Color_YELLOW " %s %s\n" Color_RESET,
						i, clr, m->vaddr, mflags, name);
				} else {
					r_cons_printf (cons, "-  %02d %s0x%08"PFMT64x Color_RESET" %s %s\n",
						i, core->cons->context->pal.addr, m->vaddr, mflags, name);
				}
			} else {
				r_cons_printf (cons, "%s %02d 0x%08"PFMT64x" %s %s\n",
					(i==*idx)? ">>": "- ", i, m->vaddr, mflags, name);
			}

			R_FREE (mflags);

			if (i++ == *idx) {
				mur = m;
			}
		}
		if (!mur) {
			*idx = i - 1;
		}
		return mur;
	}
	return NULL;
}

R_API int r_core_visual_classes(RCore *core) {
	int ch, index = 0;
	char cmd[1024];
	int mode = 'c';
	RBinClass *cur = NULL;
	RBinSymbol *mur = NULL;
	RBinField *fur = NULL;
	void *ptr;
	int oldcur = 0;
	char *grep = NULL;
	bool grepmode = false;
	RList *list = r_bin_get_classes (core->bin);
	if (r_list_empty (list)) {
		r_cons_message (core->cons, "No Classes");
		return false;
	}
	for (;;) {
		int cols;
		r_cons_clear00 (core->cons);
		if (grepmode) {
			r_cons_printf (core->cons, "Grep: %s\n", r_str_get (grep));
		}
		ptr = show_class (core, mode, &index, cur, grep, list);
		switch (mode) {
		case 'f':
			fur = (RBinField*)ptr;
			break;
		case 'm':
			mur = (RBinSymbol*)ptr;
			break;
		case 'c':
			cur = (RBinClass*)ptr;
			break;
		}

		/* update terminal size */
		(void) r_cons_get_size (core->cons, &cols);
		r_cons_visual_flush (core->cons);
		ch = r_cons_readchar (core->cons);
		if (ch == -1 || ch == 4) {
			R_FREE (grep);
			return false;
		}

		if (grepmode) {
			switch (ch) {
			case 127:
				if (grep) {
					int len = strlen (grep);
					if (len < 1) {
						grepmode = false;
					} else {
						grep[len - 1] = 0;
					}
				}
				break;
			case ' ':
			case '\r':
			case '\n':
				R_FREE (grep);
				grepmode = false;
				break;
			default:
				grep = grep
					? r_str_appendf (grep, "%c", ch)
					: r_str_newf ("%c", ch);
				break;
			}
			continue;
		}

		ch = r_cons_arrow_to_hjkl (core->cons, ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 'C':
			r_config_toggle (core->config, "scr.color");
			break;
		case '_':
			if (r_core_visual_hudclasses (core)) {
				return true;
			}
			break;
		case 'J': index += 10; break;
		case 'j': index++; break;
		case 'k':
			if (--index < 0) {
				index = 0;
			}
			break;
		case 'K':
			index -= 10;
			if (index < 0) {
				index = 0;
			}
			break;
		case 'g':
			index = 0;
			break;
		case 'G':
			index = r_list_length (list) - 1;
			break;
		case 'i':
			{
				char *num = prompt (core, "Index:", NULL);
				if (num) {
					index = atoi (num);
					free (num);
				}
			}
			break;
		case 'p':
			if (mode == 'm' && mur) {
				r_core_seek (core, mur->vaddr, true);
				r_core_cmd0 (core, "af;pdf~..");
			}
			break;
		case 'm': // methods
			mode = 'm';
			break;
		case 'f': // fields
			mode = 'f';
			break;
		case 'h':
		case 127: // backspace
		case 'b': // back
		case 'Q':
		case 'c':
		case 'q':
			if (mode == 'c') {
				return true;
			}
			mode = 'c';
			index = oldcur;
			break;
		case '/':
			grepmode = true;
			break;
		case 'l':
		case ' ':
		case '\r':
		case '\n':
			if (mur && mode == 'm') {
				r_core_seek (core, mur->vaddr, true);
				return true;
			}
			if (fur) {
				r_core_seek (core, fur->vaddr, true);
				return true;
			}
			if (cur) {
				oldcur = index;
				index = 0;
				mode = 'm';
			}
			break;
		case '?':
			r_cons_clear00 (core->cons);
			r_cons_printf (core->cons,
			"\nVF: Visual Classes help:\n\n"
			" q     - quit menu\n"
			" j/k   - down/up keys\n"
			" h/b   - go back\n"
			" g/G   - go first/last item\n"
			" i     - specify index\n"
			" /     - grep mode\n"
			" C     - toggle colors\n"
			" f     - show class fields\n"
			" m     - show class methods\n"
			" l/' ' - accept current selection\n"
			" p     - preview method disasm with less\n"
			" :     - enter command\n");
			r_cons_flush (core->cons);
			r_cons_any_key (core->cons, NULL);
			break;
		case ':':
			r_cons_show_cursor (core->cons, true);
			r_cons_set_raw (core->cons, 0);
			cmd[0] = '\0';
			r_line_set_prompt (core->cons->line, ":> ");
			if (r_cons_fgets (core->cons, cmd, sizeof (cmd), 0, NULL) < 0) {
				cmd[0]='\0';
			}
			//line[strlen(line)-1]='\0';
			r_core_cmd (core, cmd, 1);
			r_cons_set_raw (core->cons, 1);
			r_cons_show_cursor (core->cons, false);
			if (cmd[0]) {
				r_cons_any_key (core->cons, NULL);
			}
			r_cons_clear (core->cons);
			break;
		}
	}
	return true;
}

static void anal_class_print(RCore *core, const char *class_name) {
	RAnal *anal = core->anal;
	RVector *bases = r_anal_class_base_get_all (anal, class_name);
	RVector *vtables = r_anal_class_vtable_get_all (anal, class_name);
	RVector *methods = r_anal_class_method_get_all (anal, class_name);

	r_cons_print (core->cons, class_name);
	if (bases) {
		RAnalBaseClass *base;
		bool first = true;
		r_vector_foreach (bases, base) {
			if (first) {
				r_cons_print (core->cons, ": ");
				first = false;
			} else {
				r_cons_print (core->cons, ", ");
			}
			r_cons_print (core->cons, base->class_name);
		}
		r_vector_free (bases);
	}
	r_cons_print (core->cons, "\n");

	if (vtables) {
		RAnalVTable *vtable;
		r_vector_foreach (vtables, vtable) {
			r_cons_printf (core->cons, "  %2s vtable 0x%"PFMT64x" @ +0x%"PFMT64x" size:+0x%"PFMT64x"\n", vtable->id, vtable->addr, vtable->offset, vtable->size);
		}
		r_vector_free (vtables);
	}

	r_cons_print (core->cons, "\n");

	if (methods) {
		RAnalMethod *meth;
		r_vector_foreach (methods, meth) {
			r_cons_printf (core->cons, "  %s @ 0x%"PFMT64x, meth->name, meth->addr);
			if (meth->vtable_offset >= 0) {
				r_cons_printf (core->cons, " (vtable + 0x%"PFMT64x")\n", (ut64)meth->vtable_offset);
			} else {
				r_cons_print (core->cons, "\n");
			}
		}
		r_vector_free (methods);
	}
}

static const char *show_anal_classes(RCore *core, char mode, int *idx, SdbList *list, const char *class_name) {
	bool show_color = r_config_get_i (core->config, "scr.color");
	SdbListIter *iter;
	SdbKv *kv;
	int i = 0;
	int skip = *idx - 10;
	const char * cur_class = NULL;
	r_cons_printf (core->cons, "[hjkl_/Cfm]> anal classes:\n\n");

	if (mode == 'd' && class_name) {
		anal_class_print (core, class_name);
		return class_name;
	}

	ls_foreach (list, iter, kv) {
		if (*idx > 10) {
			skip--;
			if (skip > 0) {
				i++;
				continue;
			}
		}
		class_name = sdbkv_key (kv);

		if (show_color) {
			const char *pointer = "- ";
			const char *txt_clr = "";

			if (i == *idx) {
				pointer = Color_GREEN ">>";
				txt_clr = Color_YELLOW;
				cur_class = class_name;
			}
			r_cons_printf (core->cons, "%s" Color_RESET " %02d"
				" %s%s\n" Color_RESET, pointer, i, txt_clr, class_name);
		} else {
			r_cons_printf (core->cons, "%s %02d %s\n", (i==*idx) ? ">>" : "- ", i, class_name);
		}

		i++;
	}

	return cur_class;
}
// TODO add other commands that Vbc has
// Should the classes be refreshed after command execution with :
// in case new class information would be added?
// Add grep?
R_API int r_core_visual_anal_classes(RCore *core) {
	int ch, index = 0;
	char command[1024];
	SdbList *list = r_anal_class_get_all (core->anal, true);
	int oldcur = 0;
	char mode = ' ';
	const char *class_name = "";

	if (r_list_empty (list)) {
		r_cons_message (core->cons, "No Classes");
		goto cleanup;
	}
	for (;;) {
		int cols;
		r_cons_clear00 (core->cons);

		class_name = show_anal_classes (core, mode, &index, list, class_name);

		/* update terminal size */
		(void) r_cons_get_size (core->cons, &cols);
		r_cons_visual_flush (core->cons);
		ch = r_cons_readchar (core->cons);
		if (ch == -1 || ch == 4) {
			goto cleanup;
		}

		ch = r_cons_arrow_to_hjkl (core->cons, ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 'C':
			r_config_toggle (core->config, "scr.color");
			break;
		case 'J':
			index += 10;
			if (index >= list->length) {
				index = list->length -1;
			}
			break;
		case 'j':
			if (index + 1 >= list->length) {
				index = 0;
			} else {
				index++;
			}
			break;
		case 'k':
			if (index-- < 1) {
				index = list->length - 1;
			}
			break;
		case 'K':
			index -= 10;
			if (index < 0) {
				index = 0;
			}
			break;
		case 'g':
			index = 0;
			break;
		case 'G':
			index = list->length - 1;
			break;
		case 'h':
		case 127: // backspace
		case 'b': // back
		case 'Q':
		case 'c':
		case 'q':
			if (mode == ' ') {
				goto cleanup;
			}
			mode = ' ';
			index = oldcur;
			break;
		case 'l':
		case ' ':
		case '\r':
		case '\n':
			mode = 'd';
			break;
		case '?':
			r_cons_clear00 (core->cons);
			r_cons_printf (core->cons,
			"\nVF: Visual Classes help:\n\n"
			" q     - quit menu\n"
			" j/k   - down/up keys\n"
			" h/b   - go back\n"
			" g/G   - go first/last item\n"
			" l/' ' - accept current selection\n"
			" :     - enter command\n");
			r_cons_flush (core->cons);
			r_cons_any_key (core->cons, NULL);
			break;
		case ':':
			r_cons_show_cursor (core->cons, true);
			r_cons_set_raw (core->cons, 0);
			command[0] = '\0';
			r_line_set_prompt (core->cons->line, ":> ");
			if (r_cons_fgets (core->cons, command, sizeof (command), 0, NULL) < 0) {
				command[0] = '\0';
			}
			r_core_cmd (core, command, 1);
			r_cons_set_raw (core->cons, 1);
			r_cons_show_cursor (core->cons, false);
			if (command[0]) {
				r_cons_any_key (core->cons, NULL);
			}
			r_cons_clear (core->cons);
			break;
		}
	}
cleanup:
	ls_free (list);
	return true;
}

static int flag_name_sort(const void *a, const void *b) {
	const RFlagItem *fa = (const RFlagItem *)a;
	const RFlagItem *fb = (const RFlagItem *)b;
	return strcmp (fa->name, fb->name);
}

static int flag_offset_sort(const void *a, const void *b) {
	const RFlagItem *fa = (const RFlagItem *)a;
	const RFlagItem *fb = (const RFlagItem *)b;
	if (fa->addr < fb->addr) {
		return -1;
	}
	if (fa->addr > fb->addr) {
		return 1;
	}
	return 0;
}

static void sort_flags(RList *l, int sort) {
	switch (sort) {
	case SORT_NAME:
		r_list_sort (l, flag_name_sort);
		break;
	case SORT_ADDR:
		r_list_sort (l, flag_offset_sort);
		break;
	case SORT_NONE:
	default:
		break;
	}
}

// TODO: remove this statement, should be a separate .o

static char *print_rop(void *_core, void *_item, bool selected) {
	char *line = _item;
	// TODO: trim if too long
	return r_str_newf ("%c %s\n", selected?'>':' ', line);
}

R_API int r_core_visual_view_rop(RCore *core) {
	RListIter *iter;
	const int rows = 7;
	int cur = 0;

	r_line_set_prompt (core->cons->line, "rop regexp: ");
	const char *line = r_line_readline (core->cons);

	int scr_h, scr_w = r_cons_get_size (core->cons, &scr_h);

	if (R_STR_ISEMPTY (line)) {
		return false;
	}
	// maybe store in RCore, so we can save it in project and use it outside visual

	RCons *cons = core->cons;
	R_LOG_INFO ("Searching ROP gadgets");
	char *ropstr = r_core_cmd_strf (core, "\"/Rl %s\" @e:scr.color=0", line);
	RList *rops = r_str_split_list (ropstr, "\n", 0);
	int delta = 0;
	bool show_color = core->print->flags & R_PRINT_FLAGS_COLOR;
	bool forceaddr = false;
	ut64 addr = UT64_MAX;
	char *cursearch = strdup (line);
	while (true) {
		r_cons_clear00 (core->cons);
		r_cons_printf (core->cons, "[0x%08"PFMT64x"]-[visual-r2rop] %s (see pdp command)\n",
			(addr == UT64_MAX)? 0: addr + delta, cursearch);

		// compute chain
		RStrBuf *sb = r_strbuf_new ("");
		char *msg;
		r_list_foreach (core->ropchain, iter, msg) {
			if (core->rasm->config->bits == 64) {
				ut64 n = r_num_get (NULL, msg);
				n = r_read_be64 (&n);
				r_strbuf_appendf (sb, "%016"PFMT64x, n);
			} else {
				ut32 n = r_num_get (NULL, msg);
				n = r_read_be32 (&n);
				r_strbuf_appendf (sb, "%08x", n);
			}
		}
		char *chainstr = r_strbuf_drain (sb);

		char *wlist = r_str_widget_list (core, rops, rows, cur, print_rop);
		r_cons_printf (core->cons, "%s", wlist);
		char *curline = r_str_trim_dup (wlist);
		free (wlist);
		if (curline) {
			char *sp = strchr (curline, ' ');
			if (sp) {
				*sp = 0;
				if (!forceaddr) {
					addr = r_num_math (NULL, curline);
				}
				*sp = ' ';
			}
			if (addr != UT64_MAX) {
				r_cons_printf (core->cons, "Gadget:");
				// get comment
				char *output = r_core_cmd_strf (core, "piu 10 @ 0x%08"PFMT64x, addr + delta);
				if (output) {
					r_cons_print_at (cons, output, 0, 10, scr_w, 10);
					free (output);
				}
			}
		}
		int count = 0;
		r_cons_flush (cons);
		r_cons_gotoxy (cons, 0, 20);
		r_cons_printf (cons, "ROPChain:\n  %s\n", r_str_get (chainstr));
		r_list_foreach (core->ropchain, iter, msg) {
			int extra = strlen (chainstr) / scr_w;
			r_cons_gotoxy (core->cons, 0, extra + 22 + count);
			r_cons_print (core->cons, msg);
			const char *cmt = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, r_num_get (NULL, msg));
			if (cmt) {
				r_cons_print (cons, cmt);
			}
			count ++;
		}
		r_cons_flush (cons);
		int ch = r_cons_readchar (cons);
		if (ch == -1 || ch == 4) {
			free (curline);
			free (cursearch);
			R_FREE (chainstr);
			return false;
		}
#define NEWTYPE(x,y) r_mem_dup (&(y), sizeof (x));
		ch = r_cons_arrow_to_hjkl (core->cons, ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 127:
			free (r_list_pop (core->ropchain));
			break;
		case '?':
			r_cons_clear00 (core->cons);
			r_cons_printf (core->cons, "[r2rop-visual] Help\n"
					" jk - select next/prev rop gadget\n"
					" JK - scroll next/prev page from list\n"
					" hl - increase/decrease delta offset in disasm\n"
					" \\n - enter key or dot will add the current offset into the chain\n"
					" i  - enter a number to be pushed into the chain\n"
					" :  - run r2 command\n"
					" ;  - add comment in current offset\n"
					" <- - backspace - delete last gadget from the chain\n"
					" /  - highlight given word\n"
					" y  - yank current rop chain into the clipboard (y?)\n"
					" o  - seek to given offset\n"
					" r  - run /R again\n"
					" ?  - show this help message\n"
					" q  - quit this view\n"
				      );
			r_cons_flush (core->cons);
			r_cons_any_key (core->cons, NULL);
			break;
		case ':': // TODO: move this into a separate helper function
			r_cons_show_cursor (core->cons, true);
			r_cons_set_raw (core->cons, 0);
			while (true) {
				char cmd[1024];
				cmd[0] = '\0';
				r_line_set_prompt (core->cons->line, ":> ");
				if (r_cons_fgets (core->cons, cmd, sizeof (cmd), 0, NULL) < 0) {
					cmd[0] = '\0';
				}
				if (!*cmd || *cmd == 'q') {
					break;
				}
				ut64 oseek = core->addr;
				r_core_seek (core, addr + delta, false);
				r_core_cmd (core, cmd, 1);
				r_core_seek (core, oseek, false);
				r_cons_flush (core->cons);
			}
			r_cons_set_raw (core->cons, 1);
			r_cons_show_cursor (core->cons, false);
			break;
		case 'y':
			r_core_cmdf (core, "yfx %s", chainstr);
			break;
		case 'o':
			{
				r_line_set_prompt (core->cons->line, "offset: ");
				const char *line = r_line_readline (core->cons);
				if (R_STR_ISNOTEMPTY (line)) {
					ut64 off = r_num_math (core->num, line);
					r_core_seek (core, off, true);
					addr = off;
					forceaddr = true;
					delta = 0;
				}
			}
			break;
		case 'r':
			{
				r_line_set_prompt (core->cons->line, "rop regexp: ");
				const char *line = r_line_readline (core->cons);
				if (line && *line) {
					free (cursearch);
					delta = 0;
					addr = UT64_MAX;
					cur = 0;
					cursearch = strdup (line);
					free (ropstr);
					ropstr = r_core_cmd_strf (core, "\"/Rl %s\" @e:scr.color=0", line);
					r_list_free (rops);
					rops = r_str_split_list (ropstr, "\n", 0);
				}
			}
			break;
		case '/':
			r_core_cmd0 (core, "?i highlight;e scr.highlight=`yp`");
			break;
		case 'i':
			{
				r_line_set_prompt (core->cons->line, "insert value: ");
				const char *line = r_line_readline (core->cons);
				if (line && *line) {
					ut64 n = r_num_math (core->num, line);
					r_list_push (core->ropchain, r_str_newf ("0x%08"PFMT64x, n));
				}
			}
			break;
		case ';':
			{
				r_line_set_prompt (core->cons->line, "comment: ");
				const char *line = r_line_readline (core->cons);
				if (R_STR_ISNOTEMPTY (line)) {
					r_core_cmdf (core, "'@0x%08"PFMT64x"'CC %s", addr + delta, line);
				}
			}
			break;
		case '.':
		case '\n':
		case '\r':
			if (curline && *curline) {
				char *line = r_core_cmd_strf (core, "'@0x%08"PFMT64x"'piuq", addr + delta);
				r_str_replace_char (line, '\n', ';');
				if (show_color) {
					// XXX parsing fails to read this ansi-offset
					// r_list_push (core->ropchain, r_str_newf ("%s0x%08"PFMT64x Color_RESET"  %s", offsetColor, addr + delta, line));
					r_list_push (core->ropchain, r_str_newf ("0x%08"PFMT64x"  %s", addr + delta, line));
				} else {
					r_list_push (core->ropchain, r_str_newf ("0x%08"PFMT64x"  %s", addr + delta, line));
				}
				free (line);
			}
			break;
		case 'h':
			delta--;
			break;
		case 'l':
			delta++;
			break;
		case 'J':
			cur += 10;
			forceaddr = false;
			delta = 0;
			break;
		case 'K':
			delta = 0;
			forceaddr = false;
			if (cur > 10) {
				cur -= 10;
			} else {
				cur = 0;
			}
			break;
		case '0':
			delta = 0;
			cur = 0;
			break;
		case 'j':
			delta = 0;
			cur++;
			forceaddr = false;
			break;
		case 'k':
			delta = 0;
			forceaddr = false;
			if (cur > 0) {
				cur--;
			} else {
				cur = 0;
			}
			break;
		case 'q':
			free (curline);
			free (cursearch);
			R_FREE (chainstr);
			return true;
		}
		R_FREE (chainstr);
		free (curline);
	}
	free (cursearch);
	return false;
}

R_API int r_core_visual_trackflags(RCore *core) { // "vbf"
	RCoreVisual *v = &core->visual;
	const char *fs = NULL, *fs2 = NULL;
	int hit, i, j, ch;
	int _option = 0;
	int option = 0;
	char cmd[1024];
	int format = 0;
	int delta = 7;
	int menu = 0;
	int sort = SORT_NONE;

	if (r_flag_space_is_empty (core->flags)) {
		menu = 1;
	}
	for (;;) {
		bool hasColor = r_config_get_i (core->config, "scr.color");
		r_cons_clear00 (core->cons);

		if (menu) {
			r_cons_printf (core->cons, "Flags in flagspace '%s'. Press '?' for help.\n\n",
				r_flag_space_cur_name (core->flags));
			hit = 0;
			i = j = 0;
			RList *l = r_flag_all_list (core->flags, true);
			RListIter *iter;
			RFlagItem *fi;
			sort_flags (l, sort);
			r_list_foreach (l, iter, fi) {
				if (option == i) {
					fs2 = fi->name;
					hit = 1;
				}
				if ((i >= option-delta) && ((i < option + delta) || ((option<delta)&&(i < (delta << 1))))) {
					bool cur = option == i;
					if (cur && hasColor) {
						r_cons_printf (core->cons, Color_INVERT);
					}
					r_cons_printf (core->cons, " %c  %03d 0x%08"PFMT64x" %4"PFMT64d" %s\n",
						       cur?'>':' ', i, fi->addr, fi->size, fi->name);
					if (cur && hasColor) {
						r_cons_printf (core->cons, Color_RESET);
					}
					j++;
				}
				i++;
			}
			r_list_free (l);

			if (!hit && i > 0) {
				option = i - 1;
				continue;
			}
			if (fs2) {
				int cols, rows = r_cons_get_size (core->cons, &cols);
				//int rows = 20;
				rows -= 12;
				r_cons_printf (core->cons, "\n Selected: %s\n\n", fs2);
				// Honor MAX_FORMATS here
				switch (format) {
				case 0: snprintf (cmd, sizeof (cmd), "px %d @ %s!64", rows*16, fs2); v->printidx = 0; break;
				case 1: snprintf (cmd, sizeof (cmd), "pd %d @ %s!64", rows, fs2); v->printidx = 1; break;
				case 2: snprintf (cmd, sizeof (cmd), "ps @ %s!64", fs2); v->printidx = 5; break;
				case 3: strcpy (cmd, "f="); break;
				default: format = 0; continue;
				}
				if (*cmd) {
					r_core_cmd (core, cmd, 0);
				}
			} else {
				r_cons_printf (core->cons, "(no flags)\n");
			}
		} else {
			r_cons_printf (core->cons, "Flag spaces:\n\n");
			hit = 0;
			RSpaceIter *it;
			const RSpace *s, *cur = r_flag_space_cur (core->flags);
			int i = 0;
			r_flag_space_foreach (core->flags, it, s) {
				if (option == i) {
					fs = s->name;
					hit = 1;
				}
				if ((i >= option - delta) && ((i < option + delta) ||
					((option < delta) && (i < (delta << 1))))) {
					r_cons_printf (core->cons, " %c %c %s\n",
						(option == i)? '>': ' ',
						(s == cur)? '*': ' ',
						s->name);
				}
				i++;
			}
			if (option == i) {
				fs = "*";
				hit = 1;
			}
			r_cons_printf (core->cons, " %c %c %s\n", (option == i)? '>': ' ',
				!cur? '*': ' ', "*");
			i++;
			if (!hit && i > 0) {
				option = i - 1;
				continue;
			}
		}
		r_cons_visual_flush (core->cons);
		ch = r_cons_readchar (core->cons);
		if (ch == -1 || ch == 4) {
			return false;
		}
		ch = r_cons_arrow_to_hjkl (core->cons, ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 'C':
			r_config_toggle (core->config, "scr.color");
			break;
		case '_':
			if (r_core_visual_hudstuff (core)) {
				return true;
			}
			break;
		case 'J': option += 10; break;
		case 'o': sort = SORT_ADDR; break;
		case 'n': sort = SORT_NAME; break;
		case 'j': option++; break;
		case 'k':
			if (--option < 0) {
				option = 0;
			}
			break;
		case 'K':
			option -= 10;
			if (option < 0) {
				option = 0;
			}
			break;
		case 'h':
		case 'b': // back
		case 'Q':
		case 'q':
			if (menu <= 0) {
				return true;
			}
			menu--;
			option = _option;
			if (menu == 0) {
				r_flag_space_set (core->flags, NULL);
				// if no flagspaces, just quit
				if (r_flag_space_is_empty (core->flags)) {
					return true;
				}
			}
			break;
		case 'a':
			switch (menu) {
			case 0: // new flag space
				r_cons_show_cursor (core->cons, true);
				r_line_set_prompt (core->cons->line, "add flagspace: ");
				strcpy (cmd, "fs ");
				if (r_cons_fgets (core->cons, cmd + 3, sizeof (cmd) - 3, 0, NULL) > 0) {
					r_core_cmd (core, cmd, 0);
					r_cons_set_raw (core->cons, 1);
					r_cons_show_cursor (core->cons, false);
				}
				break;
			case 1: // new flag
				r_cons_show_cursor (core->cons, true);
				r_line_set_prompt (core->cons->line, "add flag: ");
				strcpy (cmd, "f ");
				if (r_cons_fgets (core->cons, cmd + 2, sizeof (cmd) - 2, 0, NULL) > 0) {
					r_core_cmd (core, cmd, 0);
					r_cons_set_raw (core->cons, 1);
					r_cons_show_cursor (core->cons, false);
				}
				break;
			}
			break;
		case 'd':
			r_flag_unset_name (core->flags, fs2);
			break;
		case 'e': // "VTe"
			/* TODO: prompt for addr, size, name */
			R_LOG_WARN ("TODO: VTe. prompt for addr, size, name");
			r_sys_sleep (1);
			break;
		case '*':
			r_core_block_size (core, core->blocksize + 16);
			break;
		case '/':
			r_core_block_size (core, core->blocksize - 16);
			break;
		case '+':
			if (menu == 1) {
				r_core_cmdf (core, "f %s=%s+1", fs2, fs2);
			} else {
				r_core_block_size (core, core->blocksize + 1);
			}
			break;
		case '-':
			if (menu == 1) {
				r_core_cmdf (core, "f %s=%s-1", fs2, fs2);
			} else {
				r_core_block_size (core, core->blocksize-1);
			}
			break;
		case 'r': // "Vtr"
			if (menu == 1) {
				char line[1024];
				r_cons_show_cursor (core->cons, true);
				r_cons_set_raw (core->cons, 0);
				r_cons_printf (core->cons, "Rename flag '%s' as:\n", fs2);
				r_cons_flush (core->cons);
				r_line_set_prompt (core->cons->line, ":> ");
				if (r_cons_fgets (core->cons, line, sizeof (line), 0, NULL) >= 0) {
					// TODO: use the API
					r_core_cmdf (core, "fr %s %s", fs2, line);
				}
				r_cons_set_raw (core->cons, 1);
				r_cons_show_cursor (core->cons, false);
			}
			break;
		case 'R':
			if (menu == 1) {
				char line[1024];
				r_cons_show_cursor (core->cons, true);
				r_cons_set_raw (core->cons, 0);
				r_cons_printf (core->cons, "Rename function '%s' as:\n", fs2);
				r_cons_flush (core->cons);
				r_line_set_prompt (core->cons->line, ":> ");
				if (r_cons_fgets (core->cons, line, sizeof (line), 0, NULL) >= 0) {
					// TODO: use the API
					r_core_cmdf (core, "afr %s %s", line, fs2);
				}
				r_cons_set_raw (core->cons, 1);
				r_cons_show_cursor (core->cons, false);
			}
			break;
		case 'P':
			if (--format < 0) {
				format = MAX_FORMAT;
			}
			break;
		case 'p': format++; break;
		case 'l':
		case ' ':
		case '\r':
		case '\n':
			if (menu == 1) {
				r_core_cmdf (core, "s %s", fs2);
				return true;
			}
			r_flag_space_set (core->flags, fs);
			menu = 1;
			_option = option;
			option = 0;
			break;
		case '?':
			r_cons_clear00 (core->cons);
			r_cons_printf (core->cons,
			"\nVF: Visual Flags help:\n\n"
			" q     - quit menu\n"
			" j/k   - line down/up keys\n"
			" J/K   - page down/up keys\n"
			" h/b   - go back\n"
			" C     - toggle colors\n"
			" l/' ' - accept current selection\n"
			" a/d/e - add/delete/edit flag\n"
			" +/-   - increase/decrease block size\n"
			" o     - sort flags by offset\n"
			" r/R   - rename flag / Rename function\n"
			" n     - sort flags by name\n"
			" p/P   - rotate print format\n"
			" _     - hud for flags and comments\n"
			" :     - enter command\n");
			r_cons_flush (core->cons);
			r_cons_any_key (core->cons, NULL);
			break;
		case ':':
			r_cons_show_cursor (core->cons, true);
			r_cons_set_raw (core->cons, 0);
			*cmd = 0;
			r_line_set_prompt (core->cons->line, ":> ");
			if (r_cons_fgets (core->cons, cmd, sizeof (cmd), 0, NULL) <0) {
				*cmd = 0;
			}
			cmd[sizeof (cmd) - 1] = 0;
			r_core_cmd_task_sync (core, cmd, 1);
			r_cons_set_raw (core->cons, 1);
			r_cons_show_cursor (core->cons, false);
			if (*cmd) {
				r_cons_any_key (core->cons, NULL);
			}
			r_cons_clear (core->cons);
			continue;
		}
	}
	return true;
}

R_API int r_core_visual_comments(RCore *core) {
	RCoreVisual *v = &core->visual;
	char *str;
	char cmd[512], *p = NULL;
	int ch, option = 0;
	int format = 0, i = 0;
	ut64 addr, from = 0, size = 0;

	for (;;) {
		r_cons_clear00 (core->cons);
		r_cons_print (core->cons, "Comments:\n");
		RIntervalTreeIter it;
		RAnalMetaItem *item;
		i = 0;
		r_interval_tree_foreach (&core->anal->meta, it, item) {
			if (item->type != R_META_TYPE_COMMENT) {
				continue;
			}
			str = item->str;
			addr = r_interval_tree_iter_get (&it)->start;
			if (option==i) {
				from = addr;
				size = 1; // XXX: remove this thing size for comments is useless d->size;
				free (p);
				p = strdup (str);
				r_cons_printf (core->cons, "  >  %s\n", str);
			} else {
				r_cons_printf (core->cons, "     %s\n", str);
			}
			i ++;
		}
		if (!i) {
			if (--option < 0) {
				r_cons_any_key (core->cons, "No comments");
				break;
			}
			continue;
		}
		r_cons_newline (core->cons);

		switch (format) {
		case 0: snprintf (cmd, sizeof (cmd), "px @ 0x%"PFMT64x":64", from); v->printidx = 0; break;
		case 1: snprintf (cmd, sizeof (cmd), "pd 12 @ 0x%"PFMT64x":64", from); v->printidx = 1; break;
		case 2: snprintf (cmd, sizeof (cmd), "ps @ 0x%"PFMT64x":64", from); v->printidx = 5; break;
		default: format = 0; continue;
		}
		if (*cmd) {
			r_core_cmd (core, cmd, 0);
		}
		r_cons_visual_flush (core->cons);
		ch = r_cons_readchar (core->cons);
		ch = r_cons_arrow_to_hjkl (core->cons, ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 'a':
			// TODO
			break;
		case 'e':
			// TODO
			break;
		case 'd':
			if (p) {
				r_meta_del (core->anal, R_META_TYPE_ANY, from, size);
			}
			break;
		case 'P':
			if (--format < 0) {
				format = MAX_FORMAT;
			}
			break;
		case 'p':
			format++;
			break;
		case 'J':
			option += 10;
			break;
		case 'j':
			option++;
			break;
		case 'k':
			if (--option < 0) {
				option = 0;
			}
			break;
		case 'K':
			option -= 10;
			if (option < 0) {
				option = 0;
			}
			break;
		case 'l':
		case ' ':
		case '\r':
		case '\n':
			r_core_cmdf (core, "s 0x%"PFMT64x, from);
			R_FREE (p);
			return true;
		case 'Q':
		case 'q':
			R_FREE (p);
			return true;
		case '?':
		case 'h':
			r_cons_clear00 (core->cons);
			r_cons_printf (core->cons,
			"\nVT: Visual Comments/Anal help:\n\n"
			" q     - quit menu\n"
			" j/k   - down/up keys\n"
			" h/b   - go back\n"
			" l/' ' - accept current selection\n"
			" a/d/e - add/delete/edit comment/anal symbol\n"
			" p/P   - rotate print format\n");
			r_cons_flush (core->cons);
			r_cons_any_key (core->cons, NULL);
			break;
		}
		R_FREE (p);
	}
	return true;
}

static void config_visual_hit_i(RCore *core, const char *name, int delta) {
	struct r_config_node_t *node;
	node = r_config_node_get (core->config, name);
	if (node && r_config_node_is_int (node)) {
		int hitDelta = r_config_get_i (core->config, name) + delta;
		(void) r_config_set_i (core->config, name, hitDelta);
	}
}

/* Visually activate the config variable */
static void config_visual_hit(RCore *core, const char *name, int editor) {
	char buf[1024];
	RConfigNode *node;

	if (!(node = r_config_node_get (core->config, name))) {
		return;
	}
	if (r_config_node_is_bool (node)) {
		r_config_set_i (core->config, name, node->i_value? 0:1);
	} else {
// XXX: must use config_set () to run callbacks!
		if (editor) {
			char *buf = r_core_editor (core, NULL, node->value);
			if (buf) {
				free (node->value);
				node->value = buf;
			}
		} else {
			// FGETS AND SO
			r_cons_printf (core->cons, "New value (old=%s): \n", node->value);
			r_cons_show_cursor (core->cons, true);
			r_cons_flush (core->cons);
			r_cons_set_raw (core->cons, false);
			r_line_set_prompt (core->cons->line, ":> ");
			r_cons_fgets (core->cons, buf, sizeof (buf), 0, 0);
			r_cons_set_raw (core->cons, true);
			r_cons_show_cursor (core->cons, false);
			r_config_set (core->config, name, buf);
			//node->value = strdup (node->value, buf);
		}
	}
}

static void show_config_options(RCore *core, const char *opt, int row) {
	RConfigNode *node = r_config_node_get (core->config, opt);
	if (node && !r_list_empty (node->options)) {
		int h, w = 25;
		r_cons_get_size (core->cons, &h);
		const char *item;
		RListIter *iter;
		RStrBuf *sb = r_strbuf_new ("|\n|\n`--[ Options ]\n");
		int linelen = 0;
		h -= (row + 8);
		int lines = 0;
		r_list_foreach (node->options, iter, item) {
			r_strbuf_appendf (sb, " %s", item);
			linelen += strlen (item);
			if (linelen > w) {
				r_strbuf_append (sb, "\n");
				linelen = 0;
				lines++;
			}
			if (lines > h) {
				r_strbuf_append (sb, "..");
				break;
			}
#if 0
			if (r_strbuf_length (sb) + 5 >= w) {
				char *s = r_strbuf_drain (sb);
				r_cons_println (core->cons, s);
				free (s);
				sb = r_strbuf_new ("");
			}
#endif
		}
		char *s = r_strbuf_drain (sb);
		r_cons_print (core->cons, s);
		free (s);
	}
}

R_API void r_core_visual_config(RCore *core) {
	char *fs = NULL, *fs2 = NULL, *desc = NULL;
	int i, j, ch, hit, show;
	int option, _option = 0;
	RListIter *iter;
	RConfigNode *bt;
	RCons *cons = core->cons;
	char old[1024] = {0};
	int delta = 9;
	int menu = 0;
	int menuboxh = 0;

	option = 0;
	for (;;) {
		r_cons_clear00 (core->cons);
		int h, w = r_cons_get_size (core->cons, &h);
		delta = h;
		delta /= 4;

		switch (menu) {
		case 0: // flag space
			r_cons_printf (core->cons, "[hjkl][Eq] Configuration:\n\n.----------------.\n");
			hit = j = i = 0;
			menuboxh = 0;
			r_list_foreach (core->config->nodes, iter, bt) {
				if (j > 20) {
					break;
				}
				menuboxh++;
				if (option == i) {
					fs = bt->name;
				}
				if (!old[0]) {
					copyuntilch (old, bt->name, '.');
					show = 1;
				} else if (r_str_ccmp (old, bt->name, '.')) {
					copyuntilch (old, bt->name, '.');
					show = 1;
				} else {
					show = 0;
				}
				if (show) {
					if (option == i) {
						hit = 1;
					}
					if ((i >= option-delta) && ((i < option+delta) || ((option < delta) && (i < (delta << 1))))) {
						char *arrow = NULL;
						const char *arrowstr = "";
						if (option == i) {
							arrow = strdup ("------------|");
							size_t n = strlen (old);
							arrowstr = arrow + n;
							arrow[n] = ' ';
							arrow[n+1] = ']';
						} else {
							arrow = strdup ("            |");
							size_t n = strlen (old);
							arrowstr = arrow + n;
						}
						r_cons_printf (core->cons, "%s%s%s\n", (option == i)?"|--[ ":"|    ", old, arrowstr);
						free (arrow);
						j++;
					}
					i++;
				}
			}
			if (!hit && j > 0) {
				option--;
				continue;
			}
			r_cons_printf (core->cons, "`----------------'\n");
			break;
		case 1: // flag selection
			r_cons_printf (core->cons, "[hjkl] [Eq] Configuration: %s\n\n.-----------------------------------.\n", fs);
			hit = 0;
			j = i = 0;
			menuboxh = 0;
			r_list_foreach (core->config->nodes, iter, bt) {
				if (!r_str_ccmp (bt->name, fs, '.')) {
					if (option == i) {
						fs2 = bt->name;
						desc = bt->desc;
						hit = 1;
					}
					if ((i>=option-delta) && ((i < option+delta)||((option<delta)&&(i < (delta<<1))))) {
						char *msg = r_str_newf ("%s = %s", bt->name, bt->value);
						char *arrow = NULL;
						const char *arrowstr = "";
						menuboxh++;
						if (option == i) {
							arrow = strdup ("-------------------------------|");
							size_t n = strlen (msg);
							arrowstr = arrow + n;
							arrow[n] = ' ';
							arrow[n + 1] = ']';
						} else {
							arrow = strdup ("                               |");
							size_t n = strlen (msg);
							arrowstr = arrow + n;
						}
						// TODO: Better align
						r_cons_printf (core->cons, "|%s %s%s\n", (option==i)?"--[":"   ", msg, arrowstr);
						R_FREE (arrow);
						j++;
					}
					i++;
				}
			}
			r_cons_printf (core->cons, "`-----------------------------------'\n");
			if (!hit && j > 0) {
				option = i - 1;
				continue;
			}
		}

		r_cons_visual_flush (cons);
		if (menu == 1 && fs2) {
			// TODO: Break long lines.
			r_cons_gotoxy (core->cons, 0, 0);
			r_cons_printf (core->cons, "[hjkq] %s", desc);
			r_cons_gotoxy (core->cons, 0, menuboxh + 4);
			show_config_options (core, fs2, menuboxh);
			r_cons_flush (cons);
		}
		if (menu != 0 && fs && r_str_startswith (fs, "asm.")) {
			char *s = r_core_cmd_str (core, "pd $r");
			r_cons_print_at (cons, s, 38, 3, w - 40, h - 2);
			free (s);
			r_cons_flush (cons);
		}
		if (menu == 0) {
			int y = 4;
			r_list_foreach (core->config->nodes, iter, bt) {
				if (!r_str_ccmp (bt->name, fs, '.')) {
					if (y > 20) {
						break;
					}
					r_cons_gotoxy (core->cons, 21, y);
					// TODO: Better align
					r_cons_printf (core->cons, "%s = %s", bt->name, bt->value);
					y++;
				}
			}
			r_cons_gotoxy (core->cons, 21, y);
			r_cons_printf (core->cons, "...");
			r_cons_gotoxy (core->cons, 0, 0);
			r_cons_flush (core->cons);
		}
		ch = r_cons_readchar (core->cons);
		if (ch == 4 || ch == -1) {
			return;
		}
		ch = r_cons_arrow_to_hjkl (core->cons, ch); // get ESC+char, return 'hjkl' char

		switch (ch) {
		case 'd':
			r_core_visual_define (core, "", 0);
			break;
		case '!':
			r_core_cmd0 (core, "ed");
			break;
		case 'j': option++; break;
		case 'k': option = (option < 1)? 0: option - 1; break;
		case 'J': option += 4; break;
		case 'K': option = (option < 4)? 0: option - 4; break;
		case 'h':
		case 'b': // back
			menu = 0;
			option = _option;
			break;
		case '_':
			r_core_visual_config_hud (core);
			break;
		case 'Q':
		case 'q':
			if (menu <= 0) {
				return;
			}
			menu--;
			option = _option;
			break;
		case '$':
			r_core_cmd0 (core, "?$");
			r_cons_any_key (core->cons, NULL);
			break;
		case '*':
		case '+':
			fs2 ? config_visual_hit_i (core, fs2, +1) : 0;
			continue;
		case '/':
			r_core_cmd0 (core, "?i highlight;e scr.highlight=`yp`");
			break;
		case '-':
			fs2 ? config_visual_hit_i (core, fs2, -1) : 0;
			continue;
		case 'E': // edit value
			// swith to visual theme
			r_core_visual_colors (core);
			break;
		case 'l':
		case 'e': // edit value
		case ' ':
		case '\r':
		case '\n': // never happens
			if (menu == 1) {
				fs2 ? config_visual_hit (core, fs2, (ch == 'E')) : 0;
			} else {
				menu = 1;
				_option = option;
				option = 0;
			}
			break;
		case '?':
			r_cons_clear00 (core->cons);
			r_cons_printf (core->cons, "\nVe: Visual Eval help:\n\n"
			" q     - quit menu\n"
			" j/k   - down/up keys\n"
			" h/b   - go back\n"
			" $     - same as ?$ - show values of vars\n"
			" e/' ' - edit/toggle current variable\n"
			" E     - edit variable with 'cfg.editor' (vi?)\n"
			" +/-   - increase/decrease numeric value (* and /, too)\n"
			" :     - enter command\n");
			r_cons_flush (core->cons);
			r_cons_any_key (core->cons, NULL);
			break;
		case ':':
			r_cons_show_cursor (core->cons, true);
			r_cons_set_raw (core->cons, false);
			{
				char *cmd = prompt (core, ":> ", NULL);
				r_core_cmd (core, cmd, 1);
				free (cmd);
			}
			r_cons_set_raw (core->cons, true);
			r_cons_show_cursor (core->cons, false);
			r_cons_any_key (core->cons, NULL);
			r_cons_clear00 (core->cons);
			continue;
		}
	}
}

R_API void r_core_visual_mounts(RCore *core) {
	RList *list = NULL;
	RFSRoot *fsroot = NULL;
	RListIter *iter;
	RFSFile *file;
	RFSPartition *part;
	int i, ch, option, mode, partition, dir, delta = 7;
	char *str, path[4096], buf[1024], *root = NULL;
	const char *n, *p;

	dir = partition = option = mode = 0;
	for (;;) {
		/* Clear */
		r_cons_clear00 (core->cons);

		/* Show */
		if (mode == 0) {
			if (list) {
				r_list_free (list);
				list = NULL;
			}
			r_cons_printf (core->cons, "Press '/' to navigate the root filesystem.\nPartitions:\n\n");
			n = r_fs_partition_type_get (partition);
			list = r_fs_partitions (core->fs, n, 0);
			i = 0;
			if (list) {
				r_list_foreach (list, iter, part) {
					if ((option-delta <= i) && (i <= option+delta)) {
						if (option == i) {
							r_cons_printf (core->cons, " > ");
						} else {
							r_cons_printf (core->cons, "   ");
						}
						r_cons_printf (core->cons, "%d %02x 0x%010"PFMT64x" 0x%010"PFMT64x"\n",
								part->number, part->type,
								part->start, part->start+part->length);
					}
					i++;
				}
				r_list_free (list);
				list = NULL;
			} else {
				r_cons_printf (core->cons, "Cannot read partition\n");
			}
		} else if (mode == 1) {
			r_cons_printf (core->cons, "Types:\n\n");
			for (i = 0; ; i++) {
				n = r_fs_partition_type_get (i);
				if (!n) {
					break;
				}
				r_cons_printf (core->cons, "%s%s\n", (i==partition)?" > ":"   ", n);
			}
		} else if (mode == 3) {
			i = 0;
			r_cons_printf (core->cons, "Mountpoints:\n\n");
			r_list_foreach (core->fs->roots, iter, fsroot) {
				if (fsroot && (option-delta <= i) && (i <= option+delta)) {
					r_cons_printf (core->cons, "%s %s\n", (option == i)?" > ":"   ",
							fsroot->path);
				}
				i++;
			}
		} else {
			if (root) {
				list = r_fs_dir (core->fs, path);
				if (list) {
					r_cons_printf (core->cons, "%s:\n\n", path);
					i = 0;
					r_list_foreach (list, iter, file) {
						if ((dir-delta <= i) && (i <= dir+delta)) {
							r_cons_printf (core->cons, "%s%c %s\n", (dir == i)?" > ":"   ",
									file->type, file->name);
						}
						i++;
					}
					r_cons_print (core->cons, "\n");
					r_list_free (list);
					list = NULL;
				} else {
					r_cons_printf (core->cons, "Cannot open '%s' directory\n", root);
				}
			} else {
				r_cons_printf (core->cons, "Root undefined\n");
			}
		}
		if (mode==2) {
			r_str_trim_path (path);
			size_t n = strlen (path);
			str = path + n;
			snprintf (str, sizeof (path) - n, "/");
			list = r_fs_dir (core->fs, path);
			file = r_list_get_n (list, dir);
			if (file && file->type != 'd') {
				r_core_cmdf (core, "px @ 0x%" PFMT64x "!64", file->off);
			}
			r_list_free (list);
			list = NULL;
			*str='\0';
		}
		r_cons_flush (core->cons);

		/* Ask for option */
		ch = r_cons_readchar (core->cons);
		if (ch == -1 || ch == 4) {
			free (root);
			return;
		}
		ch = r_cons_arrow_to_hjkl (core->cons, ch);
		switch (ch) {
			case '/':
				R_FREE (root);
				root = strdup ("/");
				strncpy (path, root, sizeof (path)-1);
				mode = 2;
				break;
			case 'l':
			case '\r':
			case '\n':
				if (mode == 0) {
					n = r_fs_partition_type_get (partition);
					list = r_fs_partitions (core->fs, n, 0);
					if (!list) {
						r_cons_printf (core->cons, "Unknown partition\n");
						r_cons_any_key (core->cons, NULL);
						r_cons_flush (core->cons);
						break;
					}
					part = r_list_get_n (list, option);
					if (!part) {
						r_cons_printf (core->cons, "Unknown partition\n");
						r_cons_any_key (core->cons, NULL);
						r_cons_flush (core->cons);
						break;
					}
					p = r_fs_partition_type (n, part->type);
					if (p) {
						if (r_fs_mount (core->fs, p, "/root", part->start)) {
							free (root);
							root = strdup ("/root");
							strncpy (path, root, sizeof (path)-1);
							mode = 2;
						} else {
							r_cons_printf (core->cons, "Cannot mount partition\n");
							r_cons_flush (core->cons);
							r_cons_any_key (core->cons, NULL);
						}
					} else {
						r_cons_printf (core->cons, "Unknown partition type\n");
						r_cons_flush (core->cons);
						r_cons_any_key (core->cons, NULL);
					}
					r_list_free (list);
					list = NULL;
				} else if (mode == 2) {
					r_str_trim_path (path);
					size_t n = strlen (path);
					snprintf (path + n, sizeof (path) - n, "/");
					list = r_fs_dir (core->fs, path);
					file = r_list_get_n (list, dir);
					if (file) {
						if (file->type == 'd') {
							n = strlen (path);
							snprintf (path + n, sizeof (path) - n, "%s", file->name);
							r_str_trim_path (path);
							if (root && strncmp (root, path, strlen (root) - 1)) {
								strncpy (path, root, sizeof (path) - 1);
							}
						} else {
							r_core_cmdf (core, "s 0x%"PFMT64x, file->off);
							r_fs_umount (core->fs, root);
							free (root);
							return;
						}
					} else {
						r_cons_printf (core->cons, "Unknown file\n");
						r_cons_flush (core->cons);
						r_cons_any_key (core->cons, NULL);
					}

				} else if (mode == 3) {
					fsroot = r_list_get_n (core->fs->roots, option);
					if (fsroot) {
						root = strdup (fsroot->path);
						strncpy (path, root, sizeof (path)-1);
					}
					mode = 2;
				}
				dir = partition = option = 0;
				break;
			case 'k':
				if (mode == 0 || mode == 3) {
					if (option > 0) {
						option--;
					}
				} else if (mode == 1) {
					if (partition > 0) {
						partition--;
					}
				} else {
					if (dir > 0) {
						dir--;
					}
				}
				break;
			case 'j':
				if (mode == 0) {
					n = r_fs_partition_type_get (partition);
					if (!n) {
						partition = 0;
						n = r_fs_partition_type_get (0);
					}
					if (n) {
						list = r_fs_partitions (core->fs, n, 0);
					}
					if (option < r_list_length (list) - 1) {
						option++;
					}
				} else if (mode == 1) {
					partition++;
				} else if (mode == 3) {
					if (option < r_list_length (core->fs->roots) - 1) {
						option++;
					}
				} else {
					list = r_fs_dir (core->fs, path);
					if (dir < r_list_length (list) - 1) {
						dir++;
					}
				}
				break;
			case 't':
				mode = 1;
				break;
			case 'h':
				if (mode == 2) {
					if (!root) {
						mode = 0;
					} else if (strcmp (path, root)) {
						strcat (path, "/..");
						r_str_trim_path (path);
					} else {
						r_fs_umount (core->fs, root);
						mode = 0;
					}
				} else if (mode == 1) {
					mode = 0;
				} else {
					return;
				}
				break;
			case 'Q':
			case 'q':
				if (mode == 2 && root) {
					r_fs_umount (core->fs, root);
					mode = 0;
				} else {
					return;
				}
				break;
			case 'g':
				if (mode == 2) {
					r_str_trim_path (path);
					size_t n = strlen (path);
					str = path + n;
					snprintf (str, sizeof (path) - n, "/");
					list = r_fs_dir (core->fs, path);
					file = r_list_get_n (list, dir);
					if (file && root) {
						n = strlen (path);
						snprintf (path + n, sizeof (path) - n, "%s", file->name);
						r_str_trim_path (path);
						if (strncmp (root, path, strlen (root) - 1)) {
							strncpy (path, root, sizeof (path) - 1);
						}
						file = r_fs_open (core->fs, path, false);
						if (file) {
							r_fs_read (core->fs, file, 0, file->size);
							r_cons_show_cursor (core->cons, true);
							r_cons_set_raw (core->cons, false);
							r_line_set_prompt (core->cons->line, "Dump path (ej: /tmp/file): ");
							r_cons_fgets (core->cons, buf, sizeof (buf), 0, 0);
							r_cons_set_raw (core->cons, true);
							r_cons_show_cursor (core->cons, false);
							r_file_dump (buf, file->data, file->size, 0);
							r_fs_close (core->fs, file);
							r_cons_printf (core->cons, "Done\n");
						} else {
							r_cons_printf (core->cons, "Cannot dump file\n");
						}
					} else {
						r_cons_printf (core->cons, "Cannot dump file\n");
					}
					r_cons_flush (core->cons);
					r_cons_any_key (core->cons, NULL);
					*str='\0';
				}
				break;
			case 'm':
				mode = 3;
				option = 0;
				break;
			case '?':
				r_cons_clear00 (core->cons);
				r_cons_printf (core->cons, "\nVM: Visual Mount points help:\n\n");
				r_cons_printf (core->cons, " q     - go back or quit menu\n");
				r_cons_printf (core->cons, " j/k   - down/up keys\n");
				r_cons_printf (core->cons, " h/l   - forward/go keys\n");
				r_cons_printf (core->cons, " t     - choose partition type\n");
				r_cons_printf (core->cons, " g     - dump file\n");
				r_cons_printf (core->cons, " m     - show mountpoints\n");
				r_cons_printf (core->cons, " :     - enter command\n");
				r_cons_printf (core->cons, " ?     - show this help\n");
				r_cons_flush (core->cons);
				r_cons_any_key (core->cons, NULL);
				break;
			case ':':
				r_cons_show_cursor (core->cons, true);
				r_cons_set_raw (core->cons, false);
				r_line_set_prompt (core->cons->line, ":> ");
				r_cons_fgets (core->cons, buf, sizeof (buf), 0, 0);
				r_cons_set_raw (core->cons, true);
				r_cons_show_cursor (core->cons, false);
				r_core_cmd (core, buf, 1);
				r_cons_any_key (core->cons, NULL);
				break;
		}
	}
}

// helper
static void function_rename(RCore *core, ut64 addr, const char *name) {
	RListIter *iter;
	RAnalFunction *fcn;

	r_list_foreach (core->anal->fcns, iter, fcn) {
		if (fcn->addr == addr) {
			r_flag_unset_name (core->flags, fcn->name);
			free (fcn->name);
			fcn->name = strdup (name);
			r_flag_set (core->flags, name, addr, r_anal_function_size_from_entry (fcn));
			break;
		}
	}
}

static void variable_rename(RCore *core, ut64 addr, int vindex, const char *name) {
	RAnalFunction* fcn = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
	ut64 a_tmp = core->addr;
	int i = 0;
	RListIter *iter;
	RList *list = r_anal_var_all_list (core->anal, fcn);
	RAnalVar* var;

	r_list_foreach (list, iter, var) {
		if (i == vindex) {
			r_core_seek (core, addr, false);
			free (r_core_cmd_strf (core, "afvn %s %s", name, var->name));
			r_core_seek (core, a_tmp, false);
			break;
		}
		i++;
	}
	r_list_free (list);
}

static void variable_set_type(RCore *core, ut64 addr, int vindex, const char *type) {
	RAnalFunction* fcn = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
	RList *list = r_anal_var_all_list (core->anal, fcn);
	RListIter *iter;
	RAnalVar* var;

	r_list_foreach (list, iter, var) {
		if (vindex == 0) {
			r_anal_var_set_type (var, type);
			break;
		}
		vindex--;
	}
	r_list_free (list);
}

// In visual mode, display function list
static ut64 var_functions_show(RCore *core, int idx, int show, int cols) {
	int wdelta = (idx > 5)? idx - 5: 0;
	char *var_functions;
	ut64 seek = core->addr;
	ut64 addr = core->addr;
	RAnalFunction *fcn;
	int window, i = 0, print_full_func;
	RListIter *iter;

	// Adjust the windows size automaticaly
	(void)r_cons_get_size (core->cons, &window);
	window -= 8; // Size of printed things
	bool color = r_config_get_i (core->config, "scr.color");
	const char *color_addr = core->cons->context->pal.addr;
	const char *color_fcn = core->cons->context->pal.fname;
	r_cons_newline (core->cons);

	r_list_foreach (core->anal->fcns, iter, fcn) {
		print_full_func = true;
		if (i >= wdelta) {
			if (i > window + wdelta - 1) {
				break;
			}
			if (idx == i) {
				addr = fcn->addr;
			}
			if (show) {
				char *tmp;
				if (color) {
					var_functions = r_str_newf ("%c%c %s0x%08"PFMT64x Color_RESET" %4"PFMT64d" %s%s"Color_RESET"",
							(seek == fcn->addr)?'>':' ',
							(idx==i)?'*':' ',
							color_addr, fcn->addr, r_anal_function_realsize (fcn),
							color_fcn, fcn->name);
				} else {
					var_functions = r_str_newf ("%c%c 0x%08"PFMT64x" %4"PFMT64d" %s",
							(seek == fcn->addr)?'>':' ',
							(idx==i)?'*':' ',
							fcn->addr, r_anal_function_realsize (fcn), fcn->name);
				}
				if (var_functions) {
					if (!core->cons->show_vals) {
						int fun_len = r_str_ansi_len (var_functions);
						int columns = fun_len > cols ? cols - 2 : cols;
						tmp = r_str_ansi_crop (var_functions, 0, 0, columns, window);
						if (r_str_ansi_len (tmp) < fun_len) {
							r_cons_printf (core->cons, "%s..%s\n", tmp, Color_RESET);
							print_full_func = false;
						}
						r_free (tmp);
					}
					if (print_full_func) {
						r_cons_println (core->cons, var_functions);
					}
					r_free (var_functions);
				}
			}
		}
		i++;
	}
	return addr;
}

// In visual mode, display the variables.
static ut64 var_variables_show(RCore* core, int idx, int *vindex, int show, int cols) {
	int i = 0;
	int window, wdelta = (idx > 5) ? idx - 5 : 0;
	const ut64 addr = var_functions_show (core, idx, 0, cols);
	RAnalFunction* fcn = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
	RListIter *iter;
	if (!fcn) {
		return UT64_MAX;
	}
	RList *list = r_anal_var_all_list (core->anal, fcn);
	RAnalVar* var;
	// Adjust the window size automatically.
	(void)r_cons_get_size (core->cons, &window);
	window -= 8;  // Size of printed things.

	// A new line so this looks reasonable.
	r_cons_newline (core->cons);

	int llen = r_list_length (list);
	if (*vindex >= llen) {
		*vindex = llen - 1;
	}

	r_list_foreach (list, iter, var) {
		if (i > window + wdelta) {
			r_cons_printf (core->cons, "...\n");
			break;
		}
		if (show) {
			switch (var->kind & 0xff) {
			case 'r':
				{
					RRegItem *r = r_reg_index_get (core->anal->reg, var->delta);
					if (!r) {
						R_LOG_ERROR ("Register not found for %d var delta", var->delta);
						break;
					}
					r_cons_printf (core->cons, "%sarg %s %s @ %s\n",
							i == *vindex ? "* ":"  ",
							var->type, var->name,
							r->name);
				}
				break;
			case 'b':
				r_cons_printf (core->cons, "%s%s %s %s @ %s%s0x%x\n",
						i == *vindex ? "* ":"  ",
						var->delta < 0? "var": "arg",
						var->type, var->name,
						r_reg_alias_getname (core->anal->reg, R_REG_ALIAS_BP),
						(var->kind == 'v')?"-":"+",
						var->delta);
				break;
			case 's':
				r_cons_printf (core->cons, "%s%s %s %s @ %s%s0x%x\n",
						i == *vindex ? "* ":"  ",
						var->delta < 0? "var": "arg",
						var->type, var->name,
						r_reg_alias_getname (core->anal->reg, R_REG_ALIAS_SP),
						(var->kind == 'v')?"-":"+",
						var->delta + fcn->maxstack);
				break;
			}
		}
		i++;
	}
	r_list_free (list);
	return addr;
}

static R_TH_LOCAL int level = 0;
static R_TH_LOCAL st64 delta = 0;
static R_TH_LOCAL int option = 0;
static R_TH_LOCAL int variable_option = 0;
static R_TH_LOCAL int printMode = 0;
static R_TH_LOCAL bool selectPanel = false;
#define lastPrintMode 6
static const char *printCmds[lastPrintMode] = {
	"pdr", "pd $r", "afi", "pdsf", "pdc", "pdr"
};

static void r_core_visual_anal_refresh_column(RCore *core, int colpos) {
	const ut64 addr = (level != 0 && level != 1)
		? core->addr
		: var_functions_show (core, option, 0, colpos);
	// RAnalFunction* fcn = r_anal_get_fcn_in(core->anal, addr, R_ANAL_FCN_TYPE_NULL);
	int h, w = r_cons_get_size (core->cons, &h);
	// int sz = (fcn)? R_MIN (r_anal_function_size (fcn), h * 15) : 16; // max instr is 15 bytes.

	const char *cmd;
	if (printMode > 0 && printMode < lastPrintMode) {
		cmd = printCmds[printMode];
	} else {
		cmd = printCmds[printMode = 0];
	}
	char *cmdf = r_str_newf ("%s @ 0x%"PFMT64x, cmd, addr + delta);
	if (!cmdf) {
		return;
	}
	char *output = r_core_cmd_str (core, cmdf);
	if (output) {
		// 'h - 2' because we have two new lines in r_cons_printf
		char *out = r_str_ansi_crop (output, 0, 0, w - colpos, h - 2);
		r_cons_printf (core->cons, "\n%s\n", out);
		free (out);
		R_FREE (output);
	}
	free (cmdf);
}

static RCoreHelpMessage help_visual_anal_actions = {
	"functions:", "Add, Modify, Delete, Xrefs Calls Vars",
	"variables:", "Add, Modify, Delete",
	NULL
};

static RCoreHelpMessage help_visual_anal_keys = {
	"j/k",	"select next/prev item; scroll disasm column",
	"J/K",	"scroll next/prev by page",
	"b/h",	"functions analysis (level 0)",
	"v/l",	"variables analysis (level 1)",
	"c",	"calls/xref analysis (level 2)",
	"q/Q",	"go back one level or quit",
	"Space/Enter",	"quit",
	"p/P",	"switch next/prev print mode",
	"x/X",	"see xrefs to the selected function",
	"Tab",	"disasm column scrolling",
	"!",	"run `afls` to sort all functions by address",
	".",	"seek to current function address",
	":",	"run r2 commands",
	"_",	"hud mode, same as `s $(afl~...)`",
	NULL
};

static R_TH_LOCAL int coldelta = 0;
static ut64 r_core_visual_anal_refresh(RCore *core) {
	R_RETURN_VAL_IF_FAIL (core, UT64_MAX);
	RCons *cons = core->cons;
	ut64 addr;
	RStrBuf *buf;
	bool color = r_config_get_i (core->config, "scr.color");
	int h, cols = r_cons_get_size (cons, &h);
	addr = core->addr;
	cols -= 50;
	int maxcols = 60 + coldelta;
	if (cols > maxcols) {
		cols = maxcols;
	}

	r_cons_clear00 (core->cons);
	r_core_visual_anal_refresh_column (core, cols);
	if (cols > 30) {
		r_cons_column (core->cons, cols);
	}
	switch (level) {
	// Show functions list help in visual mode
	case 0:
		buf = r_strbuf_new ("");
		if (color) {
			r_cons_print (core->cons, core->cons->context->pal.prompt);
		}
		r_cons_gotoxy (cons, 0, 0);
		r_cons_print (cons, ".-- functions -------------------------------.");
		r_cons_gotoxy (cons, 20, 0);
		if (selectPanel) {
			r_cons_printf (cons, "[%s]", printCmds[printMode]);
		} else {
			r_cons_printf (cons, " %s ", printCmds[printMode]);
		}
		if (color) {
			r_cons_print (cons, Color_RESET);
		}
		r_cons_newline (cons);
		r_cons_print (cons, "| (a)nalyze   (-)delete (xX)refs (jk)scroll  |\n");
		r_cons_print (cons, "| (r)ename    (c)alls   (d)efine (tab)disasm |\n");
		r_cons_print (cons, "| (d)efine    (v)ars    (?)help  (:)shell    |\n");
		r_cons_print (cons, "| (s)ignature (_)hud    (q)quit  (;)comment  |\n");
		r_cons_printf (cons, "'-------------------------------------------'");
		addr = var_functions_show (core, option, 1, cols);
		break;
	case 1:
		buf = r_strbuf_new ("");
		if (color) {
			r_cons_print (cons, core->cons->context->pal.prompt);
		}
		r_cons_print (cons, ".-[ variables ]---------------------------.");
		if (color) {
			r_cons_print (cons, "\n" Color_RESET);
		}
		r_cons_gotoxy (cons, 22, 0);
		r_cons_printf (core->cons, " 0x%08"PFMT64x" \n", addr);
		r_cons_print (core->cons, "| (a)dd     (x)refs       (r)rename       |\n");
		r_cons_print (core->cons, "| (t)ype    (g)o          (-)delete       |\n");
		r_cons_print (core->cons, "| (q)uit    (s)signature  (q)uit          |\n");
		r_cons_printf (core->cons, "'-----------------------------------------'");
		char *drained = r_strbuf_drain (buf);
		r_cons_printf (core->cons, "%s", drained);
		addr = var_variables_show (core, option, &variable_option, 1, cols);
		free (drained);
		// var_index_show (core->anal, fcn, addr, option);
		break;
	case 2:
		r_cons_printf (core->cons, "Press 'q' to quit call refs\n");
		if (color) {
			r_cons_print (core->cons, core->cons->context->pal.prompt);
		}
		r_cons_printf (core->cons, "-[ calls ]----------------------- 0x%08"PFMT64x" (TODO)\n", addr);
		if (color) {
			r_cons_print (core->cons, "\n" Color_RESET);
		}
		// TODO: filter only the callrefs. but we cant grep here
		char *output = r_core_cmd_strf (core, "afi @ 0x%08"PFMT64x, addr);
		if (output) {
			// 'h - 2' because we have two new lines in r_cons_printf
			if (core->cons->show_vals) {
				r_cons_printf (core->cons, "\n%s\n", output);
				R_FREE (output);
			} else {
				char *out = r_str_ansi_crop (output, 0, 0, cols, h - 2);
				r_cons_printf (core->cons, "\n%s\n", out);
				free (out);
				R_FREE (output);
			}
		}
		break;
	default:
		// assert
		break;
	}
	r_cons_flush (core->cons);
	return addr;
}

static void r_core_visual_anal_refresh_oneshot(RCore *core) {
	r_core_task_enqueue_oneshot (&core->tasks, (RCoreTaskOneShot) r_core_visual_anal_refresh, core);
}

static void r_core_visual_debugtraces_help(RCore *core) {
	r_cons_clear00 (core->cons);
	r_cons_printf (core->cons,
			"vbd: Visual Browse Debugtraces:\n\n"
			" q     - quit the bit editor\n"
			" Q     - Quit (jump into the disasm view)\n"
			" j/k   - Select next/previous trace\n"
			" :     - enter command\n");
	r_cons_flush (core->cons);
	r_cons_any_key (core->cons, NULL);
}

R_API void r_core_visual_debugtraces(RCore *core, const char *input) {
	int i, delta = 0;
	for (;;) {
		char *trace_addr_str = r_core_cmd_strf (core, "dtdq %d", delta);
		ut64 trace_addr = r_num_get (NULL, trace_addr_str);
		free (trace_addr_str);
		r_cons_printf (core->cons, "[0x%08"PFMT64x"]> %d dbg.trace\n", trace_addr, delta);
		for (i = 0; i < delta; i++) {
			r_core_cmdf (core, ".dte %d", i);
		}
		r_core_cmd0 (core, "x 64@r:SP");
		r_core_cmd0 (core, "dri");
		// limit by rows here
		// int rows = r_cons_get_size (core->cons, NULL);
		r_core_cmdf (core, "dtd %d", delta);
		r_cons_visual_flush (core->cons);
		signed char ch;
		if (input && *input) {
			ch = *input;
			input++;
		} else {
			ch = r_cons_readchar (core->cons);
		}
		if (ch == 4 || (int)ch == -1) {
			if (level == 0) {
				return;
			}
			level--;
			continue;
		}
		ch = r_cons_arrow_to_hjkl (core->cons, ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 'Q': // tab
			{
				ut64 oseek = core->addr;
				core->vmode = false;
				r_core_seek (core, trace_addr, true);
				r_core_visual (core, "");
				r_core_seek (core, oseek, true);
			}
			break;
		case 'q': // "vbdq"
			return;
		case ']': // "vbd]"
			r_config_set_i (core->config, "hex.cols", r_config_get_i (core->config, "hex.cols") + 1);
			break;
		case '[': // "vbd]"
			r_config_set_i (core->config, "hex.cols", r_config_get_i (core->config, "hex.cols") - 1);
			break;
		case 'J': // "vbdJ"
			delta += 10;
			break;
		case 'K': // "vbdK"
			delta -= 10;
			if (delta < 0) {
				delta = 0;
			}
		case 'j': // "vbdj"
			delta++;
			break;
		case 'k':
			delta--;
			if (delta < 0) {
				delta = 0;
			}
			break;
		case ':': // "vbd:"
			r_core_visual_prompt (core);
			r_cons_any_key (core->cons, NULL);
			break;
		case '?': // "vbd?"
			r_core_visual_debugtraces_help (core);
			break;
		}
	}
}

static char *__prompt(RCore *core, const char *msg, void *p) {
	char res[128];
	r_cons_show_cursor (core->cons, true);
	r_cons_set_raw (core->cons, false);
	r_line_set_prompt (core->cons->line, msg);
	res[0] = 0;
	if (!r_cons_fgets (core->cons, res, sizeof (res), 0, NULL)) {
		res[0] = 0;
	}
	return strdup (res);
}

static void addVar(RCore *core, int ch, const char *msg) {
	char *src = __prompt (core, msg, NULL);
	char *name = __prompt (core, "Variable Name: ", NULL);
	char *type = __prompt (core, "Type of Variable (int32_t): ", NULL);
	char *cmd = r_str_newf ("afv%c %s %s %s", ch, src, name, type);
	r_str_trim (cmd);
	r_core_cmd0 (core, cmd);
	free (cmd);
	free (src);
	free (name);
	free (type);
}

/* Like emenu but for real */
R_API void r_core_visual_anal(RCore *core, const char *input) {
	char old[218];
	int nfcns, ch, _option = 0;

	RConsEvent olde = core->cons->event_resize;
	void *olde_user = core->cons->event_data;
	ut64 addr = core->addr;

	core->cons->event_resize = NULL; // avoid running old event with new data
	core->cons->event_data = core;
	core->cons->event_resize = (RConsEvent) r_core_visual_anal_refresh_oneshot;

	level = 0;
	coldelta = 0;
	bool asmbytes = r_config_get_b (core->config, "asm.bytes");
	r_config_set_b (core->config, "asm.bytes", false);
	for (;;) {
		nfcns = r_list_length (core->anal->fcns);
		addr = r_core_visual_anal_refresh (core);
		if (input && *input) {
			ch = *input;
			input++;
		} else {
			r_cons_set_raw (core->cons, true);
			ch = r_cons_readchar (core->cons);
		}
		if (ch == 4 || ch == -1) {
			if (level == 0) {
				goto beach;
			}
			level--;
			continue;
		}
		ch = r_cons_arrow_to_hjkl (core->cons, ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case '[':
			coldelta--;
			// core->cons->show_vals = true;
			break;
		case ']':
			coldelta++;
			core->cons->show_vals = false;
			break;
		case ';':
			visual_add_comment (core, addr);
			break;
		case '?':
			r_cons_clear00 (core->cons);
			RStrBuf *rsb = r_strbuf_new ("");
			r_core_visual_append_help (core, rsb, "Funcs/Vars Visual Analysis Mode (Vv) Help", (const char *[]){ NULL });
			r_core_visual_append_help (core, rsb, "Actions Supported", help_visual_anal_actions);
			r_core_visual_append_help (core, rsb, "Keys", help_visual_anal_keys);
			r_cons_less_str (core->cons, r_strbuf_get (rsb), "?");
			r_strbuf_free (rsb);
			break;
		case 9:
			selectPanel = !selectPanel;
			if (!selectPanel) {
				delta = 0;
				printMode = 0;
			}
			break;
		case ':':
			{
				ut64 orig = core->addr;
				r_core_seek (core, addr, false);
				while (r_core_visual_prompt (core));
				r_core_seek (core, orig, false);
			}
			continue;
		case '/':
			r_core_cmd0 (core, "?i highlight;e scr.highlight=`yp`");
			break;
		case 'a':
			switch (level) {
			case 0:
				r_core_cmd0 (core, "af-$$;af"); // reanalize
				break;
			case 1:
				{
					eprintf ("Select variable source ('r'egister, 's'tackptr or 'b'aseptr): ");
					int type = r_cons_readchar (core->cons);
					switch (type) {
					case 'r':
						addVar (core, type, "Source Register Name: ");
						break;
					case 's':
						addVar (core, type, "BP Relative Delta: ");
						break;
					case 'b':
						addVar (core, type, "SP Relative Delta: ");
						break;
					}
				}
				break;
			}
			break;
		case 'r':
			{
				RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->addr, 0);
				if (!f) {
					r_cons_any_key (core->cons, "No function found in the current offset");
					break;
				}
				switch (level) {
				case 1:
					r_cons_show_cursor (core->cons, true);
					r_cons_set_raw (core->cons, false);
					r_line_set_prompt (core->cons->line, "New name: ");
					if (r_cons_fgets (core->cons, old, sizeof (old), 0, NULL)) {
						if (*old) {
							variable_rename (core, addr, variable_option, old);
						}
					}
					break;
				default:
					r_line_set_prompt (core->cons->line, "New name: ");
					if (r_cons_fgets (core->cons, old, sizeof (old), 0, NULL)) {
						if (*old) {
							function_rename (core, addr, old);
						}
					}
					break;
				}
				r_cons_set_raw (core->cons, true);
				r_cons_show_cursor (core->cons, false);
			}
			break;
		case 'R': // "VvR"
			r_core_cmd0 (core, "ecn");
			break;
		case 't':
			if (level == 1) {
				r_cons_show_cursor (core->cons, true);
				r_cons_set_raw (core->cons, false);
				r_line_set_prompt (core->cons->line, "New type: ");
				if (r_cons_fgets (core->cons, old, sizeof (old), 0, NULL)) {
					if (*old) {
						variable_set_type (core, addr, variable_option, old);
					}
				}
				r_cons_set_raw (core->cons, true);
				r_cons_show_cursor (core->cons, false);
			}
			break;
		case '.':
			delta = 0;
			break;
		case 'p':
			printMode ++;
			break;
		case 'P':
			if (printMode == 0) {
				printMode = lastPrintMode;
			} else {
				printMode --;
			}
			break;
		case 'd': // "Vvd"
			r_core_visual_define (core, "", 0);
			break;
		case '-': // "Vv-"
			if (level == 0) {
				r_core_cmdf (core, "af-0x%"PFMT64x, addr);
			}
			break;
		case 'x': // "Vvx"
			r_core_visual_refs (core, false, true);
			break;
		case 'X': // "VvX"
			r_core_visual_refs (core, true, true);
			break;
		case 's': // "Vvs"
			{
				RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->addr, 0);
				if (f) {
					r_core_cmdf (core, "afs!@0x%08"PFMT64x, addr);
				} else {
					r_cons_any_key (core->cons, "No function found in the current offset");
				}
			}
			break;
		case 'c':
			level = 2;
			break;
		case 'v':
			level = 1;
			variable_option = 0;
			break;
		case '_':
			{
				r_core_cmd0 (core, "s $(afl~...)");
				int n = 0;
				RListIter *iter;
				RAnalFunction *fcn;
				r_list_foreach (core->anal->fcns, iter, fcn) {
					if (fcn->addr == core->addr) {
						option = n;
						break;
					}
					n ++;
				}
			}
			break;
		case 'j':
			if (selectPanel) {
				printMode = 1;
				delta += 16;
			} else {
				delta = 0;
				if (level == 1) {
					variable_option++;
				} else {
					option++;
					if (option >= nfcns) {
						option--;
					}
				}
			}
			break;
		case '!':
			// TODO: use aflsn/aflsb/aflss/...
			{
			static R_TH_LOCAL int sortMode = 0;
			const char *sortModes[4] = { "aflsa", "aflss", "aflsb", "aflsn" };
			r_core_cmd0 (core, sortModes[sortMode%4]);
			sortMode++;
			}
			break;
		case 'k':
			if (selectPanel) {
				printMode = 1;
				delta -= 16;
			} else {
				delta = 0;
				switch (level) {
				case 1:
					variable_option = (variable_option <= 0)? 0: variable_option-1;
					break;
				default:
					option = (option <= 0)? 0: option-1;
					break;
				}
			}

			break;
		case 'J':
			if (selectPanel) {
				printMode = 1;
				delta += 40;
			} else {
				int rows = 0;
				r_cons_get_size (core->cons, &rows);
				option += (rows - 5);
				if (option >= nfcns) {
					option = nfcns - 1;
				}
			}
			break;
		case 'K':
			if (selectPanel) {
				printMode = 1;
				delta -= 40;
			} else {
				int rows = 0;
				r_cons_get_size (core->cons, &rows);
				option -= (rows - 5);
				if (option < 0) {
					option = 0;
				}
			}
			break;
		case 'g':
			{
			r_core_visual_showcursor (core, true);
			r_core_visual_offset (core);        // change the seek to selected offset
			RListIter *iter;		   // change the current option to selected seek
			RAnalFunction *fcn;
			int i = 0;
			r_list_foreach (core->anal->fcns, iter, fcn) {
				if (core->addr == fcn->addr) {
					option = i;
				}
				i++;
			}
			r_core_visual_showcursor (core, false);
			}
			break;
		case 'G':
			r_core_seek (core, addr, SEEK_SET);
			goto beach;
		case ' ':
		case '\r':
		case '\n':
			level = 0;
			r_core_seek (core, addr, SEEK_SET);
			goto beach;
		case 'l':
			level = 1;
			_option = option;
			break;
		case 'h':
		case 'b': // back
			level = 0;
			option = _option;
			break;
		case 'Q':
		case 'q':
			if (level == 0) {
				goto beach;
			}
			level--;
			break;
		}
	}
beach:
	core->cons->event_resize = NULL; // avoid running old event with new data
	core->cons->event_data = olde_user;
	core->cons->event_resize = olde;
	level = 0;
	r_config_set_b (core->config, "asm.bytes", asmbytes);
}

struct seek_flag_offset_t {
	ut64 offset;
	ut64 *next;
	bool is_next;
	bool found;
};

static bool seek_flag_offset(RFlagItem *fi, void *user) {
	struct seek_flag_offset_t *u = (struct seek_flag_offset_t *)user;
	if (u->is_next) {
		if (fi->addr < *u->next && fi->addr > u->offset) {
			*u->next = fi->addr;
			u->found = true;
		}
	} else {
		if (fi->addr >= *u->next && fi->addr <  u->offset) {
			*u->next = fi->addr;
			u->found = true;
		}
	}
	return true;
}

R_API void r_core_seek_next(RCore *core, const char *type) {
	RListIter *iter;
	ut64 next = UT64_MAX;
	bool found = false;
	if (strstr (type, "opc")) {
		RAnalOp aop;
		if (r_anal_op (core->anal, &aop, core->addr, core->block, core->blocksize, R_ARCH_OP_MASK_BASIC)) {
			next = core->addr + aop.size;
			found = true;
		} else {
			R_LOG_ERROR ("Invalid opcode");
		}
	} else if (strstr (type, "fun")) {
		RAnalFunction *fcni;
		r_list_foreach (core->anal->fcns, iter, fcni) {
			if (fcni->addr < next && fcni->addr > core->addr) {
				next = fcni->addr;
				found = true;
			}
		}
	} else if (strstr (type, "hit")) {
		const char *pfx = r_config_get (core->config, "search.prefix");
		struct seek_flag_offset_t u = { .offset = core->addr, .next = &next, .is_next = true, .found = false };
		r_flag_foreach_prefix (core->flags, pfx, -1, seek_flag_offset, &u);
		found = u.found;
	} else { // flags
		struct seek_flag_offset_t u = { .offset = core->addr, .next = &next, .is_next = true, .found = false };
		r_flag_foreach (core->flags, seek_flag_offset, &u);
		found = u.found;
	}
	if (found == true) {
		r_core_seek (core, next, true);
	}
}

R_API void r_core_seek_previous(RCore *core, const char *type) {
	RListIter *iter;
	ut64 next = 0;
	bool found = false;
	if (strstr (type, "opc")) {
		R_LOG_WARN ("TODO: r_core_seek_previous (opc)");
	} else if (strstr (type, "fun")) {
		RAnalFunction *fcni;
		r_list_foreach (core->anal->fcns, iter, fcni) {
			if (fcni->addr > next && fcni->addr < core->addr) {
				next = fcni->addr;
				found = true;
			}
		}
	} else if (strstr (type, "hit")) {
		const char *pfx = r_config_get (core->config, "search.prefix");
		struct seek_flag_offset_t u = { .offset = core->addr, .next = &next, .is_next = false, .found = false };
		r_flag_foreach_prefix (core->flags, pfx, -1, seek_flag_offset, &u);
		found = u.found;
	} else { // flags
		struct seek_flag_offset_t u = { .offset = core->addr, .next = &next, .is_next = false, .found = false };
		r_flag_foreach (core->flags, seek_flag_offset, &u);
		found = u.found;
	}
	if (found) {
		r_core_seek (core, next, true);
	}
}

// define the data at offset according to the type (byte, word...) n times
static void define_data_ntimes(RCore *core, ut64 off, int times, int type, int typesize) {
	int i = 0;
	if (times < 1) {
		times = 1;
	}
	ut64 amount = ((ut64)typesize) * times;
	r_meta_del (core->anal, R_META_TYPE_ANY, off, amount);
	for (i = 0; i < times; i++, off += typesize) {
		r_meta_set (core->anal, R_META_TYPE_DATA, off, type, "");
	}
}

static bool isDisasmPrint(int mode) {
	return (mode == 1 || mode == 2);
}

static void handleHints(RCore *core) {
	//TODO extend for more anal hints
	int i = 0;
	char ch[64] = {0};
	const char *lines[] = { "[dh]- Define anal hint:"
		," b [16,32,64]     set bits hint"
		, NULL};
	for (i = 0; lines[i]; i++) {
		r_cons_fill_line (core->cons);
		r_cons_printf (core->cons, "\r%s\n", lines[i]);
	}
	r_cons_flush (core->cons);
	r_line_set_prompt (core->cons->line, "anal hint: ");
	if (r_cons_fgets (core->cons, ch, sizeof (ch), 0, NULL) > 0) {
		switch (ch[0]) {
		case 'b':
			{
				char *arg = ch + 1;
				r_str_trim (arg);
				int bits = atoi (arg);
				if (bits == 8 || bits == 16 || bits == 32 || bits == 64) {
					r_anal_hint_set_bits (core->anal, core->addr, bits);
				}
			}
			break;
		default:
			break;
		}
	}
}

R_API void r_core_visual_define(RCore *core, const char *args, int distance) {
	RCoreVisual *v = &core->visual;
	int plen = core->blocksize;
	ut64 off = core->addr;
	int i, h = 0, n, ch, ntotal = 0;
	ut8 *p = core->block;
	int rep = -1;
	char *name;
	int delta = 0;
	if (core->print->cur_enabled) {
		int cur = core->print->cur;
		if (core->print->ocur != -1) {
			plen = R_ABS (core->print->cur - core->print->ocur) + 1;
			if (core->print->ocur<cur) {
				cur = core->print->ocur;
			}
		}
		off += cur;
		p += cur;
	}
	(void) r_cons_get_size (core->cons, &h);
	h -= 19;
	if (h < 0) {
		h = 0;
		r_cons_clear00 (core->cons);
	} else {
		r_cons_gotoxy (core->cons, 0, 3);
	}
	const char *lines[] = { ""
		,"[Vd]- Define current block as:"
		," $    define flag size"
		," 1    edit bits"
		," >    small integer (shift right by 1)"
		," a    assembly"
		," b    as byte (1 byte)"
		," B    define half word (16 bit, 2 byte size)"
		," c    as code (unset any data / string / format) in here"
		," C    define flag color (fc)"
		," d    set as data"
		," e    end of function"
		," E    esil debugger (aev)"
		," f    analyze function"
		," F    format"
		," h    define hint (for half-word, see 'B')"
		," i    (ahi) immediate base (b(in), o(ct), d(ec), h(ex), s(tr))"
		," I    (ahi1) immediate base (b(in), o(ct), d(ec), h(ex), s(tr))"
		," j    merge down (join this and next functions)"
		," k    merge up (join this and previous function)"
		," h    define anal hint"
		," m    manpage for current call"
		," n    rename flag or variable referenced by the instruction in cursor"
		," N    edit function signature (afs!)"
		," o    opcode string"
		," r    rename function"
		," s    set string"
		," S    set strings in current block"
		," t    set opcode type via aht hints (call, nop, jump, ...)"
		," u    undefine metadata here"
		," v    rename variable at offset that matches some hex digits"
		," x    find xrefs to current address (./r)"
		," X    find cross references /r"
		," w    set as 32bit word"
		," W    set as 64bit word"
		," q    quit menu"
		," z    zone flag"
		, NULL};
	for (i = 0; lines[i]; i++) {
		r_cons_fill_line (core->cons);
		r_cons_printf (core->cons, "\r%s\n", lines[i]);
	}
	r_cons_flush (core->cons);
	int wordsize = 0;
	// get ESC+char, return 'hjkl' char
repeat:
	if (*args) {
		ch = *args;
		args++;
	} else {
		ch = r_cons_arrow_to_hjkl (core->cons, r_cons_readchar (core->cons));
	}

onemoretime:
	wordsize = 4;
	switch (ch) {
	case 'N':
		r_core_cmdf (core, "afs! @ 0x%08"PFMT64x, off);
		break;
	case 'F':
		{
			char cmd[128];
			r_cons_show_cursor (core->cons, true);
			r_core_cmd0 (core, "pf?");
			r_cons_flush (core->cons);
			r_line_set_prompt (core->cons->line, "format: ");
			strcpy (cmd, "Cf 0 ");
			if (r_cons_fgets (core->cons, cmd + 5, sizeof (cmd) - 5, 0, NULL) > 0) {
				r_core_cmdf (core, "'@0x%08"PFMT64x"'%s", off, cmd);
				r_cons_set_raw (core->cons, true);
				r_cons_show_cursor (core->cons, false);
			}
		}
		break;
	case '1':
		r_core_visual_bit_editor (core);
		break;
	case 't':
	case 'o':
		{
			char str[128];
			r_cons_show_cursor (core->cons, true);
			r_line_set_prompt (core->cons->line, ch == 't'? "type: ": "opstr: ");
			if (r_cons_fgets (core->cons, str, sizeof (str), 0, NULL) > 0) {
				r_core_cmdf (core, "'@0x%08"PFMT64x"'ah%c %s", off, ch, str);
			}
		}
		break;
	case 'x':
		r_core_cmd0 (core, "/r $$");
		break;
	case 'i':
		{
			char str[128];
			r_cons_show_cursor (core->cons, true);
			r_line_set_prompt (core->cons->line, "immbase: ");
			if (r_cons_fgets (core->cons, str, sizeof (str), 0, NULL) > 0) {
				r_core_cmdf (core, "'@0x%08"PFMT64x"'ahi %s", off, str);
			}
		}
		break;
	case 'I':
		{
			char str[128];
			r_cons_show_cursor (core->cons, true);
			r_line_set_prompt (core->cons->line, "immbase: ");
			if (r_cons_fgets (core->cons, str, sizeof (str), 0, NULL) > 0) {
				r_core_cmdf (core, "'@0x%08"PFMT64x"'ahi1 %s", off, str);
			}
		}
		break;
	case 'a':
		r_core_visual_asm (core, off);
		break;
	case 'b':
		if (plen != core->blocksize) {
			rep = plen / 2;
		}
		wordsize = 1;
		define_data_ntimes (core, off, rep, R_BYTE_DATA, wordsize);
		break;
	case 'B': // "VdB"
		if (plen != core->blocksize) {
			rep = plen / 2;
		}
		wordsize = 2;
		define_data_ntimes (core, off, rep, R_WORD_DATA, wordsize);
		break;
	case 'w':
		if (plen != core->blocksize) {
			rep = plen / 4;
		}
		wordsize = 4;
		define_data_ntimes (core, off, rep, R_DWORD_DATA, wordsize);
		break;
	case 'W':
		if (plen != core->blocksize) {
			rep = plen / 8;
		}
		wordsize = 8;
		define_data_ntimes (core, off, rep, R_QWORD_DATA, wordsize);
		break;
	case 'm':
		{
			char *man = NULL;
			/* check for manpage */
			RAnalOp *op = r_core_anal_op (core, off, R_ARCH_OP_MASK_BASIC);
			if (op) {
				if (op->jump != UT64_MAX) {
					RFlagItem *item = r_flag_get_in (core->flags, op->jump);
					if (item) {
						const char *ptr = r_str_lchr (item->name, '.');
						if (ptr) {
							man = strdup (ptr + 1);
						}
					}
				}
				r_anal_op_free (op);
			}
			if (man) {
				char *p = strstr (man, "INODE");
				if (p) {
					*p = 0;
				}
				r_cons_clear (core->cons);
				r_cons_flush (core->cons);
				r_sys_cmdf ("man %s", man);
				free (man);
			}
			r_cons_any_key (core->cons, NULL);
		}
		break;
	case 'n':
	{
		RAnalOp op;
		char *q = NULL;
		ut64 tgt_addr = UT64_MAX;
		if (!isDisasmPrint (v->printidx)) {
			break;
		}
		// TODO: get the aligned instruction even if the cursor is in the middle of it.
		int rc = r_anal_op (core->anal, &op, off,
			core->block + off - core->addr, 32, R_ARCH_OP_MASK_BASIC);
		if (rc < 1) {
			R_LOG_ERROR ("analyzing opcode at 0x%08"PFMT64x, off);
		} else {
			tgt_addr = op.jump != UT64_MAX ? op.jump : op.ptr;
			RAnalVar *var = r_anal_get_used_function_var (core->anal, op.addr);
			if (var) {
	//			q = r_str_newf ("?i Rename variable %s to;afvn %s `yp`", op.var->name, op.var->name);
				r_strf_var (prompt, 128, "New variable name for '%s': ", var->name);
				char *newname = r_cons_input (core->cons, prompt);
				if (newname && *newname) {
					r_anal_var_rename (var, newname, true);
					free (newname);
				}
			} else if (tgt_addr != UT64_MAX) {
				RAnalFunction *fcn = r_anal_get_function_at (core->anal, tgt_addr);
				RFlagItem *f = r_flag_get_in (core->flags, tgt_addr);
				if (fcn) {
					q = r_str_newf ("?i Rename function %s to;afn `yp` 0x%"PFMT64x,
						fcn->name, tgt_addr);
				} else if (f) {
					q = r_str_newf ("?i Rename flag %s to;fr %s `yp`",
						f->name, f->name);
				} else {
					q = r_str_newf ("?i Create flag at 0x%"PFMT64x" named;f `yp` @ 0x%"PFMT64x,
						tgt_addr, tgt_addr);
				}
			}
		}

		if (q) {
			r_core_cmd0 (core, q);
			free (q);
		} else {
			R_LOG_INFO ("Sorry. No flags or variables referenced here");
			r_cons_any_key (core->cons, NULL);
		}
		r_anal_op_fini (&op);
		break;
	}
	case 'C':
		{
			RFlagItem *item = r_flag_get_in (core->flags, off);
			if (item) {
				char cmd[128];
				r_cons_show_cursor (core->cons, true);
				r_cons_flush (core->cons);
				r_line_set_prompt (core->cons->line, "color: ");
				if (r_cons_fgets (core->cons, cmd, sizeof (cmd), 0, NULL) > 0) {
					r_flag_item_set_color (core->flags, item, cmd);
					r_cons_set_raw (core->cons, true);
					r_cons_show_cursor (core->cons, false);
				}
			} else {
				R_LOG_INFO ("Sorry. No flag here");
				r_cons_any_key (core->cons, NULL);
			}
		}
		break;
	case '$':
		{
			RFlagItem *item = r_flag_get_in (core->flags, off);
			if (item) {
				char cmd[128];
				r_cons_printf (core->cons, "Current flag size is: %" PFMT64d "\n", item->size);
				r_cons_show_cursor (core->cons, true);
				r_cons_flush (core->cons);
				r_line_set_prompt (core->cons->line, "new size: ");
				if (r_cons_fgets (core->cons, cmd, sizeof (cmd), 0, NULL) > 0) {
					item->size = r_num_math (core->num, cmd);
					r_cons_set_raw (core->cons, 1);
					r_cons_show_cursor (core->cons, false);
				}
			} else {
				R_LOG_INFO ("Sorry. No flag here");
				r_cons_any_key (core->cons, NULL);
			}
		}
		break;
	case 'e':
		// set function size
		{
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, off, 0);
		if (!fcn) {
			fcn = r_anal_get_fcn_in (core->anal, core->addr, 0);
		}
		if (fcn) {
			RAnalOp op;
			ut64 size;
			if (r_anal_op (core->anal, &op, off, core->block+delta,
					core->blocksize-delta, R_ARCH_OP_MASK_BASIC)) {
				size = off - fcn->addr + op.size;
				r_anal_function_resize (fcn, size);
			}
		}
		}
		break;
	case 'E':
		r_core_visual_esil (core, ""); // "aev"
		break;
	case 'j':
		r_core_cmdf (core, "afm $$+$F @0x%08"PFMT64x, off);
		break;
	case 'k':
		R_LOG_TODO ("merge up");
		r_cons_any_key (core->cons, NULL);
		break;
	// very weak and incomplete
	case 'h': // "Vdh"
		handleHints (core);
		break;
	case 'r': // "Vdr"
		{
			RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->addr, 0);
			if (f) {
				r_core_cmdf (core, "cls;pd 10 @ 0x%08"PFMT64x, off);
				r_core_cmdf (core, "?i new function name;afn `yp` @ 0x%08"PFMT64x, off);
			} else {
				r_cons_any_key (core->cons, "No function found in the current offset");
			}
		}
		break;
	case 'z': // "Vdz"
		r_core_cmdf (core, "?i zone name;fz `yp` @ 0x%08"PFMT64x, off);
		break;
	case 'X': // "VdX"
		R_LOG_INFO ("Finding cross-references to 0x%08"PFMT64x, off);
		r_core_cmdf (core, "./r 0x%08"PFMT64x" @ $S", off);
		break;
	case 'S':
		{
		int i, j;
		bool is_wide = false;
		do {
			n = r_str_nlen_w ((const char *)p + ntotal,
					plen - ntotal) + 1;
			if (n < 2) {
				break;
			}
			name = malloc (n + 10);
			strcpy (name, "str.");
			for (i = 0, j = 0; i < n; i++, j++) {
				name[4 + i] = p[j + ntotal];
				if (!p[j + ntotal]) {
					break;
				}
				if (!p[j + 1 + ntotal])  {
					//check if is still wide
					if (j + 3 + ntotal < n) {
						if (p[j + 3]) {
							break;
						}
					}
					is_wide = true;
					j++;
				}
			}
			name[4 + n] = '\0';
			if (is_wide) {
				r_meta_set (core->anal, R_META_TYPE_STRING,
							off + ntotal, (n * 2) + ntotal,
							(const char *) name + 4);
			} else {
				r_meta_set (core->anal, R_META_TYPE_STRING,
							off + ntotal, n + ntotal,
							(const char *) name + 4);
			}
			r_name_filter (name, n + 10);
			r_flag_set (core->flags, name, off + ntotal, n);
			free (name);
			if (is_wide) {
				ntotal += n * 2 - 1;
			} else {
				ntotal += n;
			}
		} while (ntotal < plen);
		wordsize = ntotal;
		}
		break;
	case 's':
		{
		int i, j;
		bool is_wide = false;
		if (core->print->ocur != -1) {
			n = plen;
		} else {
			n = r_str_nlen_w ((const char*)p, plen) + 1;
		}
		name = malloc (n + 10);
		if (!name) {
			break;
		}
		strcpy (name, "str.");
		for (i = 0, j = 0; i < n; i++, j++) {
			name[4 + i] = p[j];
			if (!p[j + 1]) {
				break;
			}
			if (!p[j + 1]) {
				if (j + 3 < n) {
					if (p[j + 3]) {
						break;
					}
				}
				is_wide = true;
				j++;
			}
		}
		name[4 + n] = '\0';
		// handle wide strings
		// memcpy (name + 4, (const char *)p, n);
		if (is_wide) {
			r_meta_set (core->anal, R_META_TYPE_STRING, off,
						n * 2, (const char *) name + 4);
		} else {
			r_meta_set (core->anal, R_META_TYPE_STRING, off,
						n, (const char *) name + 4);
		}
		r_name_filter (name, n + 10);
		r_flag_set (core->flags, name, off, n);
		wordsize = n;
		free (name);
		}
		break;
	case 'd': // TODO: check
		r_meta_del (core->anal, R_META_TYPE_ANY, off, plen);
		r_meta_set (core->anal, R_META_TYPE_DATA, off, plen, "");
		break;
	case 'c': // TODO: check
		r_meta_del (core->anal, R_META_TYPE_ANY, off, plen);
		r_meta_set (core->anal, R_META_TYPE_CODE, off, plen, "");
		break;
	case 'u':
		r_core_anal_undefine (core, off);
		break;
	case 'f':
		{
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->addr, 0);
			if (fcn) {
				r_anal_function_resize (fcn, core->addr - fcn->addr);
			}
			r_cons_break_push (core->cons, NULL, NULL);
			r_core_cmdf_at (core, off, "af");
			r_cons_break_pop (core->cons);
		}
		break;
	case 'v':
	{
		ut64 N;
		char *endptr = NULL;
		char *end_off = r_cons_input (core->cons, "Last hexadecimal digits of instruction: ");
		if (end_off) {
			N = strtoull (end_off, &endptr, 16);
		}
		if (!end_off || end_off == endptr) {
			R_LOG_ERROR ("Invalid numeric input");
			r_cons_any_key (core->cons, NULL);
			free (end_off);
			break;
		}
		free (end_off);

		ut64 incr = 0x10;
		ut64 tmp_N = N >> 4;
		while (tmp_N > 0) {
			tmp_N = tmp_N >> 4;
			incr = incr << 4;
		}
		ut64 mask = incr - 1;

		ut64 start_off = (off & ~mask) ^ N;
		if ((off & mask) > N) {
			if (start_off > incr) {
				start_off -= incr;
			} else {
				start_off = N;
			}
		}

		ut64 try_off;
		RAnalOp *op = NULL;
		RAnalVar *var = NULL;
		for (try_off = start_off; try_off < start_off + incr*16; try_off += incr) {
			r_anal_op_free (op);
			op = r_core_anal_op (core, try_off, R_ARCH_OP_MASK_ALL);
			if (!op) {
				break;
			}
			var = r_anal_get_used_function_var (core->anal, op->addr);
			if (var) {
				break;
			}
		}

		if (var) {
			r_strf_var (promptstr, 128, "New variable name for '%s': ", var->name);
			char *newname = r_cons_input (core->cons, promptstr);
			if (newname && *newname) {
				r_anal_var_rename (var, newname, true);
				free (newname);
			}
		} else {
			R_LOG_ERROR ("Cannot find instruction with a variable");
			r_cons_any_key (core->cons, NULL);
		}

		r_anal_op_free (op);
		break;
	}
	case 'Q':
	case 'q':
	default:
		if (isdigit (ch)) {
			if (rep < 0) {
				rep = 0;
			}
			rep = rep * 10 + atoi ((char *)&ch);
			goto repeat;
		}
		break;
	}
	if (distance > 0) {
		distance--;
		off += wordsize;
		goto onemoretime;
	}
}

R_API void r_core_visual_colors(RCore *core) {
	char *color = NULL;
	char cstr[32];
	char preview_cmd[128] = "pd $r";
	int ch, opt = 0, oopt = -1;
	char *rgb_xxx_fmt = "rgb:%02x%02x%02x";
	const char *k;
	bool show_help = false;
	RColor rcolor, zcolor = { 0 };
	r_cons_show_cursor (core->cons, false);
	RCons *cons = core->cons;
	rcolor = r_cons_pal_get_i (cons, opt);
	for (;;) {
		r_cons_clear (core->cons);
		r_cons_gotoxy (core->cons, 0, 0);
		k = r_cons_pal_get_name (cons, opt);
		if (!k) {
			opt = 0;
			k = r_cons_pal_get_name (cons, opt);
		}
		color = r_str_newf (rgb_xxx_fmt, rcolor.r, rcolor.g, rcolor.b);
		if (rcolor.r2 || rcolor.g2 || rcolor.b2) {
			color = r_str_append (color, " ");
			color = r_str_appendf (color, rgb_xxx_fmt, rcolor.r2, rcolor.g2, rcolor.b2);
			rcolor.a = ALPHA_FGBG;
		} else {
			rcolor.a = ALPHA_FG;
		}
		r_cons_rgb_str (cons, cstr, sizeof (cstr), &rcolor);
		char *esc = strchr (cstr + 1, '\x1b');
		char *curtheme = r_core_get_theme (core);

		if (show_help) {
			// r_cons_printf (core->cons, ".-[q hjkl e] Color theme editor ---------------------------------------------.\n");
			r_cons_printf (core->cons, ".-[q]-[hjkl] Color theme editor ---------------------------------------------.\n");
			r_cons_printf (core->cons, "| Use '.' to randomize current color and '@' to randomize palette            |\n");
			r_cons_printf (core->cons, "| Press '"Color_RED"rR"Color_GREEN"gG"Color_BLUE"bB"Color_RESET
				"' or '"Color_BGRED"eE"Color_BGGREEN"fF"Color_BGBLUE"vV"Color_RESET
				"' to change foreground/background color           |\n");
			r_cons_printf (core->cons, "| Export colorscheme with command 'ec* > filename'                           |\n");
			r_cons_printf (core->cons, "| Preview command: '%s' - Press 'c' to change it.                         |\n", preview_cmd);
			r_cons_printf (core->cons, "`----------------------------------------------------------------------------'\n");
		} else {
			r_cons_printf (core->cons, "--[?]-[hjkl] Color theme editor [rRgGbB]----- ---  --   -\n\n");
		}
		r_cons_printf (core->cons, "  eco %s # left/right keys to change colors theme\n", r_str_get_fail (curtheme, "default"));
		/// r_cons_printf (core->cons, "  Item (%s)  - Use 'jk' or up/down arrow keys to change element\n", k);
		r_cons_printf (core->cons, "  ec %s %s # %d (\\x1b%.*s)\n",
			k, color, atoi (cstr + 7), esc ? (int)(esc - cstr - 1) : (int)strlen (cstr + 1), cstr+1);
		if (esc) {
			r_cons_printf (cons, " (\\x1b%s)", esc + 1);
		}

		if (memcmp (&rcolor, &zcolor, sizeof (rcolor)) != 0) {
			r_core_cmdf (core, "ec %s %s", k, color);
		}
		char * res = r_core_cmd_str (core, preview_cmd);
		int h, w = r_cons_get_size (core->cons, &h);
		if (w > 80) {
			char *body = r_str_ansi_crop (res, 0, 0, w - 10, h - 12);
			if (body) {
				r_cons_printf (core->cons, "\n%s", body);
				free (body);
			}
		} else {
			r_cons_printf (core->cons, "\n%s", res);
		}
		r_cons_flush (cons);
		ch = r_cons_readchar (core->cons);
		ch = r_cons_arrow_to_hjkl (core->cons, ch);
		switch (ch) {
#define CASE_RGB(x,X,y) \
	case x:if ((y) > 0x00) { (y)--; } break;\
	case X:if ((y) < 0xff) { (y)++; } break;
		CASE_RGB ('R', 'r', rcolor.r);
		CASE_RGB ('G', 'g', rcolor.g);
		CASE_RGB ('B', 'b', rcolor.b);
		CASE_RGB ('E', 'e', rcolor.r2);
		CASE_RGB ('F', 'f', rcolor.g2);
		CASE_RGB ('V', 'v', rcolor.b2);
		case 'Q':
		case 'q':
			free (res);
			free (color);
			return;
		case 'd':
			r_core_visual_define (core, "", 0);
			break;
		case '!':
			r_core_cmd0 (core, "ed");
			break;
		case 'k':
			opt--;
			break;
		case 'j':
			opt++;
			break;
		case 'l':
			r_core_cmd0 (core, "ecn");
			oopt = -1;
			break;
		case 'h':
			r_core_cmd0 (core, "ecp");
			oopt = -1;
			break;
		case 'K':
			opt = 0;
			break;
		case 'J':
			opt = r_cons_pal_len () - 1;
			break;
		case '@':
			r_core_cmd_call (core, "ecr");
			break;
		case 'p':
		case 'P':
			if (r_str_startswith (preview_cmd, "pd")) {
				strcpy (preview_cmd, "px $r*16");
			} else {
				strcpy (preview_cmd, "pd $r");
			}
			break;
		case '?':
			show_help = !show_help;
			break;
		case ':':
			r_core_visual_prompt_input (core);
			break;
		case ',':
			r_cons_pal_random (core->cons);
			break;
		case '.':
			rcolor.r = r_num_rand (0xff);
			rcolor.g = r_num_rand (0xff);
			rcolor.b = r_num_rand (0xff);
			break;
		case 'c':
			r_line_set_prompt (core->cons->line, "Preview command> ");
			r_cons_show_cursor (core->cons, true);
			{
				char newcmd[128] = {0};
				r_cons_fgets (core->cons, newcmd, sizeof (newcmd), 0, NULL);
				if (*newcmd) {
					r_str_ncpy (preview_cmd, newcmd, sizeof (preview_cmd) - 1);
				}
			}
			r_cons_show_cursor (core->cons, false);
		}
		opt = R_DIM (opt, 0, r_cons_pal_len () - 1);
		if (opt != oopt) {
			rcolor = r_cons_pal_get_i (core->cons, opt);
			oopt = opt;
		}
		free (res);
	}
}
