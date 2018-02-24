/* radare - LGPL - Copyright 2009-2018 - pancake */

#include "r_core.h"
#include "r_util.h"

#include <string.h>

#define MAX_FORMAT 3

enum {
	R_BYTE_DATA  = 1,
	R_WORD_DATA  = 2,
	R_DWORD_DATA = 4,
	R_QWORD_DATA = 8
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

// TODO: move this helper into r_cons
static char *prompt(const char *str, const char *txt) {
	char cmd[1024];
	char *res = NULL;
	char *oprompt = strdup (r_cons_singleton()->line->prompt);
	r_cons_show_cursor (true);
	if (txt && *txt) {
		free (r_cons_singleton ()->line->contents);
		r_cons_singleton ()->line->contents = strdup (txt);
	} else {
		free (r_cons_singleton ()->line->contents);
		r_cons_singleton ()->line->contents = NULL;
	}
	*cmd = '\0';
	r_line_set_prompt (str);
	if (r_cons_fgets (cmd, sizeof (cmd) - 1, 0, NULL) < 0) {
		*cmd = '\0';
	}
	//line[strlen(line)-1]='\0';
	if (*cmd) {
		res = strdup (cmd);
	}
	r_line_set_prompt (oprompt);
	free (oprompt);
	free (r_cons_singleton ()->line->contents);
	r_cons_singleton ()->line->contents = NULL;
	return res;
}

static inline char *getformat (RCoreVisualTypes *vt, const char *k) {
	return sdb_get (vt->core->anal->sdb_types,
		sdb_fmt (0, "type.%s", k), 0);
}

static char *colorize_asm_string(RCore *core, const char *buf_asm, int optype) {
	char *tmp, *spacer = NULL;
	char *source = (char*)buf_asm;
	bool use_color = core->print->flags & R_PRINT_FLAGS_COLOR;
	const char *color_num = core->cons->pal.num;
	const char *color_reg = core->cons->pal.reg;

	if (!use_color) {
		return strdup (source);
	}
	// workaround dummy colorizer in case of paired commands (tms320 & friends)
	spacer = strstr (source, "||");
	if (spacer) {
		char *scol1, *s1 = r_str_ndup (source, spacer - source);
		char *scol2, *s2 = strdup (spacer + 2);
		scol1 = r_print_colorize_opcode (core->print, s1, color_reg, color_num, false);
		free (s1);
		scol2 = r_print_colorize_opcode (core->print, s2, color_reg, color_num, false);
		free (s2);
		if (!scol1) {
			scol1 = strdup ("");
		}
		if (!scol2) {
			scol2 = strdup ("");
		}
		source = malloc (strlen(scol1) + strlen(scol2) + 2 + 1); // reuse source variable
		sprintf (source, "%s||%s", scol1, scol2);
		free (scol1);
		free (scol2);
		return source;
	}
	char *res = strdup("");
	res = r_str_append (res, r_print_color_op_type (core->print, optype));
	tmp = r_print_colorize_opcode (core->print, source, color_reg, color_num, false);
	res = r_str_append (res, tmp);
	free (tmp);
	return res;
}

static int rotate_nibble (const ut8 b, int dir) {
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
	while (w && n--) {
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

static void showreg(RAnalEsil *esil, const char *rn, const char *desc) {
	ut64 nm = 0;
	int sz = 0;
	r_cons_printf ("%s 0x%08"PFMT64x" (%d) ; %s\n", rn, nm, sz, desc);
}

R_API bool r_core_visual_esil(RCore *core) {
	const int nbits = sizeof (ut64) * 8;
	int analopType;
	char *word = NULL;
	int x = 0;
	RAnalEsil *esil;
	RAsmOp asmop;
	RAnalOp analop;
	ut8 buf[sizeof (ut64)];

	if (core->blocksize < sizeof (ut64)) {
		return false;
	}
	memcpy (buf, core->block, sizeof (ut64));
	esil = r_anal_esil_new (20, 0);
	esil->anal = core->anal;
	r_anal_esil_set_pc (esil, core->offset);
	for (;;) {
		r_cons_clear00 ();
		// bool use_color = core->print->flags & R_PRINT_FLAGS_COLOR;
		(void) r_asm_disassemble (core->assembler, &asmop, buf, sizeof (ut64));
		analop.type = -1;
		(void)r_anal_op (core->anal, &analop, core->offset, buf, sizeof (ut64));
		analopType = analop.type & R_ANAL_OP_TYPE_MASK;
		r_cons_printf ("r2's esil debugger:\n\n");
		r_cons_printf ("pos: %d\n", x);
		{
			char *res = r_print_hexpair (core->print, asmop.buf_hex, -1);
			r_cons_printf ("hex: %s\n"Color_RESET, res);
			free (res);
		}
		{
			char *op = colorize_asm_string (core, asmop.buf_asm, analopType);
			r_cons_printf (Color_RESET"asm: %s\n"Color_RESET, op);
			free (op);
		}
		{
			const char *expr = r_strbuf_get (&analop.esil);
			r_cons_printf (Color_RESET"esil: %s\n"Color_RESET, expr);
			int wp = wordpos (expr, x);
			char *pas = strdup (r_str_pad (' ', wp ? wp + 1: 0));
			int wp2 = wordpos (expr, x + 1);
			free (word);
			word = r_str_ndup (expr + (wp?(wp+1):0), (wp2 - wp) - (wp?1:0));
			if (wp == wp2) {
				// x --;
				eprintf ("Done\n");
				x = 0;
				r_sys_sleep (1);
				free (pas);
				continue;
			}
			const char *pad = r_str_pad ('-', wp2 - ((wp > 0)? wp + 1: 0));
			r_cons_printf (Color_RESET"      %s%s\n"Color_RESET, pas, pad);
			free (pas);
			// free (pad);
		}
		r_cons_printf ("esil regs:\n");
		showreg (esil, "$$", "address");
		showreg (esil, "$z", "zero");
		showreg (esil, "$b", "borrow");
		showreg (esil, "$c", "carry");
		showreg (esil, "$o", "overflow");
		showreg (esil, "$p", "parity");
		showreg (esil, "$r", "regsize");
		showreg (esil, "$s", "sign");
		showreg (esil, "$d", "delay");
		showreg (esil, "$j", "jump");

		r_cons_printf ("regs:\n");
		{
			char *r = r_core_cmd_str (core, "dr=");
			r_cons_printf ("%s", r);
			free (r);
		}
		r_cons_printf ("esil stack:\n");
		r_anal_esil_dumpstack (esil);
		r_anal_op_fini (&analop);
		r_cons_newline ();
		r_cons_visual_flush ();

		int ch = r_cons_readchar ();
		if (ch == -1 || ch == 4) {
			break;
		}
		ch = r_cons_arrow_to_hjkl (ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 'Q':
		case 'q':
			goto beach;
		case 's':
			eprintf ("step ((%s))\n", word);
			r_sys_usleep (500);
			x = R_MIN (x + 1, nbits - 1);
			r_anal_esil_runword (esil, word);
			break;
		case 'S':
			eprintf ("esil step over :D\n");
			r_sys_usleep (500);
			break;
		case 'r':
		case 'h':
			x = 0; //R_MAX (x - 1, 0);
			break;
		case '?':
			r_cons_clear00 ();
			r_cons_printf (
			"Vd1?: Visual Bit Editor Help:\n\n"
			" q     - quit the bit editor\n"
			" h/r   - reset / go back (reinitialize esil state)\n"
			" s     - esil step in\n"
			" j/k   - toggle bit value (same as space key)\n"
			" :     - enter command\n");
			r_cons_flush ();
			r_cons_any_key (NULL);
			break;
		case ':': // TODO: move this into a separate helper function
			{
			char cmd[1024];
			r_cons_show_cursor (true);
			r_cons_set_raw (0);
			cmd[0]='\0';
			r_line_set_prompt (":> ");
			if (r_cons_fgets (cmd, sizeof (cmd)-1, 0, NULL) < 0) {
				cmd[0] = '\0';
			}
			r_core_cmd (core, cmd, 1);
			r_cons_set_raw (1);
			r_cons_show_cursor (false);
			if (cmd[0]) {
				r_cons_any_key (NULL);
			}
			r_cons_clear ();
			}
			break;
		}
	}
beach:
	r_anal_esil_free (esil);
	free (word);
	return true;
}

static bool edit_bits (RCore *core) {
	const int nbits = sizeof (ut64) * 8;
	bool colorBits = false;
	int analopType;
	int i, j, x = 0;
	RAsmOp asmop;
	RAnalOp analop;
	ut8 buf[sizeof (ut64)];

	if (core->blocksize < sizeof (ut64)) {
		return false;
	}
	memcpy (buf, core->block, sizeof (ut64));
	for (;;) {
		r_cons_clear00 ();
		bool use_color = core->print->flags & R_PRINT_FLAGS_COLOR;
		(void) r_asm_disassemble (core->assembler, &asmop, buf, sizeof (ut64));
		analop.type = -1;
		(void)r_anal_op (core->anal, &analop, core->offset, buf, sizeof (ut64));
		analopType = analop.type & R_ANAL_OP_TYPE_MASK;
		r_cons_printf ("r2's bit editor:\n\n");
		{
			char *res = r_print_hexpair (core->print, asmop.buf_hex, -1);
			r_cons_printf ("hex: %s\n"Color_RESET, res);
			free (res);
		}
		r_cons_printf ("len: %d\n", asmop.size);
		{
			ut32 word = (x % 32);
			r_cons_printf ("shift: >> %d << %d\n", word, (asmop.size * 8) - word - 1);
		}
		{
			char *op = colorize_asm_string (core, asmop.buf_asm, analopType);
			r_cons_printf (Color_RESET"asm: %s\n"Color_RESET, op);
			free (op);
		}
		r_cons_printf (Color_RESET"esl: %s\n"Color_RESET, r_strbuf_get (&analop.esil));
		r_anal_op_fini (&analop);
		r_cons_printf ("chr:");
		for (i = 0; i < 8; i++) {
			const ut8 *byte = buf + i;
			char ch = IS_PRINTABLE (*byte)? *byte: '?';
			if (i == 4) {
				r_cons_printf (" |");
			}
			if (use_color) {
				r_cons_printf (" %5s'%s%c"Color_RESET"'", " ", core->cons->pal.btext, ch);
			} else {
				r_cons_printf (" %5s'%c'", " ", ch);
			}
		}
		r_cons_printf ("\ndec:");
		for (i = 0; i < 8; i++) {
			const ut8 *byte = buf + i;
			if (i == 4) {
				r_cons_printf (" |");
			}
			r_cons_printf (" %8d", *byte);
		}
		r_cons_printf ("\nhex:");
		for (i = 0; i < 8; i++) {
			const ut8 *byte = buf + i;
			if (i == 4) {
				r_cons_printf (" |");
			}
			r_cons_printf ("     0x%02x", *byte);
		}
		r_cons_printf ("\nbit: ");
		if (use_color) {
			r_cons_print (core->cons->pal.b0x7f);
			colorBits = true;
		}
		for (i = 0; i < 8; i++) {
			ut8 *byte = buf + i;
			if (i == 4) {
				r_cons_printf ("| ");
			}
			if (colorBits && i >= asmop.size) {
				r_cons_print (Color_RESET);
				colorBits = false;
			}
			for (j = 0; j < 8; j++) {
				bool bit = R_BIT_CHK (byte, 7 - j);
				r_cons_printf ("%d", bit? 1: 0);
			}
			r_cons_print (" ");
		}
		r_cons_newline ();
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
		r_cons_printf ("pos: %s\n", str_pos);
		r_cons_newline ();
		r_cons_visual_flush ();

		int ch = r_cons_readchar ();
		if (ch == -1 || ch == 4) {
			break;
		}
		ch = r_cons_arrow_to_hjkl (ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 'Q':
		case 'q':
			return false;
		case 'j':
		case 'k':
		case ' ':
			//togglebit();
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
			buf[x/8] = rotate_nibble (buf [(x / 8)], -1);
			break;
		case '<':
			buf[x/8] = rotate_nibble (buf [(x / 8)], 1);
			break;
		case 'i':
			{
				r_line_set_prompt ("> ");
				const char *line = r_line_readline ();
				ut64 num = r_num_math (core->num, line);
				if (num || (!num && *line == '0')) {
					buf[x/8] = num;
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
		case '+':
			buf[(x/8)]++;
			break;
		case '-':
			buf[(x/8)]--;
			break;
		case 'h':
			x = R_MAX (x - 1, 0);
			break;
		case 'l':
			x = R_MIN (x + 1, nbits - 1);
			break;
		case '?':
			r_cons_clear00 ();
			r_cons_printf (
			"Vd1?: Visual Bit Editor Help:\n\n"
			" q     - quit the bit editor\n"
			" R     - randomize color palette\n"
			" j/k   - toggle bit value (same as space key)\n"
			" h/l   - select next/previous bit\n"
			" +/-   - increment or decrement byte value\n"
			" </>   - rotate left/right byte value\n"
			" i     - insert numeric value of byte\n"
			" :     - enter command\n");
			r_cons_flush ();
			r_cons_any_key (NULL);
			break;
		case ':': // TODO: move this into a separate helper function
			{
			char cmd[1024];
			r_cons_show_cursor (true);
			r_cons_set_raw (0);
			cmd[0]='\0';
			r_line_set_prompt (":> ");
			if (r_cons_fgets (cmd, sizeof (cmd)-1, 0, NULL) < 0) {
				cmd[0] = '\0';
			}
			r_core_cmd (core, cmd, 1);
			r_cons_set_raw (1);
			r_cons_show_cursor (false);
			if (cmd[0]) {
				r_cons_any_key (NULL);
			}
			r_cons_clear ();
			}
			break;
		}
	}
	return true;
}

// belongs to r_core_visual_types
static int sdbforcb (void *p, const char *k, const char *v) {
	const char *pre = " ";
	RCoreVisualTypes *vt = (RCoreVisualTypes*)p;
	bool use_color = vt->core->print->flags & R_PRINT_FLAGS_COLOR;
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
				if (use_color && *pre=='>')
					r_cons_printf (Color_YELLOW" %s %s  %s\n"
						Color_RESET, pre, k+strlen (s), v);
				else
					r_cons_printf (" %s %s  %s\n",
						pre, k+strlen (s), v);
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
					if (use_color && *pre=='>') {
						r_cons_printf (Color_YELLOW" %s %s  %s\n"
							Color_RESET, pre, k, v);
					} else {
						r_cons_printf (" %s %s  %s\n",
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
			if (use_color && *pre=='>') {
				r_cons_printf (Color_YELLOW" %s pf %3s   %s\n"
					Color_RESET,pre, fmt, k);
			} else {
				r_cons_printf (" %s pf %3s   %s\n",
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
				r_cons_printf (Color_YELLOW" %s %s\n"Color_RESET,
					(vt->t_idx == vt->t_ctr)?
					">":" ", k);
			} else {
				r_cons_printf (" %s %s\n",
					(vt->t_idx == vt->t_ctr)?
					">":" ", k);
			}
		}
		vt->t_ctr ++;
	}
        return 1;
}

R_API int r_core_visual_types(RCore *core) {
	RCoreVisualTypes vt = {core, 0, 0};
	int i, j, ch;
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
		NULL
	};
	bool use_color = core->print->flags & R_PRINT_FLAGS_COLOR;
	for (j = i = 0; i < R_FLAG_SPACES_MAX; i++) {
		if (core->flags->spaces[i]) {
			j = 1;
		}
	}
	if (j == 0) {
		menu = 1;
	}
	for (;;) {
		r_cons_clear00 ();
		for (i = 0; opts[i]; i++) {
			const char *fmt = use_color
				? (h_opt == i)
					? Color_BGREEN"[%s] "Color_RESET
					: Color_GREEN" %s  "Color_RESET
				: (h_opt == i)
					? "[%s] "
					: " %s  ";
			r_cons_printf (fmt, opts[i]);
		}
		r_cons_newline ();
		if (optword) {
			r_cons_printf (">> %s\n", optword);
		}
		vt.t_idx = option;
		vt.t_ctr = 0;
		vt.type = opts[h_opt];
		vt.optword = optword;
                sdb_foreach (core->anal->sdb_types, sdbforcb, &vt);

		r_cons_visual_flush ();
		ch = r_cons_readchar ();
		if (ch == -1 || ch == 4) {
			return false;
		}
		ch = r_cons_arrow_to_hjkl (ch); // get ESC+char, return 'hjkl' char
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
				char *file = prompt ("Filename: ", NULL);
				if (file) {
					r_core_cmdf (core, "\"to %s\"", file);
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
			if (menu==0) {
				// if no flagspaces, just quit
				for (j = i = 0; i < R_FLAG_SPACES_MAX; i++) {
					if (core->flags->spaces[i]) {
						j = 1;
					}
				}
				if (!j) {
					return true;
				}
			}
			break;
		case 'a':
			{
				txt = prompt ("add C type: ", NULL);
				if (txt) {
					r_core_cmdf (core, "\"td %s\"", txt);
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
				case 0: // type
					/* TODO: do something with this data */
					prompt ("name: ", vt.curname);
					prompt ("pf: ", vt.curfmt);
					break;
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
			r_cons_clear00 ();
			r_cons_printf (
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
			r_cons_flush ();
			r_cons_any_key (NULL);
			break;
		case ':':
			r_cons_show_cursor (true);
			r_cons_set_raw (0);
			cmd[0] = '\0';
			r_line_set_prompt (":> ");
			if (r_cons_fgets (cmd, sizeof (cmd) - 1, 0, NULL) < 0) {
				cmd[0]='\0';
			}
			r_core_cmd (core, cmd, 1);
			r_cons_set_raw (1);
			r_cons_show_cursor (false);
			if (cmd[0]) {
				r_cons_any_key (NULL);
			}
			r_cons_clear ();
			continue;
		}
	}
	return true;
}

static int cmtcb(void *usr, const char *k, const char *v) {
	if (!strncmp (k, "meta.C.", 7)) {
		RList *list = (RList*)usr;
		char *msg, *comma = strchr (v, ',');
		if (comma) {
			comma = strchr (comma + 1, ',');
			if (comma) {
				msg = (char *)sdb_decode (comma + 1, NULL);
				if (msg) {
					msg = r_str_replace (msg, "\n", "", true);
					r_list_append (list, r_str_newf ("%s  %s", k+7, msg));
					free (msg);
				}
			}
		}
	}
	return 1;
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
	list->free = free;
	RList *classes = r_bin_get_classes (core->bin);
	r_list_foreach (classes, iter, c) {
		r_list_foreach (c->fields, iter2, f) {
			r_list_append (list, r_str_newf ("0x%08"PFMT64x"  %s %s",
				f->vaddr, c->name, f->name));
		}
		r_list_foreach (c->methods, iter2, m) {
			const char *name = m->dname? m->dname: m->name;
			r_list_append (list, r_str_newf ("0x%08"PFMT64x"  %s %s",
				m->vaddr, c->name, name));
		}
	}
	res = r_cons_hud (list, NULL);
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
	return res? true: false;
}

R_API bool r_core_visual_hudstuff(RCore *core) {
	RListIter *iter;
	RFlagItem *flag;
	ut64 addr;
	char *res;
	RList *list = r_list_new ();
	if (!list) {
		return false;
	}
	list->free = free;
	r_list_foreach (core->flags->flags, iter, flag) {
		r_list_append (list, r_str_newf ("0x%08"PFMT64x"  %s",
			flag->offset, flag->name));
	}
	sdb_foreach (core->anal->sdb_meta, cmtcb, list);
	res = r_cons_hud (list, NULL);
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
	return res? true: false;
}

static bool r_core_visual_config_hud(RCore *core) {
	RListIter *iter;
	RConfigNode *bt;
	RList *list = r_list_new ();
	if (!list) return false;
	char *res;
	list->free = free;
	r_list_foreach (core->config->nodes, iter, bt) {
		r_list_append (list, r_str_newf ("%s %s", bt->name, bt->value));
	}
	res = r_cons_hud (list, NULL);
	if (res) {
		const char *oldvalue = NULL;
		char cmd[512];
		char *p = strchr (res, ' ');
		if (p) *p = 0;
		oldvalue = r_config_get (core->config, res);
		r_cons_show_cursor (true);
		r_cons_set_raw (0);
		cmd[0] = '\0';
		eprintf ("set new value for %s (old=%s)\n", res, oldvalue);
		r_line_set_prompt (":> ");
		if (r_cons_fgets (cmd, sizeof (cmd) - 1, 0, NULL) < 0)
			cmd[0]='\0';
		r_config_set (core->config, res, cmd);
		r_cons_set_raw (1);
		r_cons_show_cursor (false);
	}
	r_list_free (list);
	return true;
}

// TODO: skip N first elements
// TODO: show only N elements of the list
// TODO: wrap index when out of boundaries
// TODO: Add support to show class fields too
static void *show_class(RCore *core, int mode, int idx, RBinClass *_c, const char *grep, RList *list) {
	bool show_color = r_config_get_i (core->config, "scr.color");
	RListIter *iter;
	RBinClass *c, *cur = NULL;
	RBinSymbol *m, *mur = NULL;
	int i = 0;
	int skip = idx - 10;

	switch (mode) {
	case 'c':
		r_cons_printf ("Classes:\n\n");
		r_list_foreach (list, iter, c) {
			if (grep) {
				if (!r_str_casestr (c->name, grep)) {
					i++;
					continue;
				}
			} else {
				if (idx > 10) {
					skip--;
					if (skip > 0) {
						i++;
						continue;
					}
				}
			}
			if (show_color) {
				if (i == idx) {
					const char *clr = Color_BLUE;
					r_cons_printf (Color_GREEN ">>" Color_RESET " %02d %s0x%08"
							PFMT64x Color_YELLOW "  %s\n" Color_RESET,
						i, clr, c->addr, c->name);
				} else {
					r_cons_printf ("-  %02d %s0x%08"PFMT64x Color_RESET"  %s\n",
						i, core->cons->pal.offset, c->addr, c->name);
				}
			} else {
				r_cons_printf ("%s %02d 0x%08"PFMT64x"  %s\n",
					(i==idx)?">>":"- ", i, c->addr, c->name);
			}
			if (i++ == idx) {
				cur = c;
			}
		}
		return cur;
	case 'f':
		// show fields
		r_cons_printf ("Fields:\n\n");
		break;
	case 'm':
		// show methods
		if (!_c) {
			eprintf ("No class defined\n");
			return mur;
		}
		r_cons_printf ("MethodsFor: %s\n\n", _c->name);
		r_list_foreach (_c->methods, iter, m) {
			const char *name = m->dname? m->dname: m->name;
			char *mflags;
			if (grep) {
				if (!r_str_casestr (name, grep)) {
					i++;
					continue;
				}
			} else {
				if (idx > 10) {
					skip--;
					if (skip > 0) {
						i++;
						continue;
					}
				}
			}

			mflags = r_core_bin_method_flags_str (m->method_flags, 0);

			if (show_color) {
				if (i == idx) {
					const char *clr = Color_BLUE;
					r_cons_printf (Color_GREEN ">>" Color_RESET " %02d %s0x%08"
							PFMT64x Color_YELLOW " %s %s\n" Color_RESET,
						i, clr, m->vaddr, mflags, name);
				} else {
					r_cons_printf ("-  %02d %s0x%08"PFMT64x Color_RESET" %s %s\n",
						i, core->cons->pal.offset, m->vaddr, mflags, name);
				}
			} else {
				r_cons_printf ("%s %02d 0x%08"PFMT64x" %s %s\n",
					(i==idx)? ">>": "- ", i, m->vaddr, mflags, name);
			}

			R_FREE (mflags);

			if (i++ == idx) {
				mur = m;
			}
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
	void *ptr;
	int oldcur = 0;
	char *grep = NULL;
	bool grepmode = false;
	RList *list = r_bin_get_classes (core->bin);
	if (r_list_empty (list)) {
		r_cons_message ("No Classes");
		return false;
	}
	for (;;) {
		int cols;
		r_cons_clear00 ();
		if (grepmode) {
			r_cons_printf ("Grep: %s\n", grep? grep: "");
		}
		ptr = show_class (core, mode, index, cur, grep, list);
		switch (mode) {
		case 'm':
			mur = (RBinSymbol*)ptr;
			break;
		case 'c':
			cur = (RBinClass*)ptr;
			break;
		}

		/* update terminal size */
		(void) r_cons_get_size (&cols);
		r_cons_visual_flush ();
		ch = r_cons_readchar ();
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

		ch = r_cons_arrow_to_hjkl (ch); // get ESC+char, return 'hjkl' char
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
			{
				char *num = prompt ("Index:", NULL);
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
		case 'h':
		case 127: // backspace
		case 'b': // back
		case 'Q':
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
			if (cur) {
				oldcur = index;
				index = 0;
				mode = 'm';
			}
			break;
		case '?':
			r_cons_clear00 ();
			r_cons_printf (
			"\nVF: Visual Classes help:\n\n"
			" q     - quit menu\n"
			" j/k   - down/up keys\n"
			" h/b   - go back\n"
			" /     - grep mode\n"
			" C     - toggle colors\n"
			" l/' ' - accept current selection\n"
			" p     - preview method disasm with less\n"
			" :     - enter command\n");
			r_cons_flush ();
			r_cons_any_key (NULL);
			break;
		case ':':
			r_cons_show_cursor (true);
			r_cons_set_raw (0);
			cmd[0] = '\0';
			r_line_set_prompt (":> ");
			if (r_cons_fgets (cmd, sizeof (cmd)-1, 0, NULL) < 0) {
				cmd[0]='\0';
			}
			//line[strlen(line)-1]='\0';
			r_core_cmd (core, cmd, 1);
			r_cons_set_raw (1);
			r_cons_show_cursor (false);
			if (cmd[0]) {
				r_cons_any_key (NULL);
			}
			//cons_gotoxy(0,0);
			r_cons_clear ();
			break;
		}
	}
	return true;
}

R_API int r_core_visual_trackflags(RCore *core) {
	const char *fs = NULL, *fs2 = NULL;
	int hit, i, j, ch;
	RListIter *iter;
	RFlagItem *flag;
	int _option = 0;
	int option = 0;
	char cmd[1024];
	int format = 0;
	int delta = 7;
	int menu = 0;

	for (j=i=0; i<R_FLAG_SPACES_MAX; i++) {
		if (core->flags->spaces[i]) {
			j = 1;
		}
	}
	if (j == 0) {
		menu = 1;
	}
	for (;;) {
		bool hasColor = r_config_get_i (core->config, "scr.color");
		r_cons_clear00 ();

		if (menu) {
			r_cons_printf ("Flags in flagspace '%s'. Press '?' for help.\n\n",
			(core->flags->space_idx==-1)?"*":core->flags->spaces[core->flags->space_idx]);
			hit = 0;
			i = j = 0;
			r_list_foreach (core->flags->flags, iter, flag) {
				/* filter per flag spaces */
				if ((core->flags->space_idx != -1) &&
					(flag->space != core->flags->space_idx)) {
					continue;
				}
				if (option == i) {
					fs2 = flag->name;
					hit = 1;
				}
				if ((i>=option-delta) && ((i<option+delta)||((option<delta)&&(i<(delta<<1))))) {
					bool cur = option == i;
					if (cur && hasColor) {
						r_cons_printf (Color_INVERT);
					}
					r_cons_printf (" %c  %03d 0x%08"PFMT64x" %4"PFMT64d" %s\n",
							cur?'>':' ', i, flag->offset, flag->size, flag->name);
					if (cur && hasColor) {
						r_cons_printf (Color_RESET);
					}
					j++;
				}
				i++;
			}
			if (!hit && i > 0) {
				option = i - 1;
				continue;
			}
			if (fs2) {
				int cols, rows = r_cons_get_size (&cols);
				//int rows = 20;
				rows -= 12;
				r_cons_printf ("\n Selected: %s\n\n", fs2);
				// Honor MAX_FORMATS here
				switch (format) {
				case 0: snprintf (cmd, sizeof (cmd), "px %d @ %s!64", rows*16, fs2); core->printidx = 0; break;
				case 1: snprintf (cmd, sizeof (cmd), "pd %d @ %s!64", rows, fs2); core->printidx = 1; break;
				case 2: snprintf (cmd, sizeof (cmd), "ps @ %s!64", fs2); core->printidx = 5; break;
				case 3: strcpy (cmd, "f="); break;
				default: format = 0; continue;
				}
				if (*cmd) r_core_cmd (core, cmd, 0);
			} else {
				r_cons_printf ("(no flags)\n");
			}
		} else {
			r_cons_printf ("Flag spaces:\n\n");
			hit = 0;
			for (j=i=0;i<R_FLAG_SPACES_MAX;i++) {
				if (core->flags->spaces[i]) {
					if (option == i) {
						fs = core->flags->spaces[i];
						hit = 1;
					}
					if ((i >= option - delta) && ((i < option + delta)|| \
							((option < delta) && (i < (delta << 1))))) {
						r_cons_printf(" %c %02d %c %s\n",
							(option==i)?'>':' ', j,
							(i==core->flags->space_idx)?'*':' ',
							core->flags->spaces[i]);
						j++;
					}
				}
			}
			if (core->flags->spaces[9]) {
				if (option == j) {
					fs = "*";
					hit = 1;
				}
				r_cons_printf (" %c %02d %c %s\n",
					(option==j)?'>':' ', j,
					(i==core->flags->space_idx)?'*':' ',
					"*");
			}
			if (!hit && j > 0) {
				option = j - 1;
				continue;
			}
		}
		r_cons_visual_flush ();
		ch = r_cons_readchar ();
		if (ch == -1 || ch == 4) {
			return false;
		}
		ch = r_cons_arrow_to_hjkl (ch); // get ESC+char, return 'hjkl' char
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
		case 'o': r_flag_sort (core->flags, 0); break;
		case 'n': r_flag_sort (core->flags, 1); break;
		case 'j': option++; break;
		case 'k': if (--option<0) option = 0; break;
		case 'K': option-=10; if (option<0) option = 0; break;
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
				for (j=i=0;i<R_FLAG_SPACES_MAX;i++) {
					if (core->flags->spaces[i]) {
						j = 1;
					}
				}
				if (!j) {
					return true;
				}
			}
			break;
		case 'a':
			switch (menu) {
			case 0: // new flag space
				r_cons_show_cursor (true);
				r_line_set_prompt ("add flagspace: ");
				strcpy (cmd, "fs ");
				if (r_cons_fgets (cmd+3, sizeof (cmd)-4, 0, NULL) > 0) {
					r_core_cmd (core, cmd, 0);
					r_cons_set_raw (1);
					r_cons_show_cursor (false);
				}
				break;
			case 1: // new flag
				r_cons_show_cursor (true);
				r_line_set_prompt ("add flag: ");
				strcpy (cmd, "f ");
				if (r_cons_fgets (cmd+2, sizeof (cmd)-3, 0, NULL) > 0) {
					r_core_cmd (core, cmd, 0);
					r_cons_set_raw (1);
					r_cons_show_cursor (false);
				}
				break;
			}
			break;
		case 'd':
			r_flag_unset_name (core->flags, fs2);
			break;
		case 'e':
			/* TODO: prompt for addr, size, name */
			eprintf ("TODO\n");
			r_sys_sleep (1);
			break;
		case '*':
			r_core_block_size (core, core->blocksize+16);
			break;
		case '/':
			r_core_block_size (core, core->blocksize-16);
			break;
		case '+':
			if (menu==1)
				r_core_cmdf (core, "f %s=%s+1", fs2, fs2);
			else r_core_block_size (core, core->blocksize+1);
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
				int len;
				r_cons_show_cursor (true);
				r_cons_set_raw (0);
				// TODO: use r_flag_rename or wtf?..fr doesnt uses this..
				snprintf (cmd, sizeof (cmd), "fr %s ", fs2);
				len = strlen (cmd);
				eprintf ("Rename flag '%s' as:\n", fs2);
				r_line_set_prompt (":> ");
				if (r_cons_fgets (cmd + len, sizeof (cmd) - len - 1, 0, NULL) < 0) {
					cmd[0] = '\0';
				}
				r_core_cmd (core, cmd, 0);
				r_cons_set_raw (1);
				r_cons_show_cursor (false);
			}
			break;
		case 'R':
			if (menu == 1) {
				char line[1024];
				r_cons_show_cursor (true);
				r_cons_set_raw (0);
				eprintf ("Rename function '%s' as:\n", fs2);
				r_line_set_prompt (":> ");
				if (r_cons_fgets (line, sizeof (line), 0, NULL) < 0) {
					cmd[0]='\0';
				}
				snprintf (cmd, sizeof (cmd), "afr %s %s", line, fs2);
				r_core_cmd (core, cmd, 0);
				r_cons_set_raw (1);
				r_cons_show_cursor (false);
			}
			break;
		case 'P': if (--format<0) format = MAX_FORMAT; break;
// = (format<=0)? MAX_FORMAT: format-1; break;
		case 'p': format++; break;
		case 'l':
		case ' ':
		case '\r':
		case '\n':
			if (menu == 1) {
				sprintf (cmd, "s %s", fs2);
				r_core_cmd (core, cmd, 0);
				return true;
			}
			r_flag_space_set (core->flags, fs);
			menu = 1;
			_option = option;
			option = 0;
			break;
		case '?':
			r_cons_clear00 ();
			r_cons_printf (
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
			r_cons_flush ();
			r_cons_any_key (NULL);
			break;
		case ':':
			r_cons_show_cursor (true);
			r_cons_set_raw (0);
			*cmd = 0;
			r_line_set_prompt (":> ");
			if (r_cons_fgets (cmd, sizeof (cmd) - 1, 0, NULL) <0) {
				*cmd = 0;
			}
			cmd[sizeof (cmd) - 1] = 0;
			r_core_cmd (core, cmd, 1);
			r_cons_set_raw (1);
			r_cons_show_cursor (false);
			if (*cmd) {
				r_cons_any_key (NULL);
			}
			//cons_gotoxy(0,0);
			r_cons_clear ();
			continue;
		}
	}
	return true;
}

R_API int r_core_visual_comments (RCore *core) {
#undef DB
#define DB core->anal->sdb_meta
	const char *val, *comma = NULL;
	char *list = sdb_get (DB, "meta.C", 0);
	char *str, *next, *cur = list;
	char key[128], cmd[512], *p = NULL;
	int i, ch, option = 0, delta = 7;
	int format = 0, found = 0;
	ut64 addr, from = 0, size = 0;

	for (;;) {
		r_cons_clear00 ();
		r_cons_strcat ("Comments:\n");
		i = 0;
		found = 0;
		if (list) {
			for (i=0; ;i++) {
				cur = sdb_anext (cur, &next);
				addr = sdb_atoi (cur);
				snprintf (key, sizeof (key)-1, "meta.C.0x%08"PFMT64x, addr);
				val = sdb_const_get (DB, key, 0);
				if (val)
					comma = strchr (val, ',');
				if (comma) {
					str = (char *)sdb_decode (comma+1, 0);
					if ((i>=option-delta) && ((i<option+delta)||((option<delta)&&(i<(delta<<1))))) {
						r_str_sanitize (str);
						if (option==i) {
							found = 1;
							from = addr;
							size = 1; // XXX: remove this thing size for comments is useless d->size;
							free (p);
							p = str;
							r_cons_printf ("  >  %s\n", str);
						} else {
							r_cons_printf ("     %s\n", str);
							free (str);
						}
					} else free (str);
				}
				if (!next) {
					break;
				}
				cur = next;
			}
		}

		if (!found) {
			if (--option < 0) {
				break;
			}
			continue;
		}
		r_cons_newline ();

		switch (format) {
		case 0: sprintf (cmd, "px @ 0x%"PFMT64x":64", from); core->printidx = 0; break;
		case 1: sprintf (cmd, "pd 12 @ 0x%"PFMT64x":64", from); core->printidx = 1; break;
		case 2: sprintf (cmd, "ps @ 0x%"PFMT64x":64", from); core->printidx = 5; break;
		default: format = 0; continue;
		}
		if (*cmd) {
			r_core_cmd (core, cmd, 0);
		}
		r_cons_visual_flush ();
		ch = r_cons_readchar ();
		ch = r_cons_arrow_to_hjkl (ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 'a':
			//TODO
			break;
		case 'e':
			//TODO
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
			r_cons_clear00 ();
			r_cons_printf (
			"\nVT: Visual Comments/Anal help:\n\n"
			" q     - quit menu\n"
			" j/k   - down/up keys\n"
			" h/b   - go back\n"
			" l/' ' - accept current selection\n"
			" a/d/e - add/delete/edit comment/anal symbol\n"
			" p/P   - rotate print format\n");
			r_cons_flush ();
			r_cons_any_key (NULL);
			break;
		}
		R_FREE (p);
	}
	return true;
}

static void config_visual_hit_i(RCore *core, const char *name, int delta) {
	struct r_config_node_t *node;
	node = r_config_node_get (core->config, name);
	if (node && ((node->flags & CN_INT) || (node->flags & CN_OFFT))) {
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
	if (node->flags & CN_BOOL) {
		r_config_set_i (core->config, name, node->i_value? 0:1);
	} else {
// XXX: must use config_set () to run callbacks!
		if (editor) {
			char * buf = r_core_editor (core, NULL, node->value);
			node->value = r_str_dup (node->value, buf);
			free (buf);
		} else {
			// FGETS AND SO
			r_cons_printf ("New value (old=%s): \n", node->value);
			r_cons_show_cursor (true);
			r_cons_flush ();
			r_cons_set_raw (0);
			r_line_set_prompt (":> ");
			r_cons_fgets (buf, sizeof (buf)-1, 0, 0);
			r_cons_set_raw (1);
			r_cons_show_cursor (false);
			r_config_set (core->config, name, buf);
			//node->value = r_str_dup (node->value, buf);
		}
	}
}

R_API void r_core_visual_config(RCore *core) {
	char *fs = NULL, *fs2 = NULL, *desc = NULL;
	int i, j, ch, hit, show;
	int option, _option = 0;
	RListIter *iter;
	RConfigNode *bt;
	char old[1024];
	int delta = 9;
	int menu = 0;
	old[0]='\0';

	option = 0;
	for (;;) {
		r_cons_clear00 ();
		r_cons_get_size (&delta);
		delta /= 4;

		switch (menu) {
		case 0: // flag space
			r_cons_printf ("[EvalSpace]\n\n");
			hit = j = i = 0;
			r_list_foreach (core->config->nodes, iter, bt) {
				if (option==i) {
					fs = bt->name;
				}
				if (old[0]=='\0') {
					r_str_ccpy (old, bt->name, '.');
					show = 1;
				} else if (r_str_ccmp (old, bt->name, '.')) {
					r_str_ccpy (old, bt->name, '.');
					show = 1;
				} else show = 0;

				if (show) {
					if (option == i) hit = 1;
					if ( (i >=option-delta) && ((i<option+delta)||((option<delta)&&(i<(delta<<1))))) {
						r_cons_printf(" %c  %s\n", (option==i)?'>':' ', old);
						j++;
					}
					i++;
				}
			}
			if (!hit && j>0) {
				option--;
				continue;
			}
			r_cons_printf ("\n Sel:%s \n\n", fs);
			break;
		case 1: // flag selection
			r_cons_printf ("[EvalSpace < Variables: %s]\n\n", fs);
			hit = 0;
			j = i = 0;
			// TODO: cut -d '.' -f 1 | sort | uniq !!!
			r_list_foreach (core->config->nodes, iter, bt) {
				if (!r_str_ccmp (bt->name, fs, '.')) {
					if (option==i) {
						fs2 = bt->name;
						desc = bt->desc;
						hit = 1;
					}
					if ( (i>=option-delta) && ((i<option+delta)||((option<delta)&&(i<(delta<<1))))) {
						// TODO: Better align
						r_cons_printf (" %c  %s = %s\n", (option==i)?'>':' ', bt->name, bt->value);
						j++;
					}
					i++;
				}
			}
			if (!hit && j>0) {
				option = i-1;
				continue;
			}
			if (fs2 != NULL)
				// TODO: Break long lines.
				r_cons_printf ("\n Selected: %s (%s)\n\n",
						fs2, desc);
		}

		if (fs && !strncmp (fs, "asm.", 4)) {
			r_core_cmd (core, "pd $r", 0);
		}
		r_cons_visual_flush ();
		ch = r_cons_readchar ();
		if (ch==4 || ch==-1)
			return;
		ch = r_cons_arrow_to_hjkl (ch); // get ESC+char, return 'hjkl' char

		switch (ch) {
		case 'j': option++; break;
		case 'k': option = (option<=0)? 0: option-1; break;
		case 'J': option+=4; break;
		case 'K': option = (option<=3)? 0: option-4; break;
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
			r_cons_any_key (NULL);
			break;
		case '*':
		case '+':
			fs2 ? config_visual_hit_i (core, fs2, +1) : 0;
			continue;
		case '/':
		case '-':
			fs2 ? config_visual_hit_i (core, fs2, -1) : 0;
			continue;
		case 'l':
		case 'E': // edit value
		case 'e': // edit value
		case ' ':
		case '\r':
		case '\n': // never happens
			if (menu == 1) {
				fs2 ? config_visual_hit (core, fs2, (ch=='E')) : 0;
			} else {
				menu = 1;
				_option = option;
				option = 0;
			}
			break;
		case '?':
			r_cons_clear00 ();
			r_cons_printf ("\nVe: Visual Eval help:\n\n"
			" q     - quit menu\n"
			" j/k   - down/up keys\n"
			" h/b   - go back\n"
			" $     - same as ?$ - show values of vars\n"
			" e/' ' - edit/toggle current variable\n"
			" E     - edit variable with 'cfg.editor' (vi?)\n"
			" +/-   - increase/decrease numeric value (* and /, too)\n"
			" :     - enter command\n");
			r_cons_flush ();
			r_cons_any_key (NULL);
			break;
		case ':':
			r_cons_show_cursor (true);
			r_cons_set_raw(0);
			 {
				char *cmd = prompt (":> ", NULL);
				r_core_cmd (core, cmd, 1);
				free (cmd);
			 }
			r_cons_set_raw (1);
			r_cons_show_cursor (false);
			r_cons_any_key (NULL);
			r_cons_clear00 ();
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
		r_cons_clear00 ();

		/* Show */
		if (mode == 0) {
			if (list) {
				r_list_free (list);
				list = NULL;
			}
			r_cons_printf ("Press '/' to navigate the root filesystem.\nPartitions:\n\n");
			n = r_fs_partition_type_get (partition);
			list = r_fs_partitions (core->fs, n, 0);
			i = 0;
			if (list) {
				r_list_foreach (list, iter, part) {
					if ((option-delta <= i) && (i <= option+delta)) {
						if (option == i)
							r_cons_printf (" > ");
						else r_cons_printf ("   ");
						r_cons_printf ("%d %02x 0x%010"PFMT64x" 0x%010"PFMT64x"\n",
								part->number, part->type,
								part->start, part->start+part->length);
					}
					i++;
				}
				r_list_free (list);
				list = NULL;
			} else r_cons_printf ("Cannot read partition\n");
		} else if (mode == 1) {
			r_cons_printf ("Types:\n\n");
			for(i=0;;i++) {
				n = r_fs_partition_type_get (i);
				if (!n) break;
				r_cons_printf ("%s%s\n", (i==partition)?" > ":"   ", n);
			}
		} else if (mode == 3) {
			i = 0;
			r_cons_printf ("Mountpoints:\n\n");
			r_list_foreach (core->fs->roots, iter, fsroot) {
				if (fsroot && (option-delta <= i) && (i <= option+delta)) {
					r_cons_printf ("%s %s\n", (option == i)?" > ":"   ",
							fsroot->path);
				}
				i++;
			}
		} else {
			if (root) {
				list = r_fs_dir (core->fs, path);
				if (list) {
					r_cons_printf ("%s:\n\n", path);
					i = 0;
					r_list_foreach (list, iter, file) {
						if ((dir-delta <= i) && (i <= dir+delta)) {
							r_cons_printf ("%s%c %s\n", (dir == i)?" > ":"   ",
									file->type, file->name);
						}
						i++;
					}
					r_cons_printf ("\n");
					r_list_free (list);
					list = NULL;
				} else r_cons_printf ("Cannot open '%s' directory\n", root);
			} else r_cons_printf ("Root undefined\n");
		}
		if (mode==2) {
			r_str_trim_path (path);
			str = path + strlen (path);
			strncat (path, "/", sizeof (path)-strlen (path)-1);
			list = r_fs_dir (core->fs, path);
			file = r_list_get_n (list, dir);
			if (file && file->type != 'd')
				r_core_cmdf (core, "px @ 0x%"PFMT64x"!64", file->off);
			r_list_free (list);
			list = NULL;
			*str='\0';
		}
		r_cons_flush ();

		/* Ask for option */
		ch = r_cons_readchar ();
		if (ch==-1||ch==4){
			free (root);
			return;
		}
		ch = r_cons_arrow_to_hjkl (ch);
		switch (ch) {
			case '/':
				if (root) R_FREE (root);
				root = strdup ("/");
				strncpy (path, root, sizeof (path)-1);
				R_FREE (root);
				mode = 2;
				break;
			case 'l':
			case '\r':
			case '\n':
				if (mode == 0) {
					n = r_fs_partition_type_get (partition);
					list = r_fs_partitions (core->fs, n, 0);
					if (!list) {
						r_cons_printf ("Unknown partition\n");
						r_cons_any_key (NULL);
						r_cons_flush ();
						break;
					}
					part = r_list_get_n (list, option);
					if (!part) {
						r_cons_printf ("Unknown partition\n");
						r_cons_any_key (NULL);
						r_cons_flush ();
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
							r_cons_printf ("Cannot mount partition\n");
							r_cons_flush ();
							r_cons_any_key (NULL);
						}
					} else {
						r_cons_printf ("Unknown partition type\n");
						r_cons_flush ();
						r_cons_any_key (NULL);
					}
					r_list_free (list);
					list = NULL;
				} else if (mode == 2){
					r_str_trim_path (path);
					strncat (path, "/", sizeof (path)-strlen (path)-1);
					list = r_fs_dir (core->fs, path);
					file = r_list_get_n (list, dir);
					if (file) {
						if (file->type == 'd') {
							strncat (path, file->name, sizeof (path)-strlen (path)-1);
							r_str_trim_path (path);
							if (root && strncmp (root, path, strlen (root)-1))
								strncpy (path, root, sizeof (path)-1);
						} else {
							r_core_cmdf (core, "s 0x%"PFMT64x, file->off);
							r_fs_umount (core->fs, root);
							free (root);
							return;
						}
					} else {
						r_cons_printf ("Unknown file\n");
						r_cons_flush ();
						r_cons_any_key (NULL);
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
					if (option > 0)
						option--;
				} else if (mode == 1) {
					if (partition > 0)
						partition--;
				} else {
					if (dir>0)
						dir--;
				}
				break;
			case 'j':
				if (mode == 0) {
					n = r_fs_partition_type_get (partition);
					list = r_fs_partitions (core->fs, n, 0);
					if (option < r_list_length (list)-1)
						option++;
				} else if (mode == 1) {
					if (partition < r_fs_partition_get_size ()-1)
						partition++;
				} else if (mode == 3) {
					if (option < r_list_length (core->fs->roots)-1)
						option++;
				} else {
					list = r_fs_dir (core->fs, path);
					if (dir < r_list_length (list)-1)
						dir++;
				}
				break;
			case 't':
				mode = 1;
				break;
			case 'h':
				if (mode == 2) {
					if (!root) {
						mode = 0;
					} else
					if (strcmp (path, root)) {
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
					str = path + strlen (path);
					strncat (path, "/", sizeof (path)-strlen (path)-1);
					list = r_fs_dir (core->fs, path);
					file = r_list_get_n (list, dir);
					if (file && root) {
						strncat (path, file->name, sizeof (path)-strlen (path)-1);
						r_str_trim_path (path);
						if (strncmp (root, path, strlen (root)-1))
							strncpy (path, root, sizeof (path)-1);
						file = r_fs_open (core->fs, path);
						if (file) {
							r_fs_read (core->fs, file, 0, file->size);
							r_cons_show_cursor (true);
							r_cons_set_raw (0);
							r_line_set_prompt ("Dump path (ej: /tmp/file): ");
							r_cons_fgets (buf, sizeof (buf)-1, 0, 0);
							r_cons_set_raw (1);
							r_cons_show_cursor (false);
							r_file_dump (buf, file->data, file->size, 0);
							r_fs_close (core->fs, file);
							r_cons_printf ("Done\n");
						} else r_cons_printf ("Cannot dump file\n");
					} else r_cons_printf ("Cannot dump file\n");
					r_cons_flush ();
					r_cons_any_key (NULL);
					*str='\0';
				}
				break;
			case 'm':
				mode = 3;
				option = 0;
				break;
			case '?':
				r_cons_clear00 ();
				r_cons_printf ("\nVM: Visual Mount points help:\n\n");
				r_cons_printf (" q     - go back or quit menu\n");
				r_cons_printf (" j/k   - down/up keys\n");
				r_cons_printf (" h/l   - forward/go keys\n");
				r_cons_printf (" t     - choose partition type\n");
				r_cons_printf (" g     - dump file\n");
				r_cons_printf (" m     - show mountpoints\n");
				r_cons_printf (" :     - enter command\n");
				r_cons_printf (" ?     - show this help\n");
				r_cons_flush ();
				r_cons_any_key (NULL);
				break;
			case ':':
				r_cons_show_cursor (true);
				r_cons_set_raw (0);
				r_line_set_prompt (":> ");
				r_cons_fgets (buf, sizeof (buf)-1, 0, 0);
				r_cons_set_raw (1);
				r_cons_show_cursor (false);
				r_core_cmd (core, buf, 1);
				r_cons_any_key (NULL);
				break;
		}
	}
}

#if 0
static void var_index_show(RAnal *anal, RAnalFunction *fcn, ut64 addr, int idx) {
	int i = 0;
	RAnalVar *v;
	RAnalVarAccess *x;
	RListIter *iter, *iter2;
	int window ;

	// Adjust the windows size automaticaly
	(void)r_cons_get_size (&window);
	window-=5; // Size of printed things

	int wdelta = (idx>5)?idx-5:0;
	if (!fcn) return;
	r_list_foreach(fcn->vars, iter, v) {
		if (addr == 0 || (addr >= v->addr && addr <= v->eaddr)) {
			if (i>=wdelta) {
				if (i>window+wdelta) {
					r_cons_printf("...\n");
					break;
				}
				if (idx == i) r_cons_printf (" * ");
				else r_cons_printf ("   ");
#if 0
				if (v->type->type == R_ANAL_TYPE_ARRAY) {
eprintf ("TODO: support for arrays\n");
					r_cons_printf ("0x%08llx - 0x%08llx scope=%s type=%s name=%s delta=%d array=%d\n",
						v->addr, v->eaddr, r_anal_var_scope_to_str (anal, v->scope),
						r_anal_type_to_str (anal, v->type, ""),
						v->name, v->delta, v->type->custom.a->count);
				} else
#endif
				{
					char *s = r_anal_type_to_str (anal, v->type);
					if (!s) s = strdup ("<unk>");
					r_cons_printf ("0x%08llx - 0x%08llx scope=%d type=%s name=%s delta=%d\n",
						v->addr, v->eaddr, v->scope, s, v->name, v->delta);
					free (s);
				}
				r_list_foreach (v->accesses, iter2, x) {
					r_cons_printf ("  0x%08llx %s\n", x->addr, x->set?"set":"get");
				}
			}
			i++;
		}
	}
}
#endif

// helper
static void function_rename(RCore *core, ut64 addr, const char *name) {
	RListIter *iter;
	RAnalFunction *fcn;

	r_list_foreach (core->anal->fcns, iter, fcn) {
		if (fcn->addr == addr) {
			r_flag_unset_name (core->flags, fcn->name);
			free (fcn->name);
			fcn->name = strdup (name);
			r_flag_set (core->flags, name, addr, r_anal_fcn_size (fcn));
			break;
		}
	}
}

static void variable_rename (RCore *core, ut64 addr, int vindex, const char *name) {
	RAnalFunction* fcn = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
	ut64 a_tmp = core->offset;
	int i = 0;
	RListIter *iter;
	// arguments.
	RList* list2 = r_anal_var_list (core->anal, fcn, true);
	// variables.
	RList* list = r_anal_var_list (core->anal, fcn, false);
	r_list_join (list, list2);
	RAnalVar* var;

	r_list_foreach (list, iter, var) {
		if (i == vindex) {
			r_core_seek (core, addr, false);
			r_core_cmd_strf (core, "afvn %s %s", var->name, name);
			r_core_seek (core, a_tmp, false);
			break;
		}
		++i;
	}
	r_list_free (list);
	r_list_free (list2);
}

// In visual mode, display function list
static ut64 var_functions_show(RCore *core, int idx, int show) {
	int wdelta = (idx > 5)? idx - 5: 0;
	ut64 seek = core->offset;
	ut64 addr = core->offset;
	RAnalFunction *fcn;
	int window, i = 0;
	RListIter *iter;

	// Adjust the windows size automaticaly
	(void)r_cons_get_size (&window);
	window -= 8; // Size of printed things

	r_list_foreach (core->anal->fcns, iter, fcn) {
		if (i >= wdelta) {
			if (i> window+wdelta) {
				r_cons_printf ("...\n");
				break;
			}
			if (idx == i) {
				addr = fcn->addr;
			}
			if (show)
				r_cons_printf ("%c%c 0x%08"PFMT64x" %4d %s\n",
					(seek == fcn->addr)?'>':' ',
					(idx==i)?'*':' ',
					fcn->addr, r_anal_fcn_realsize (fcn), fcn->name);
		}
		i++;
	}
	return addr;
}

// In visual mode, display the variables.
static ut64 var_variables_show(RCore* core, int idx, int *vindex, int show) {
	int i = 0;
	const ut64 addr = var_functions_show (core, idx, 0);
	RAnalFunction* fcn = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
	int window;
	int wdelta = (idx > 5) ? idx - 5 : 0;
	RListIter *iter;
	// arguments.
	RList* list2 = r_anal_var_list (core->anal, fcn, true);
	// variables.
	RList* list = r_anal_var_list (core->anal, fcn, false);
	r_list_join (list, list2);
	RAnalVar* var;
	// Adjust the window size automatically.
	(void)r_cons_get_size (&window);
	window -= 8;  // Size of printed things.

	// A new line so this looks reasonable.
	r_cons_newline ();

	int llen = r_list_length (list);
	if (*vindex >= llen) {
		*vindex = llen - 1;
	}

	r_list_foreach (list, iter, var) {
		if (i >= wdelta) {
			if (i > window + wdelta) {
				r_cons_printf ("...\n");
				break;
			}
			if (show) {
				r_cons_printf ("%s%s %s %s @ %s%s0x%x\n",
						i == *vindex ? "* ":"",
						var->kind=='v'?"var":"arg",
						var->type, var->name,
						core->anal->reg->name[R_REG_NAME_BP],
						(var->kind=='v')?"-":"+",
						var->delta);
			}
		}
		++i;
	}
	r_list_free (list);
	r_list_free (list2);
	return addr;
}

static int level = 0;
static ut64 addr = 0;
static int option = 0;
static int variable_option = 0;
static int printMode = 0;
#define lastPrintMode 5

static void r_core_visual_anal_refresh_column (RCore *core, int colpos) {
	const ut64 addr = (level != 0 && level != 1)
		? core->offset
		: var_functions_show (core, option, 0);
	// RAnalFunction* fcn = r_anal_get_fcn_in(core->anal, addr, R_ANAL_FCN_TYPE_NULL);
	int h, w = r_cons_get_size (&h);
	// int sz = (fcn)? R_MIN (r_anal_fcn_size (fcn), h * 15) : 16; // max instr is 15 bytes.

	const char *cmd, *printCmds[lastPrintMode] = {
		"pdf", "afi", "pds", "pdc", "pdr"
	};
	if (printMode > 0 && printMode < lastPrintMode) {
		cmd = printCmds[printMode];
	} else {
		cmd = printCmds[printMode = 0];
	}
	char *cmdf = r_str_newf ("%s @ 0x%"PFMT64x, cmd, addr);
	if (!cmdf) {
		return;
	}
	char *output = r_core_cmd_str (core, cmdf);
	if (output) {
		// 'h - 2' because we have two new lines in r_cons_printf
		char *out = r_str_ansi_crop (output, 0, 0, w - colpos, h - 2);
		r_cons_printf ("Visual code review (%s)\n%s\n", cmd, out);
		free (out);
		R_FREE (output);
	}
	free (cmdf);
}

static ut64 r_core_visual_anal_refresh (RCore *core) {
	ut64 addr;
	char old[1024];
	int cols = r_cons_get_size (NULL);
	if (!core) {
		return 0LL;
	}
	old[0] = '\0';
	addr = core->offset;
	cols -= 50;
	if (cols > 60) {
		cols = 60;
	}

	r_cons_clear00 ();
	r_cons_flush ();
	r_core_visual_anal_refresh_column (core, cols);
	if (cols > 30) {
		r_cons_column (cols);
	}
	switch (level) {
	// Show functions list help in visual mode
	case 0:
		r_cons_printf ("-[ functions ]---------------- \n"
			"(a) add     (x)xrefs     (q)quit \n"
			"(r) rename  (c)calls     (g)go \n"
			"(d) delete  (v)variables (?)help \n");
		addr = var_functions_show (core, option, 1);
		break;
	case 1:
		r_cons_printf (
			"-[ variables ]----- 0x%08"PFMT64x"\n"
			"(a) add     (x)xrefs  \n"
			"(r) rename  (g)go     \n"
			"(d) delete  (q)quit   \n", addr);
		addr = var_variables_show (core, option, &variable_option, 1);
		// var_index_show (core->anal, fcn, addr, option);
		break;
	case 2:
		r_cons_printf ("Press 'q' to quit call refs\n");
		r_cons_printf ("-[ calls ]----------------------- 0x%08"PFMT64x" (TODO)\n", addr);
		// TODO: filter only the callrefs. but we cant grep here
		sprintf(old, "afi @ 0x%08"PFMT64x, addr);
		r_core_cmd0 (core, old);
		break;
	case 3:
		r_cons_printf ("Press 'q' to view call refs\n");
		r_cons_printf ("-[ xrefs ]----------------------- 0x%08"PFMT64x"\n", addr);
		//sprintf (old, "axl~0x%08"PFMT64x, addr);
		r_core_cmd0 (core, "pd 1");
		//r_core_cmd0 (core, old);
		break;
	}
	r_cons_flush ();
	return addr;
}

/* Like emenu but for real */
R_API void r_core_visual_anal(RCore *core) {
	char old[218];
	int ch, _option = 0;
	int nfcns = r_list_length (core->anal->fcns);
	RConsEvent olde = core->cons->event_resize;
	core->cons->event_resize = (RConsEvent) r_core_visual_anal_refresh;
	core->cons->event_data = (void *) core;
	level = 0;
	addr = core->offset;

	int asmbytes = r_config_get_i (core->config, "asm.bytes");
	r_config_set_i (core->config, "asm.bytes", 0);
	for (;;) {
		addr = r_core_visual_anal_refresh (core);
		ch = r_cons_readchar ();
		if (ch == 4 || ch == -1) {
			if (level == 0) {
				goto beach;
			}
			level--;
			continue;
		}
		ch = r_cons_arrow_to_hjkl (ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case '?':
			r_cons_clear ();
			r_cons_printf (
				"Usage: Vv [\n"
				"Actions supported:\n"
				" functions: Add, Modify, Delete, Xrefs Calls Vars\n"
				" variables: Add, Modify, Delete\n"
				"Moving:\n"
				" j,k     select next/prev item\n"
				" J,K     scroll next/prev page\n"
				" h,q     go back, quit\n"
				" p,P     switch next/prev print mode\n"
				" l,ret   enter, function\n"
			);
			r_cons_flush ();
			r_cons_any_key (NULL);
			break;
		case ':':
			r_core_visual_prompt (core);
			r_cons_any_key (NULL);
			continue;
		case 'a':
			switch (level) {
			case 0:
				eprintf ("TODO: Add new function manually\n");
/*
				r_cons_show_cursor (true);
				r_cons_set_raw (false);
				r_line_set_prompt ("Address: ");
				if (!r_cons_fgets (old, sizeof (old), 0, NULL)) break;
				old[strlen (old)-1] = 0;
				if (!*old) break;
				addr = r_num_math (core->num, old);
				r_line_set_prompt ("Size: ");
				if (!r_cons_fgets (old, sizeof (old), 0, NULL)) break;
				old[strlen (old)-1] = 0;
				if (!*old) break;
				size = r_num_math (core->num, old);
				r_line_set_prompt ("Name: ");
				if (!r_cons_fgets (old, sizeof (old), 0, NULL)) break;
				old[strlen (old)-1] = 0;
				r_flag_set (core->flags, old, addr, 0, 0);
				//XXX sprintf(cmd, "CF %lld @ 0x%08llx", size, addr);
				// XXX r_core_cmd0(core, cmd);
				r_cons_set_raw (true);
				r_cons_show_cursor (false);
*/
				break;
			case 1:
				break;
			}
			break;
		case 'r':
			{
				switch (level) {
				case 1:
					r_cons_show_cursor (true);
					r_cons_set_raw (false);
					r_line_set_prompt ("New name: ");
					if (r_cons_fgets (old, sizeof (old), 0, NULL)) {
						if (*old) {
							//old[strlen (old)-1] = 0;
							variable_rename (core, addr, variable_option, old);
						}
					}
					break;
				default:
					r_line_set_prompt ("New name: ");
					if (r_cons_fgets (old, sizeof (old), 0, NULL)) {
						if (*old) {
							//old[strlen (old)-1] = 0;
							function_rename (core, addr, old);
						}
					}
					break;
				}
				r_cons_set_raw (true);
				r_cons_show_cursor (false);
			}
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
		case 'd':
			switch (level) {
			case 0:
				eprintf ("TODO\n");
				//data_del(addr, DATA_FUN, 0);
				// XXX correcly remove all the data contained inside the size of the function
				//flag_remove_at(addr);
				break;
			}
			break;
		case 'x': level = 3; break;
		case 'c': level = 2; break;
		case 'v': level = 1; variable_option = 0; break;
		case 'j':
			{
				switch (level) {
					case 1:
						variable_option++;
						break;
					default:
						option++;
						if (option >= nfcns) --option;
				}
			}
			break;
		case 'k':
			{
				switch (level) {
					case 1:
						variable_option = (variable_option<=0)? 0: variable_option-1;
						break;
					default:
						option = (option<=0)? 0: option-1;
						break;
				}
			}

			break;
		case 'J':
			{
				int rows = 0;
				r_cons_get_size (&rows);
				option += (rows - 5);
				if (option >= nfcns) {
					option = nfcns - 1;
				}
			}
			break;
		case 'K':
			{
				int rows = 0;
				r_cons_get_size (&rows);
				option -= (rows - 5);
				if (option < 0) {
					option = 0;
				}
			}
			break;
		case 'g':
			r_core_seek (core, addr, SEEK_SET);
			goto beach;
		case ' ':
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
	core->cons->event_resize = olde;
	level = 0;
	r_config_set_i (core->config, "asm.bytes", asmbytes);
}

R_API void r_core_seek_next(RCore *core, const char *type) {
	RListIter *iter;
	ut64 next = UT64_MAX;
	if (strstr (type, "opc")) {
		RAnalOp aop;
		if (r_anal_op (core->anal, &aop, core->offset, core->block, core->blocksize)) {
			next = core->offset + aop.size;
		} else {
			eprintf ("Invalid opcode\n");
		}
	} else
	if (strstr (type, "fun")) {
		RAnalFunction *fcni;
		r_list_foreach (core->anal->fcns, iter, fcni) {
			if (fcni->addr < next && fcni->addr > core->offset) {
				next = fcni->addr;
			}
		}
	} else
	if (strstr (type, "hit")) {
		const char *pfx = r_config_get (core->config, "search.prefix");
		RFlagItem *flag;
		r_list_foreach (core->flags->flags, iter, flag) {
			if (!strncmp (flag->name, pfx, strlen (pfx))) {
				if (flag->offset < next && flag->offset > core->offset) {
					next = flag->offset;
				}
			}
		}
	} else { // flags
		RFlagItem *flag;
		r_list_foreach (core->flags->flags, iter, flag) {
			if (flag->offset < next && flag->offset > core->offset) {
				next = flag->offset;
			}
		}
	}
	if (next != UT64_MAX) {
		r_core_seek (core, next, 1);
	}
}

R_API void r_core_seek_previous (RCore *core, const char *type) {
	RListIter *iter;
	ut64 next = 0;
	if (strstr (type, "opc")) {
		eprintf ("TODO: r_core_seek_previous (opc)\n");
	} else
	if (strstr (type, "fun")) {
		RAnalFunction *fcni;
		r_list_foreach (core->anal->fcns, iter, fcni) {
			if (fcni->addr > next && fcni->addr < core->offset)
				next = fcni->addr;
		}
	} else
	if (strstr (type, "hit")) {
		RFlagItem *flag;
		const char *pfx = r_config_get (core->config, "search.prefix");
		r_list_foreach (core->flags->flags, iter, flag) {
			if (!strncmp (flag->name, pfx, strlen (pfx)))
				if (flag->offset > next && flag->offset< core->offset)
					next = flag->offset;
		}
	} else { // flags
		RFlagItem *flag;
		r_list_foreach (core->flags->flags, iter, flag) {
			if (flag->offset > next && flag->offset < core->offset)
				next = flag->offset;
		}
	}
	if (next!=0)
		r_core_seek (core, next, 1);
}

//define the data at offset according to the type (byte, word...) n times
static void define_data_ntimes (RCore *core, ut64 off, int times, int type) {
	int i = 0;
	r_meta_cleanup (core->anal, off, off + core->blocksize);
	if (times < 0) {
		times = 1;
	}
	for (i = 0; i < times; i++, off += type) {
		r_meta_add (core->anal, R_META_TYPE_DATA, off, off + type, "");
	}
}

static bool isDisasmPrint(int mode) {
	return (mode == 1 || mode == 2);
}

static void handleHints(RCore *core) {
	//TODO extend for more anal hints
	int i = 0;
	char ch[64] = R_EMPTY;
	const char *lines[] = {"[dh]- Define anal hint:"
		," b [16,32,64]     set bits hint"
		, NULL};
	for (i = 0; lines[i]; i++) {
		r_cons_fill_line ();
		r_cons_printf ("\r%s\n", lines[i]);
	}
	r_cons_flush ();
	r_line_set_prompt ("anal hint: ");
	if (r_cons_fgets (ch, sizeof (ch) - 1, 0, NULL) > 0) {
		switch (ch[0]) {
		case 'b':
			{
			int bits = atoi (r_str_trim_head_tail (ch + 1));
			if (bits == 8 || bits == 16 || bits == 32 || bits == 64) {
				r_anal_hint_set_bits (core->anal, core->offset, bits);
			}
			}
			break;
		default:
			break;
		}
	}
}

R_API void r_core_visual_define (RCore *core, const char *args) {
	int plen = core->blocksize;
	ut64 off = core->offset;
	int i, h = 0, n, ch, ntotal = 0;
	ut8 *p = core->block;
	int rep = -1;
	char *name;
	int delta = 0;
	if (core->print->cur_enabled) {
		int cur = core->print->cur;
		if (core->print->ocur != -1) {
			plen = R_ABS (core->print->cur- core->print->ocur)+1;
			if (core->print->ocur<cur) {
				cur = core->print->ocur;
			}
		}
		off += cur;
		p += cur;
	}
	(void) r_cons_get_size (&h);
	h -= 19;
	if (h < 0) {
		h = 0;
		r_cons_clear00 ();
	} else {
		r_cons_gotoxy (0, h);
	}
	const char *lines[] = { ""
		,"[Vd]- Define current block as:"
		," $    define flag size"
		," 1    edit bits"
		," b    set as byte"
		," B    set as short word (2 bytes)"
		," c    set as code"
		," C    define flag color (fc)"
		," d    set as data"
		," e    end of function"
		," f    analyze function"
		," F    format"
		," i    immediate base (b(in), o(ct), d(ec), h(ex), s(tr))"
		," j    merge down (join this and next functions)"
		," k    merge up (join this and previous function)"
		," h    define anal hint"
		," m    manpage for current call"
		," n    rename flag used at cursor"
		," r    rename function"
		," R    find references /r"
		," s    set string"
		," S    set strings in current block"
		," u    undefine metadata here"
		," x    find xrefs to current address (./r)"
		," w    set as 32bit word"
		," W    set as 64bit word"
		," q    quit menu"
		," z    zone flag"
		, NULL};
	for (i = 0; lines[i]; i++) {
		r_cons_fill_line ();
		r_cons_printf ("\r%s\n", lines[i]);
	}
	r_cons_flush ();
	// get ESC+char, return 'hjkl' char
repeat:
	if (*args) {
		ch = *args;
		args++;
	} else {
		ch = r_cons_arrow_to_hjkl (r_cons_readchar ());
	}

	switch (ch) {
	case 'F':
		{
			char cmd[128];
			r_cons_show_cursor (true);
			r_core_cmd0 (core, "pf?");
			r_cons_flush ();
			r_line_set_prompt ("format: ");
			strcpy (cmd, "Cf 0 ");
			if (r_cons_fgets (cmd+5, sizeof (cmd)-6, 0, NULL) > 0) {
				r_core_cmd (core, cmd, 0);
				r_cons_set_raw (1);
				r_cons_show_cursor (false);
			}
		}
		break;
	case '1':
		edit_bits (core);
		break;
	case 'x':
		r_core_cmd0 (core, "/r $$");
		break;
	case 'i':
		{
			char str[128];
			r_cons_show_cursor (true);
			r_line_set_prompt ("immbase: ");
			if (r_cons_fgets (str, sizeof (str), 0, NULL) > 0) {
				r_core_cmdf (core, "ahi %s @ 0x%"PFMT64x, str, off);
			}
		}
		break;
	case 'b':
		if (plen != core->blocksize) {
			rep = plen / 2;
		}
		define_data_ntimes (core, off, rep, R_BYTE_DATA);
		break;
	case 'B':
		if (plen != core->blocksize) {
			rep = plen;
		}
		define_data_ntimes (core, off, rep, R_WORD_DATA);
		break;
	case 'w':
		if (plen != core->blocksize) {
			rep = plen / 4;
		}
		define_data_ntimes (core, off, rep, R_DWORD_DATA);
		break;
	case 'W':
		if (plen != core->blocksize) {
			rep = plen / 8;
		}
		define_data_ntimes (core, off, rep, R_QWORD_DATA);
		break;
	case 'm':
		{
			char *man = NULL;
			/* check for manpage */
			RAnalOp *op = r_core_anal_op (core, off);
			if (op) {
				if (op->jump != UT64_MAX) {
					RFlagItem *item = r_flag_get_i (core->flags, op->jump);
					if (item) {
						const char *ptr = r_str_lchr (item->name, '.');
						if (ptr)
							man = strdup (ptr+1);
					}
				}
				r_anal_op_free (op);
			}
			if (man) {
				char *p = strstr (man, "INODE");
				if (p) *p = 0;
				r_cons_clear();
				r_cons_flush();
				r_sys_cmdf ("man %s", man);
				free (man);
			}
			r_cons_any_key (NULL);
		}
		break;
	case 'n':
	{
		RAnalOp op;
		char *q = NULL;
		ut64 tgt_addr = UT64_MAX;
		if (!isDisasmPrint (core->printidx)) {
			break;
		}
		// TODO: get the aligned instruction even if the cursor is in the middle of it.
		r_anal_op (core->anal, &op, off,
			core->block + off - core->offset, 32);

		tgt_addr = op.jump != UT64_MAX ? op.jump : op.ptr;
		if (op.var) {
//			q = r_str_newf ("?i Rename variable %s to;afvn %s `?y`", op.var->name, op.var->name);
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, off, 0);
			if (fcn) {
				RAnalVar *bar = r_anal_var_get_byname (core->anal, fcn, op.var->name);
				if (!bar) {
					bar = r_anal_var_get_byname (core->anal, fcn, op.var->name);
					if (!bar) {
						bar = r_anal_var_get_byname (core->anal, fcn, op.var->name);
					}
				}
				if (bar) {
					char *newname = r_cons_input (sdb_fmt (0, "New variable name for '%s': ", bar->name));
					if (newname) {
						if (*newname) {
							r_anal_var_rename (core->anal, fcn->addr, bar->scope,
								bar->kind, bar->name, newname);
						}
						free (newname);
					}
				} else {
					eprintf ("Cannot find variable\n");
					r_sys_sleep (1);
				}
			} else {
				eprintf ("Cannot find function\n");
				r_sys_sleep (1);
			}
		} else if (tgt_addr != UT64_MAX) {
			RAnalFunction *fcn = r_anal_get_fcn_at (core->anal, tgt_addr, R_ANAL_FCN_TYPE_NULL);
			RFlagItem *f = r_flag_get_i (core->flags, tgt_addr);
			if (fcn) {
				q = r_str_newf ("?i Rename function %s to;afn `?y` 0x%"PFMT64x,
					fcn->name, tgt_addr);
			} else if (f) {
				q = r_str_newf ("?i Rename flag %s to;fr %s `?y`",
					f->name, f->name);
			} else {
				q = r_str_newf ("?i Create flag at 0x%"PFMT64x" named;f `?y` @ 0x%"PFMT64x,
					tgt_addr, tgt_addr);
			}
		}

		if (q) {
			r_core_cmd0 (core, q);
			free (q);
		}
		r_anal_op_fini (&op);
		break;
	}
	case 'C':
		{
			RFlagItem *item = r_flag_get_i (core->flags, off);
			if (item) {
				char cmd[128];
				r_cons_show_cursor (true);
				r_cons_flush ();
				r_line_set_prompt ("color: ");
				if (r_cons_fgets (cmd, sizeof (cmd)-1, 0, NULL) > 0) {
					r_flag_color (core->flags, item, cmd);
					r_cons_set_raw (1);
					r_cons_show_cursor (false);
				}
			} else {
				eprintf ("Sorry. No flag here\n");
				r_cons_any_key (NULL);
			}
		}
		break;
	case '$':
		{
			RFlagItem *item = r_flag_get_i (core->flags, off);
			if (item) {
				char cmd[128];
				r_cons_printf ("Current flag size is: %d\n", item->size);
				r_cons_show_cursor (true);
				r_cons_flush ();
				r_line_set_prompt ("new size: ");
				if (r_cons_fgets (cmd, sizeof (cmd)-1, 0, NULL) > 0) {
					item->size = r_num_math (core->num, cmd);
					r_cons_set_raw (1);
					r_cons_show_cursor (false);
				}
			} else {
				eprintf ("Sorry. No flag here\n");
				r_cons_any_key (NULL);
			}
		}
		break;
	case 'e':
		// set function size
		{
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, off, 0);
		if (!fcn) {
			fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
		}
		if (fcn) {
			RAnalOp op;
			ut64 size;
			if (r_anal_op (core->anal, &op, off, core->block+delta,
					core->blocksize-delta)) {
				size = off - fcn->addr + op.size;
				r_anal_fcn_resize (fcn, size);
			}
		}
		}
		break;
	case 'j':
		r_core_cmdf (core, "afm $$+$F @0x%08"PFMT64x, off);
		break;
	case 'k':
		eprintf ("TODO: merge up\n");
		r_cons_any_key (NULL);
		break;
	case 'h': // "Vdh"
		handleHints (core);
		//r_core_cmdf (core, "?i highlight;e scr.highlight=`?y` @ 0x%08"PFMT64x, off);
		break;
	case 'r': // "Vdr"
		r_core_cmdf (core, "?i new function name;afn `?y` @ 0x%08"PFMT64x, off);
		break;
	case 'z': // "Vdz"
		r_core_cmdf (core, "?i zone name;fz `?y` @ 0x%08"PFMT64x, off);
		break;
	case 'R': // "VdR"
		eprintf ("Finding references to 0x%08"PFMT64x" ...\n", off);
		r_core_cmdf (core, "./r 0x%08"PFMT64x" @ $S", off);
		break;
	case 'S':
		{
		int i, j;
		bool is_wide = false;
		do {
			n = r_str_nlen_w ((const char *)p + ntotal,
					plen - ntotal) + 1;
			if (n < 2) break;
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
				r_meta_add (core->anal, R_META_TYPE_STRING,
				  off + ntotal, off + (n * 2) + ntotal,
						   (const char *)name + 4);
			} else {
				r_meta_add (core->anal, R_META_TYPE_STRING,
				  off + ntotal, off + n + ntotal,
						   (const char *)name + 4);
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
		//handle wide strings
		//memcpy (name + 4, (const char *)p, n);
		if (is_wide) {
			r_meta_add (core->anal, R_META_TYPE_STRING, off,
				    off + (n * 2), (const char *)name + 4);
		} else {
			r_meta_add (core->anal, R_META_TYPE_STRING, off,
				    off + n, (const char *)name + 4);
		}
		r_name_filter (name, n + 10);
		r_flag_set (core->flags, name, off, n);
		free (name);
		}
		break;
	case 'd': // TODO: check
		r_meta_cleanup (core->anal, off, off+plen);
		r_meta_add (core->anal, R_META_TYPE_DATA, off, off+plen, "");
		break;
	case 'c': // TODO: check
		r_meta_cleanup (core->anal, off, off+plen);
		r_meta_add (core->anal, R_META_TYPE_CODE, off, off+plen, "");
		break;
	case 'u':
		r_core_anal_undefine (core, off);
		break;
	case 'f':
		{
			int funsize = 0;
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			if (fcn) {
				r_anal_fcn_resize (fcn, core->offset - fcn->addr);
			}
			//int depth = r_config_get_i (core->config, "anal.depth");
			if (core->print->cur_enabled) {
				if (core->print->ocur != -1) {
					funsize = 1 + R_ABS (core->print->cur - core->print->ocur);
				}
				//depth = 0;
			}
			r_cons_break_push (NULL, NULL);
			r_core_cmdf (core, "af @ 0x%08" PFMT64x, off); // required for thumb autodetection
			r_cons_break_pop ();
			if (funsize) {
				RAnalFunction *f = r_anal_get_fcn_in (core->anal, off, -1);
				r_anal_fcn_set_size (f, funsize);
			}
		}
		break;
	case 'Q':
	case 'q':
	default:
		if (IS_DIGIT(ch)) {
			if (rep < 0) {
				rep = 0;
			}
			rep = rep * 10 + atoi ((char *)&ch);
			goto repeat;
		}
		break;
	}
}

R_API void r_core_visual_colors(RCore *core) {
	char color[32], cstr[32];
	int ch, opt = 0, oopt = -1;
	const char *k;
	RColor rcolor;

	rcolor = r_cons_pal_get_i (opt);
	for (;;) {
		r_cons_clear ();
		k = r_cons_pal_get_name (opt);
		if (!k) {
			opt = 0;
			k = r_cons_pal_get_name (opt);
		}
		r_cons_gotoxy (0, 0);
		r_cons_rgb_str (cstr, &rcolor);
		if (r_cons_singleton ()->color < COLOR_MODE_16M) {
			rcolor.r &= 0xf;
			rcolor.g &= 0xf;
			rcolor.b &= 0xf;
		}
		sprintf (color, "rgb:%x%x%x", rcolor.r, rcolor.g, rcolor.b);
		r_cons_printf ("# Colorscheme %d - Use '.' and ':' to randomize palette\n"
			"# Press 'rRgGbB', 'jk' or 'q'\nec %s %s   # %d (%s)\n",
			opt, k, color, atoi (cstr+7), cstr+1);
		r_core_cmdf (core, "ec %s %s", k, color);
		char * res = r_core_cmd_str (core, "pd $r");
		int h, w = r_cons_get_size (&h);
		char *body = r_str_ansi_crop (res, 0, 0, w, h - 4);
		r_cons_printf("%s", body);
		r_cons_flush ();
		ch = r_cons_readchar ();
		ch = r_cons_arrow_to_hjkl (ch);
		switch (ch) {
#define CASE_RGB(x,X,y) \
	case x:y--;if(y>0x7f)y=0;break;\
	case X:y++;if(y>15)y=15;break;
		CASE_RGB ('R','r',rcolor.r);
		CASE_RGB ('G','g',rcolor.g);
		CASE_RGB ('B','b',rcolor.b);
		case 'Q':
		case 'q': return;
		case 'k': opt--; break;
		case 'j': opt++; break;
		case 'K': opt=0; break;
		case 'J': opt=0; break; // XXX must go to end
		case ':': r_cons_pal_random (); break;
		case '.':
			rcolor.r = r_num_rand (0xff);
			rcolor.g = r_num_rand (0xff);
			rcolor.b = r_num_rand (0xff);
			break;
		}
		if (opt != oopt) {
			rcolor = r_cons_pal_get_i (opt);
			oopt = opt;
		}
	}
}
