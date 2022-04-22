/* radare - LGPL - Copyright 2009-2022 - pancake */

#include <r_core.h>

#define NPF 5
#define PIDX (R_ABS (core->printidx % NPF))

static void visual_refresh(RCore *core);

// remove globals pls
static int obs = 0;
static int blocksize = 0;
static bool autoblocksize = true;
static int disMode = 0;
static int hexMode = 0;
static int printMode = 0;
static bool snowMode = false;
static RList *snows = NULL;
static int color = 1;
static int zoom = 0;

typedef struct {
	int x;
	int y;
} Snow;

#define KEY_ALTQ 0xc5

static const char *printfmtSingle[NPF] = {
	"xc",  // HEXDUMP
	"pd $r",  // ASSEMBLY
	"pxw 64@r:SP;dr=;drcq;pd $r",  // DEBUGGER
	"prc", // OVERVIEW
	"pss", // PC//  copypasteable views
};

static const char *printfmtColumns[NPF] = {
	"pCx",  // HEXDUMP // + pCw
	"pCd $r-1",  // ASSEMBLY
	"pCD",  // DEBUGGER
	"pCA", // OVERVIEW
	"pCc", // PC//  copypasteable views
};

// to print the stack in the debugger view
#define PRINT_HEX_FORMATS 10
#define PRINT_3_FORMATS 2
#define PRINT_4_FORMATS 9
#define PRINT_5_FORMATS 8

static int currentFormat = 0;
static int current0format = 0;
static const char *printHexFormats[PRINT_HEX_FORMATS] = {
	"px", "pxa", "pxr", "prx", "pxb", "pxh", "pxw", "pxq", "pxd", "pxr",
};
static int current3format = 0;
static const char *print3Formats[PRINT_3_FORMATS] = { //  not used at all. its handled by the pd format
	"pxw 64@r:SP;dr=;drcq;pd $r", // DEBUGGER
	"pCD"
};
static int current4format = 0;
static const char *print4Formats[PRINT_4_FORMATS] = {
	"prc", "p2", "prc=a", "pxAv", "pxx", "p=e $r-2", "pq 64", "pk 64", "pri",
};
static int current5format = 0;
static const char *print5Formats[PRINT_5_FORMATS] = {
	"pca", "pcA", "p8", "pcc", "pss", "pcp", "pcd", "pcj"
};

R_API void r_core_visual_applyHexMode(RCore *core, int hexMode) {
	currentFormat = R_ABS (hexMode) % PRINT_HEX_FORMATS;
	switch (currentFormat) {
	case 0: /* px */
	case 3: /* prx */
	case 6: /* pxw */
	case 9: /* pxr */
		r_config_set (core->config, "hex.compact", "false");
		r_config_set (core->config, "hex.comments", "true");
		break;
	case 1: /* pxa */
		r_config_set (core->config, "hex.compact", "false");
		r_config_set (core->config, "hex.comments", "true");
		break;
	case 4: /* pxb */
	case 7: /* pxq */
		r_config_set (core->config, "hex.compact", "true");
		r_config_set (core->config, "hex.comments", "true");
		break;
	case 2: /* pxr */
	case 5: /* pxh */
	case 8: /* pxd */
		r_config_set (core->config, "hex.compact", "false");
		r_config_set (core->config, "hex.comments", "false");
		break;
	}
}

R_API void r_core_visual_toggle_decompiler_disasm(RCore *core, bool for_graph, bool reset) {
	static RConfigHold *hold = NULL; // should be a tab-specific var
	if (hold) {
		r_config_hold_restore (hold);
		r_config_hold_free (hold);
		hold = NULL;
		return;
	}
	if (reset) {
		return;
	}
	hold = r_config_hold_new (core->config);
	r_config_hold (hold, "asm.hint.pos", "asm.cmt.col", "asm.offset", "asm.lines",
	"asm.indent", "asm.bytes", "asm.comments", "asm.dwarf", "asm.usercomments", "asm.instr", NULL);
	if (for_graph) {
		r_config_set (core->config, "asm.hint.pos", "-2");
		r_config_set (core->config, "asm.lines", "false");
		r_config_set (core->config, "asm.indent", "false");
	} else {
		r_config_set (core->config, "asm.hint.pos", "0");
		r_config_set (core->config, "asm.indent", "true");
		r_config_set (core->config, "asm.lines", "true");
	}
	r_config_set (core->config, "asm.cmt.col", "0");
	r_config_set (core->config, "asm.offset", "false");
	r_config_set (core->config, "asm.dwarf", "true");
	r_config_set (core->config, "asm.bytes", "false");
	r_config_set (core->config, "asm.comments", "false");
	r_config_set (core->config, "asm.usercomments", "true");
	r_config_set (core->config, "asm.instr", "false");
}

static void setcursor(RCore *core, bool cur) {
	int flags = core->print->flags; // wtf
	if (core->print->cur_enabled) {
		flags |= R_PRINT_FLAGS_CURSOR;
	} else {
		flags &= ~(R_PRINT_FLAGS_CURSOR);
	}
	core->print->cur_enabled = cur;
	if (core->print->cur == -1) {
		core->print->cur = 0;
	}
	r_print_set_flags (core->print, flags);
	core->print->col = core->print->cur_enabled? 1: 0;
}

R_API void r_core_visual_applyDisMode(RCore *core, int disMode) {
	currentFormat = R_ABS (disMode) % 5;
	switch (currentFormat) {
	case 0:
		r_config_set (core->config, "asm.pseudo", "false");
		r_config_set (core->config, "asm.bytes", "true");
		r_config_set (core->config, "asm.esil", "false");
		r_config_set (core->config, "emu.str", "false");
		r_config_set (core->config, "asm.emu", "false");
		break;
	case 1:
		r_config_set (core->config, "asm.pseudo", "false");
		r_config_set (core->config, "asm.bytes", "true");
		r_config_set (core->config, "asm.esil", "false");
		r_config_set (core->config, "asm.emu", "false");
		r_config_set (core->config, "emu.str", "true");
		break;
	case 2:
		r_config_set (core->config, "asm.pseudo", "true");
		r_config_set (core->config, "asm.bytes", "true");
		r_config_set (core->config, "asm.esil", "true");
		r_config_set (core->config, "emu.str", "true");
		r_config_set (core->config, "asm.emu", "true");
		break;
	case 3:
		r_config_set (core->config, "asm.pseudo", "false");
		r_config_set (core->config, "asm.bytes", "false");
		r_config_set (core->config, "asm.esil", "false");
		r_config_set (core->config, "asm.emu", "false");
		r_config_set (core->config, "emu.str", "true");
		break;
	case 4:
		r_config_set (core->config, "asm.pseudo", "true");
		r_config_set (core->config, "asm.bytes", "false");
		r_config_set (core->config, "asm.esil", "false");
		r_config_set (core->config, "asm.emu", "false");
		r_config_set (core->config, "emu.str", "true");
		break;
	}
}

static void nextPrintCommand(void) {
	current0format++;
	current0format %= PRINT_HEX_FORMATS;
	currentFormat = current0format;
}

static void prevPrintCommand(void) {
	current0format--;
	if (current0format < 0) {
		current0format = 0;
	}
	currentFormat = current0format;
}

static const char *stackPrintCommand(RCore *core) {
	if (current0format == 0) {
		if (r_config_get_i (core->config, "dbg.slow")) {
			return "pxr";
		}
		if (r_config_get_i (core->config, "stack.bytes")) {
			return "px";
		}
		switch (core->rasm->config->bits) {
		case 64: return "pxq"; break;
		case 32: return "pxw"; break;
		}
		return "px";
	}
	return printHexFormats[current0format % PRINT_HEX_FORMATS];
}

static const char *__core_visual_print_command(RCore *core) {
	if (core->visual.tabs) {
		RCoreVisualTab *tab = r_list_get_n (core->visual.tabs, core->visual.tab);
		if (tab && tab->name[0] == ':') {
			return tab->name + 1;
		}
	}
	if (r_config_get_i (core->config, "scr.dumpcols")) {
		free (core->stkcmd);
		core->stkcmd = r_str_new (stackPrintCommand (core));
		return printfmtColumns[PIDX];
	}
	return printfmtSingle[PIDX];
}

static bool __core_visual_gogo(RCore *core, int ch) {
	RIOMap *map;
	int ret = -1;
	switch (ch) {
	case 'g':
		if (core->io->va) {
			map = r_io_map_get_at (core->io, core->offset);
			if (!map) {
				RIOBank *bank = r_io_bank_get (core->io, core->io->bank);
				if (bank && r_list_length (bank->maprefs)) {
					map = r_io_map_get (core->io,
						((RIOMapRef *)r_list_get_top (bank->maprefs))->id);
				}
			}
			if (map) {
				r_core_seek (core, r_io_map_begin (map), true);
			}
		} else {
			r_core_seek (core, 0, true);
		}
		r_io_sundo_push (core->io, core->offset, r_print_get_cursor (core->print));
		return true;
	case 'G':
		map = r_io_map_get_at (core->io, core->offset);
		if (!map) {
			RIOBank *bank = r_io_bank_get (core->io, core->io->bank);
			if (bank && r_list_length (bank->maprefs)) {
				map = r_io_map_get (core->io,
					((RIOMapRef *)r_list_get_top (bank->maprefs))->id);
			}
		}
		if (map) {
			RPrint *p = core->print;
			int scr_rows;
			if (!p->consbind.get_size) {
				break;
			}
			(void)p->consbind.get_size (&scr_rows);
			ut64 scols = r_config_get_i (core->config, "hex.cols");
			ret = r_core_seek (core, r_io_map_end (map) - (scr_rows - 2) * scols, true);
		}
		if (ret != -1) {
			r_io_sundo_push (core->io, core->offset, r_print_get_cursor (core->print));
		}
		return true;
	}
	return false;
}

static const char *help_visual[] = {
	"?", "full help",
	"!", "enter panels",
	"a", "code analysis",
	"c", "toggle cursor",
	"d", "debugger / emulator",
	"e", "toggle configurations",
	"i", "insert / write",
	"m", "moving around (seeking)",
	"p", "print commands and modes",
	"v", "view management",
	NULL
};

static const char *help_msg_visual[] = {
	"?", "show visual mode help (short)",
	"??", "show visual mode help (full)",
	"$", "set the program counter to the current offset + cursor",
	"&", "rotate asm.bits between 8, 16, 32 and 64 applying hints",
	"%", "in cursor mode finds matching pair, otherwise toggle autoblocksz",
	"^", "seek to the beginning of the function",
	"!", "swap into visual panels mode",
	"TAB", "switch to the next print mode (or element in cursor mode)",
	"_", "enter the flag/comment/functions/.. hud (same as VF_)",
	"=", "set cmd.vprompt (top row)",
	"|", "set cmd.cprompt (right column)",
	".", "seek to program counter",
	"#", "toggle decompiler comments in disasm (see pdd* from r2dec)",
	"\\", "toggle visual split mode",
	"\"", "toggle the column mode (uses pC..)",
	"/", "in cursor mode search in current block",
	"(", "toggle snow",
	")", "toggle emu.str",
	":cmd", "run radare command",
	";[-]cmt", "add/remove comment",
	"0", "seek to beginning of current function",
	"[1-9]", "follow jmp/call identified by shortcut (like ;[1])",
	",file", "add a link to the text file",
	"/*+-[]", "change block size, [] = resize hex.cols",
	"<,>", "seek aligned to block size (in cursor slurp or dump files)",
	"a/A", "(a)ssemble code, visual (A)ssembler",
	"b", "browse evals, symbols, flags, mountpoints, evals, classes, ...",
	"B", "toggle breakpoint",
	"c/C", "toggle (c)ursor and (C)olors",
	"d[f?]", "define function, data, code, ..",
	"D", "enter visual diff mode (set diff.from/to)",
	"f/F", "set/unset or browse flags. f- to unset, F to browse, ..",
	"hjkl", "move around (or HJKL) (left-down-up-right)",
	"i", "insert hex or string (in hexdump) use tab to toggle",
	"I", "insert hexpair block ",
	"mK/'K", "mark/go to Key (any key)",
	"n/N", "seek next/prev function/flag/hit (scr.nkey)",
	"g", "go/seek to given offset (g[g/G]<enter> to seek begin/end of file)",
	"O", "toggle asm.pseudo and asm.esil",
	"p/P", "rotate print modes (hex, disasm, debug, words, buf)",
	"q", "back to radare shell",
	"r", "toggle callhints/jmphints/leahints",
	"R", "randomize color palette (ecr)",
	"sS", "step / step over",
	"tT", "tt new tab, t[1-9] switch to nth tab, t= name tab, t- close tab",
	"uU", "undo/redo seek",
	"v", "visual function/vars code analysis mode",
	"V", "(V)iew interactive ascii art graph (agfv)",
	"wW", "seek cursor to next/prev word",
	"xX", "show xrefs/refs of current function from/to data/code",
	"yY", "copy and paste selection",
	"z", "fold/unfold comments in disassembly",
	"Z", "shift-tab rotate print modes", // ctoggle zoom mode",
	"Enter", "follow address of jump/call",
	NULL
};

static const char *help_msg_visual_fn[] = {
	"F2", "toggle breakpoint",
	"F4", "run to cursor",
	"F7", "single step",
	"F8", "step over",
	"F9", "continue",
	NULL
};

static bool splitView = false;
static ut64 splitPtr = UT64_MAX;

#undef USE_THREADS
#define USE_THREADS 1

#if USE_THREADS

static void printSnow(RCore *core) {
	if (!snows) {
		snows = r_list_newf (free);
	}
	int i, h, w = r_cons_get_size (&h);
	int amount = r_num_rand (4);
	if (amount > 0) {
		for (i = 0; i < amount; i++) {
			Snow *snow = R_NEW (Snow);
			snow->x = r_num_rand (w);
			snow->y = 0;
			r_list_append (snows, snow);
		}
	}
	RListIter *iter, *iter2;
	Snow *snow;
	r_list_foreach_safe (snows, iter, iter2, snow) {
		int pos = (r_num_rand (3)) - 1;
		snow->x += pos;
		snow->y++;
		if (snow->x >= w) {
			r_list_delete (snows, iter);
			continue;
		}
		if (snow->y > h) {
			r_list_delete (snows, iter);
			continue;
		}
		r_cons_gotoxy (snow->x, snow->y);
		r_cons_printf ("*");
	}
	// r_cons_gotoxy (10 , 10);
	r_cons_flush ();
}
#endif

static void rotateAsmBits(RCore *core) {
	RAnalHint *hint = r_anal_hint_get (core->anal, core->offset);
	int bits = hint? hint->bits : r_config_get_i (core->config, "asm.bits");
	int retries = 4;
	while (retries > 0) {
		int nb = bits == 64 ? 8:
			bits == 32 ? 64:
			bits == 16 ? 32:
			bits == 8 ? 16: bits;
		if ((core->rasm->cur->bits & nb) == nb) {
			r_core_cmdf (core, "ahb %d", nb);
			break;
		}
		bits = nb;
		retries--;
	}
	r_anal_hint_free (hint);
}

static const char *rotateAsmemu(RCore *core) {
	const bool isEmuStr = r_config_get_i (core->config, "emu.str");
	const bool isEmu = r_config_get_i (core->config, "asm.emu");
	if (isEmu) {
		if (isEmuStr) {
			r_config_set (core->config, "emu.str", "false");
		} else {
			r_config_set (core->config, "asm.emu", "false");
		}
	} else {
		r_config_set (core->config, "emu.str", "true");
	}
	return "pd";
}

R_API void r_core_visual_showcursor(RCore *core, int x) {
	if (core && core->vmode) {
		r_cons_show_cursor (x);
		r_cons_enable_mouse (r_config_get_i (core->config, "scr.wheel"));
	} else {
		r_cons_enable_mouse (false);
	}
	r_cons_flush ();
}

static void printFormat(RCore *core, const int next) {
	switch (core->printidx) {
	case R_CORE_VISUAL_MODE_PX: // 0 // xc
		hexMode += next;
		r_core_visual_applyHexMode (core, hexMode);
		printfmtSingle[0] = printHexFormats[R_ABS (hexMode) % PRINT_HEX_FORMATS];
		break;
	case R_CORE_VISUAL_MODE_PD: // pd
		disMode += next;
		r_core_visual_applyDisMode (core, disMode);
		printfmtSingle[1] = rotateAsmemu (core);
		break;
	case R_CORE_VISUAL_MODE_DB: // debugger
		disMode += next;
		r_core_visual_applyDisMode (core, disMode);
		printfmtSingle[1] = rotateAsmemu (core);
		current3format += next;
		currentFormat = R_ABS (current3format) % PRINT_3_FORMATS;
		printfmtSingle[2] = print3Formats[currentFormat];
		break;
	case R_CORE_VISUAL_MODE_OV: // overview
		current4format += next;
		currentFormat = R_ABS (current4format) % PRINT_4_FORMATS;
		printfmtSingle[3] = print4Formats[currentFormat];
		break;
	case R_CORE_VISUAL_MODE_CD: // code
		current5format += next;
		currentFormat = R_ABS (current5format) % PRINT_5_FORMATS;
		printfmtSingle[4] = print5Formats[currentFormat];
		break;
	}
}

static inline void nextPrintFormat(RCore *core) {
	printFormat (core, 1);
}

static inline void prevPrintFormat(RCore *core) {
	printFormat (core, -1);
}

R_API int r_core_visual_hud(RCore *core) {
	const char *c = r_config_get (core->config, "hud.path");
	char *f = r_str_newf (R_JOIN_3_PATHS ("%s", R2_HUD, "main"),
		r_sys_prefix (NULL));
	int use_color = core->print->flags & R_PRINT_FLAGS_COLOR;
	char *homehud = r_str_home (R2_HOME_HUD);
	char *res = NULL;
	char *p = 0;
	r_cons_context ()->color_mode = use_color;

	r_core_visual_showcursor (core, true);
	if (c && *c && r_file_exists (c)) {
		res = r_cons_hud_file (c);
	}
	if (!res && homehud) {
		res = r_cons_hud_file (homehud);
	}
	if (!res && r_file_exists (f)) {
		res = r_cons_hud_file (f);
	}
	if (!res) {
		r_cons_message ("Cannot find hud file");
	}

	r_cons_clear ();
	if (res) {
		p = strchr (res, ';');
		r_cons_println (res);
		r_cons_flush ();
		if (p) {
			r_core_cmd0 (core, p + 1);
		}
		free (res);
	}
	r_core_visual_showcursor (core, false);
	r_cons_flush ();
	free (homehud);
	free (f);
	return (int) (size_t) p;
}

R_API void r_core_visual_jump(RCore *core, ut8 ch) {
	char chbuf[2];
	chbuf[0] = ch;
	chbuf[1] = '\0';
	ut64 off = r_core_get_asmqjmps (core, chbuf);
	if (off != UT64_MAX && off != UT32_MAX) {
		int delta = R_ABS ((st64) off - (st64) core->offset);
		r_io_sundo_push (core->io, core->offset, r_print_get_cursor (core->print));
		if (core->print->cur_enabled && delta < 100) {
			core->print->cur = delta;
		} else {
			r_core_visual_seek_animation (core, off);
			core->print->cur = 0;
		}
		r_core_block_read (core);
	}
}

// TODO: merge with r_cons_cmd_help
R_API void r_core_visual_append_help(RStrBuf *p, const char *title, const char **help) {
	RCons *cons = r_cons_singleton ();
	bool use_color = cons->context->color_mode;
	const char
		*pal_input_color = use_color ? cons->context->pal.input : "",
		*pal_args_color = use_color ? cons->context->pal.args : "",
		*pal_help_color = use_color ? cons->context->pal.help : "",
		*pal_reset = use_color ? cons->context->pal.reset : "";
	int i, max_length = 0, padding = 0;
	const char *help_cmd = NULL, *help_desc = NULL;

	// calculate padding for description text in advance
	for (i = 0; help[i]; i += 2) {
		max_length = R_MAX (max_length, strlen (help[i]));
	}

	/* Usage header */
	r_strbuf_appendf (p, "%s%s%s\n",
		pal_args_color, title, pal_reset);

	/* Body of help text, indented */
	for (i = 0; help[i]; i += 2) {
		help_cmd  = help[i + 0];
		help_desc = help[i + 1];

		padding = max_length - (strlen (help[i]));
		r_strbuf_appendf (p, "| %s%s%*s  %s%s%s\n",
			pal_input_color, help_cmd,
			padding, "",
			pal_help_color, help_desc, pal_reset);
	}
}

static int visual_help(RCore *core) {
	int ret = 0;
	RStrBuf *p, *q;
repeat:
	p = r_strbuf_new (NULL);
	q = r_strbuf_new (NULL);
	if (!p) {
		return 0;
	}
	r_cons_clear00 ();
	r_core_visual_append_help (q, "Visual Mode Help (short)", help_visual);
	r_cons_printf ("%s", r_strbuf_get (q));
	r_cons_flush ();
	switch (r_cons_readchar ()) {
	case 'q':
		r_strbuf_free (p);
		r_strbuf_free (q);
		return ret;
	case '!':
		r_core_panels_root (core, core->panels_root);
		break;
	case '?':
		r_core_visual_append_help (p, "Visual Mode Help (full)", help_msg_visual);
		r_core_visual_append_help (p, "Function Keys Defaults  # Use `e key.` to owerwrite", help_msg_visual_fn);
		ret = r_cons_less_str (r_strbuf_get (p), "?");
		break;
	case 'v':
		r_strbuf_appendf (p, "Visual Views:\n\n");
		r_strbuf_appendf (p,
			" \\     toggle horizonal split mode\n"
			" tt     create a new tab (same as t+)\n"
			" t=     give a name to the current tab\n"
			" t-     close current tab\n"
			" th     select previous tab (same as tj)\n"
			" tl     select next tab (same as tk)\n"
			" t[1-9] select nth tab\n"
			" C   -> rotate scr.color=0,1,2,3\n"
			" R   -> rotate color theme with ecr command which honors scr.randpal\n"
		);
		ret = r_cons_less_str (r_strbuf_get (p), "?");
		break;
	case 'p':
		r_strbuf_appendf (p, "Visual Print Modes:\n\n");
		r_strbuf_appendf (p,
			" pP  -> change to the next/previous print mode (hex, dis, ..)\n"
			" TAB -> rotate between all the configurations for the current print mode\n"
		);
		ret = r_cons_less_str (r_strbuf_get (p), "?");
		break;
	case 'e':
		r_strbuf_appendf (p, "Visual Evals:\n\n");
		r_strbuf_appendf (p,
			" E      toggle asm.hint.lea\n"
			" &      rotate asm.bits=16,32,64\n"
		);
		ret = r_cons_less_str (r_strbuf_get (p), "?");
		break;
	case 'c':
		setcursor (core, !core->print->cur_enabled);
		r_strbuf_free (p);
		return ret;
	case 'i':
		r_strbuf_appendf (p, "Visual Insertion Help:\n\n");
		r_strbuf_appendf (p,
			" i   -> insert bits, bytes or text depending on view\n"
			" a   -> assemble instruction and write the bytes in the current offset\n"
			" A   -> visual assembler\n"
			" +   -> increment value of byte\n"
			" -   -> decrement value of byte\n"
		);
		ret = r_cons_less_str (r_strbuf_get (p), "?");
		break;
	case 'd':
		r_strbuf_appendf (p, "Visual Debugger Help:\n\n");
		r_strbuf_appendf (p,
			" $   -> set the program counter (PC register)\n"
			" s   -> step in\n"
			" S   -> step over\n"
			" B   -> toggle breakpoint\n"
			" :dc -> continue\n"
		);
		ret = r_cons_less_str (r_strbuf_get (p), "?");
		break;
	case 'm':
		r_strbuf_appendf (p, "Visual Moving Around:\n\n");
		r_strbuf_appendf (p,
			" g        type flag/offset/register name to seek\n"
			" hl       seek to the next/previous byte\n"
			" jk       seek to the next row (core.offset += hex.cols)\n"
			" JK       seek one page down\n"
			" ^        seek to the beginning of the current map\n"
			" $        seek to the end of the current map\n"
			" c        toggle cursor mode (use hjkl to move and HJKL to select a range)\n"
			" mK/'K    mark/go to Key (any key)\n"
		);
		ret = r_cons_less_str (r_strbuf_get (p), "?");
		break;
	case 'a':
		r_strbuf_appendf (p, "Visual Analysis:\n\n");
		r_strbuf_appendf (p,
			" df -> define function\n"
			" du -> undefine function\n"
			" dc -> define as code\n"
			" dw -> define as dword (32bit)\n"
			" dw -> define as qword (64bit)\n"
			" dd -> define current block or selected bytes as data\n"
			" V  -> view graph (same as press the 'space' key)\n"
		);
		ret = r_cons_less_str (r_strbuf_get (p), "?");
		break;
	}
	r_strbuf_free (p);
	r_strbuf_free (q);
	goto repeat;
}

static void prompt_read(const char *p, char *buf, int buflen) {
	if (!buf || buflen < 1) {
		return;
	}
	*buf = 0;
	r_line_set_prompt (p);
	r_core_visual_showcursor (NULL, true);
	r_cons_fgets (buf, buflen, 0, NULL);
	r_core_visual_showcursor (NULL, false);
}

static void reset_print_cur(RPrint *p) {
	p->cur = 0;
	p->ocur = -1;
}

static bool __holdMouseState(RCore *core) {
	bool m = r_cons_singleton ()->mouse;
	r_cons_enable_mouse (false);
	return m;
}

static void backup_current_addr(RCore *core, ut64 *addr, ut64 *bsze, ut64 *newaddr) {
	*addr = core->offset;
	*bsze = core->blocksize;
	if (core->print->cur_enabled) {
		if (core->print->ocur != -1) {
			int newsz = core->print->cur - core->print->ocur;
			*newaddr = core->offset + core->print->ocur;
			r_core_block_size (core, newsz);
		} else {
			*newaddr = core->offset + core->print->cur;
		}
		r_core_seek (core, *newaddr, true);
	}
}

static void restore_current_addr(RCore *core, ut64 addr, ut64 bsze, ut64 newaddr) {
	bool restore_seek = true;
	if (core->offset != newaddr) {
		bool cursor_moved = false;
		// when new address is in the screen bounds, just move
		// the cursor if enabled and restore seek
		if (core->print->cur != -1 && core->print->screen_bounds > 1) {
			if (core->offset >= addr &&
			    core->offset < core->print->screen_bounds) {
				core->print->ocur = -1;
				core->print->cur = core->offset - addr;
				cursor_moved = true;
			}
		}

		if (!cursor_moved) {
			restore_seek = false;
			reset_print_cur (core->print);
		}
	}

	if (core->print->cur_enabled) {
		if (restore_seek) {
			r_core_seek (core, addr, true);
			r_core_block_size (core, bsze);
		}
	}
}

R_API void r_core_visual_prompt_input(RCore *core) {
	ut64 addr, bsze, newaddr = 0LL;
	int ret, h;
	(void) r_cons_get_size (&h);
	bool mouse_state = __holdMouseState(core);
	r_cons_gotoxy (0, h);
	r_cons_reset_colors ();
	//r_cons_printf ("\nPress <enter> to return to Visual mode.\n");
	r_cons_show_cursor (true);
	core->vmode = false;

	int curbs = core->blocksize;
	if (autoblocksize) {
		r_core_block_size (core, obs);
	}
	backup_current_addr (core, &addr, &bsze, &newaddr);
	do {
		ret = r_core_visual_prompt (core);
	} while (ret);
	restore_current_addr (core, addr, bsze, newaddr);
	if (autoblocksize) {
		obs = core->blocksize;
		r_core_block_size (core, curbs);
	}

	r_cons_show_cursor (false);
	core->vmode = true;
	r_cons_enable_mouse (mouse_state && r_config_get_i (core->config, "scr.wheel"));
	r_cons_show_cursor (true);
}

R_API int r_core_visual_prompt(RCore *core) {
	char buf[1024];
	int ret;
	if (PIDX != 2) {
		core->seltab = 0;
	}
#if __UNIX__
	r_line_set_prompt (Color_RESET ":> ");
#else
	r_line_set_prompt (":> ");
#endif
	r_core_visual_showcursor (core, true);
	r_cons_fgets (buf, sizeof (buf), 0, NULL);
	if (!strcmp (buf, "q")) {
		ret = false;
	} else if (*buf) {
		r_line_hist_add (buf);
		r_core_cmd (core, buf, 0);
		r_cons_echo (NULL);
		r_cons_flush ();
		ret = true;
		if (r_config_get_b (core->config, "cfg.debug")) {
			r_core_cmd (core, ".dr*", 0);
		}
	} else {
		ret = false;
		//r_cons_any_key (NULL);
		r_cons_clear00 ();
		r_core_visual_showcursor (core, false);
	}
	return ret;
}

static void visual_single_step_in(RCore *core) {
	if (r_config_get_b (core->config, "cfg.debug")) {
		if (core->print->cur_enabled) {
			// dcu 0xaddr
			r_core_cmdf (core, "dcu 0x%08"PFMT64x, core->offset + core->print->cur);
			core->print->cur_enabled = 0;
		} else {
			r_core_cmd (core, "ds", 0);
			r_core_cmd (core, ".dr*", 0);
		}
	} else {
		r_core_cmd (core, "aes", 0);
		r_core_cmd (core, ".ar*", 0);
	}
}

static void __core_visual_step_over(RCore *core) {
	bool io_cache = r_config_get_i (core->config, "io.cache");
	r_config_set_i (core->config, "io.cache", false);
	if (r_config_get_b (core->config, "cfg.debug")) {
		if (core->print->cur_enabled) {
			r_core_cmd (core, "dcr", 0);
			core->print->cur_enabled = 0;
		} else {
			r_core_cmd (core, "dso", 0);
			r_core_cmd (core, ".dr*", 0);
		}
	} else {
		r_core_cmd (core, "aeso", 0);
		r_core_cmd (core, ".ar*", 0);
	}
	r_config_set_i (core->config, "io.cache", io_cache);
}

static void visual_breakpoint(RCore *core) {
	r_core_cmd (core, "dbs $$", 0);
}

static void visual_continue(RCore *core) {
	if (r_config_get_b (core->config, "cfg.debug")) {
		r_core_cmd (core, "dc", 0);
	} else {
		r_core_cmd (core, "aec;.ar*", 0);
	}
}

static int visual_nkey(RCore *core, int ch) {
	const char *cmd;
	ut64 oseek = UT64_MAX;
	if (core->print->ocur == -1) {
		oseek = core->offset;
		r_core_seek (core, core->offset + core->print->cur, false);
	}

	switch (ch) {
	case R_CONS_KEY_F1:
		cmd = r_config_get (core->config, "key.f1");
		if (cmd && *cmd) {
			ch = r_core_cmd0 (core, cmd);
		} else {
			visual_help (core);
		}
		break;
	case R_CONS_KEY_F2:
		cmd = r_config_get (core->config, "key.f2");
		if (cmd && *cmd) {
			ch = r_core_cmd0 (core, cmd);
		} else {
			visual_breakpoint (core);
		}
		break;
	case R_CONS_KEY_F3:
		cmd = r_config_get (core->config, "key.f3");
		if (cmd && *cmd) {
			ch = r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F4:
		cmd = r_config_get (core->config, "key.f4");
		if (cmd && *cmd) {
			ch = r_core_cmd0 (core, cmd);
		} else {
			if (core->print->cur_enabled) {
				// dcu 0xaddr
				r_core_cmdf (core, "dcu 0x%08"PFMT64x, core->offset + core->print->cur);
				core->print->cur_enabled = 0;
			}
		}
		break;
	case R_CONS_KEY_F5:
		cmd = r_config_get (core->config, "key.f5");
		if (cmd && *cmd) {
			ch = r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F6:
		cmd = r_config_get (core->config, "key.f6");
		if (cmd && *cmd) {
			ch = r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F7:
		cmd = r_config_get (core->config, "key.f7");
		if (cmd && *cmd) {
			ch = r_core_cmd0 (core, cmd);
		} else {
			visual_single_step_in (core);
		}
		break;
	case R_CONS_KEY_F8:
		cmd = r_config_get (core->config, "key.f8");
		if (cmd && *cmd) {
			ch = r_core_cmd0 (core, cmd);
		} else {
			__core_visual_step_over (core);
		}
		break;
	case R_CONS_KEY_F9:
		cmd = r_config_get (core->config, "key.f9");
		if (cmd && *cmd) {
			ch = r_core_cmd0 (core, cmd);
		} else {
			visual_continue (core);
		}
		break;
	case R_CONS_KEY_F10:
		cmd = r_config_get (core->config, "key.f10");
		if (cmd && *cmd) {
			ch = r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F11:
		cmd = r_config_get (core->config, "key.f11");
		if (cmd && *cmd) {
			ch = r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F12:
		cmd = r_config_get (core->config, "key.f12");
		if (cmd && *cmd) {
			ch = r_core_cmd0 (core, cmd);
		}
		break;
	}
	if (oseek != UT64_MAX) {
		r_core_seek (core, oseek, false);
	}
	return ch;
}

static void setdiff(RCore *core) {
	char from[64], to[64];
	prompt_read ("diff from: ", from, sizeof (from));
	r_config_set (core->config, "diff.from", from);
	prompt_read ("diff to: ", to, sizeof (to));
	r_config_set (core->config, "diff.to", to);
}

static void findPair(RCore *core) {
	ut8 buf[256];
	int i, len, d = core->print->cur + 1;
	int delta = 0;
	const ut8 *p, *q = NULL;
	const char *keys = "{}[]()<>";
	ut8 ch = core->block[core->print->cur];

	p = (const ut8 *) strchr (keys, ch);
	if (p) {
		char p_1 = 0;
		if ((const char *) p > keys) {
			p_1 = p[-1];
		}
		delta = (size_t) (p - (const ut8 *) keys);
		ch = (delta % 2 && p != (const ut8 *) keys)? p_1: p[1];
	}
	len = 1;
	buf[0] = ch;

	if (p && (delta % 2)) {
		for (i = d - 1; i >= 0; i--) {
			if (core->block[i] == ch) {
				q = core->block + i;
				break;
			}
		}
	} else {
		q = r_mem_mem (core->block + d, core->blocksize - d,
			(const ut8 *) buf, len);
		if (!q) {
			q = r_mem_mem (core->block, R_MIN (core->blocksize, d),
				(const ut8 *) buf, len);
		}
	}
	if (q) {
		core->print->cur = (int) (size_t) (q - core->block);
		core->print->ocur = -1;
		r_core_visual_showcursor (core, true);
	}
}

static void findNextWord(RCore *core) {
	int i, d = core->print->cur_enabled? core->print->cur: 0;
	for (i = d + 1; i < core->blocksize; i++) {
		switch (core->block[i]) {
		case ' ':
		case '.':
		case '\t':
		case '\n':
			if (core->print->cur_enabled) {
				core->print->cur = i + 1;
				core->print->ocur = -1;
				r_core_visual_showcursor (core, true);
			} else {
				r_core_seek (core, core->offset + i + 1, true);
			}
			return;
		}
	}
}

static int isSpace(char ch) {
	switch (ch) {
	case ' ':
	case '.':
	case ',':
	case '\t':
	case '\n':
		return 1;
	}
	return 0;
}

static void findPrevWord(RCore *core) {
	int i = core->print->cur_enabled? core->print->cur: 0;
	while (i > 1) {
		if (isSpace (core->block[i])) {
			i--;
		} else if (isSpace (core->block[i - 1])) {
			i -= 2;
		} else {
			break;
		}
	}
	for (; i >= 0; i--) {
		if (isSpace (core->block[i])) {
			if (core->print->cur_enabled) {
				core->print->cur = i + 1;
				core->print->ocur = -1;
				r_core_visual_showcursor (core, true);
			}
			break;
		}
	}
}

// TODO: integrate in '/' command with search.inblock ?
static void visual_search(RCore *core) {
	const ut8 *p;
	int len, d = core->print->cur;
	char str[128], buf[sizeof (str) * 2 + 1];

	r_line_set_prompt ("search byte/string in block: ");
	r_cons_fgets (str, sizeof (str), 0, NULL);
	len = r_hex_str2bin (str, (ut8 *) buf);
	if (*str == '"') {
		r_str_ncpy (buf, str + 1, sizeof (buf));
		len = strlen (buf);
		char *e = buf + len - 1;
		if (e > buf && *e == '"') {
			*e = 0;
			len--;
		}
	} else if (len < 1) {
		r_str_ncpy (buf, str, sizeof (buf));
		len = strlen (buf);
	}
	p = r_mem_mem (core->block + d, core->blocksize - d,
		(const ut8 *) buf, len);
	if (p) {
		core->print->cur = (int) (size_t) (p - core->block);
		if (len > 1) {
			core->print->ocur = core->print->cur + len - 1;
		} else {
			core->print->ocur = -1;
		}
		r_core_visual_showcursor (core, true);
		eprintf ("Found in offset 0x%08"PFMT64x" + %d\n", core->offset, core->print->cur);
		r_cons_any_key (NULL);
	} else {
		eprintf ("Cannot find bytes.\n");
		r_cons_any_key (NULL);
		r_cons_clear00 ();
	}
}

R_API void r_core_visual_show_char(RCore *core, char ch) {
	if (r_config_get_i (core->config, "scr.feedback") < 2) {
		return;
	}
	if (!IS_PRINTABLE (ch)) {
		return;
	}
	r_cons_gotoxy (1, 2);
	r_cons_printf (".---.\n");
	r_cons_printf ("| %c |\n", ch);
	r_cons_printf ("'---'\n");
	r_cons_flush ();
	r_sys_sleep (1);
}

R_API void r_core_visual_seek_animation(RCore *core, ut64 addr) {
	r_core_seek (core, addr, true);
	if (r_config_get_i (core->config, "scr.feedback") < 1) {
		return;
	}
	if (core->offset == addr) {
		return;
	}
	r_cons_gotoxy (1, 2);
	if (addr > core->offset) {
		r_cons_printf (".----.\n");
		r_cons_printf ("| \\/ |\n");
		r_cons_printf ("'----'\n");
	} else {
		r_cons_printf (".----.\n");
		r_cons_printf ("| /\\ |\n");
		r_cons_printf ("'----'\n");
	}
	r_cons_flush ();
	r_sys_usleep (90000);
}

static void setprintmode(RCore *core, int n) {
	RAsmOp op;

	if (n > 0) {
		core->printidx = R_ABS ((core->printidx + 1) % NPF);
	} else {
		if (core->printidx) {
			core->printidx--;
		} else {
			core->printidx = NPF - 1;
		}
	}
	switch (core->printidx) {
	case R_CORE_VISUAL_MODE_PD:
	case R_CORE_VISUAL_MODE_DB:
		r_asm_op_init (&op);
		r_asm_disassemble (core->rasm, &op, core->block, R_MIN (32, core->blocksize));
		r_asm_op_fini (&op);
		break;
	default:
		break;
	}
}

#define OPDELTA 32
static ut64 prevop_addr(RCore *core, ut64 addr) {
	ut8 buf[OPDELTA * 2];
	ut64 target, base;
	RAnalBlock *bb;
	RAnalOp op;
	int len, ret, i;
	int minop = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MIN_OP_SIZE);
	int maxop = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MAX_OP_SIZE);

	if (minop == maxop) {
		if (minop == -1) {
			return addr - 4;
		}
		return addr - minop;
	}

	// let's see if we can use anal info to get the previous instruction
	// TODO: look in the current basicblock, then in the current function
	// and search in all functions only as a last chance, to try to speed
	// up the process.
	bb = r_anal_bb_from_offset (core->anal, addr - minop);
	if (bb) {
		ut64 res = r_anal_bb_opaddr_at (bb, addr - minop);
		if (res != UT64_MAX) {
			if (res < addr && addr - res <= maxop) {
				return res;
			}
		}
	}
	// if we anal info didn't help then fallback to the dumb solution.
	int midflags = r_config_get_i (core->config, "asm.flags.middle");
	target = addr;
	base = target > OPDELTA ? target - OPDELTA : 0;
	r_io_read_at (core->io, base, buf, sizeof (buf));
	for (i = 0; i < sizeof (buf); i++) {
		ret = r_anal_op (core->anal, &op, base + i,
			buf + i, sizeof (buf) - i, R_ANAL_OP_MASK_BASIC);
		if (ret) {
			len = op.size;
			if (len < 1) {
				len = 1;
			}
			r_anal_op_fini (&op); // XXX
			if (midflags >= R_MIDFLAGS_REALIGN) {
				int skip_bytes = r_core_flag_in_middle (core, base + i, len, &midflags);
				if (skip_bytes && base + i + skip_bytes < target) {
					i += skip_bytes - 1;
					continue;
				}
			}
		} else {
			len = 1;
		}
		if (target <= base + i + len) {
			return base + i;
		}
		i += len - 1;
	}
	return target > 4 ? target - 4 : 0;
}

//  Returns true if we can use analysis to find the previous operation address,
//  sets prev_addr to the value of the instruction numinstrs back.
//  If we can't use the anal, then set prev_addr to UT64_MAX and return false;
R_API bool r_core_prevop_addr(RCore *core, ut64 start_addr, int numinstrs, ut64 *prev_addr) {
	// Check that we're in a bb, otherwise this prevop stuff won't work.
	RAnalBlock *bb = r_anal_bb_from_offset (core->anal, start_addr);
	if (bb) {
		if (r_anal_bb_opaddr_at (bb, start_addr) != UT64_MAX) {
			int i;
			for (i = 0; i < numinstrs; i++) {
				*prev_addr = prevop_addr (core, start_addr);
				start_addr = *prev_addr;
			}
			return true;
		}
	}
	// Dang! not in a bb, return false and fallback to other methods.
	*prev_addr = UT64_MAX;
	return false;
}

//  Like r_core_prevop_addr(), but also uses fallback from prevop_addr() if
//  no anal info is available.
R_API ut64 r_core_prevop_addr_force(RCore *core, ut64 start_addr, int numinstrs) {
	int i;
	for (i = 0; i < numinstrs; i++) {
		start_addr = prevop_addr (core, start_addr);
	}
	return start_addr;
}

R_API int r_line_hist_offset_up(RLine *line) {
	RCore *core = line->user;
	RIOUndo *undo = &core->io->undo;
	if (line->offset_hist_index <= -undo->undos) {
		return false;
	}
	line->offset_hist_index--;
	ut64 off = undo->seek[undo->idx + line->offset_hist_index].off;
	RFlagItem *f = r_flag_get_at (core->flags, off, false);
	char *command;
	if (f && f->offset == off && f->offset > 0) {
		command = r_str_newf ("%s", f->name);
	} else {
		command = r_str_newf ("0x%"PFMT64x, off);
	}
	strncpy (line->buffer.data, command, R_LINE_BUFSIZE - 1);
	line->buffer.index = line->buffer.length = strlen (line->buffer.data);
	free (command);
	return true;
}

R_API int r_line_hist_offset_down(RLine *line) {
	RCore *core = line->user;
	RIOUndo *undo = &core->io->undo;
	if (line->offset_hist_index >= undo->redos) {
		return false;
	}
	line->offset_hist_index++;
	if (line->offset_hist_index == undo->redos) {
		line->buffer.data[0] = '\0';
		line->buffer.index = line->buffer.length = 0;
		return false;
	}
	ut64 off = undo->seek[undo->idx + line->offset_hist_index].off;
	RFlagItem *f = r_flag_get_at (core->flags, off, false);
	char *command = (f && f->offset == off && f->offset > 0)
		? r_str_newf ("%s", f->name)
		: r_str_newf ("0x%"PFMT64x, off);
	r_str_ncpy (line->buffer.data, command, R_LINE_BUFSIZE - 1);
	line->buffer.index = line->buffer.length = strlen (line->buffer.data);
	free (command);
	return true;
}

R_API void r_core_visual_offset(RCore *core) {
	ut64 addr, bsze, newaddr = 0LL;
	char buf[256];

	backup_current_addr (core, &addr, &bsze, &newaddr);
	core->cons->line->prompt_type = R_LINE_PROMPT_OFFSET;
	r_line_set_hist_callback (core->cons->line,
		&r_line_hist_offset_up,
		&r_line_hist_offset_down);
	r_line_set_prompt ("[offset]> ");
	strcpy (buf, "s ");
	if (r_cons_fgets (buf + 2, sizeof (buf) - 2, 0, NULL) > 0) {
		if (!strcmp (buf + 2, "g") || !strcmp (buf + 2, "G")) {
			__core_visual_gogo (core, buf[2]);
		} else {
			if (buf[2] == '.') {
				buf[1] = '.';
			}
			r_core_cmd0 (core, buf);
			restore_current_addr (core, addr, bsze, newaddr);
		}
	}
	r_line_set_hist_callback (core->cons->line, &r_line_hist_cmd_up, &r_line_hist_cmd_down);
	core->cons->line->prompt_type = R_LINE_PROMPT_DEFAULT;
}

R_API int r_core_visual_prevopsz(RCore *core, ut64 addr) {
	ut64 prev_addr = prevop_addr (core, addr);
	return addr - prev_addr;
}

static void addComment(RCore *core, ut64 addr) {
	char buf[1024];
	r_cons_printf ("Enter comment for reference:\n");
	r_core_visual_showcursor (core, true);
	r_cons_flush ();
	r_cons_set_raw (false);
	r_line_set_prompt (":> ");
	r_cons_enable_mouse (false);
	if (r_cons_fgets (buf, sizeof (buf), 0, NULL) < 0) {
		buf[0] = '\0';
	}
	r_core_cmdf (core, "\"CC %s\"@0x%08"PFMT64x, buf, addr);
	r_core_visual_showcursor (core, false);
	r_cons_set_raw (true);
}

static void add_ref(RCore *core) {
	// read name provided by user
	char *fn = r_cons_input ("Reference From: ");
	if (R_STR_ISNOTEMPTY (fn)) {
		r_core_cmdf (core, "ax $$ %s", fn);
	}
	free (fn);
}

static bool delete_ref(RCore *core, RList *xrefs, int choice, int xref) {
	RAnalRef *refi = r_list_get_n (xrefs, choice);
	if (refi) {
		if (core->print->cur_enabled) {
			core->print->cur = 0;
		}
		return r_anal_xref_del (core->anal, refi->addr, refi->at);
	}
	return false;
}
static int follow_ref(RCore *core, RList *xrefs, int choice, int xref) {
	RAnalRef *refi = r_list_get_n (xrefs, choice);
	if (refi) {
		if (core->print->cur_enabled) {
			core->print->cur = 0;
		}
		ut64 addr = refi->addr;
		r_io_sundo_push (core->io, core->offset, -1);
		r_core_seek (core, addr, true);
		return 1;
	}
	return 0;
}

static const char *help_msg_visual_xref[] = {
	"j/k",	"select next or previous item (use arrows)",
	"J/K",	"scroll by 10 refs",
	"g/G",	"scroll to top / bottom",
	"p/P",	"rotate between various print modes",
	":",	"run r2 command",
	"/",	"highlight given word",
	"?",	"show this help message",
	"x/<",	"show xrefs",
	"X/>",	"show refs",
	"l/Space/Enter",	"seek to ref or xref",
	"Tab",	"toggle between address and function references",
	"h/q/Q",	"quit xref mode",
	NULL
};

R_API int r_core_visual_refs(RCore *core, bool xref, bool fcnInsteadOfAddr) {
	ut64 cur_ref_addr = UT64_MAX;
	int ret = 0;
	char ch;
	int count = 0;
	RList *xrefs = NULL;
	RAnalRef *refi;
	RListIter *iter;
	int skip = 0;
	int idx = 0;
	char cstr[32];
	ut64 addr = core->offset;
	bool xrefsMode = fcnInsteadOfAddr;
	int lastPrintMode = 3;
	if (core->print->cur_enabled) {
		addr += core->print->cur;
	}
repeat:
	r_list_free (xrefs);
	if (xrefsMode) {
		RAnalFunction *fun = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
		if (fun) {
			if (xref) { //  function xrefs
				xrefs = r_anal_xrefs_get (core->anal, addr);
				//XXX xrefs = r_anal_function_get_xrefs (core->anal, fun);
				// this function is buggy so we must get the xrefs of the addr
			} else { // functon refs
				xrefs = r_anal_function_get_refs (fun);
			}
		} else {
			xrefs = NULL;
		}
	} else {
		if (xref) { // address xrefs
			xrefs = r_anal_xrefs_get (core->anal, addr);
		} else { // address refs
			xrefs = r_anal_refs_get (core->anal, addr);
		}
	}

	r_cons_clear00 ();
	r_cons_gotoxy (1, 1);
	{
		char *address = (core->dbg->bits & R_SYS_BITS_64)
			? r_str_newf ("0x%016"PFMT64x, addr)
			: r_str_newf ("0x%08"PFMT64x, addr);
		r_cons_printf ("[%s%srefs]> %s # (TAB/jk/q/?) ",
				xrefsMode? "fcn.": "addr.", xref ? "x": "", address);
		free (address);
	}
	if (!xrefs || r_list_empty (xrefs)) {
		r_list_free (xrefs);
		xrefs = NULL;
		r_cons_printf ("\n\n(no %srefs)\n", xref ? "x": "");
	} else {
		int h, w = r_cons_get_size (&h);
		bool asm_bytes = r_config_get_i (core->config, "asm.bytes");
		r_config_set_i (core->config, "asm.bytes", false);
		r_core_cmd0 (core, "fd");

		int maxcount = 9;
		int rows, cols = r_cons_get_size (&rows);
		count = 0;
		char *dis = NULL;
		rows -= 4;
		idx = 0;
		ut64 curat = UT64_MAX;
		r_list_foreach (xrefs, iter, refi) {
			if (idx - skip > maxcount) {
				r_cons_printf ("...");
				break;
			}
			if (!iter->n && idx < skip) {
				skip = idx;
			}
			if (idx >= skip) {
				if (count > maxcount) {
					strcpy (cstr, "?");
				} else {
					snprintf (cstr, sizeof (cstr), "%d", count);
				}
				if (idx == skip) {
					cur_ref_addr = refi->addr;
				}
				RAnalFunction *fun = r_anal_get_fcn_in (core->anal, refi->addr, R_ANAL_FCN_TYPE_NULL);
				char *name;
				if (fun) {
					name = strdup (fun->name);
				} else {
					RFlagItem *f = r_flag_get_at (core->flags, refi->addr, true);
					if (f) {
						name = r_str_newf ("%s + %" PFMT64d, f->name, refi->addr - f->offset);
					} else {
						name = strdup ("unk");
					}
				}
				if (w > 45) {
					if (strlen (name) > w -45) {
						name[w - 45] = 0;
					}
				} else {
					name[0] = 0;
				}
				char *cmt = r_core_cmd_strf (core, "CC.@0x%08"PFMT64x, refi->addr);
				r_str_trim (cmt);
				r_cons_printf (" %d [%s] 0x%08"PFMT64x" 0x%08"PFMT64x " %s %sref (%s) ; %s\n",
					idx, cstr, refi->at, refi->addr,
					r_anal_xrefs_type_tostring (refi->type),
					xref ? "x":"", name, cmt);
				free (cmt);
				free (name);
				if (idx == skip) {
					free (dis);
					curat = refi->addr;
					char *res = r_core_cmd_strf (core, "pd 4 @ 0x%08"PFMT64x"@e:asm.flags.limit=1", refi->at);
					// TODO: show disasm with context. not seek addr
					// dis = r_core_cmd_strf (core, "pd $r-4 @ 0x%08"PFMT64x, refi->addr);
					dis = NULL;
					res = r_str_appendf (res, "; ---------------------------\n");
					switch (printMode) {
					case 0:
						dis = r_core_cmd_strf (core, "pd--6 @ 0x%08"PFMT64x, refi->addr);
						break;
					case 1:
						dis = r_core_cmd_strf (core, "pds @ 0x%08"PFMT64x, refi->addr);
						break;
					case 2:
						dis = r_core_cmd_strf (core, "px @ 0x%08"PFMT64x, refi->addr);
						break;
					case 3:
						dis = r_core_cmd_strf (core, "pxr @ 0x%08"PFMT64x, refi->addr);
						break;
					}
					if (dis) {
						res = r_str_append (res, dis);
						free (dis);
					}
					dis = res;
				}
				if (++count >= rows) {
					r_cons_printf ("...");
					break;
				}
			}
			idx++;
		}
		if (dis) {
			if (count < rows) {
				r_cons_newline ();
			}
			int i = count;
			for (; i < 9; i++)  {
				r_cons_newline ();
			}
			/* prepare highlight */
			char *cmd = strdup (r_config_get (core->config, "scr.highlight"));
			char *ats = r_str_newf ("%"PFMT64x, curat);
			if (ats && !*cmd) {
				(void) r_config_set (core->config, "scr.highlight", ats);
			}
			/* print disasm */
			char *d = r_str_ansi_crop (dis, 0, 0, cols, rows - 9);
			if (d) {
				r_cons_printf ("%s", d);
				free (d);
			}
			/* flush and restore highlight */
			r_cons_flush ();
			r_config_set (core->config, "scr.highlight", cmd);
			free (ats);
			free (cmd);
			free (dis);
			dis = NULL;
		}
		r_config_set_i (core->config, "asm.bytes", asm_bytes);
	}
	r_cons_flush ();
	r_cons_enable_mouse (r_config_get_i (core->config, "scr.wheel"));
	ch = r_cons_readchar ();
	ch = r_cons_arrow_to_hjkl (ch);
	switch (ch) {
	case ':':
		r_core_visual_prompt_input (core);
		goto repeat;
		break;
	case '?':
		r_cons_clear00 ();
		RStrBuf *rsb = r_strbuf_new ("");
		r_core_visual_append_help (rsb, "Xrefs Visual Analysis Mode (Vv + x) Help", help_msg_visual_xref);
		ret = r_cons_less_str (r_strbuf_get (rsb), "?");
		r_strbuf_free (rsb);
		goto repeat;
	case 9: // TAB
		xrefsMode = !xrefsMode;
		r_core_visual_toggle_decompiler_disasm (core, false, true);
		goto repeat;
	case 'p':
		r_core_visual_toggle_decompiler_disasm (core, false, true);
		printMode++;
		if (printMode > lastPrintMode) {
			printMode = 0;
		}
		goto repeat;
	case 'P':
		r_core_visual_toggle_decompiler_disasm (core, false, true);
		printMode--;
		if (printMode < 0) {
			printMode = lastPrintMode;
		}
		goto repeat;
	case '/':
		r_core_cmd0 (core, "?i highlight;e scr.highlight=`yp`");
		goto repeat;
	case '+':
		add_ref (core);
		goto repeat;
	case '-':
		r_cons_gotoxy (0, 0);
		if (r_cons_yesno ('y', "Do you want to delete this xref? (Y/n)")) {
			delete_ref (core, xrefs, skip, xref);
		}
		goto repeat;
	case '<':
	case 'x':
		xref = true;
		xrefsMode = !xrefsMode;
		goto repeat;
	case '>':
	case 'X':
		xref = false;
		xrefsMode = !xrefsMode;
		goto repeat;
	case 'g':
		skip = 0;
		goto repeat;
	case 'G':
		skip = 9999;
		goto repeat;
	case ';':
		addComment (core, cur_ref_addr);
		goto repeat;
	case '.':
		skip = 0;
		goto repeat;
	case 'j':
		skip++;
		goto repeat;
	case 'J':
		skip += 10;
		goto repeat;
	case 'k':
		skip--;
		if (skip < 0) {
			skip = 0;
		}
		goto repeat;
	case 'K':
		skip = (skip < 10) ? 0: skip - 10;
		goto repeat;
	default:
		if (ch == ' ' || ch == '\n' || ch == '\r' || ch == 'l') {
			ret = follow_ref (core, xrefs, skip, xref);
		} else if (IS_DIGIT (ch)) {
			ret = follow_ref (core, xrefs, ch - 0x30, xref);
		} else if (ch != 'q' && ch != 'Q' && ch != 'h') {
			goto repeat;
		}
		break;
	}
	r_list_free (xrefs);

	return ret;
}

#if __WINDOWS__
void SetWindow(int Width, int Height) {
	COORD coord;
	coord.X = Width;
	coord.Y = Height;

	SMALL_RECT Rect;
	Rect.Top = 0;
	Rect.Left = 0;
	Rect.Bottom = Height - 1;
	Rect.Right = Width - 1;

	HANDLE Handle = GetStdHandle (STD_OUTPUT_HANDLE);
	SetConsoleScreenBufferSize (Handle, coord);
	SetConsoleWindowInfo (Handle, TRUE, &Rect);
}
#endif

// unnecesarily public
char *getcommapath(RCore *core) {
	char *cwd;
	const char *dir = r_config_get (core->config, "dir.projects");
	const char *prj = r_config_get (core->config, "prj.name");
	if (dir && *dir && prj && *prj) {
		char *abspath = r_file_abspath (dir);
		/* use prjdir as base directory for comma-ent files */
		cwd = r_str_newf ("%s"R_SYS_DIR "%s.d", abspath, prj);
		free (abspath);
	} else {
		/* use cwd as base directory for comma-ent files */
		cwd = r_sys_getdir ();
	}
	return cwd;
}

static void visual_comma(RCore *core) {
	bool mouse_state = __holdMouseState (core);
	ut64 addr = core->offset + (core->print->cur_enabled? core->print->cur: 0);
	char *comment, *cwd, *cmtfile;
	const char *prev_cmt = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
	comment = prev_cmt ? strdup (prev_cmt) : NULL;
	cmtfile = r_str_between (comment, ",(", ")");
	cwd = getcommapath (core);
	if (!cmtfile) {
		char *fn = r_cons_input ("<comment-file> ");
		if (fn && *fn) {
			cmtfile = strdup (fn);
			if (!comment || !*comment) {
				comment = r_str_newf (",(%s)", fn);
				r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, comment);
			} else {
				// append filename in current comment
				char *nc = r_str_newf ("%s ,(%s)", comment, fn);
				r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, nc);
				free (nc);
			}
		}
		free (fn);
	}
	if (cmtfile) {
		char *cwf = r_str_newf ("%s"R_SYS_DIR "%s", cwd, cmtfile);
		char *odata = r_file_slurp (cwf, NULL);
		if (!odata) {
			eprintf ("Could not open '%s'.\n", cwf);
			free (cwf);
			goto beach;
		}
		char *data = r_core_editor (core, NULL, odata);
		r_file_dump (cwf, (const ut8 *) data, -1, 0);
		free (data);
		free (odata);
		free (cwf);
	} else {
		eprintf ("No commafile found.\n");
	}
beach:
	free (comment);
	r_cons_enable_mouse (mouse_state && r_config_get_i (core->config, "scr.wheel"));
}

static bool isDisasmPrint(int mode) {
	return (mode == R_CORE_VISUAL_MODE_PD || mode == R_CORE_VISUAL_MODE_DB);
}

static void cursor_ocur(RCore *core, bool use_ocur) {
	RPrint *p = core->print;
	if (use_ocur && p->ocur == -1) {
		p->ocur = p->cur;
	} else if (!use_ocur) {
		p->ocur = -1;
	}
}

static ut64 insoff(RCore *core, int delta) {
	int minop = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MIN_OP_SIZE);
	int maxop = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MAX_OP_SIZE);
	ut64 addr = core->offset + delta; // should be core->print->cur
	RAnalBlock *bb = r_anal_bb_from_offset (core->anal, addr - minop);
	if (bb) {
		ut64 res = r_anal_bb_opaddr_at (bb, addr - minop);
		if (res != UT64_MAX) {
			if (res < addr && addr - res <= maxop) {
				return res;
			}
		}
	}
	return addr;
}

static void nextOpcode(RCore *core) {
	ut64 opaddr = insoff (core, core->print->cur);
	RAnalOp *aop = r_core_anal_op (core, opaddr, R_ANAL_OP_MASK_BASIC);
	RPrint *p = core->print;
	if (aop) {
		p->cur += aop->size;
		r_anal_op_free (aop);
	} else {
		p->cur += 4;
	}
}

static void prevOpcode(RCore *core) {
	RPrint *p = core->print;
	// ut64 addr, oaddr = core->offset + core->print->cur;
	ut64 addr = 0;
	ut64 opaddr = insoff (core, core->print->cur);
	if (r_core_prevop_addr (core, opaddr, 1, &addr)) {
		const int delta = opaddr - addr;
		p->cur -= delta;
	} else {
		p->cur -= 4;
	}
}

static void cursor_nextrow(RCore *core, bool use_ocur) {
	RPrint *p = core->print;
	ut32 roff, next_roff;
	int row, sz, delta;
	RAsmOp op;

	cursor_ocur (core, use_ocur);
	if (PIDX == 1) { // DISASM
		nextOpcode (core);
		return;
	}

	if (PIDX == 7 || !strcmp ("prc", r_config_get (core->config, "cmd.visual"))) {
		p->cur += r_config_get_i (core->config, "hex.cols");
		return;
	}
	if (splitView) {
		int w = r_config_get_i (core->config, "hex.cols");
		if (w < 1) {
			w = 16;
		}
		if (core->seltab == 0) {
			splitPtr += w;
		} else {
			core->offset += w;
		}
		return;
	}
	if (PIDX == R_CORE_VISUAL_MODE_DB) {
		const int cols = core->dbg->regcols;
		int w = r_config_get_i (core->config, "hex.cols");
		switch (core->seltab) {
		case 0:
			if (w < 1) {
				w = 16;
			}
			r_config_set_i (core->config, "stack.delta",
					r_config_get_i (core->config, "stack.delta") - w);
			return;
		case 1:
			p->cur += cols > 0? cols: 3;
			return;
		default:
			nextOpcode (core);
			return;
		}
	}
	if (p->row_offsets) {
		// FIXME: cache the current row
		row = r_print_row_at_off (p, p->cur);
		roff = r_print_rowoff (p, row);
		if (roff == -1) {
			p->cur++;
			return;
		}
		next_roff = r_print_rowoff (p, row + 1);
		if (next_roff == UT32_MAX) {
			p->cur++;
			return;
		}
		if (next_roff > core->blocksize) {
			p->cur += 32; // XXX workaround to "fix" cursor nextrow far away scrolling issue
			return;
		}
		if (next_roff + 32 < core->blocksize) {
			sz = r_asm_disassemble (core->rasm, &op,
				core->block + next_roff, 32);
			if (sz < 1) {
				sz = 1;
			}
		} else {
			sz = 1;
		}
		delta = p->cur - roff;
		p->cur = next_roff + R_MIN (delta, sz - 1);
	} else {
		p->cur += R_MAX (1, p->cols);
	}
}

static void cursor_prevrow(RCore *core, bool use_ocur) {
	RPrint *p = core->print;
	ut32 roff, prev_roff;
	int row;

	cursor_ocur (core, use_ocur);
	if (PIDX == 1) { // DISASM
		prevOpcode (core);
		return;
	}

	if (PIDX == 7 || !strcmp ("prc", r_config_get (core->config, "cmd.visual"))) {
		int cols = r_config_get_i (core->config, "hex.cols");
		p->cur -= R_MAX (cols, 0);
		return;
	}

	if (splitView) {
		int w = r_config_get_i (core->config, "hex.cols");
		if (w < 1) {
			w = 16;
		}
		if (core->seltab == 0) {
			splitPtr -= w;
		} else {
			core->offset -= w;
		}
		return;
	}
	if (PIDX == R_CORE_VISUAL_MODE_DB) {
		switch (core->seltab) {
		case 0:
			{
				int w = r_config_get_i (core->config, "hex.cols");
				if (w < 1) {
					w = 16;
				}
				r_config_set_i (core->config, "stack.delta",
						r_config_get_i (core->config, "stack.delta") + w);
			}
			return;
		case 1:
			{
				const int cols = core->dbg->regcols;
				p->cur -= cols > 0? cols: 4;
				return;
			}
		default:
			prevOpcode (core);
			return;
		}
	}
	if (p->row_offsets) {
		int delta, prev_sz;

		// FIXME: cache the current row
		row = r_print_row_at_off (p, p->cur);
		roff = r_print_rowoff (p, row);
		if (roff == UT32_MAX) {
			p->cur--;
			return;
		}
		prev_roff = row > 0? r_print_rowoff (p, row - 1): UT32_MAX;
		delta = p->cur - roff;
		if (prev_roff == UT32_MAX) {
			ut64 prev_addr = prevop_addr (core, core->offset + roff);
			if (prev_addr > core->offset) {
				prev_roff = 0;
				prev_sz = 1;
			} else {
				RAsmOp op;
				prev_roff = 0;
				r_core_seek (core, prev_addr, true);
				prev_sz = r_asm_disassemble (core->rasm, &op,
					core->block, 32);
			}
		} else {
			prev_sz = roff - prev_roff;
		}
		int res = R_MIN (delta, prev_sz - 1);
		ut64 cur = prev_roff + res;
		if (cur == p->cur) {
			if (p->cur > 0) {
				p->cur--;
			}
		} else {
			p->cur = prev_roff + delta; //res;
		}
	} else {
		p->cur -= p->cols;
	}
}

static void cursor_left(RCore *core, bool use_ocur) {
	if (PIDX == 2) {
		if (core->seltab == 1) {
			core->print->cur--;
			return;
		}
	}
	cursor_ocur (core, use_ocur);
	core->print->cur--;
}

static void cursor_right(RCore *core, bool use_ocur) {
	if (PIDX == 2) {
		if (core->seltab == 1) {
			core->print->cur++;
			return;
		}
	}
	cursor_ocur (core, use_ocur);
	core->print->cur++;
}

static bool fix_cursor(RCore *core) {
	RPrint *p = core->print;
	int offscreen = (core->cons->rows - 3) * p->cols;
	bool res = false;

	if (!core->print->cur_enabled) {
		return false;
	}
	if (core->print->screen_bounds > 1) {
		bool off_is_visible = core->offset < core->print->screen_bounds;
		bool cur_is_visible = core->offset + p->cur < core->print->screen_bounds;
		bool is_close = core->offset + p->cur < core->print->screen_bounds + 32;

		if ((!cur_is_visible && !is_close) || (!cur_is_visible && p->cur == 0)) {
			// when the cursor is not visible and it's far from the
			// last visible byte, just seek there.
			r_core_seek_delta (core, p->cur);
			reset_print_cur (p);
		} else if ((!cur_is_visible && is_close) || !off_is_visible) {
			RAsmOp op;
			int sz = r_asm_disassemble (core->rasm,
				&op, core->block, 32);
			if (sz < 1) {
				sz = 1;
			}
			r_core_seek_delta (core, sz);
			p->cur = R_MAX (p->cur - sz, 0);
			if (p->ocur != -1) {
				p->ocur = R_MAX (p->ocur - sz, 0);
			}
			res |= off_is_visible;
		}
	} else if (core->print->cur >= offscreen) {
		r_core_seek (core, core->offset + p->cols, true);
		p->cur -= p->cols;
		if (p->ocur != -1) {
			p->ocur -= p->cols;
		}
	}

	if (p->cur < 0) {
		int sz = p->cols;
		if (isDisasmPrint (core->printidx)) {
			sz = r_core_visual_prevopsz (core, core->offset + p->cur);
			if (sz < 1) {
				sz = 1;
			}
		}
		r_core_seek_delta (core, -sz);
		p->cur += sz;
		if (p->ocur != -1) {
			p->ocur += sz;
		}
	}
	return res;
}

static bool __ime = false;
static int __nib = -1;

static bool insert_mode_enabled(RCore *core) {
	if (!__ime) {
		return false;
	}
	char ch = (ut8)r_cons_readchar ();
	if ((ut8)ch == KEY_ALTQ) {
		(void)r_cons_readchar ();
		__ime = false;
		return true;
	}
	char arrows = r_cons_arrow_to_hjkl (ch);
	switch (ch) {
	case ':':
		if (core->print->col != 2) {
			r_core_visual_prompt_input (core);
		}
		break;
	case 127:
		core->print->cur = R_MAX (0, core->print->cur - 1);
		return true;
	case 9: // tab "tab" TAB
		core->print->col = core->print->col == 1? 2: 1;
		break;
	}
	if (ch != 'h' && arrows == 'h') {
		core->print->cur = R_MAX (0, core->print->cur - 1);
		return true;
	} else if (ch != 'l' && arrows == 'l') {
		core->print->cur = core->print->cur + 1;
		return true;
	} else if (ch != 'j' && arrows == 'j') {
		cursor_nextrow (core, false);
		return true;
	} else if (ch != 'k' && arrows == 'k') {
		cursor_prevrow (core, false);
		return true;
	}
	if (core->print->col == 2) {
		/* ascii column */
		switch (ch) {
		case 0x1b: // ESC
			core->print->col = 0;
			break;
		case ' ':
			r_core_cmdf (core, "wx 20 @ $$+%d", core->print->cur);
			core->print->cur++;
			break;
		default:
			if (IS_PRINTABLE (ch)) {
				r_core_cmdf (core, "\"w %c\" @ $$+%d", ch, core->print->cur);
				core->print->cur++;
			}
		}
		return true;
	} else {
		if (ch == '+') {
			// inc byte
			r_core_cmdf (core, "woa 01 @ $$+%i!1", core->print->cur);
		} else if (ch == '-') {
			// dec byte
			r_core_cmdf (core, "wos 01 @ $$+%i!1", core->print->cur);
		}
	}
	ch = arrows;
	/* hex column */
	switch (ch) {
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
	case 'a':
	case 'b':
	case 'c':
	case 'd':
	case 'e':
	case 'f':
		if (__nib != -1) {
			r_core_cmdf (core, "wx %c%c @ $$+%d", __nib, ch, core->print->cur);
			core->print->cur++;
			__nib = -1;
		} else {
			r_core_cmdf (core, "wx %c. @ $$+%d", ch, core->print->cur);
			__nib = ch;
		}
		break;
	case 'r':
		r_core_cmdf (core, "r-1 @ 0x%08"PFMT64x, core->offset + core->print->cur);
		break;
	case 'R':
		r_core_cmdf (core, "r+1 @ 0x%08"PFMT64x, core->offset + core->print->cur);
		break;
	case 'h':
		core->print->cur = R_MAX (0, core->print->cur - 1);
		break;
	case 'l':
		core->print->cur = core->print->cur + 1;
		break;
	case 'j':
		cursor_nextrow (core, false);
		break;
	case 'k':
		cursor_prevrow (core, false);
		break;
	case 'Q':
	case 'q':
		__ime = false;
		break;
	case '?':
		r_cons_less_str ("\nVisual Insert Mode:\n\n"
			" tab          - toggle between ascii and hex columns\n"
			" q (or alt-q) - quit insert mode\n"
			"\nHex column:\n"
			" r            - remove byte in cursor\n"
			" R            - insert byte in cursor\n"
			" [0-9a-f]     - insert hexpairs in hex column\n"
			" hjkl         - move around\n"
			"\nAscii column:\n"
			" arrows       - move around\n"
			" alt-q        - quit insert mode\n"
			, "?");
		break;
	}
	return true;
}

R_API void r_core_visual_browse(RCore *core, const char *input) {
	const char *browsemsg = \
		"Browse stuff:\n"
		"-------------\n"
		" _  hud mode (V_)\n"
		" 1  bit editor (vd1)\n"
		" b  blocks\n"
		" a  anal classes\n"
		" c  classes\n"
		" C  comments\n"
		" d  debug traces\n"
		" e  eval var configurations\n"
		" E  esil debugger mode\n"
		" f  flags\n"
		" F  functions\n"
		" g  graph\n"
		" h  history\n"
		" i  imports\n"
		" l  chat logs (previously VT)\n"
		" m  maps\n"
		" M  mountpoints\n"
		" p  pids/threads\n"
		" q  quit\n"
		" r  ROP gadgets\n"
		" s  symbols\n"
		" t  types\n"
		" T  themes\n"
		" v  vars\n"
		" x  xrefs\n"
		" X  refs\n"
		" z  browse function zignatures\n"
		" :  run command\n"
	;
	for (;;) {
		r_cons_clear00 ();
		r_cons_printf ("%s\n", browsemsg);
		r_cons_flush ();
		char ch = 0;
		if (input && *input) {
			ch = *input;
			input++;
		} else {
			ch = r_cons_readchar ();
		}
		ch = r_cons_arrow_to_hjkl (ch);
		switch (ch) {
		case '1':
			r_core_visual_bit_editor (core);
			break;
		case 'M':
			if (!r_list_empty (core->fs->roots)) {
				r_core_visual_mounts (core);
			}
			break;
		case 'z': // "vbz"
			if (r_core_visual_view_zigns (core)) {
				return;
			}
			break;
		case 'g': // "vbg"
			if (r_core_visual_view_graph (core)) {
				return;
			}
			break;
		case 'r': // "vbr"
			r_core_visual_view_rop (core);
			break;
		case 'f': // "vbf"
			r_core_visual_trackflags (core);
			break;
		case 'F': // "vbF"
			r_core_visual_anal (core, NULL);
			// r_core_cmd0 (core, "s $(afl~...)");
			break;
		case 'd': // "vbd"
			r_core_visual_debugtraces (core, NULL);
			break;
		case 'v': // "vbv"
			r_core_visual_anal (core, "v");
			break;
		case 'e': // "vbe"
			r_core_visual_config (core);
			break;
		case 'E': // "vbe"
			r_core_visual_esil (core, NULL);
			break;
		case 'c': // "vbc"
			r_core_visual_classes (core);
			break;
		case 'a': // "vba"
			r_core_visual_anal_classes (core);
			break;
		case 'C': // "vbC"
			r_core_visual_comments (core);
			//r_core_cmd0 (core, "s $(CC~...)");
			break;
		case 't': // "vbt"
			r_core_visual_types (core);
			break;
		case 'T': // "vbT"
			r_core_cmd0 (core, "eco $(eco~...)");
			break;
		case 'l': // previously VT
			if (r_sandbox_enable (0)) {
				eprintf ("sandbox not enabled\n");
			} else {
				if (r_cons_is_interactive ()) {
					r_core_cmd0 (core, "TT");
				}
			}
			break;
		case 'p':
			r_core_cmd0 (core, "dpt=$(dpt~[1-])");
			break;
		case 'b':
			r_core_cmd0 (core, "s $(afb~...)");
			break;
		case 'i':
			// XXX ii shows index first and iiq shows no offset :(
			r_core_cmd0 (core, "s $(ii~...)");
			break;
		case 's':
			r_core_cmd0 (core, "s $(isq~...)");
			break;
		case 'm':
			r_core_cmd0 (core, "s $(dm~...)");
			break;
		case 'x':
			r_core_visual_refs (core, true, true);
			break;
		case 'X':
			r_core_visual_refs (core, false, true);
			break;
		case 'h': // seek history
			r_core_cmdf (core, "s!~...");
			break;
		case '_':
			r_core_visual_hudstuff (core);
			break;
		case ':':
			r_core_visual_prompt_input (core);
			break;
		case 127: // backspace
		case 'q':
			return;
		}
	}
}

#include "visual_tabs.inc"

static bool isNumber(RCore *core, int ch) {
	if (ch > '0' && ch <= '9') {
		return true;
	}
	if (core->print->cur_enabled) {
		return ch == '0';
	}
	return false;
}

static char numbuf[32] = {0};
static int numbuf_i = 0;

static void numbuf_append(int ch) {
	if (numbuf_i >= sizeof (numbuf) - 1) {
		numbuf_i = 0;
	}
	numbuf[numbuf_i++] = ch;
	numbuf[numbuf_i] = 0;
}

static int numbuf_pull(void) {
	int distance = 1;
	if (numbuf_i) {
		numbuf[numbuf_i] = 0;
		distance = atoi (numbuf);
		if (!distance) {
			distance = 1;
		}
		numbuf_i = 0;
	}
	return distance;
}

static bool canWrite(RCore *core, ut64 addr) {
	if (r_config_get_i (core->config, "io.cache")) {
		return true;
	}
	RIOMap *map = r_io_map_get_at (core->io, addr);
	return (map && (map->perm & R_PERM_W));
}

static bool toggle_bb(RCore *core, ut64 addr) {
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
	if (fcn) {
		RAnalBlock *bb = r_anal_function_bbget_in (core->anal, fcn, addr);
		if (bb) {
			bb->folded = !bb->folded;
		} else {
			r_warn_if_reached ();
		}
		return true;
	}
	return false;
}

static int process_get_click(RCore *core, int ch) {
	int x, y;
	if (r_cons_get_click (&x, &y)) {
		if (y == 1) {
			if (x < 13) {
				ch = '_';
			} else if (x < 20) {
				ch = 'p';
			} else if (x < 24) {
				ch = 9;
			}
		} else if (y == 2) {
			if (x < 2) {
				visual_closetab (core);
			} else if (x < 5) {
				visual_newtab (core);
			} else {
				visual_nexttab (core);
			}
			return 0;
		} else {
			ch = 0; //'c';
		}
	}
	return ch;
}

R_API int r_core_visual_cmd(RCore *core, const char *arg) {
	ut8 och = arg[0];
	RAsmOp op;
	ut64 offset = core->offset;
	char buf[4096];
	const char *key_s;
	int i, cols = core->print->cols;
	int wheelspeed;
	int ch = och;
	if ((ut8)ch == KEY_ALTQ) {
		r_cons_readchar ();
		ch = 'q';
	}
	ch = r_cons_arrow_to_hjkl (ch);
	ch = visual_nkey (core, ch);
	if (ch < 2) {
		ch = process_get_click (core, ch);
		if (!ch) {
			return 1;
		}
	}
	if (r_cons_singleton ()->mouse_event) {
		wheelspeed = r_config_get_i (core->config, "scr.wheel.speed");
	} else {
		wheelspeed = 1;
	}

	if (ch == 'l' && och == 6) {
		ch = 'J';
	} else if (ch == 'h' && och == 2) {
		ch = 'K';
	}

	// do we need hotkeys for data references? not only calls?
	// '0' is handled to seek at the beginning of the function
	// unless the cursor is set, then, the 0 is captured here
	if (isNumber (core, ch)) {
		// only in disasm and debug prints..
		if (isDisasmPrint (core->printidx)) {
			if (r_config_get_i (core->config, "asm.hints") && (r_config_get_i (core->config, "asm.hint.jmp")
			|| r_config_get_i (core->config, "asm.hint.lea") || r_config_get_i (core->config, "asm.hint.emu")
			|| r_config_get_i (core->config, "asm.hint.imm")
			|| r_config_get_i (core->config, "asm.hint.call"))) {
				r_core_visual_jump (core, ch);
			} else {
				numbuf_append (ch);
			}
		} else {
			numbuf_append (ch);
		}
	} else {
		switch (ch) {
#if __WINDOWS__
		case 0xf5:
			SetWindow (81, 25);
			break;
		case 0xcf5:
			SetWindow (81, 40);
			break;
#endif
		case 0x0d: // "enter" "\\n" "newline"
			if (r_config_get_b (core->config, "scr.cursor")) {
				r_cons_set_click (core->cons->cpos.x, core->cons->cpos.y);
				char buf[10];
				int ch = process_get_click (core, 0);
				buf[0] = ch;
				buf[1] = 0;
				r_core_visual_cmd(core, buf);
			} else {
			RAnalOp *op;
			int wheel = r_config_get_i (core->config, "scr.wheel");
			if (wheel) {
				r_cons_enable_mouse (true);
			}
			do {
				op = r_core_anal_op (core, core->offset + core->print->cur, R_ANAL_OP_MASK_BASIC);
				if (op) {
					if (op->type == R_ANAL_OP_TYPE_JMP ||
					op->type == R_ANAL_OP_TYPE_CJMP ||
					op->type == R_ANAL_OP_TYPE_CALL ||
					op->type == R_ANAL_OP_TYPE_CCALL) {
						if (core->print->cur_enabled) {
							int delta = R_ABS ((st64) op->jump - (st64) offset);
							if (op->jump < core->offset || op->jump >= core->print->screen_bounds) {
								r_io_sundo_push (core->io, offset, r_print_get_cursor (core->print));
								r_core_visual_seek_animation (core, op->jump);
								core->print->cur = 0;
							} else {
								r_io_sundo_push (core->io, offset, r_print_get_cursor (core->print));
								core->print->cur = delta;
							}
						} else {
							r_io_sundo_push (core->io, offset, 0);
							r_core_visual_seek_animation (core, op->jump);
						}
					}
				}
				r_anal_op_free (op);
			} while (--wheelspeed > 0);
		}
		break;
		case 'o': // tab TAB
			nextPrintFormat (core);
			break;
		case 'O': // tab TAB
		case 9: // tab TAB
			r_core_visual_toggle_decompiler_disasm (core, false, true);
			if (splitView) {
				// this split view is kind of useless imho, we should kill it or merge it into tabs
				core->print->cur = 0;
				core->curtab = 0;
				core->seltab++;
				if (core->seltab > 1) {
					core->seltab = 0;
				}
			} else {
				if (core->print->cur_enabled) {
					core->curtab = 0;
					if (core->printidx == R_CORE_VISUAL_MODE_DB) {
						core->print->cur = 0;
						core->seltab++;
						if (core->seltab > 2) {
							core->seltab = 0;
						}
					} else {
						core->seltab = 0;
						ut64 f = r_config_get_i (core->config, "diff.from");
						ut64 t = r_config_get_i (core->config, "diff.to");
						if (f == t && f == 0) {
							core->print->col = core->print->col == 1? 2: 1;
						}
					}
				} else {
					prevPrintFormat (core);
				}
			}
			break;
		case '&':
			rotateAsmBits (core);
			break;
		case 'a':
		{
			{
				ut64 addr = core->offset;
				if (PIDX == 2) {
					if (core->seltab == 0) {
						addr = r_debug_reg_get (core->dbg, "SP");
					}
				}
				if (!canWrite (core, addr)) {
					r_cons_printf ("\nFile has been opened in read-only mode. Use -w flag, oo+ or e io.cache=true\n");
					r_cons_any_key (NULL);
					return true;
				}
			}
			r_cons_printf ("Enter assembler opcodes separated with ';':\n");
			r_core_visual_showcursor (core, true);
			r_cons_flush ();
			r_cons_set_raw (false);
			strcpy (buf, "\"wa ");
			r_line_set_prompt (":> ");
			r_cons_enable_mouse (false);
			if (r_cons_fgets (buf + 4, sizeof (buf) - 4, 0, NULL) < 0) {
				buf[0] = '\0';
			}
			strcat (buf, "\"");
			int wheel = r_config_get_i (core->config, "scr.wheel");
			if (wheel) {
				r_cons_enable_mouse (true);
			}
			if (*buf) {
				if (core->print->cur_enabled) {
					int t = core->offset + core->print->cur;
					r_core_seek (core, t, false);
				}
				r_core_cmd (core, buf, true);
				if (core->print->cur_enabled) {
					int t = core->offset - core->print->cur;
					r_core_seek (core, t, true);
				}
			}
			r_core_visual_showcursor (core, false);
			r_cons_set_raw (true);
		}
		break;
		case '=':
		{ // TODO: edit
			r_core_visual_showcursor (core, true);
			const char *buf = NULL;
			#define I core->cons
			const char *cmd = r_config_get (core->config, "cmd.vprompt");
			r_line_set_prompt ("cmd.vprompt> ");
			I->line->contents = strdup (cmd);
			buf = r_line_readline ();
			I->line->contents = NULL;
			(void)r_config_set (core->config, "cmd.vprompt", buf);
			r_core_visual_showcursor (core, false);
		}
		break;
		case '|':
		{ // TODO: edit
			r_core_visual_showcursor (core, true);
			const char *buf = NULL;
			#define I core->cons
			const char *cmd = r_config_get (core->config, "cmd.cprompt");
			r_line_set_prompt ("cmd.cprompt> ");
			I->line->contents = strdup (cmd);
			buf = r_line_readline ();
			if (buf && !strcmp (buf, "|")) {
				R_FREE (I->line->contents);
				core->print->cur_enabled = true;
				core->print->cur = 0;
				(void)r_config_set (core->config, "cmd.cprompt", "p=e $r-2");
			} else {
				R_FREE (I->line->contents);
				(void)r_config_set (core->config, "cmd.cprompt", r_str_get (buf));
			}
			r_core_visual_showcursor (core, false);
		}
		break;
		case '!':
			r_core_panels_root (core, core->panels_root);
			setcursor (core, false);
			return false;
		case 'g':
			r_core_visual_showcursor (core, true);
			r_core_visual_offset (core);
			r_core_visual_showcursor (core, false);
			break;
		case 'G':
			__core_visual_gogo (core, 'G');
			break;
		case 'A':
		{
			const int oce = core->print->cur_enabled;
			const int oco = core->print->ocur;
			const int occ = core->print->cur;
			ut64 off = oce? core->offset + core->print->cur: core->offset;
			core->print->cur_enabled = 0;
			r_cons_enable_mouse (false);
			r_core_visual_asm (core, off);
			core->print->cur_enabled = oce;
			core->print->cur = occ;
			core->print->ocur = oco;
			if (r_config_get_i (core->config, "scr.wheel")) {
				r_cons_enable_mouse (true);
			}
		}
		break;
		case '\\':
			if (splitPtr == UT64_MAX) {
				splitPtr = core->offset;
			}
			splitView = !splitView;
			setcursor (core, splitView);
			break;
		case 'c':
			setcursor (core, !core->print->cur_enabled);
			break;
		case '$':
			if (core->print->cur_enabled) {
				r_core_cmdf (core, "dr PC=$$+%d", core->print->cur);
			} else {
				r_core_cmd0 (core, "dr PC=$$");
			}
			break;
		case '@':
			if (core->print->cur_enabled) {
				char buf[128];
				prompt_read ("cursor at:", buf, sizeof (buf));
				core->print->cur = (st64) r_num_math (core->num, buf);
			}
			break;
		case 'C':
			if (++color > 2) {
				color = 0;
			}
			r_config_set_i (core->config, "scr.color", color);
			break;
		case 'd': {
			bool mouse_state = __holdMouseState (core);
			r_core_visual_showcursor (core, true);
			int distance = numbuf_pull ();
			r_core_visual_define (core, arg + 1, distance - 1);
			r_core_visual_showcursor (core, false);
			r_cons_enable_mouse (mouse_state && r_config_get_i(core->config, "scr.wheel"));
		}
			break;
		case 'D':
			setdiff (core);
			break;
		case 'f':
		{
			bool mouse_state = __holdMouseState (core);
			int range, min, max;
			char name[256], *n;
			r_line_set_prompt ("flag name: ");
			r_core_visual_showcursor (core, true);
			if (r_cons_fgets (name, sizeof (name), 0, NULL) >= 0 && *name) {
				n = name;
				r_str_trim (n);
				if (core->print->ocur != -1) {
					min = R_MIN (core->print->cur, core->print->ocur);
					max = R_MAX (core->print->cur, core->print->ocur);
				} else {
					min = max = core->print->cur;
				}
				range = max - min + 1;
				if (!strcmp (n, "-")) {
					r_flag_unset_off (core->flags, core->offset + core->print->cur);
				} else if (*n == '.') {
					if (n[1] == '-') {
						//unset
						r_core_cmdf (core, "f.-%s@0x%"PFMT64x, n + 1, core->offset + min);
					} else {
						r_core_cmdf (core, "f.%s@0x%"PFMT64x, n + 1, core->offset + min);
					}
				} else if (*n == '-') {
					if (*n) {
						r_flag_unset_name (core->flags, n + 1);
					}
				} else {
					if (range < 1) {
						range = 1;
					}
					if (*n) {
						r_flag_set (core->flags, n,
							core->offset + min, range);
					}
				}
			}
			r_cons_enable_mouse (mouse_state && r_config_get_i(core->config, "scr.wheel"));
		}
			r_core_visual_showcursor (core, false);
			break;
		case ',':
			visual_comma (core);
			break;
		case 't':
			{
				r_cons_gotoxy (0, 0);
				if (core->visual.tabs) {
					r_cons_printf ("[tnp:=+-] ");
				} else {
					r_cons_printf ("[t] ");
				}
				r_cons_flush();
				int ch = r_cons_readchar ();
				if (isdigit (ch)) {
					visual_nthtab (core, ch - '0' - 1);
				}
				switch (ch) {
				case 'h':
				case 'k':
				case 'p':
					visual_prevtab (core);
					break;
				case 9: // t-TAB
				case 'l':
				case 'j':
				case 'n':
					visual_nexttab (core);
					break;
				case '=':
					visual_tabname (core);
					break;
				case '-':
					visual_closetab (core);
					break;
				case ':':
					{
						RCoreVisualTab *tab = visual_newtab (core);
						if (tab) {
							tab->name[0] = ':';
							r_cons_fgets (tab->name + 1, sizeof (tab->name) - 1, 0, NULL);
						}
					}
					break;
				case '+':
				case 't':
				case 'a':
					visual_newtab (core);
					break;
				}
			}
			break;
		case 'T':
			visual_closetab (core);
			break;
		case 'n':
			r_core_seek_next (core, r_config_get (core->config, "scr.nkey"));
			break;
		case 'N':
			r_core_seek_previous (core, r_config_get (core->config, "scr.nkey"));
			break;
		case 'i':
		case 'I':
			{
			ut64 oaddr = core->offset;
			int delta = (core->print->ocur != -1)? R_MIN (core->print->cur, core->print->ocur): core->print->cur;
			ut64 addr = core->offset + delta;
			if (!canWrite (core, addr)) {
				r_cons_printf ("\nFile has been opened in read-only mode. Use -w flag, oo+ or e io.cache=true\n");
				r_cons_any_key (NULL);
				return true;
			}
			if (PIDX == 0) {
				if (strstr (printfmtSingle[0], "pxb")) {
					r_core_visual_define (core, "1", 1);
					return true;
				}
				if (core->print->ocur == -1) {
					__ime = true;
					core->print->cur_enabled = true;
					return true;
				}
			} else if (PIDX == 2) {
				if (core->seltab == 0) {
					addr = r_debug_reg_get (core->dbg, "SP") + delta;
				} else if (core->seltab == 1) {
					char buf[128];
					prompt_read ("new-reg-value> ", buf, sizeof (buf));
					if (*buf) {
						const char *creg = core->dbg->creg;
						if (creg) {
							r_core_cmdf (core, "dr %s = %s\n", creg, buf);
						}
					}
					return true;
				}
			}
			r_core_visual_showcursor (core, true);
			r_cons_flush ();
			r_cons_set_raw (0);
			if (ch == 'I') {
				strcpy (buf, "wow ");
				r_line_set_prompt ("insert hexpair block: ");
				if (r_cons_fgets (buf + 4, sizeof (buf) - 4, 0, NULL) < 0) {
					buf[0] = '\0';
				}
				char *p = strdup (buf);
				int cur = core->print->cur;
				if (cur >= core->blocksize) {
					cur = core->print->cur - 1;
				}
				snprintf (buf, sizeof (buf), "%s @ $$0!%i", p,
					core->blocksize - cur);
				r_core_cmd (core, buf, 0);
				free (p);
				break;
			}
			if (core->print->col == 2) {
				strcpy (buf, "\"w ");
				r_line_set_prompt ("insert string: ");
				if (r_cons_fgets (buf + 3, sizeof (buf) - 3, 0, NULL) < 0) {
					buf[0] = '\0';
				}
				strcat (buf, "\"");
			} else {
				r_line_set_prompt ("insert hex: ");
				if (core->print->ocur != -1) {
					int bs = R_ABS (core->print->cur - core->print->ocur) + 1;
					core->blocksize = bs;
					strcpy (buf, "wow ");
				} else {
					strcpy (buf, "wx ");
				}
				if (r_cons_fgets (buf + strlen (buf), sizeof (buf) - strlen (buf), 0, NULL) < 0) {
					buf[0] = '\0';
				}
			}
			if (core->print->cur_enabled) {
				r_core_seek (core, addr, false);
			}
			r_core_cmd (core, buf, 1);
			if (core->print->cur_enabled) {
				r_core_seek (core, addr, true);
			}
			r_cons_set_raw (1);
			r_core_visual_showcursor (core, false);
			r_core_seek (core, oaddr, true);
			}
			break;
		case 'R':
			if (r_config_get_i (core->config, "scr.randpal")) {
				r_core_cmd0 (core, "ecr");
			} else {
				r_core_cmd0 (core, "ecn");
			}
			break;
		case 'e':
			r_core_visual_config (core);
			break;
		case '^':
			  {
				  RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
				  if (fcn) {
					  r_core_seek (core, fcn->addr, false);
				  } else {
					  __core_visual_gogo (core, 'g');
				  }
			  }
			  break;
		case 'E':
			r_core_visual_colors (core);
			break;
		case 'x':
			r_core_visual_refs (core, true, false);
			break;
		case 'X':
			r_core_visual_refs (core, false, false);
			break;
		case 'r':
			// TODO: toggle shortcut hotkeys
			if (r_config_get_i (core->config, "asm.hint.call")) {
				r_core_cmd0 (core, "e!asm.hint.call");
				r_core_cmd0 (core, "e asm.hint.jmp=true");
			} else if (r_config_get_i (core->config, "asm.hint.jmp")) {
				r_core_cmd0 (core, "e!asm.hint.jmp");
				r_core_cmd0 (core, "e asm.hint.imm=true");
			} else if (r_config_get_i (core->config, "asm.hint.imm")) {
				r_core_cmd0 (core, "e!asm.hint.imm");
				r_core_cmd0 (core, "e asm.hint.emu=true");
			} else if (r_config_get_i (core->config, "asm.hint.emu")) {
				r_core_cmd0 (core, "e!asm.hint.emu");
				r_core_cmd0 (core, "e asm.hint.lea=true");
			} else if (r_config_get_i (core->config, "asm.hint.lea")) {
				r_core_cmd0 (core, "e!asm.hint.lea");
				r_core_cmd0 (core, "e asm.hint.call=true");
			} else {
				r_core_cmd0 (core, "e asm.hint.call=true");
			}
			visual_refresh (core);
			break;
		case ' ':
		case 'V':
			if (r_config_get_i (core->config, "graph.web")) {
				r_core_cmd0 (core, "agv $$");
			} else {
				RAnalFunction *fun = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
				int ocolor = r_config_get_i (core->config, "scr.color");
				if (!fun) {
					r_cons_message ("Not in a function. Type 'df' to define it here");
					break;
				} else if (r_list_empty (fun->bbs)) {
					r_cons_message ("No basic blocks in this function. You may want to use 'afb+'.");
					break;
				}
				reset_print_cur (core->print);
				eprintf ("\rRendering graph...");
				r_core_visual_graph (core, NULL, NULL, true);
				r_config_set_i (core->config, "scr.color", ocolor);
			}
			break;
		case 'v':
			r_core_visual_anal (core, NULL);
			break;
		case 'h':
		case 'l':
			if (r_config_get_b (core->config, "scr.cursor")) {
				core->cons->cpos.x += ch == 'h'? -1: 1;
				if (core->cons->cpos.x < 1) {
					core->cons->cpos.x = 0;
				}
				int h, w = r_cons_get_size (&h);
				if (core->cons->cpos.x >= w) {
					core->cons->cpos.x = w;
				}
			} else {
				int distance = numbuf_pull ();
				if (core->print->cur_enabled) {
					if (ch == 'h') {
						for (i = 0; i < distance; i++) {
							cursor_left (core, false);
						}
					} else {
						for (i = 0; i < distance; i++) {
							cursor_right (core, false);
						}
					}
				} else {
					if (ch == 'h') {
						distance = -distance;
					}
					r_core_seek_delta (core, distance);
				}
			}
			break;
		case 'L':
		case 'H':
			if (r_config_get_b (core->config, "scr.cursor")) {
				int distance = 8; // numbuf_pull ();
				core->cons->cpos.x += (ch == 'h' || ch == 'H')? -distance: distance;
				if (core->cons->cpos.x < 1) {
					core->cons->cpos.x = 0;
				}
				int h, w = r_cons_get_size (&h);
				if (core->cons->cpos.x >= w) {
					core->cons->cpos.x = w;
				}
			} else {
				int distance = numbuf_pull ();
				if (core->print->cur_enabled) {
					if (ch == 'H') {
						for (i = 0; i < distance; i++) {
							cursor_left (core, true);
						}
					} else {
						for (i = 0; i < distance; i++) {
							cursor_right (core, true);
						}
					}
				} else {
					if (ch == 'H') {
						distance = -distance;
					}
					r_core_seek_delta (core, distance * 2);
				}
			}
			break;
		case 'j':
			if (r_config_get_b (core->config, "scr.cursor")) {
				core->cons->cpos.y++;
				int h;
				(void)r_cons_get_size (&h);
				if (core->cons->cpos.y >= h) {
					core->cons->cpos.y = h;
				}
			} else if (core->print->cur_enabled) {
				int distance = numbuf_pull ();
				for (i = 0; i < distance; i++) {
					cursor_nextrow (core, false);
				}
			} else {
				if (r_config_get_i (core->config, "scr.wheel.nkey")) {
					int i, distance = numbuf_pull ();
					if (distance < 1)  {
						distance =  1;
					}
					for (i = 0; i < distance; i++) {
						r_core_cmd0 (core, "sn");
					}
				} else {
					int times = R_MAX (1, wheelspeed);
					// Check if we have a data annotation.
					ut64 amisize;
					RAnalMetaItem *ami = r_meta_get_at (core->anal, core->offset, R_META_TYPE_DATA, &amisize);
					if (!ami) {
						ami = r_meta_get_at (core->anal, core->offset, R_META_TYPE_STRING, &amisize);
					}
					if (ami) {
						r_core_seek_delta (core, amisize);
					} else {
						int distance = numbuf_pull ();
						if (distance > 1) {
							times = distance;
						}
						while (times--) {
							if (isDisasmPrint (core->printidx)) {
								r_core_visual_disasm_down (core, &op, &cols);
							} else if (!strcmp (__core_visual_print_command (core),
									"prc")) {
								cols = r_config_get_i (core->config, "hex.cols");
							}
							r_core_seek (core, core->offset + cols, true);
						}
					}
				}
			}
			break;
		case 'J':
			if (r_config_get_b (core->config, "scr.cursor")) {
				int distance = 4;// numbuf_pull ();
				core->cons->cpos.y += distance;
				int h;
				(void)r_cons_get_size (&h);
				if (core->cons->cpos.y >= h) {
					core->cons->cpos.y = h;
				}
			} else if (core->print->cur_enabled) {
				int distance = numbuf_pull ();
				for (i = 0; i < distance; i++) {
					cursor_nextrow (core, true);
				}
			} else {
				if (core->print->screen_bounds > 1 && core->print->screen_bounds >= core->offset) {
					ut64 addr = UT64_MAX;
					if (isDisasmPrint (core->printidx)) {
						if (core->print->screen_bounds == core->offset) {
							r_asm_disassemble (core->rasm, &op, core->block, 32);
						}
						if (addr == core->offset || addr == UT64_MAX) {
							addr = core->offset + 48;
						}
					} else {
						int h;
						int hexCols = r_config_get_i (core->config, "hex.cols");
						if (hexCols < 1) {
							hexCols = 16;
						}
						(void)r_cons_get_size (&h);
						int delta = hexCols * (h / 4);
						addr = core->offset + delta;
					}
					r_core_seek (core, addr, true);
				} else {
					r_core_seek (core, core->offset + obs, true);
				}
			}
			break;
		case 'k':
			if (r_config_get_b (core->config, "scr.cursor")) {
				core->cons->cpos.y--;
				if (core->cons->cpos.y < 1) {
					core->cons->cpos.y = 0;
				}
			} else if (core->print->cur_enabled) {
				int distance = numbuf_pull ();
				for (i = 0; i < distance; i++) {
					cursor_prevrow (core, false);
				}
			} else {
				if (r_config_get_i (core->config, "scr.wheel.nkey")) {
					int i, distance = numbuf_pull ();
					if (distance < 1)  {
						distance =  1;
					}
					for (i = 0; i < distance; i++) {
						r_core_cmd0 (core, "sp");
					}
				} else {
					int times = wheelspeed;
					if (times < 1) {
						times = 1;
					}
					int distance = numbuf_pull ();
					if (distance > 1) {
						times = distance;
					}
					while (times--) {
						if (isDisasmPrint (core->printidx)) {
							r_core_visual_disasm_up (core, &cols);
						} else if (!strcmp (__core_visual_print_command (core), "prc")) {
							cols = r_config_get_i (core->config, "hex.cols");
						}
						r_core_seek_delta (core, -cols);
					}
				}
			}
			break;
		case 'K':
			if (r_config_get_b (core->config, "scr.cursor")) {
				int distance = 4;// numbuf_pull ();
				core->cons->cpos.y -= distance;
				if (core->cons->cpos.y < 1) {
					core->cons->cpos.y = 0;
				}
			} else if (core->print->cur_enabled) {
				int distance = numbuf_pull ();
				for (i = 0; i < distance; i++) {
					cursor_prevrow (core, true);
				}
			} else {
				if (core->print->screen_bounds > 1 && core->print->screen_bounds > core->offset) {
					int delta = (core->print->screen_bounds - core->offset);
					if (core->offset >= delta) {
						r_core_seek (core, core->offset - delta, true);
					} else {
						r_core_seek (core, 0, true);
					}
				} else {
					ut64 at = (core->offset > obs)? core->offset - obs: 0;
					if (core->offset > obs) {
						r_core_seek (core, at, true);
					} else {
						r_core_seek (core, 0, true);
					}
				}
			}
			break;
		case '[':
			// comments column
			if (core->print->cur_enabled &&
				(core->printidx == R_CORE_VISUAL_MODE_PD ||
				(core->printidx == R_CORE_VISUAL_MODE_DB && core->seltab == 2))) {
				int cmtcol = r_config_get_i (core->config, "asm.cmt.col");
				if (cmtcol > 2) {
					r_config_set_i (core->config, "asm.cmt.col", cmtcol - 2);
				}
			}
			// hex column
			if ((core->printidx != R_CORE_VISUAL_MODE_PD && core->printidx != R_CORE_VISUAL_MODE_DB) ||
				(core->printidx == R_CORE_VISUAL_MODE_DB && core->seltab != 2)) {
				int scrcols = r_config_get_i (core->config, "hex.cols");
				if (scrcols > 1) {
					r_config_set_i (core->config, "hex.cols", scrcols - 1);
				}
			}
			break;
		case ']':
			// comments column
			if (core->print->cur_enabled &&
				(core->printidx == R_CORE_VISUAL_MODE_PD ||
				(core->printidx == R_CORE_VISUAL_MODE_DB && core->seltab == 2))) {
				int cmtcol = r_config_get_i (core->config, "asm.cmt.col");
				r_config_set_i (core->config, "asm.cmt.col", cmtcol + 2);
			}
			// hex column
			if ((core->printidx != R_CORE_VISUAL_MODE_PD && core->printidx != R_CORE_VISUAL_MODE_DB) ||
				(core->printidx == R_CORE_VISUAL_MODE_DB && core->seltab != 2)) {
				int scrcols = r_config_get_i (core->config, "hex.cols");
				r_config_set_i (core->config, "hex.cols", scrcols + 1);
			}
			break;
#if 0
		case 'I':
			r_core_cmd (core, "dsp", 0);
			r_core_cmd (core, ".dr*", 0);
			break;
#endif
		case 's':
			key_s = r_config_get (core->config, "key.s");
			if (key_s && *key_s) {
				r_core_cmd0 (core, key_s);
			} else {
				visual_single_step_in (core);
			}
			break;
		case 'S':
			key_s = r_config_get (core->config, "key.S");
			if (key_s && *key_s) {
				r_core_cmd0 (core, key_s);
			} else {
				__core_visual_step_over (core);
			}
			break;
		case '"':
			r_config_toggle (core->config, "scr.dumpcols");
			break;
		case 'p':
			r_core_visual_toggle_decompiler_disasm (core, false, true);
			if (core->printidx == R_CORE_VISUAL_MODE_DB && core->print->cur_enabled) {
				nextPrintCommand ();
			} else {
				setprintmode (core, 1);
			}
			break;
		case 'P':
			if (core->printidx == R_CORE_VISUAL_MODE_DB && core->print->cur_enabled) {
				prevPrintCommand ();
			} else {
				setprintmode (core, -1);
			}
			break;
		case '%':
			if (core->print->cur_enabled) {
				findPair (core);
			} else {
				/* do nothing? */
				autoblocksize = !autoblocksize;
				if (autoblocksize) {
					obs = core->blocksize;
				} else {
					r_core_block_size (core, obs);
				}
				r_cons_clear ();
			}
			break;
		case 'w':
			findNextWord (core);
			break;
		case 'W':
			findPrevWord (core);
			//r_core_cmd0 (core, "=H");
			break;
		case 'm':
			{
				r_cons_gotoxy (0, 0);
				r_cons_printf (R_CONS_CLEAR_LINE"Set shortcut key for 0x%"PFMT64x"\n", core->offset);
				r_cons_flush ();
				int ch = r_cons_readchar ();
				r_core_visual_mark (core, ch);
			}
			break;
		case 'M':
			{
				r_cons_gotoxy (0, 0);
				if (r_core_visual_mark_dump (core)) {
					r_cons_printf (R_CONS_CLEAR_LINE"Remove a shortcut key from the list\n");
					r_cons_flush ();
					int ch = r_cons_readchar ();
					r_core_visual_mark_del (core, ch);
				}
			}
			break;
		case '\'':
			{
				r_cons_gotoxy (0, 0);
				if (r_core_visual_mark_dump (core)) {
					r_cons_flush ();
					int ch = r_cons_readchar ();
					r_core_visual_mark_seek (core, ch);
				}
			}
			break;
		case 'y':
			if (core->print->ocur == -1) {
				r_core_yank (core, core->offset + core->print->cur, 1);
			} else {
				r_core_yank (core, core->offset + ((core->print->ocur < core->print->cur) ?
					core->print->ocur: core->print->cur), R_ABS (core->print->cur - core->print->ocur) + 1);
			}
			break;
		case 'Y':
			if (!core->yank_buf) {
				r_cons_strcat ("Cannot paste, clipboard is empty.\n");
				r_cons_flush ();
				r_cons_any_key (NULL);
				r_cons_clear00 ();
			} else {
				r_core_yank_paste (core, core->offset + core->print->cur, 0);
			}
			break;
		case '0':
		{
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
			if (fcn) {
				r_core_seek (core, fcn->addr, true);
			}
		}
		break;
		case '-':
			if (core->print->cur_enabled) {
				if (core->seltab < 2 && core->printidx == R_CORE_VISUAL_MODE_DB) {
					if (core->seltab) {
						const char *creg = core->dbg->creg;
						if (creg) {
							r_core_cmdf (core, "dr %s = %s-1\n", creg, creg);
						}
					} else {
						int w = r_config_get_i (core->config, "hex.cols");
						r_config_set_i (core->config, "stack.size",
							r_config_get_i (core->config, "stack.size") - w);
					}
				} else {
					if (!canWrite (core, core->offset)) {
						r_cons_printf ("\nFile has been opened in read-only mode. Use -w flag, oo+ or e io.cache=true\n");
						r_cons_any_key (NULL);
						return true;
					}
					if (core->print->ocur == -1) {
						r_core_cmdf (core, "wos 01 @ $$+%i!1", core->print->cur);
					} else {
						r_core_cmdf (core, "wos 01 @ $$+%i!%i", core->print->cur < core->print->ocur
							? core->print->cur
							: core->print->ocur,
							R_ABS (core->print->ocur - core->print->cur) + 1);
					}
				}
			} else {
				if (!autoblocksize) {
					r_core_block_size (core, core->blocksize - 1);
				}
			}
			break;
		case '+':
			if (core->print->cur_enabled) {
				if (core->seltab < 2 && core->printidx == R_CORE_VISUAL_MODE_DB) {
					if (core->seltab) {
						const char *creg = core->dbg->creg;
						if (creg) {
							r_core_cmdf (core, "dr %s = %s+1\n", creg, creg);
						}
					} else {
						int w = r_config_get_i (core->config, "hex.cols");
						r_config_set_i (core->config, "stack.size",
							r_config_get_i (core->config, "stack.size") + w);
					}
				} else {
					if (!canWrite (core, core->offset)) {
						r_cons_printf ("\nFile has been opened in read-only mode. Use -w flag, oo+ or e io.cache=true\n");
						r_cons_any_key (NULL);
						return true;
					}
					if (core->print->ocur == -1) {
						r_core_cmdf (core, "woa 01 @ $$+%i!1", core->print->cur);
					} else {
						r_core_cmdf (core, "woa 01 @ $$+%i!%i", core->print->cur < core->print->ocur
							? core->print->cur
							: core->print->ocur,
							R_ABS (core->print->ocur - core->print->cur) + 1);
					}
				}
			} else {
				if (!autoblocksize) {
					r_core_block_size (core, core->blocksize + 1);
				}
			}
			break;
		case '/': {
			bool mouse_state = __holdMouseState (core);
			if (core->print->cur_enabled) {
				if (core->seltab < 2 && core->printidx == R_CORE_VISUAL_MODE_DB) {
					if (core->seltab) {
						const char *creg = core->dbg->creg;
						if (creg) {
							int delta = core->rasm->config->bits / 8;
							r_core_cmdf (core, "dr %s = %s-%d\n", creg, creg, delta);
						}
					} else {
						int w = r_config_get_i (core->config, "hex.cols");
						r_config_set_i (core->config, "stack.size",
							r_config_get_i (core->config, "stack.size") - w);
					}
				} else {
					visual_search (core);
				}
			} else {
				if (autoblocksize) {
					r_core_cmd0 (core, "?i highlight;e scr.highlight=`yp`");
				} else {
					r_core_block_size (core, core->blocksize - cols);
				}
			}
			r_cons_enable_mouse (mouse_state && r_config_get_i (core->config, "scr.wheel"));
		}	break;
		case '(':
			snowMode = !snowMode;
			if (!snowMode) {
				r_list_free (snows);
				snows = NULL;
			}
			break;
		case ')':
			rotateAsmemu (core);
			break;
		case '#':
			if (core->printidx == 1) {
				r_core_visual_toggle_decompiler_disasm (core, false, false);
			} else {
				// do nothing for now :?, px vs pxa?
			}
			break;
		case '*':
			if (core->print->cur_enabled) {
				if (core->seltab < 2 && core->printidx == R_CORE_VISUAL_MODE_DB) {
					if (core->seltab) {
						const char *creg = core->dbg->creg;
						if (creg) {
							int delta = core->rasm->config->bits / 8;
							r_core_cmdf (core, "dr %s = %s+%d\n", creg, creg, delta);
						}
					} else {
						int w = r_config_get_i (core->config, "hex.cols");
						r_config_set_i (core->config, "stack.size",
							r_config_get_i (core->config, "stack.size") + w);
					}
				} else {
					r_core_cmdf (core, "dr PC=0x%08"PFMT64x, core->offset + core->print->cur);
				}
			} else if (!autoblocksize) {
				r_core_block_size (core, core->blocksize + cols);
			}
			break;
		case '>':
			if (core->print->cur_enabled) {
				if (core->print->ocur == -1) {
					eprintf ("No range selected. Use HJKL.\n");
					r_cons_any_key (NULL);
					break;
				}
				char buf[128];
				// TODO autocomplete filenames
				prompt_read ("dump to file: ", buf, sizeof (buf));
				if (buf[0]) {
					ut64 from = core->offset + core->print->ocur;
					ut64 size = R_ABS (core->print->cur - core->print->ocur) + 1;
					r_core_dump (core, buf, from, size, false);
				}
			} else {
				r_core_seek (core, core->offset + core->blocksize, false);
				r_io_sundo_push (core->io, core->offset, r_print_get_cursor (core->print));
			}
			break;
		case '<': // "V<"
			if (core->print->cur_enabled) {
				char buf[128];
				// TODO autocomplete filenames
				prompt_read ("load from file: ", buf, sizeof (buf));
				if (buf[0]) {
					size_t sz;
					char *data = r_file_slurp (buf, &sz);
					if (data) {
						int cur;
						if (core->print->ocur != -1) {
							cur = R_MIN (core->print->cur, core->print->ocur);
						} else {
							cur = core->print->cur;
						}
						ut64 from = core->offset + cur;
						ut64 size = R_ABS (core->print->cur - core->print->ocur) + 1;
						ut64 s = R_MIN (size, (ut64)sz);
						r_io_write_at (core->io, from, (const ut8*)data, s);
					}
				}
			} else {
				r_core_seek (core, core->offset - core->blocksize, false);
				r_io_sundo_push (core->io, core->offset, r_print_get_cursor (core->print));
			}
			break;
		case '.': // "V."
			r_io_sundo_push (core->io, core->offset, r_print_get_cursor (core->print));
			if (core->print->cur_enabled) {
				r_config_set_i (core->config, "stack.delta", 0);
				r_core_seek (core, core->offset + core->print->cur, true);
				core->print->cur = 0;
			} else {
				ut64 addr = r_debug_reg_get (core->dbg, "PC");
				if (addr && addr != UT64_MAX) {
					r_core_seek (core, addr, true);
					r_core_cmdf (core, "ar `arn PC`=0x%"PFMT64x, addr);
				} else {
					ut64 entry = r_num_get (core->num, "entry0");
					if (!entry || entry == UT64_MAX) {
						RBinObject *o = r_bin_cur_object (core->bin);
						RBinSection *s = o?  r_bin_get_section_at (o, addr, core->io->va): NULL;
						if (s) {
							entry = s->vaddr;
						} else {
							RIOMap *map = NULL;
							RIOBank *bank = r_io_bank_get (core->io, core->io->bank);
							if (bank && r_list_length (bank->maprefs)) {
								map = r_io_map_get (core->io,
									((RIOMapRef *)r_list_get_top (bank->maprefs))->id);
							}
							if (map) {
								entry = r_io_map_from (map);
							} else {
								entry = r_config_get_i (core->config, "bin.baddr");
							}
						}
					}
					if (entry != UT64_MAX) {
						r_core_seek (core, entry, true);
					}
				}
			}
			break;
#if 0
		case 'n': r_core_seek_delta (core, core->blocksize); break;
		case 'N': r_core_seek_delta (core, 0 - (int) core->blocksize); break;
#endif
		case ':':
			r_core_visual_prompt_input (core);
			break;
		case '_':
			r_core_visual_hudstuff (core);
			break;
		case ';':
			r_cons_enable_mouse (false);
			r_cons_gotoxy (0, 0);
			r_cons_printf ("Enter a comment: ('-' to remove, '!' to use $EDITOR)\n");
			r_core_visual_showcursor (core, true);
			r_cons_flush ();
			r_cons_set_raw (false);
			r_line_set_prompt ("comment: ");
			strcpy (buf, "\"CC ");
			i = strlen (buf);
			if (r_cons_fgets (buf + i, sizeof (buf) - i, 0, NULL) > 0) {
				ut64 addr, orig;
				addr = orig = core->offset;
				if (core->print->cur_enabled) {
					addr += core->print->cur;
					r_core_seek (core, addr, false);
					r_core_cmdf (core, "s 0x%"PFMT64x, addr);
				}
				const char *command = "CC ";
				const char *argument = NULL;
				switch (buf[i]) {
				case '-':
					command = "CC-";
					argument = r_str_trim_head_ro (buf + i + 1);
					break;
				case '!':
					command = "CC!";
					argument = r_str_trim_head_ro (buf + i + 1);
					break;
				default:
					command = "CC ";
					argument = r_str_trim_head_ro (buf + i);
					break;
				}
				r_core_cmdf (core, "\"%s%s\"", command, argument);
				if (core->print->cur_enabled) {
					r_core_seek (core, orig, true);
				}
			}
			r_cons_set_raw (true);
			r_core_visual_showcursor (core, false);
			break;
		case 'b':
			r_core_visual_browse (core, arg + 1);
			break;
		case 'B':
			{
			ut64 addr = core->print->cur_enabled? core->offset + core->print->cur: core->offset;
			r_core_cmdf (core, "dbs 0x%08"PFMT64x, addr);
			}
			break;
		case 'u':
		{
			RIOUndos *undo = r_io_sundo (core->io, core->offset);
			if (undo) {
				r_core_visual_seek_animation (core, undo->off);
				core->print->cur = undo->cursor;
			} else {
				eprintf ("Cannot undo\n");
			}
		}
		break;
		case 'U':
		{
			RIOUndos *undo = r_io_sundo_redo (core->io);
			if (undo) {
				r_core_visual_seek_animation (core, undo->off);
				reset_print_cur (core->print);
			}
		}
		break;
		case 'z':
		{
			RAnalFunction *fcn;
			if (core->print->cur_enabled) {
				fcn = r_anal_get_fcn_in (core->anal,
					core->offset + core->print->cur, R_ANAL_FCN_TYPE_NULL);
			} else {
				fcn = r_anal_get_fcn_in (core->anal,
					core->offset, R_ANAL_FCN_TYPE_NULL);
			}
			if (fcn) {
				fcn->folded = !fcn->folded;
			} else {
				r_config_toggle (core->config, "asm.cmt.fold");
			}
		}
		break;
		case 'Z': // shift-tab SHIFT-TAB
			if (och == 27) { // shift-tab
				if (core->print->cur_enabled && core->printidx == R_CORE_VISUAL_MODE_DB) {
					core->print->cur = 0;
					core->seltab--;
					if (core->seltab < 0) {
						core->seltab = 2;
					}
				} else {
					prevPrintFormat (core);
				}
			} else { // "Z"
				ut64 addr = core->print->cur_enabled? core->offset + core->print->cur: core->offset;
				toggle_bb (core, addr);
			}
			break;
		case '?':
			if (visual_help (core) == '?') {
				r_core_visual_hud (core);
			}
			break;
		case 0x1b:
		case 'q':
		case 'Q':
			setcursor (core, false);
			return false;
		}
		numbuf_i = 0;
	}
	r_core_block_read (core);
	return true;
}

R_API void r_core_visual_title(RCore *core, int color) {
	bool showDelta = r_config_get_b (core->config, "asm.slow");
	static ut64 oldpc = 0;
	const char *BEGIN = core->cons->context->pal.prompt;
	const char *filename;
	char pos[512], bar[512], pcs[32];
	if (!oldpc) {
		oldpc = r_debug_reg_get (core->dbg, "PC");
	}
	/* automatic block size */
	int pc, hexcols = r_config_get_i (core->config, "hex.cols");
	if (autoblocksize) {
		switch (core->printidx) {
#if 0
		case R_CORE_VISUAL_MODE_PXR: // prc
		case R_CORE_VISUAL_MODE_PRC: // prc
			r_core_block_size (core, (int)(core->cons->rows * hexcols * 3.5));
			break;
		case R_CORE_VISUAL_MODE_PXa: // pxa
		case R_CORE_VISUAL_MODE_PW: // XXX pw
			r_core_block_size (core, (int)(core->cons->rows * hexcols));
			break;
		case R_CORE_VISUAL_MODE_PC: // XXX pc
			r_core_block_size (core, (int)(core->cons->rows * hexcols * 4));
			break;
		case R_CORE_VISUAL_MODE_PXA: // pxA
			r_core_block_size (core, hexcols * core->cons->rows * 8);
			break;
#endif
		case R_CORE_VISUAL_MODE_PX: // x
			if (currentFormat == 3 || currentFormat == 9 || currentFormat == 5) { // prx
				r_core_block_size (core, (int)(core->cons->rows * hexcols * 4));
			} else if ((R_ABS (hexMode) % 3) == 0) { // prx
				r_core_block_size (core, (int)(core->cons->rows * hexcols));
			} else {
				r_core_block_size (core, (int)(core->cons->rows * hexcols * 2));
			}
			break;
		case R_CORE_VISUAL_MODE_OV:
		case R_CORE_VISUAL_MODE_CD:
			r_core_block_size (core, (int)(core->cons->rows * hexcols * 2));
			break;
		case R_CORE_VISUAL_MODE_PD: // pd
		case R_CORE_VISUAL_MODE_DB: // pd+dbg
		{
			int bsize = core->cons->rows * 5;
			if (core->print->screen_bounds > 1) {
				// estimate new blocksize with the size of the last
				// printed instructions
				int new_sz = core->print->screen_bounds - core->offset + 32;
				new_sz = R_MIN (new_sz, 16 * 1024);
				if (new_sz > bsize) {
					bsize = new_sz;
				}
			}
			r_core_block_size (core, bsize);
			break;
		}
		}
	}
	if (r_config_get_i (core->config, "scr.scrollbar") == 2) {
		r_core_cmd (core, "fz:", 0);
	}
	if (r_config_get_b (core->config, "cfg.debug")) {
		ut64 curpc = r_debug_reg_get (core->dbg, "PC");
		if (curpc && curpc != UT64_MAX && curpc != oldpc) {
			// check dbg.follow here
			int follow = (int) (st64) r_config_get_i (core->config, "dbg.follow");
			if (follow > 0) {
				if ((curpc < core->offset) || (curpc > (core->offset + follow))) {
					r_core_seek (core, curpc, true);
				}
			} else if (follow < 0) {
				r_core_seek (core, curpc + follow, true);
			}
			oldpc = curpc;
		}
	}
	RIOMap *map = r_io_map_get_at (core->io, core->offset);
	RIODesc *desc = map ? r_io_desc_get (core->io, map->fd) : core->io->desc;
	filename = desc? desc->name: "";

	{ /* get flag with delta */
		ut64 addr = core->offset + (core->print->cur_enabled? core->print->cur: 0);
		/* TODO: we need a helper into r_flags to do that */
		RFlagItem *f = NULL;
		if (r_flag_space_push (core->flags, R_FLAGS_FS_SYMBOLS)) {
			f = r_flag_get_at (core->flags, addr, showDelta);
			r_flag_space_pop (core->flags);
		}
		if (!f) {
			f = r_flag_get_at (core->flags, addr, showDelta);
		}
		if (f) {
			if (f->offset == addr || !f->offset) {
				snprintf (pos, sizeof (pos), "@ %s", f->name);
			} else {
				snprintf (pos, sizeof (pos), "@ %s+%d # 0x%"PFMT64x,
					f->name, (int) (addr - f->offset), addr);
			}
		} else {
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, 0);
			if (fcn) {
				int delta = addr - fcn->addr;
				if (delta > 0) {
					snprintf (pos, sizeof (pos), "@ %s+%d", fcn->name, delta);
				} else if (delta < 0) {
					snprintf (pos, sizeof (pos), "@ %s%d", fcn->name, delta);
				} else {
					snprintf (pos, sizeof (pos), "@ %s", fcn->name);
				}
			} else {
				pos[0] = 0;
			}
		}
	}

	if (core->print->cur < 0) {
		core->print->cur = 0;
	}

	if (color) {
		r_cons_strcat (BEGIN);
	}
	const char *cmd_visual = r_config_get (core->config, "cmd.visual");
	if (cmd_visual && *cmd_visual) {
		r_str_ncpy (bar, cmd_visual, sizeof (bar) - 1);
		bar[10] = '.'; // chop cmdfmt
		bar[11] = '.'; // chop cmdfmt
		bar[12] = 0; // chop cmdfmt
	} else {
		const char *cmd = __core_visual_print_command (core);
		if (cmd) {
			r_str_ncpy (bar, cmd, sizeof (bar) - 1);
			bar[10] = '.'; // chop cmdfmt
			bar[11] = '.'; // chop cmdfmt
			bar[12] = 0; // chop cmdfmt
		}
	}
	{
		ut64 sz = r_io_size (core->io);
		ut64 pa = core->offset;
		{
			RIOMap *map = r_io_map_get_at (core->io, core->offset);
			if (map) {
				pa = map->delta;
			}
		}
		if (sz == UT64_MAX) {
			pcs[0] = 0;
		} else {
			if (!sz || pa > sz) {
				pc = 0;
			} else {
				pc = (pa * 100) / sz;
			}
			sprintf (pcs, "%d%% ", pc);
		}
	}
	{
		char *title;
		char *address = (core->print->wide_offsets && core->dbg->bits & R_SYS_BITS_64)
			? r_str_newf ("0x%016"PFMT64x, core->offset)
			: r_str_newf ("0x%08"PFMT64x, core->offset);
		if (__ime) {
			title = r_str_newf ("[%s + %d> * INSERT MODE *\n",
				address, core->print->cur);
		} else {
			char pm[32] = "[XADVC]";
			int i;
			for(i=0;i<6;i++) {
				if (core->printidx == i) {
					pm[i + 1] = toupper((unsigned char)pm[i + 1]);
				} else {
					pm[i + 1] = tolower((unsigned char)pm[i + 1]);
				}
			}
			if (core->print->cur_enabled) {
				if (core->print->ocur == -1) {
					title = r_str_newf ("[%s *0x%08"PFMT64x" %s%d ($$+0x%x)]> %s %s\n",
						address, core->offset + core->print->cur,
						pm, currentFormat, core->print->cur,
						bar, pos);
				} else {
					title = r_str_newf ("[%s 0x%08"PFMT64x" %s%d [0x%x..0x%x] %d]> %s %s\n",
						address, core->offset + core->print->cur,
						pm, currentFormat, core->print->ocur, core->print->cur,
						R_ABS (core->print->cur - core->print->ocur) + 1,
						bar, pos);
				}
			} else {
				title = r_str_newf ("[%s %s%d %s%d %s]> %s %s\n",
					address, pm, currentFormat, pcs, core->blocksize, filename, bar, pos);
			}
		}
		const int tabsCount = __core_visual_tab_count (core);
		if (tabsCount > 0) {
			const char *kolor = core->cons->context->pal.prompt;
			char *tabstring = __core_visual_tab_string (core, kolor);
			if (tabstring) {
				title = r_str_append (title, tabstring);
				free (tabstring);
			}
#if 0
			// TODO: add an option to show this tab mode instead?
			const int curTab = core->visual.tab;
			r_cons_printf ("[");
			int i;
			for (i = 0; i < tabsCount; i++) {
				if (i == curTab) {
					r_cons_printf ("%d", curTab + 1);
				} else {
					r_cons_printf (".");
				}
			}
			r_cons_printf ("]");
			r_cons_printf ("[tab:%d/%d]", core->visual.tab, tabsCount);
#endif
		}
		r_cons_print (title);
		free (title);
		free (address);
	}
	if (color) {
		r_cons_strcat (Color_RESET);
	}
}

static int visual_responsive(RCore *core) {
	int h, w = r_cons_get_size (&h);
	if (r_config_get_i (core->config, "scr.responsive")) {
		if (w < 110) {
			r_config_set_i (core->config, "asm.cmt.right", 0);
		} else {
			r_config_set_i (core->config, "asm.cmt.right", 1);
		}
		if (w < 68) {
			r_config_set_i (core->config, "hex.cols", (int)(w / 5.2));
		} else {
			r_config_set_i (core->config, "hex.cols", 16);
		}
		if (w < 25) {
			r_config_set_i (core->config, "asm.offset", 0);
		} else {
			r_config_set_i (core->config, "asm.offset", 1);
		}
		if (w > 80) {
			r_config_set_i (core->config, "asm.lines.width", 14);
			r_config_set_i (core->config, "asm.lines.width", w - (int)(w / 1.2));
			r_config_set_i (core->config, "asm.cmt.col", w - (int)(w / 2.5));
		} else {
			r_config_set_i (core->config, "asm.lines.width", 7);
		}
		if (w < 70) {
			r_config_set_i (core->config, "asm.lines.width", 1);
			r_config_set_i (core->config, "asm.bytes", 0);
		} else {
			r_config_set_i (core->config, "asm.bytes", 1);
		}
	}
	return w;
}

// TODO: use colors
// TODO: find better name
R_API void r_core_print_scrollbar(RCore *core) {
	int i, h, w = r_cons_get_size (&h);

	int scrollbar = r_config_get_i (core->config, "scr.scrollbar");
	if (scrollbar == 2) {
		// already handled by r_core_cmd("zf:") in visual.c
		return;
	}
	if (scrollbar > 2) {
		r_core_print_scrollbar_bottom (core);
		return;
	}

	if (w < 10 || h < 3) {
		return;
	}
	ut64 from = 0;
	ut64 to = UT64_MAX;
	if (r_config_get_b (core->config, "cfg.debug")) {
		from = r_num_math (core->num, "$D");
		to = r_num_math (core->num, "$D+$DD");
	} else if (r_config_get_i (core->config, "io.va")) {
		from = r_num_math (core->num, "$S");
		to = r_num_math (core->num, "$S+$SS");
	} else {
		to = r_num_math (core->num, "$s");
	}
	char *s = r_str_newf ("[0x%08"PFMT64x"]", from);
	r_cons_gotoxy (w - strlen (s) + 1, 2);
	r_cons_strcat (s);
	free (s);

	ut64 block = (to - from) / h;

	RList *words = r_flag_zone_barlist (core->flags, from, block, h);

	bool hadMatch = false;
	for (i = 0; i < h ; i++) {
		const char *word = r_list_pop_head (words);
		if (word && *word) {
			r_cons_gotoxy (w - strlen (word) - 1, i + 3);
			r_cons_printf ("%s>", word);
		}
		r_cons_gotoxy (w, i + 3);
		if (hadMatch) {
			r_cons_printf ("|");
		} else {
			ut64 cur = from + (block * i);
			ut64 nex = from + (block * (i + 1));
			if (R_BETWEEN (cur, core->offset, nex)) {
				r_cons_printf (Color_INVERT"|"Color_RESET);
				hadMatch = true;
			} else {
				r_cons_printf ("|");
			}
		}
	}
	s = r_str_newf ("[0x%08"PFMT64x"]", to);
	if (s) {
		r_cons_gotoxy (w - strlen (s) + 1, h + 1);
		r_cons_strcat (s);
		free (s);
	}
	r_list_free (words);
	r_cons_flush ();
}

R_API void r_core_print_scrollbar_bottom(RCore *core) {
	int i, h, w = r_cons_get_size (&h);

	if (w < 10 || h < 4) {
		return;
	}
	ut64 from = 0;
	ut64 to = UT64_MAX;
	if (r_config_get_b (core->config, "cfg.debug")) {
		from = r_num_math (core->num, "$D");
		to = r_num_math (core->num, "$D+$DD");
	} else if (r_config_get_i (core->config, "io.va")) {
		from = r_num_math (core->num, "$S");
		to = r_num_math (core->num, "$S+$SS");
	} else {
		to = r_num_math (core->num, "$s");
	}
	char *s = r_str_newf ("[0x%08"PFMT64x"]", from);
	int slen = strlen (s) + 1;
	r_cons_gotoxy (0, h + 1);
	r_cons_strcat (s);
	free (s);

	int linew = (w - (slen * 2)) + 1;
	ut64 block = (to - from) / linew;

	RList *words = r_flag_zone_barlist (core->flags, from, block, h);

	bool hadMatch = false;
	for (i = 0; i < linew + 1; i++) {
		r_cons_gotoxy (i + slen, h + 1);
		if (hadMatch) {
			r_cons_strcat ("-");
		} else {
			ut64 cur = from + (block * i);
			ut64 nex = from + (block * (i + 2));
			if (R_BETWEEN (cur, core->offset, nex)) {
				r_cons_strcat (Color_INVERT"-"Color_RESET);
				hadMatch = true;
			} else {
				r_cons_strcat ("-");
			}
		}
	}
	for (i = 0; i < linew; i++) {
		const char *word = r_list_pop_head (words);
		if (word && *word) {
			ut64 cur = from + (block * i);
			ut64 nex = from + (block * (i + strlen (word) + 1));
			r_cons_gotoxy (i + slen - 1, h);
			if (R_BETWEEN (cur, core->offset, nex)) {
				r_cons_printf (Color_INVERT"{%s}"Color_RESET, word);
			} else {
				r_cons_printf ("{%s}", word);
			}
		}
	}
	s = r_str_newf ("[0x%08"PFMT64x"]", to);
	if (s) {
		r_cons_gotoxy (linew + slen + 1, h + 1);
		r_cons_strcat (s);
		free (s);
	}
	r_list_free (words);
	r_cons_flush ();
}

static void show_cursor(RCore *core) {
	const bool keyCursor = r_config_get_b (core->config, "scr.cursor");
	if (keyCursor) {
		r_cons_gotoxy (core->cons->cpos.x, core->cons->cpos.y);
		r_cons_show_cursor (1);
		//r_cons_invert (1, 1);
		//r_cons_print ("#");
		r_cons_flush ();
	}
}

static void visual_refresh(RCore *core) {
	static ut64 oseek = UT64_MAX;
	const char *vi, *vcmd, *cmd_str;
	if (!core) {
		return;
	}
	r_print_set_cursor (core->print, core->print->cur_enabled, core->print->ocur, core->print->cur);
	core->cons->blankline = true;
	int notch = r_config_get_i (core->config, "scr.notch");

	int w = visual_responsive (core);

	if (autoblocksize) {
		r_cons_gotoxy (0, 0);
	} else {
		r_cons_clear ();
	}
	r_cons_flush ();
	r_cons_print_clear ();
	core->cons->context->noflush = true;

	int hex_cols = r_config_get_i (core->config, "hex.cols");
	int split_w = 12 + 4 + hex_cols + (hex_cols * 3);
	bool ce = core->print->cur_enabled;

	vi = r_config_get (core->config, "cmd.cprompt");
	bool vsplit = (vi && *vi);

	if (vsplit) {
		// XXX: slow
		core->cons->blankline = false;
		{
			int hex_cols = r_config_get_i (core->config, "hex.cols");
			int split_w = 12 + 4 + hex_cols + (hex_cols * 3);
			if (split_w > w) {
				// do not show column contents
			} else {
				r_cons_printf ("[cmd.cprompt=%s]\n", vi);
				if (oseek != UT64_MAX) {
					r_core_seek (core, oseek, true);
				}
				r_core_cmd0 (core, vi);
				r_cons_column (split_w);
				if (!strncmp (vi, "p=", 2) && core->print->cur_enabled) {
					oseek = core->offset;
					core->print->cur_enabled = false;
					r_core_seek (core, core->num->value, true);
				} else {
					oseek = UT64_MAX;
				}
			}
		}
		r_cons_gotoxy (0, 0);
	}
	int i;
	for (i = 0; i < notch; i++) {
		r_cons_printf (R_CONS_CLEAR_LINE"\n");
	}
	vi = r_config_get (core->config, "cmd.vprompt");
	if (vi && *vi) {
		r_core_cmd0 (core, vi);
#if 0
		char *output = r_core_cmd_str (core, vi);
		r_cons_strcat_at (output, 10, 5, 20, 20);
		free (output);
#endif
	}
	r_core_visual_title (core, color);
	vcmd = r_config_get (core->config, "cmd.visual");
	if (vcmd && *vcmd) {
		// disable screen bounds when it's a user-defined command
		// because it can cause some issues
		core->print->screen_bounds = 0;
		cmd_str = vcmd;
	} else {
		if (splitView) {
			static char debugstr[512];
			const char *pxw = NULL;
			int h = r_num_get (core->num, "$r");
			int size = (h * 16) / 2;
			switch (core->printidx) {
			case 1:
				size = (h - 2) / 2;
				pxw = "pd";
				break;
			default:
				pxw = stackPrintCommand (core);
				break;
			}
			snprintf (debugstr, sizeof (debugstr),
					"?t0;%s %d @ %"PFMT64d";cl;"
					"?t1;%s %d @ %"PFMT64d";",
					pxw, size, splitPtr,
					pxw, size, core->offset);
			core->print->screen_bounds = 1LL;
			cmd_str = debugstr;
		} else {
			core->print->screen_bounds = 1LL;
			cmd_str = (zoom ? "pz" : __core_visual_print_command (core));
		}
	}
	if (cmd_str && *cmd_str) {
		if (vsplit) {
			char *cmd_result = r_core_cmd_str (core, cmd_str);
			cmd_result = r_str_ansi_crop (cmd_result, 0, 0, split_w, -1);
			r_cons_strcat (cmd_result);
			free (cmd_result);
		} else {
			char *res = r_core_cmd_str (core, cmd_str);
			r_cons_strcat (res);
			free (res);
		}
	}
	core->print->cur_enabled = ce;
#if 0
	if (core->print->screen_bounds != 1LL) {
		r_cons_printf ("[0x%08"PFMT64x "..0x%08"PFMT64x "]\n",
			core->offset, core->print->screen_bounds);
	}
#endif
	blocksize = core->num->value? core->num->value: core->blocksize;
	core->cons->context->noflush = false;
	/* this is why there's flickering */
	if (core->print->vflush) {
		r_cons_visual_flush ();
	} else {
		r_cons_reset ();
	}
	if (core->scr_gadgets) {
		r_core_cmd0 (core, "pg");
		r_cons_flush ();
	}
	core->cons->blankline = false;
	core->cons->blankline = true;
	core->curtab = 0; // which command are we focusing
	//core->seltab = 0; // user selected tab

	if (snowMode) {
		printSnow (core);
	}
	if (r_config_get_i (core->config, "scr.scrollbar")) {
		r_core_print_scrollbar (core);
	}
	show_cursor (core);
}

static void visual_refresh_oneshot(RCore *core) {
	r_core_task_enqueue_oneshot (&core->tasks, (RCoreTaskOneShot) visual_refresh, core);
}

R_API void r_core_visual_disasm_up(RCore *core, int *cols) {
	RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
	if (f && f->folded) {
		*cols = core->offset - f->addr; // + f->size;
		if (*cols < 1) {
			*cols = 4;
		}
	} else {
		*cols = r_core_visual_prevopsz (core, core->offset);
	}
}

R_API void r_core_visual_disasm_down(RCore *core, RAsmOp *op, int *cols) {
	int midflags = r_config_get_i (core->config, "asm.flags.middle");
	const bool midbb = r_config_get_i (core->config, "asm.bbmiddle");
	RAnalFunction *f = NULL;
	f = r_anal_get_fcn_in (core->anal, core->offset, 0);
	op->size = 1;
	if (f && f->folded) {
		*cols = core->offset - r_anal_function_max_addr (f);
	} else {
		r_asm_set_pc (core->rasm, core->offset);

		int maxopsize = r_anal_archinfo (core->anal,
			R_ANAL_ARCHINFO_MAX_OP_SIZE);
		size_t bufsize = maxopsize > -1? R_MAX (maxopsize, 32): 32;
		ut8 *buf = calloc (bufsize, sizeof (ut8));
		if (!buf) {
			r_cons_eprintf ("Cannot allocate %d byte(s)\n", (int)bufsize);
			return;
		};
		ut64 orig = core->offset;
		size_t bufpos = 0;
		size_t cpysize = 0;
		while (bufpos < bufsize) {
			cpysize = bufsize - bufpos;
			if (cpysize > core->blocksize) {
				cpysize = core->blocksize;
			}
			memcpy (buf + bufpos, core->block, cpysize);
			bufpos += cpysize;
			r_core_seek (core, orig + bufpos, true);
		}
		r_core_seek (core, orig, true);
		*cols = r_asm_disassemble (core->rasm,
			op, buf, bufsize);
		free (buf);

		if (midflags || midbb) {
			int skip_bytes_flag = 0, skip_bytes_bb = 0;
			if (midflags >= R_MIDFLAGS_REALIGN) {
				skip_bytes_flag = r_core_flag_in_middle (core, core->offset, *cols, &midflags);
			}
			if (midbb) {
				skip_bytes_bb = r_core_bb_starts_in_middle (core, core->offset, *cols);
			}
			if (skip_bytes_flag) {
				*cols = skip_bytes_flag;
			}
			if (skip_bytes_bb && skip_bytes_bb < *cols) {
				*cols = skip_bytes_bb;
			}
		}
	}
	if (*cols < 1) {
		*cols = op->size > 1 ? op->size : 1;
	}
}

#ifdef __WINDOWS__

static bool is_mintty(RCons *cons) {
	return cons->term_xterm;
}

static void flush_stdin(void) {
	while (r_cons_readchar_timeout (1) != -1) ;
}

#else

static bool is_mintty(RCons *cons) {
	return false;
}

static void flush_stdin(void) {
#ifndef __wasi__
	tcflush (STDIN_FILENO, TCIFLUSH);
#endif
}

#endif

R_API int r_core_visual(RCore *core, const char *input) {
	const char *teefile;
	ut64 scrseek;
	int flags, ch;
	bool skip;
	char arg[2] = {
		input[0], 0
	};

	splitPtr = UT64_MAX;

	if (r_cons_get_size (&ch) < 1 || ch < 1) {
		eprintf ("Cannot create Visual context. Use scr.fix_{columns|rows}\n");
		return 0;
	}

	obs = core->blocksize;
	//r_cons_set_cup (true);
	if (strchr (input, '?')) {
		// show V? help message, disables oneliner to open visual help
		return 0;
	}
	core->vmode = false;
	/* honor vim */
	if (!strncmp (input, "im", 2)) {
		char *cmd = r_str_newf ("!v%s", input);
		int ret = r_core_cmd0 (core, cmd);
		free (cmd);
		return ret;
	}
	while (*input) {
		int len = *input == 'd'? 2: 1;
		if (!r_core_visual_cmd (core, input)) {
			return 0;
		}
		input += len;
	}
	core->vmode = true;

	// disable tee in cons
	teefile = r_cons_singleton ()->teefile;
	r_cons_singleton ()->teefile = "";

	static char debugstr[512];
	core->print->flags |= R_PRINT_FLAGS_ADDRMOD;
	do {
dodo:
		r_core_visual_tab_update (core);
		// update the cursor when it's not visible anymore
		skip = fix_cursor (core);
		r_cons_show_cursor (false);
		r_cons_set_raw (1);
		const int ref = r_config_get_i (core->config, "dbg.slow");
#if 1
		// This is why multiple debug views dont work
		if (core->printidx == R_CORE_VISUAL_MODE_DB) {
			const int pxa = r_config_get_i (core->config, "stack.anotated"); // stack.anotated
			const char *reg = r_config_get (core->config, "stack.reg");
			const int size = r_config_get_i (core->config, "stack.size");
			const int delta = r_config_get_i (core->config, "stack.delta");
			const char *cmdvhex = r_config_get (core->config, "cmd.stack");

			if (cmdvhex && *cmdvhex) {
				snprintf (debugstr, sizeof (debugstr),
					"?t0;f tmp;ssr %s;%s;?t1;%s;drcq;?t1;"
					"ss tmp;f-tmp;pd $r", reg, cmdvhex,
					ref? "drr": "dr=");
				debugstr[sizeof (debugstr) - 1] = 0;
			} else {
				const char *pxw = stackPrintCommand (core);
				const char sign = (delta < 0)? '+': '-';
				const int absdelta = R_ABS (delta);
				snprintf (debugstr, sizeof (debugstr),
					"diq;?t0;f tmp;ssr %s;%s %d@$$%c%d;"
					"?t1;%s;drcq;"
					"?t1;ss tmp;f-tmp;afal;pd $r",
					reg, pxa? "pxa": pxw, size, sign, absdelta,
					ref? "drr": "dr=");
			}
			printfmtSingle[2] = debugstr;
		}
#endif
		r_cons_show_cursor (false);
		r_cons_enable_mouse (r_config_get_i (core->config, "scr.wheel"));
		core->cons->event_resize = NULL; // avoid running old event with new data
		core->cons->event_data = core;
		core->cons->event_resize = (RConsEvent) visual_refresh_oneshot;
		flags = core->print->flags;
		color = r_config_get_i (core->config, "scr.color");
		if (color) {
			flags |= R_PRINT_FLAGS_COLOR;
		}
		flags |= R_PRINT_FLAGS_ADDRMOD | R_PRINT_FLAGS_HEADER;
		r_print_set_flags (core->print, flags);
		scrseek = r_num_math (core->num,
			r_config_get (core->config, "scr.seek"));
		if (scrseek != 0LL) {
			r_core_seek (core, scrseek, true);
		}
		if (r_config_get_b (core->config, "cfg.debug")) {
			r_core_cmd (core, ".dr*", 0);
		}
#if 0
		cmdprompt = r_config_get (core->config, "cmd.vprompt");
		if (cmdprompt && *cmdprompt) {
			r_core_cmd (core, cmdprompt, 0);
		}
#endif
		core->print->vflush = !skip;

		visual_refresh (core);
		if (insert_mode_enabled (core)) {
			goto dodo;
		}
		if (!skip) {
			if (snowMode) {
				ch = r_cons_readchar_timeout (300);
				if (ch == -1) {
					skip = 1;
					continue;
				}
			} else {
				ch = r_cons_readchar ();
			}
			if (I->vtmode == 2 && !is_mintty (core->cons)) {
				// Prevent runaway scrolling
				if (IS_PRINTABLE (ch) || ch == '\t' || ch == '\n') {
					flush_stdin ();
				} else if (ch == 0x1b) {
					char chrs[2];
					int chrs_read = 1;
					chrs[0] = r_cons_readchar ();
					if (chrs[0] == '[') {
						chrs[1] = r_cons_readchar ();
						chrs_read++;
						if (chrs[1] >= 'A' && chrs[1] <= 'D') { // arrow keys
							flush_stdin ();
#ifndef __WINDOWS__
							// Following seems to fix an issue where scrolling slows
							// down to a crawl for some terminals after some time
							// mashing the up and down arrow keys
							r_cons_set_raw (false);
							r_cons_set_raw (true);
#endif
						}
					}
					(void)r_cons_readpush (chrs, chrs_read);
				}
			}
			if (r_cons_is_breaked()) {
				break;
			}
			r_core_visual_show_char (core, ch);
			if (ch == -1 || ch == 4) {
				break;                  // error or eof
			}
			arg[0] = ch;
			arg[1] = 0;
		}
	} while (skip || (*arg && r_core_visual_cmd (core, arg)));

	r_cons_enable_mouse (false);
	if (color) {
		r_cons_strcat (Color_RESET);
	}
	r_config_set_i (core->config, "scr.color", color);
	core->print->cur_enabled = false;
	if (autoblocksize) {
		r_core_block_size (core, obs);
	}
	r_cons_singleton ()->teefile = teefile;
	r_cons_set_cup (false);
	r_cons_clear00 ();
	core->vmode = false;
	core->cons->event_resize = NULL;
	core->cons->event_data = NULL;
	r_cons_show_cursor (true);
	return 0;
}

R_API RListInfo *r_listinfo_new(const char *name, RInterval pitv, RInterval vitv, int perm, const char *extra) {
	RListInfo *info = R_NEW (RListInfo);
	if (info) {
		info->name = name ? strdup (name) : NULL;
		info->pitv = pitv;
		info->vitv = vitv;
		info->perm = perm;
		info->extra = extra ? strdup (extra) : NULL;
	}
	return info;
}

R_API void r_listinfo_free(RListInfo *info) {
	if (!info) {
		return;
	}
	free (info->name);
	free (info->extra);
	free (info);
}
