/* radare - LGPL - Copyright 2009-2025 - pancake */

#include <r_core.h>
#include <r_vec.h>

R_VEC_TYPE(RVecAnalRef, RAnalRef);

#define NPF 5
#define PIDX (R_ABS (core->visual.printidx % NPF))

R_IPI void visual_refresh(RCore *core);
R_IPI void visual_add_comment(RCore *core, ut64 at);

typedef struct {
	int x;
	int y;
} Snow;

#define KEY_ALTQ 0xc5

static const char *printfmtSingle[NPF] = {
	"xc",  // HEXDUMP
	"afsQ;pd $r",  // ASSEMBLY
	"pxw 64@r:SP;dr=;drcq;afsQ;pd $r",  // DEBUGGER
	"prc", // OVERVIEW
	"psb", // PC//  copypasteable views
};

static const char *printfmtColumns[NPF] = {
	"pCx",  // HEXDUMP // + pCw
	"pCd $r-1",  // ASSEMBLY
	"pCD",  // DEBUGGER
	"pCA", // OVERVIEW
	"pCc", // PC//  copypasteable views
};

// to print the stack in the debugger view
#define PRINT_HEX_FORMATS 12
#define PRINT_3_FORMATS 2
#define PRINT_4_FORMATS 9
#define PRINT_5_FORMATS 7

// always in pairs, because thats how <space> knows how to toggle
static const char *printHexFormats[PRINT_HEX_FORMATS] = {
	"px", "pxa",
	"pxr", "pxr4",
	"prcn", "prcb",
	"pxb", "pxh",
	"pxw", "pxq",
	"pxu", "pxd",
};
static const char *print3Formats[PRINT_3_FORMATS] = { //  not used at all. its handled by the pd format
	"pxw 64@r:SP;dr=;drcq;pd $r", // DEBUGGER
	"pCD"
};
static const char *print4Formats[PRINT_4_FORMATS] = {
	"prc", "p2", "prc=a", "pxAv", "pxx", "p=e $r-2", "pq 64", "pk 64", "pri",
};
static const char *print5Formats[PRINT_5_FORMATS] = {
	"pca", "pcA", "p8x", "pcc", "psb", "pcp", "pcd",
};

R_IPI void applyHexMode(RCore *core) {
	int hexMode = core->visual.hexMode;
	core->visual.currentFormat = R_ABS (hexMode) % PRINT_HEX_FORMATS;
	switch (core->visual.currentFormat) {
	case 0: /* px */
	case 3: /* prx */
	case 6: /* pxw */
	case 10: /* pxr */
		r_config_set_b (core->config, "hex.compact", false);
		r_config_set_b (core->config, "hex.comments", true);
		break;
	case 1: /* pxa */
		r_config_set_b (core->config, "hex.compact", false);
		r_config_set_b (core->config, "hex.comments", true);
		break;
	case 4: /* pxb */
	case 7: /* pxq */
		r_config_set_b (core->config, "hex.compact", true);
		r_config_set_b (core->config, "hex.comments", true);
		break;
	case 2: /* pxr */
	case 5: /* pxh */
	case 8: /* pxu */
	case 9: /* pxd */
		r_config_set_b (core->config, "hex.compact", false);
		r_config_set_b (core->config, "hex.comments", false);
		break;
	}
}

R_API void r_core_visual_toggle_decompiler_disasm(RCore *core, bool for_graph, bool reset) {
	if (core->visual.hold) {
		r_config_hold_restore (core->visual.hold);
		r_config_hold_free (core->visual.hold);
		core->visual.hold = NULL;
		return;
	}
	if (reset) {
		return;
	}
	core->visual.hold = r_config_hold_new (core->config);
	r_config_hold (core->visual.hold, "asm.hint.pos", "asm.cmt.col", "asm.addr", "asm.lines",
	"asm.indent", "asm.bytes", "asm.comments", "asm.dwarf", "asm.cmt.user", "asm.instr", NULL);
	if (for_graph) {
		r_config_set (core->config, "asm.hint.pos", "-2");
		r_config_set_b (core->config, "asm.lines", false);
		r_config_set_b (core->config, "asm.indent", false);
	} else {
		r_config_set (core->config, "asm.hint.pos", "0");
		r_config_set_b (core->config, "asm.indent", true);
		r_config_set_b (core->config, "asm.lines", true);
	}
	r_config_set_i (core->config, "asm.cmt.col", 0);
	r_config_set_b (core->config, "asm.addr", false);
	r_config_set_b (core->config, "asm.dwarf", true);
	r_config_set_b (core->config, "asm.bytes", false);
	r_config_set_b (core->config, "asm.comments", false);
	r_config_set_b (core->config, "asm.cmt.user", true);
	r_config_set_b (core->config, "asm.instr", false);
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

R_IPI void applyDisMode(RCore *core) {
	const int disMode = core->visual.disMode;
	core->visual.currentFormat = R_ABS (disMode) % 5;
	switch (core->visual.currentFormat) {
	case 0:
		r_config_set_b (core->config, "asm.pseudo", false);
		r_config_set_b (core->config, "asm.bytes", true);
		r_config_set_b (core->config, "asm.esil", false);
		r_config_set_b (core->config, "emu.str", false);
		r_config_set_b (core->config, "asm.emu", false);
		break;
	case 1:
		r_config_set_b (core->config, "asm.pseudo", false);
		r_config_set_b (core->config, "asm.bytes", true);
		r_config_set_b (core->config, "asm.esil", false);
		r_config_set_b (core->config, "asm.emu", false);
		r_config_set_b (core->config, "emu.str", true);
		break;
	case 2:
		r_config_set_b (core->config, "asm.pseudo", true);
		r_config_set_b (core->config, "asm.bytes", true);
		r_config_set_b (core->config, "asm.esil", true);
		r_config_set_b (core->config, "emu.str", true);
		r_config_set_b (core->config, "asm.emu", true);
		break;
	case 3:
		r_config_set_b (core->config, "asm.pseudo", false);
		r_config_set_b (core->config, "asm.bytes", false);
		r_config_set_b (core->config, "asm.esil", false);
		r_config_set_b (core->config, "asm.emu", false);
		r_config_set_b (core->config, "emu.str", true);
		break;
	case 4:
		r_config_set_b (core->config, "asm.pseudo", true);
		r_config_set_b (core->config, "asm.bytes", false);
		r_config_set_b (core->config, "asm.esil", false);
		r_config_set_b (core->config, "asm.emu", false);
		r_config_set_b (core->config, "emu.str", true);
		break;
	}
}

static void nextPrintCommand(RCore *core) {
	core->visual.current0format++;
	core->visual.current0format %= PRINT_HEX_FORMATS;
	core->visual.currentFormat = core->visual.current0format;
}

static void prevPrintCommand(RCore *core) {
	core->visual.current0format--;
	if (core->visual.current0format < 0) {
		core->visual.current0format = 0;
	}
	core->visual.currentFormat = core->visual.current0format;
}

static const char *stackPrintCommand(RCore *core) {
	if (core->visual.current0format == 0) {
		if (r_config_get_b (core->config, "dbg.slow")) {
			return "pxr";
		}
		if (r_config_get_b (core->config, "stack.bytes")) {
			return "px";
		}
		switch (core->rasm->config->bits) {
		case 64: return "pxq"; break;
		case 32: return "pxw"; break;
		}
		return "px";
	}
	return printHexFormats[core->visual.current0format % PRINT_HEX_FORMATS];
}

static const char *__core_visual_print_command(RCore *core) {
	if (core->visual.tabs) {
		RCoreVisualTab *tab = r_list_get_n (core->visual.tabs, core->visual.tab);
		if (tab && tab->name[0] == ':') {
			return tab->name + 1;
		}
	}
	if (r_config_get_b (core->config, "scr.dumpcols")) {
		free (core->stkcmd);
		core->stkcmd = R_STR_DUP (stackPrintCommand (core));
		return printfmtColumns[PIDX];
	}
	if (PIDX == 1) {
		if (r_config_get_b (core->config, "asm.pseudo.linear")) {
			return "afsQ;pdcl";
		}
	}
	return printfmtSingle[PIDX];
}

static bool __core_visual_gogo(RCore *core, int ch) {
	RIOMap *map;
	int ret = -1;
	switch (ch) {
	case 'g':
		if (core->io->va) {
			map = r_io_map_get_at (core->io, core->addr);
			if (!map) {
				RIOBank *bank = r_io_bank_get (core->io, core->io->bank);
				if (bank && r_list_length (bank->maprefs)) {
					map = r_io_map_get (core->io,
						((RIOMapRef *)r_list_last (bank->maprefs))->id);
				}
			}
			if (map) {
				r_core_seek (core, r_io_map_begin (map), true);
			}
		} else {
			r_core_seek (core, 0, true);
		}
		r_io_sundo_push (core->io, core->addr, r_print_get_cursor (core->print));
		return true;
	case 'G':
		map = r_io_map_get_at (core->io, core->addr);
		if (!map) {
			RIOBank *bank = r_io_bank_get (core->io, core->io->bank);
			if (bank && r_list_length (bank->maprefs)) {
				map = r_io_map_get (core->io,
					((RIOMapRef *)r_list_last (bank->maprefs))->id);
			}
		}
		if (map) {
			RPrint *p = core->print;
			int scr_rows;
			if (!p->consb.get_size) {
				break;
			}
			(void)p->consb.get_size (p->consb.cons, &scr_rows);
			ut64 scols = r_config_get_i (core->config, "hex.cols");
			ret = r_core_seek (core, r_io_map_end (map) - (scr_rows - 2) * scols, true);
		}
		if (ret != -1) {
			r_io_sundo_push (core->io, core->addr, r_print_get_cursor (core->print));
		}
		return true;
	}
	return false;
}

static RCoreHelpMessage help_visual = {
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

static RCoreHelpMessage help_msg_visual = {
	"?", "show visual mode help (short)",
	"??", "show visual mode help (full)",
	"$", "set the program counter to the current offset + cursor",
	"&", "rotate asm.bits between 8, 16, 32 and 64 applying hints",
	"%", "in cursor mode finds matching pair, otherwise toggle autoblocksz",
	"0", "reset print mode (V0pp)",
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

static RCoreHelpMessage help_msg_visual_fn = {
	"F2", "toggle breakpoint",
	"F4", "run to cursor",
	"F7", "single step",
	"F8", "step over",
	"F9", "continue",
	NULL
};

#undef USE_THREADS
#define USE_THREADS 1

#if USE_THREADS

static void printSnow(RCore *core) {
	if (!core->visual.snows) {
		core->visual.snows = r_list_newf (free);
	}
	int i, h, w = r_cons_get_size (core->cons, &h);
	int amount = r_num_rand (4);
	if (amount > 0) {
		for (i = 0; i < amount; i++) {
			Snow *snow = R_NEW (Snow);
			snow->x = r_num_rand (w);
			snow->y = 0;
			r_list_append (core->visual.snows, snow);
		}
	}
	RListIter *iter, *iter2;
	Snow *snow;
	r_list_foreach_safe (core->visual.snows, iter, iter2, snow) {
		int pos = (r_num_rand (3)) - 1;
		snow->x += pos;
		snow->y++;
		if (snow->x >= w) {
			r_list_delete (core->visual.snows, iter);
			continue;
		}
		if (snow->y > h) {
			r_list_delete (core->visual.snows, iter);
			continue;
		}
		r_cons_gotoxy (core->cons, snow->x, snow->y);
		r_cons_printf (core->cons, "*");
	}
	// r_cons_gotoxy (core->cons, 10 , 10);
	r_cons_flush (core->cons);
}
#endif

static void rotate_asm_bits(RCore *core) {
	RAnalHint *hint = r_anal_hint_get (core->anal, core->addr);
	int bits = hint? hint->bits : r_config_get_i (core->config, "asm.bits");
	int retries = 4;
	while (retries > 0) {
		int nb = bits == 64 ? 8:
			bits == 32 ? 64:
			bits == 16 ? 32:
			bits == 8 ? 16: bits;
		if ((core->rasm->config->bits & nb) == nb) {
			r_core_cmdf (core, "ahb %d", nb);
			break;
		}
		bits = nb;
		retries--;
	}
	r_anal_hint_free (hint);
}

static const char *rotateAsmemu(RCore *core) {
	const bool isEmuStr = r_config_get_b (core->config, "emu.str");
	const bool isEmu = r_config_get_b (core->config, "asm.emu");
	if (isEmu) {
		if (isEmuStr) {
			r_config_set_b (core->config, "emu.str", false);
		} else {
			r_config_set_b (core->config, "asm.emu", false);
		}
	} else {
		r_config_set_b (core->config, "emu.str", true);
	}
	if (r_config_get_b (core->config, "asm.pseudo.linear")) {
		return "afsQ;pdcl";
	}
	return "afsQ;pd $r";  // ASSEMBLY
	// return "pd";
}

R_API void r_core_visual_showcursor(RCore *core, int x) {
	RCons *cons = core->cons;
	if (core->vmode) {
		r_cons_show_cursor (cons, x);
		r_cons_enable_mouse (cons, r_config_get_i (core->config, "scr.wheel"));
	} else {
		r_cons_enable_mouse (cons, false);
	}
	r_cons_flush (cons);
}

static void printFormat(RCore *core, int next) {
	switch (core->visual.printidx) {
	case R_CORE_VISUAL_MODE_PX: // 0 // xc
		core->visual.hexMode += next;
		applyHexMode (core);
		printfmtSingle[0] = printHexFormats[R_ABS (core->visual.hexMode) % PRINT_HEX_FORMATS];
		break;
	case R_CORE_VISUAL_MODE_PD: // pd
		core->visual.disMode += next;
		applyDisMode (core);
		printfmtSingle[1] = rotateAsmemu (core);
		break;
	case R_CORE_VISUAL_MODE_DB: // debugger
		core->visual.disMode += next;
		applyDisMode (core);
		printfmtSingle[1] = rotateAsmemu (core);
		core->visual.current3format += next;
		core->visual.currentFormat = R_ABS (core->visual.current3format) % PRINT_3_FORMATS;
		printfmtSingle[2] = print3Formats[core->visual.currentFormat];
		break;
	case R_CORE_VISUAL_MODE_OV: // overview
		core->visual.current4format += next;
		core->visual.currentFormat = R_ABS (core->visual.current4format) % PRINT_4_FORMATS;
		printfmtSingle[3] = print4Formats[core->visual.currentFormat];
		break;
	case R_CORE_VISUAL_MODE_CD: // code
		core->visual.current5format += next;
		core->visual.currentFormat = R_ABS (core->visual.current5format) % PRINT_5_FORMATS;
		printfmtSingle[4] = print5Formats[core->visual.currentFormat];
		break;
	}
}

static inline void nextPrintFormat(RCore *core) {
	if (core->visual.printidx == R_CORE_VISUAL_MODE_PX) {
		if (!(core->visual.hexMode % 2)) {
			printFormat (core, 1);
		}
	}
	printFormat (core, 1);
}

static inline void prevPrintFormat(RCore *core) {
	if (core->visual.printidx == R_CORE_VISUAL_MODE_PX) {
		if (!(core->visual.hexMode % 2)) {
			printFormat (core, -1);
		}
	}
	printFormat (core, -1);
}

R_API bool r_core_visual_hud(RCore *core) {
	const char *c = r_config_get (core->config, "hud.path");
	char *f = r_str_newf (R_JOIN_3_PATHS ("%s", R2_HUD, "main"), r_sys_prefix (NULL));
	const int use_color = core->print->flags & R_PRINT_FLAGS_COLOR;
	char *homehud = r_xdg_datadir ("hud");
	bool ready = false;
	char *res = NULL;
	core->cons->context->color_mode = use_color;

	r_core_visual_showcursor (core, true);
	if (R_STR_ISNOTEMPTY (c) && r_file_exists (c)) {
		res = r_cons_hud_file (core->cons, c);
	}
	if (!res && homehud) {
		res = r_cons_hud_file (core->cons, homehud);
	}
	if (!res && r_file_exists (f)) {
		res = r_cons_hud_file (core->cons, f);
	}
	if (!res) {
		r_cons_message (core->cons, "Cannot find hud file");
	}
	r_cons_clear (core->cons);
	if (res) {
		char *p = strchr (res, ';');
		if (res) {
			r_cons_println (core->cons, res);
			r_cons_flush (core->cons);
		}
		if (R_STR_ISNOTEMPTY (p)) {
			r_core_cmd0 (core, p + 1);
		}
		R_FREE (res);
		ready = true;
	}
	r_core_visual_showcursor (core, false);
	r_cons_flush (core->cons);
	free (homehud);
	free (f);
	return ready;
}

R_API void r_core_visual_jump(RCore *core, ut8 ch) {
	char chbuf[2];
	chbuf[0] = ch;
	chbuf[1] = '\0';
	ut64 off = r_core_get_asmqjmps (core, chbuf);
	if (off != UT64_MAX && off != UT32_MAX) {
		int delta = R_ABS ((st64) off - (st64) core->addr);
		r_io_sundo_push (core->io, core->addr, r_print_get_cursor (core->print));
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
R_API void r_core_visual_append_help(RCore *core, RStrBuf *p, const char *title, const char * const * help) {
	RCons *cons = core->cons;
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
	r_cons_clear00 (core->cons);
	r_core_visual_append_help (core, q, "Visual Mode Help (short)", help_visual);
	r_cons_printf (core->cons, "%s", r_strbuf_get (q));
	r_cons_flush (core->cons);
	const char *lesstr = NULL;
	switch (r_cons_readchar (core->cons)) {
	case 'q':
		r_strbuf_free (p);
		r_strbuf_free (q);
		return ret;
	case '!':
		r_core_panels_root (core, core->panels_root);
		break;
	case '?':
		r_core_visual_append_help (core, p, "Visual Mode Help (full)", help_msg_visual);
		r_core_visual_append_help (core, p, "Function Keys Defaults  # Use `e key.` to owerwrite", help_msg_visual_fn);
		lesstr = r_strbuf_get (p);
		break;
	case 'v':
		r_strbuf_append (p, "Visual Views:\n\n");
		r_strbuf_append (p,
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
		lesstr = r_strbuf_get (p);
		break;
	case 'p':
		r_strbuf_append (p, "Visual Print Modes:\n\n");
		r_strbuf_append (p,
			" pP     change to the next/previous print mode (hex, dis, ..)\n"
			" TAB    rotate between all the configurations for the current print mode\n"
			" SPACE  toggle between graph/disasm or similar hex modes\n"
		);
		lesstr = r_strbuf_get (p);
		break;
	case 'e':
		r_strbuf_append (p, "Visual Evals:\n\n");
		r_strbuf_append (p,
			" E   toggle asm.hint.lea\n"
			" &   rotate asm.bits=16,32,64\n"
		);
		lesstr = r_strbuf_get (p);
		break;
	case 'c':
		setcursor (core, !core->print->cur_enabled);
		r_strbuf_free (p);
		return ret;
	case 'i':
		r_strbuf_append (p, "Visual Insertion Help:\n\n");
		r_strbuf_append (p,
			" i   insert bits, bytes or text depending on view\n"
			" a   assemble instruction and write the bytes in the current offset\n"
			" A   visual assembler\n"
			" +   increment value of byte\n"
			" -   decrement value of byte\n"
		);
		lesstr = r_strbuf_get (p);
		break;
	case 'd':
		r_strbuf_append (p, "Visual Debugger Help:\n\n");
		r_strbuf_append (p,
			" $    set the program counter (PC register)\n"
			" s    step in\n"
			" S    step over\n"
			" B    toggle breakpoint\n"
			" :dc  continue\n"
		);
		lesstr = r_strbuf_get (p);
		break;
	case 'm':
		r_strbuf_append (p, "Visual Moving Around:\n\n");
		r_strbuf_append (p,
			" g        type flag/offset/register name to seek\n"
			" hl       seek to the next/previous byte\n"
			" jk       seek to the next row (core.offset += hex.cols)\n"
			" JK       seek one page down\n"
			" ^        seek to the beginning of the current map\n"
			" $        seek to the end of the current map\n"
			" c        toggle cursor mode (use hjkl to move and HJKL to select a range)\n"
			" mK/'K    mark/go to Key (any key)\n"
		);
		lesstr = r_strbuf_get (p);
		break;
	case 'a':
		r_strbuf_append (p, "Visual Analysis:\n\n");
		r_strbuf_append (p,
			" df  define function\n"
			" du  undefine function\n"
			" dc  define as code\n"
			" dw  define as dword (32bit)\n"
			" dw  define as qword (64bit)\n"
			" dd  define current block or selected bytes as data\n"
			" V   view graph (same as press the 'space' key)\n"
		);
		lesstr = r_strbuf_get (p);
		break;
	}
	if (lesstr) {
		ret = r_cons_less_str (core->cons, lesstr, "?");
		lesstr = NULL;

	}
	r_strbuf_free (p);
	r_strbuf_free (q);
	goto repeat;
}

static bool prompt_read(RCore *core, const char *p, char *buf, int buflen) {
	if (!buf || buflen < 1) {
		return false;
	}
	*buf = 0;
	r_line_set_prompt (core->cons->line, p);
	r_core_visual_showcursor (core, true);
	r_cons_fgets (core->cons, buf, buflen, 0, NULL);
	r_core_visual_showcursor (core, false);
	return *buf != 0;
}

static void reset_print_cur(RPrint *p) {
	p->cur = 0;
	p->ocur = -1;
}

static bool __holdMouseState(RCore *core) {
	bool m = core->cons->mouse;
	r_cons_enable_mouse (core->cons, false);
	return m;
}

static void backup_current_addr(RCore *core, ut64 *addr, ut64 *bsze, ut64 *newaddr) {
	*addr = core->addr;
	*bsze = core->blocksize;
	if (core->print->cur_enabled) {
		if (core->print->ocur != -1) {
			int newsz = core->print->cur - core->print->ocur;
			*newaddr = core->addr + core->print->ocur;
			r_core_block_size (core, newsz);
		} else {
			*newaddr = core->addr + core->print->cur;
		}
		r_core_seek (core, *newaddr, true);
	}
}

static void restore_current_addr(RCore *core, ut64 addr, ut64 bsze, ut64 newaddr) {
	bool restore_seek = true;
	if (core->addr != newaddr) {
		bool cursor_moved = false;
		// when new address is in the screen bounds, just move
		// the cursor if enabled and restore seek
		if (core->print->cur != -1 && core->print->screen_bounds > 1) {
			if (core->addr >= addr &&
			    core->addr < core->print->screen_bounds) {
				core->print->ocur = -1;
				core->print->cur = core->addr - addr;
				cursor_moved = true;
			}
		}
		if (!cursor_moved) {
			restore_seek = false;
			reset_print_cur (core->print);
		}
	}
	if (core->print->cur_enabled && restore_seek) {
		r_core_seek (core, addr, true);
		r_core_block_size (core, bsze);
	}
}

R_API void r_core_visual_prompt_input(RCore *core) {
	ut64 addr, bsze, newaddr = 0LL;
	int ret, h;
	(void) r_cons_get_size (core->cons, &h);
	bool mouse_state = __holdMouseState(core);
	r_cons_gotoxy (core->cons, 0, h);
	r_cons_reset_colors (core->cons);
	r_cons_show_cursor (core->cons, true);
	core->vmode = false;
	const int ovtmode = r_config_get_i (core->config, "scr.vtmode");
	r_config_set_i (core->config, "scr.vtmode", 1);

	int curbs = core->blocksize;
	if (core->visual.autoblocksize) {
		r_core_block_size (core, core->visual.obs);
	}
	backup_current_addr (core, &addr, &bsze, &newaddr);
	do {
		ret = r_core_visual_prompt (core);
	} while (ret);
	restore_current_addr (core, addr, bsze, newaddr);
	if (core->visual.autoblocksize) {
		core->visual.obs = core->blocksize;
		r_core_block_size (core, curbs);
	}

	r_cons_show_cursor (core->cons, false);
	core->vmode = true;
	r_cons_enable_mouse (core->cons, mouse_state && r_config_get_i (core->config, "scr.wheel"));
	r_cons_show_cursor (core->cons, true);
	r_config_set_i (core->config, "scr.vtmode", ovtmode);
}

R_API int r_core_visual_prompt(RCore *core) {
	char buf[1024];
	if (PIDX != 2) {
		core->seltab = 0;
	}
	r_line_set_prompt (core->cons->line, "> ");
	r_core_visual_showcursor (core, true);
	r_cons_fgets (core->cons, buf, sizeof (buf), 0, NULL);
	if (!strcmp (buf, "q")) {
		return 0;
	}
	if (*buf) {
		r_line_hist_add (core->cons->line, buf);
		r_core_cmd (core, buf, 0);
		r_cons_echo (core->cons, NULL);
		r_cons_flush (core->cons);
		if (r_config_get_b (core->config, "cfg.debug")) {
			r_core_cmd (core, ".dr*", 0);
		}
		return 1;
	}
	r_cons_clear00 (core->cons);
	r_core_visual_showcursor (core, false);
	return 0;
}

static void visual_single_step_in(RCore *core) {
	if (r_config_get_b (core->config, "cfg.debug")) {
		if (core->print->cur_enabled) {
			// dcu 0xaddr
			r_core_cmdf (core, "dcu 0x%08"PFMT64x, core->addr + core->print->cur);
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
	r_config_set_b (core->config, "io.cache", false);
	if (r_config_get_b (core->config, "cfg.debug")) {
		if (core->print->cur_enabled) {
			r_core_cmd_call (core, "dcr");
			core->print->cur_enabled = 0;
		} else {
			r_core_cmd_call (core, "dso");
			r_core_cmd (core, ".dr*", 0);
		}
	} else {
		r_core_cmd_call (core, "aeso");
		r_core_cmd (core, ".ar*", 0);
	}
	r_config_set_b (core->config, "io.cache", io_cache);
}

static void visual_breakpoint(RCore *core) {
	r_core_cmd_call (core, "dbs $$");
}

static void visual_continue(RCore *core) {
	if (r_config_get_b (core->config, "cfg.debug")) {
		r_core_cmd_call (core, "dc");
	} else {
		r_core_cmd (core, "aec;.ar*", 0);
	}
}

static int visual_nkey(RCore *core, int ch) {
	const char *cmd;
	ut64 oseek = UT64_MAX;
	if (core->print->ocur == -1) {
		oseek = core->addr;
		r_core_seek (core, core->addr + core->print->cur, false);
	}

	switch (ch) {
	case R_CONS_KEY_F1:
		cmd = r_config_get (core->config, "key.f1");
		if (R_STR_ISNOTEMPTY (cmd)) {
			ch = r_core_cmd0 (core, cmd);
		} else {
			visual_help (core);
		}
		break;
	case R_CONS_KEY_F2:
		cmd = r_config_get (core->config, "key.f2");
		if (R_STR_ISNOTEMPTY (cmd)) {
			ch = r_core_cmd0 (core, cmd);
		} else {
			visual_breakpoint (core);
		}
		break;
	case R_CONS_KEY_F3:
		cmd = r_config_get (core->config, "key.f3");
		if (R_STR_ISNOTEMPTY (cmd)) {
			ch = r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F4:
		cmd = r_config_get (core->config, "key.f4");
		if (R_STR_ISNOTEMPTY (cmd)) {
			ch = r_core_cmd0 (core, cmd);
		} else {
			if (core->print->cur_enabled) {
				// dcu 0xaddr
				r_core_cmdf (core, "dcu 0x%08"PFMT64x, core->addr + core->print->cur);
				core->print->cur_enabled = 0;
			}
		}
		break;
	case R_CONS_KEY_F5:
		cmd = r_config_get (core->config, "key.f5");
		if (R_STR_ISNOTEMPTY (cmd)) {
			ch = r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F6:
		cmd = r_config_get (core->config, "key.f6");
		if (R_STR_ISNOTEMPTY (cmd)) {
			ch = r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F7:
		cmd = r_config_get (core->config, "key.f7");
		if (R_STR_ISNOTEMPTY (cmd)) {
			ch = r_core_cmd0 (core, cmd);
		} else {
			visual_single_step_in (core);
			oseek = UT64_MAX;
		}
		break;
	case R_CONS_KEY_F8:
		cmd = r_config_get (core->config, "key.f8");
		if (R_STR_ISNOTEMPTY (cmd)) {
			ch = r_core_cmd0 (core, cmd);
		} else {
			__core_visual_step_over (core);
			oseek = UT64_MAX;
		}
		break;
	case R_CONS_KEY_F9:
		cmd = r_config_get (core->config, "key.f9");
		if (R_STR_ISNOTEMPTY (cmd)) {
			ch = r_core_cmd0 (core, cmd);
		} else {
			visual_continue (core);
			oseek = UT64_MAX;
		}
		break;
	case R_CONS_KEY_F10:
		cmd = r_config_get (core->config, "key.f10");
		if (R_STR_ISNOTEMPTY (cmd)) {
			ch = r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F11:
		cmd = r_config_get (core->config, "key.f11");
		if (R_STR_ISNOTEMPTY (cmd)) {
			ch = r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F12:
		cmd = r_config_get (core->config, "key.f12");
		if (R_STR_ISNOTEMPTY (cmd)) {
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
	if (prompt_read (core, "diff from: ", from, sizeof (from))) {
		r_config_set (core->config, "diff.from", from);
	}
	if (prompt_read (core, "diff to: ", to, sizeof (to))) {
		r_config_set (core->config, "diff.to", to);
	}
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
				r_core_seek (core, core->addr + i + 1, true);
			}
			return;
		}
	}
}

static bool isSpace(char ch) {
	switch (ch) {
	case ' ':
	case '.':
	case ',':
	case '\t':
	case '\n':
		return true;
	}
	return false;
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

	r_line_set_prompt (core->cons->line, "search byte/string in block: ");
	r_cons_fgets (core->cons, str, sizeof (str), 0, NULL);
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
		R_LOG_INFO ("Found in offset 0x%08"PFMT64x" + %d", core->addr, core->print->cur);
		r_cons_any_key (core->cons, NULL);
	} else {
		R_LOG_ERROR ("Cannot find bytes");
		r_cons_any_key (core->cons, NULL);
		r_cons_clear00 (core->cons);
	}
}

R_API void r_core_visual_show_char(RCore *core, char ch) {
	if (r_config_get_i (core->config, "scr.feedback") < 2) {
		return;
	}
	if (!IS_PRINTABLE (ch)) {
		return;
	}
	RCons *cons = core->cons;
	r_cons_gotoxy (cons, 1, 2);
	r_cons_printf (cons, ".---.\n");
	r_cons_printf (cons, "| %c |\n", ch);
	r_cons_printf (cons, "'---'\n");
	r_cons_flush (cons);
	r_sys_sleep (1);
}

R_API void r_core_visual_seek_animation(RCore *core, ut64 addr) {
	r_core_seek (core, addr, true);
	if (r_config_get_i (core->config, "scr.feedback") < 1) {
		return;
	}
	if (core->addr == addr) {
		return;
	}
	RCons *cons = core->cons;
	r_cons_gotoxy (cons, 1, 2);
	r_cons_printf (cons, ".----.\n");
	if (addr > core->addr) {
		r_cons_printf (cons, "| \\/ |\n");
	} else {
		r_cons_printf (cons, "| /\\ |\n");
	}
	r_cons_printf (cons, "'----'\n");
	r_cons_flush (cons);
	r_sys_usleep (90000);
}

static void setprintmode(RCore *core, int n) {
	RCoreVisual *v = &core->visual;
	RAnalOp op;

	if (n > 0) {
		v->printidx = R_ABS ((v->printidx + 1) % NPF);
	} else if (n < 0) {
		if (v->printidx) {
			v->printidx--;
		} else {
			v->printidx = NPF - 1;
		}
	} else {
		v->printidx = 0;
	}
	switch (v->printidx) {
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
	RAnalOp op;
	int len, ret, i;
	RIntervalNode *in = r_meta_get_in (core->anal, addr, R_META_TYPE_DATA);
	if (in) {
		// RAnalMetaItem *ami = (RAnalMetaItem *)in->data;
		const int hexcols = r_config_get_i (core->config, "hex.cols");
		int amisize = r_meta_item_size (in->start, in->end);
		if (amisize > hexcols) {
			return addr - hexcols;
		}
		return addr - amisize;
	}

	const int minop = r_anal_archinfo (core->anal, R_ARCH_INFO_MINOP_SIZE);
	const int maxop = r_anal_archinfo (core->anal, R_ARCH_INFO_MAXOP_SIZE);
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
	RAnalBlock *bb = r_anal_bb_from_offset (core->anal, addr - minop);
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
			buf + i, sizeof (buf) - i, R_ARCH_OP_MASK_BASIC);
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
	char *command = (f && f->addr == off && f->addr > 0)
		? r_str_newf ("%s", f->name)
		: r_str_newf ("0x%"PFMT64x, off);
	r_str_ncpy (line->buffer.data, command, R_LINE_BUFSIZE - 1);
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
	char *command = (f && f->addr == off && f->addr > 0)
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
	r_line_set_prompt (core->cons->line, "[offset]> ");
	strncpy (buf, "s ", sizeof (buf));
	if (r_cons_fgets (core->cons, buf + 2, sizeof (buf) - 2, 0, NULL) > 0) {
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
	r_cons_printf (core->cons, "Enter comment for reference:\n");
	r_core_visual_showcursor (core, true);
	r_cons_flush (core->cons);
	r_cons_set_raw (core->cons, false);
	r_line_set_prompt (core->cons->line, "> ");
	r_cons_enable_mouse (core->cons, false);
	char buf[1024];
	if (r_cons_fgets (core->cons, buf, sizeof (buf), 0, NULL) < 0) {
		buf[0] = '\0';
	}
	r_core_cmdf (core, "'@0x%08"PFMT64x"'CC %s", addr, buf);
	r_cons_set_raw (core->cons, true);
	r_cons_enable_mouse (core->cons, r_config_get_b (core->config, "scr.wheel"));
	r_core_visual_showcursor (core, false);
}

static void add_ref(RCore *core) {
	// read name provided by user
	char *fn = r_cons_input (core->cons, "Reference From: ");
	if (R_STR_ISNOTEMPTY (fn)) {
		r_core_cmd_callf (core, "ax $$ %s", fn);
	}
	free (fn);
}

static bool delete_ref(RCore *core, RVecAnalRef *xrefs, int choice, int xref) {
	if (!xrefs) {
		return false;
	}

	RAnalRef *refi = RVecAnalRef_at (xrefs, choice);
	if (refi) {
		if (core->print->cur_enabled) {
			core->print->cur = 0;
		}
		return r_anal_xref_del (core->anal, refi->addr, refi->at);
	}

	return false;
}

static int follow_ref(RCore *core, RVecAnalRef *xrefs, int choice, int xref) {
	if (!xrefs) {
		return 0;
	}

	RAnalRef *refi = RVecAnalRef_at (xrefs, choice);
	if (refi) {
		if (core->print->cur_enabled) {
			core->print->cur = 0;
		}
		ut64 addr = refi->addr;
		r_io_sundo_push (core->io, core->addr, -1);
		r_core_seek (core, addr, true);
		return 1;
	}

	return 0;
}

static RCoreHelpMessage help_msg_visual_xref = {
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
	RCons *cons = core->cons;
	int ret = 0;
	char ch;
	int count = 0;
	RVecAnalRef *xrefs = NULL;
	RAnalRef *refi;
	int skip = 0;
	int idx = 0;
	char cstr[32];
	ut64 addr = core->addr;
	bool xrefsMode = fcnInsteadOfAddr;
	int lastPrintMode = 3;
	if (core->print->cur_enabled) {
		addr += core->print->cur;
	}
repeat:
	RVecAnalRef_free (xrefs);
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
		xrefs = xref
			? r_anal_xrefs_get (core->anal, addr)
			: r_anal_refs_get (core->anal, addr);
	}

	r_cons_clear00 (cons);
	r_cons_gotoxy (cons, 1, 1);
	{
		char *address = R_SYS_BITS_CHECK (core->dbg->bits, 64)
			? r_str_newf ("0x%016"PFMT64x, addr)
			: r_str_newf ("0x%08"PFMT64x, addr);
		r_cons_printf (cons, "[%s%srefs]> %s # (TAB/jk/q/?) ",
				xrefsMode? "fcn.": "addr.", xref ? "x": "", address);
		free (address);
	}
	if (!xrefs || RVecAnalRef_empty (xrefs)) {
		RVecAnalRef_free (xrefs);
		xrefs = NULL;
		r_cons_printf (cons, "\n\n(no %srefs)\n", xref ? "x": "");
	} else {
		int h, w = r_cons_get_size (cons, &h);
		bool asm_bytes = r_config_get_b (core->config, "asm.bytes");
		r_config_set_i (core->config, "asm.bytes", false);
		r_core_cmd_call (core, "fd");

		int secondColumn = (w > 120)? 80: 0;
		int maxcount = 9;
		int rows = h; // XXX dupe
		count = 0;
		char *dis = NULL;
		rows -= 4;
		idx = 0;
		ut64 curat = UT64_MAX;
		const ut64 num_xrefs = RVecAnalRef_length (xrefs);
		R_VEC_FOREACH (xrefs, refi) {
			if (idx - skip > maxcount) {
				r_cons_printf (cons, "...");
				break;
			}

			if (idx == num_xrefs - 1 && idx < skip) {
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
						name = r_str_newf ("%s + %" PFMT64d, f->name, refi->addr - f->addr);
					} else {
						name = strdup ("unk");
					}
				}
				if (w > 45) {
					if (strlen (name) > w - 45) {
						name[w - 45] = 0;
					}
				} else {
					name[0] = 0;
				}
				char *cmt = r_core_cmd_strf (core, "CC.@0x%08"PFMT64x, refi->addr);
				r_str_trim (cmt);
				r_cons_printf (cons, " %d [%s] 0x%08"PFMT64x" 0x%08"PFMT64x " %s %sref (%s) ; %s\n",
					idx, cstr, refi->at, refi->addr,
					r_anal_ref_type_tostring (refi->type),
					xref ? "x":"", name, cmt);
				free (cmt);
				free (name);
				if (idx == skip) {
					free (dis);
					curat = refi->addr;
					char *res = NULL;
					char *res2 = NULL;
					if (secondColumn) {
						res = r_core_cmd_strf (core, "pd 10 @ 0x%08"PFMT64x"@e:asm.flags.limit=1@e:asm.lines=0@e:asm.xrefs=0", refi->at);
						int height = R_MAX (h / 3, h - 13);
						res2 = r_str_ansi_crop (res, 0, 0, w - secondColumn - 2, height);
						free (res);
						res = res2;
					} else {
						int height = R_MIN (h / 3, 13);
						res2 = r_str_ansi_crop (res, 0, 0, 0, height);
						free (res);
						res = res2;
					}
					dis = NULL;
					r_cons_print_at (cons, "; ----------------------------", 0, 11, secondColumn? secondColumn: w - 1, 2);
					if (secondColumn) {
						r_cons_print_at (core->cons, res, secondColumn, 2, w - secondColumn, 15);
						free (res);
						res = strdup ("");
					}
					switch (core->visual.printMode) {
					case 0:
						dis = r_core_cmd_strf (core, "pd--%d @ 0x%08"PFMT64x"@e:asm.lines=0", h/4, refi->addr);
						break;
					case 1:
						dis = r_core_cmd_strf (core, "pds @ 0x%08"PFMT64x"@e:asm.lines=0", refi->addr);
						break;
					case 2:
						dis = r_core_cmd_strf (core, "px @ 0x%08"PFMT64x"@e:asm.lines=0", refi->addr);
						break;
					case 3:
						dis = r_core_cmd_strf (core, "pxr @ 0x%08"PFMT64x"@e:asm.lines=0", refi->addr);
						break;
					}
					if (dis) {
						res = r_str_append (res, dis);
						free (dis);
					}
					dis = res;
				}
				if (++count >= rows) {
					r_cons_printf (cons, "...");
					break;
				}
			}
			idx++;
		}
		if (dis) {
			if (count < rows) {
				r_cons_newline (cons);
			}
			int i = count;
			for (; i < 9; i++)  {
				r_cons_newline (cons);
			}
			/* prepare highlight */
			char *cmd = strdup (r_config_get (core->config, "scr.highlight"));
			char *ats = r_str_newf ("%"PFMT64x, curat);
			if (ats && !*cmd) {
				(void) r_config_set (core->config, "scr.highlight", ats);
			}
			/* print disasm */
			if (secondColumn) {
				r_cons_print_at (cons, dis, 0, 13, secondColumn, h - 13);
			} else {
				r_cons_print_at (cons, dis, 0, 12, w - 1, h - 13);
			}
			/* flush and restore highlight */
			r_cons_flush (cons);
			r_config_set (core->config, "scr.highlight", cmd);
			free (ats);
			free (cmd);
			free (dis);
			dis = NULL;
		}
		r_config_set_i (core->config, "asm.bytes", asm_bytes);
	}
	r_cons_flush (cons);
	r_cons_enable_mouse (cons, r_config_get_i (core->config, "scr.wheel"));
	r_cons_set_raw (cons, true);
	ch = r_cons_readchar (cons);
	ch = r_cons_arrow_to_hjkl (cons, ch);
	switch (ch) {
	case ':':
		r_core_visual_prompt_input (core);
		goto repeat;
	case '?':
		r_cons_clear00 (core->cons);
		RStrBuf *rsb = r_strbuf_new ("");
		r_core_visual_append_help (core, rsb, "Xrefs Visual Analysis Mode (Vv + x) Help", help_msg_visual_xref);
		ret = r_cons_less_str (core->cons, r_strbuf_get (rsb), "?");
		r_strbuf_free (rsb);
		goto repeat;
	case 9: // TAB
		xrefsMode = !xrefsMode;
		r_core_visual_toggle_decompiler_disasm (core, false, true);
		goto repeat;
	case 'p':
		r_core_visual_toggle_decompiler_disasm (core, false, true);
		core->visual.printMode++;
		if (core->visual.printMode > lastPrintMode) {
			core->visual.printMode = 0;
		}
		goto repeat;
	case 'P':
		r_core_visual_toggle_decompiler_disasm (core, false, true);
		core->visual.printMode--;
		if (core->visual.printMode < 0) {
			core->visual.printMode = lastPrintMode;
		}
		goto repeat;
	case '/':
		r_core_cmd0 (core, "?i highlight;e scr.highlight=`yp`");
		goto repeat;
	case '+':
		add_ref (core);
		goto repeat;
	case '-':
		r_cons_gotoxy (cons, 0, 0);
		if (r_cons_yesno (cons, 'y', "Do you want to delete this xref? (Y/n)")) {
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
	case ';': // "Vx;"
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
		} else if (isdigit (ch)) {
			ret = follow_ref (core, xrefs, ch - 0x30, xref);
		} else if (ch != 'q' && ch != 'Q' && ch != 'h') {
			goto repeat;
		}
		break;
	}
	RVecAnalRef_free (xrefs);

	return ret;
}

#if R2__WINDOWS__
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

static void visual_textlogs(RCore *core) {
	int shiftbody = 0;
	int shift = 0;
	int index = 1;
	int skiplines = 0;
	bool showhelp = false;
	bool inbody = false;
	RCons *cons = core->cons;
	while (true) {
		int log_level = r_log_get_level ();
		r_cons_clear00 (cons);
		int notch = r_config_get_i (core->config, "scr.notch");
		while (notch-- > 0) {
			r_cons_newline (cons);
		}
		const char *vi = r_config_get (core->config, "cmd.vprompt");
		if (R_STR_ISNOTEMPTY (vi)) {
			r_core_cmd0 (core, vi);
		}
#define TEXTLOGS_TITLE "[visual-text-logs] Press '?' for help. idx %d log.level=%d"
		if (r_config_get_i (core->config, "scr.color") > 0) {
			r_cons_printf (cons, Color_YELLOW "" TEXTLOGS_TITLE "\n"Color_RESET, index, log_level);
		} else {
			r_cons_printf (cons, TEXTLOGS_TITLE "\n", index, log_level);
		}
		if (showhelp) {
			const char help[] = \
			" <tab>   - toggle between list and log body\n"
			" 0       - jump to index 0\n"
			" =       - edit visual prompt\n"
			" !       - edit current message with cfg.editor\n"
			" :       - run a radare command\n"
			" +-      - change log level\n"
			" []      - adjust scroll of message in list\n"
			" i       - insert a new message\n"
			" q       - quit this viewer mode\n"
			" jk      - scroll up and down\n"
			" JK      - faster scroll up and down (10x)\n";
			r_cons_print (cons, help);
		} else {
			r_core_cmdf (core, "Tv %d %d", index, shift);
			if (inbody) {
				r_cons_printf (cons, "--v--\n");
			} else {
				r_cons_printf (cons, "--^--\n");
			}
			char *s = r_core_cmd_strf (core, "Tm %d~{}", index);
			r_str_trim (s);
			if (R_STR_ISEMPTY (s)) {
				free (s);
				s = r_core_cmd_strf (core, "Tm %d", index);
			}
			int w = r_cons_get_size (cons, NULL);
			char *wrapped = r_str_wrap (s, w);
			free (s);
			s = wrapped;
			if (shiftbody) {
				char *r = s;
				int sh = shiftbody;
				while (*r && sh > 0) {
					sh--;
					r++;
				}
				r = strdup (r);
				free (s);
				s = r;
			}
			if (skiplines > 0) {
				char *r = s;
				int w = r_cons_get_size (cons, NULL);
				int line = skiplines;
				int col = 0;
				while (*r) {
					if (*r == '\n') {
						col = 0;
						line--;
					}
					if (col >= w) {
						line--;
						col = 0;
					}
					if (line < 1) {
						break;
					}
					col++;
					r++;
				}
				r = strdup (r);
				free (s);
				s = r;
			}
			r_cons_printf (cons, "%s\n", s);
			free (s);
			const char *vi2 = r_config_get (core->config, "cmd.vprompt2");
			if (R_STR_ISNOTEMPTY (vi2)) {
				r_core_cmd0 (core, vi2);
			}
		}
		r_cons_visual_flush (cons);
		char ch = (ut8)r_cons_readchar (cons);
		ch = r_cons_arrow_to_hjkl (cons, ch);
		if (showhelp) {
			showhelp = false;
			continue;
		}
		switch (ch) {
		case 'q':
			return;
		case 'i':
			r_core_cmdf (core, "T `?ie message`");
			break;
		case '?':
			showhelp = true;
			break;
		case 9: // tab
			inbody = !inbody;
			break;
		case 'h':
		case '[':
			if (inbody) {
				if (shiftbody > 0) {
					shiftbody--;
				}
			} else {
				if (shift > 0) {
					shift --;
				}
			}
			break;
		case 'l':
		case ']':
			if (inbody) {
				shiftbody++;
			} else {
				shift ++;
			}
			break;
		case '+':
			if (log_level <= R_LOG_LEVEL_LAST) {
				r_log_set_level (log_level + 1);
			}
			break;
		case '-':
			if (log_level > 0) {
				r_log_set_level (log_level - 1);
			}
			break;
		case '=':
			{ // TODO: edit
				r_core_visual_showcursor (core, true);
				const char *buf = NULL;
				#define I core->cons
				const char *cmd = r_config_get (core->config, "cmd.vprompt");
				r_line_set_prompt (cons->line, "cmd.vprompt> ");
				I->line->contents = strdup (cmd);
				buf = r_line_readline (core->cons);
				I->line->contents = NULL;
				(void)r_config_set (core->config, "cmd.vprompt", buf);
				r_core_visual_showcursor (core, false);
			}
			break;
		case '!':
			r_core_cmdf (core, "T-%d", index);
			break;
		case '0':
			index = 0;
			break;
		case 'j':
			if (inbody) {
				skiplines++;
			} else {
				index++;
				skiplines = 0;
				shiftbody = 0;
			}
			break;
		case 'J':
			if (inbody) {
				skiplines += 2;
			} else {
				index += 10;
				skiplines = 0;
				shiftbody = 0;
			}
			break;
		case 'k':
			if (inbody) {
				skiplines--;
			} else {
				skiplines = 0;
				if (index > 1) {
					index--;
				} else {
					index = 1;
				}
			}
			break;
		case 'K':
			if (inbody) {
				skiplines -= 2;
			} else {
				skiplines = 0;
				if (index > 10) {
					index -= 10;
				} else {
					index = 1;
				}
			}
			break;
		case ':':
			r_core_visual_prompt_input (core);
			break;
		}
	}
}

static void visual_comma(RCore *core) {
	bool mouse_state = __holdMouseState (core);
	ut64 addr = core->addr + (core->print->cur_enabled? core->print->cur: 0);
	const char *prev_cmt = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
	char *comment = prev_cmt ? strdup (prev_cmt) : NULL;
	char *cmtfile = r_str_between (comment, ",(", ")");
	char *cwd = getcommapath (core);
	if (!cmtfile) {
		char *fn = r_cons_input (core->cons, "<comment-file> ");
		if (fn && *fn) {
			cmtfile = strdup (fn);
			if (R_STR_ISEMPTY (comment)) {
				comment = r_str_newf (",(%s)", fn);
				r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, comment);
				R_FREE (comment);
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
			R_LOG_ERROR ("Could not open '%s'", cwf);
			free (cwf);
			goto beach;
		}
		char *data = r_core_editor (core, NULL, odata);
		r_file_dump (cwf, (const ut8 *) data, -1, 0);
		free (data);
		free (odata);
		free (cwf);
	} else {
		R_LOG_ERROR ("No commafile found");
	}
beach:
	free (comment);
	r_cons_enable_mouse (core->cons, mouse_state && r_config_get_i (core->config, "scr.wheel"));
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
	int minop = r_anal_archinfo (core->anal, R_ARCH_INFO_MINOP_SIZE);
	int maxop = r_anal_archinfo (core->anal, R_ARCH_INFO_MAXOP_SIZE);
	ut64 addr = core->addr + delta; // should be core->print->cur
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
	RAnalOp *aop = r_core_anal_op (core, opaddr, R_ARCH_OP_MASK_BASIC);
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
	// ut64 addr, oaddr = core->addr + core->print->cur;
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
	RAnalOp op;

	cursor_ocur (core, use_ocur);
	if (PIDX == 1) { // DISASM
		nextOpcode (core);
		return;
	}
	if (PIDX == 4) { // TEXT
		int idx = p->cur_enabled? p->cur: 0;
		const ut8 *buf = core->block;
		if (idx < core->blocksize) {
			const ut8* nl = r_mem_mem (core->block + idx, core->blocksize - idx, (const ut8*)"\n", 1);
			if (nl) {
				p->cur = (int)(size_t)(nl - buf + 1);
			}
		}
		return;
	}

	if (PIDX == 7 || !strcmp ("prc", r_config_get (core->config, "cmd.visual"))) {
		p->cur += r_config_get_i (core->config, "hex.cols");
		return;
	}
	if (core->visual.splitView) {
		int w = r_config_get_i (core->config, "hex.cols");
		if (w < 1) {
			w = 16;
		}
		if (core->seltab == 0) {
			core->visual.splitPtr += w;
		} else {
			core->addr += w;
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

	if (core->visual.splitView) {
		int w = r_config_get_i (core->config, "hex.cols");
		if (w < 1) {
			w = 16;
		}
		if (core->seltab == 0) {
			core->visual.splitPtr -= w;
		} else {
			core->addr -= w;
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
			ut64 prev_addr = prevop_addr (core, core->addr + roff);
			if (prev_addr > core->addr) {
				prev_roff = 0;
				prev_sz = 1;
			} else {
				RAnalOp op;
				prev_roff = 0;
				r_asm_op_init (&op);
				r_core_seek (core, prev_addr, true);
				r_asm_set_pc (core->rasm, prev_addr);
				prev_sz = r_asm_disassemble (core->rasm, &op,
					core->block, 32);
				r_asm_op_fini (&op);
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
			p->cur = prev_roff + delta; // res;
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
	if (PIDX != 2) {
		return false;
	}
	if (core->print->screen_bounds > 1) {
		bool off_is_visible = core->addr < core->print->screen_bounds;
		bool cur_is_visible = core->addr + p->cur < core->print->screen_bounds;
		bool is_close = core->addr + p->cur < core->print->screen_bounds + 32;

		if ((!cur_is_visible && !is_close) || (!cur_is_visible && p->cur == 0)) {
			// when the cursor is not visible and it's far from the
			// last visible byte, just seek there.
			r_core_seek_delta (core, p->cur);
			reset_print_cur (p);
		} else if ((!cur_is_visible && is_close) || !off_is_visible) {
			RAnalOp op;
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
			r_asm_op_fini (&op);
		}
	} else if (core->print->cur >= offscreen) {
		r_core_seek (core, core->addr + p->cols, true);
		p->cur -= p->cols;
		if (p->ocur != -1) {
			p->ocur -= p->cols;
		}
	}

	if (p->cur < 0) {
		int sz = p->cols;
		if (isDisasmPrint (core->visual.printidx)) {
			sz = r_core_visual_prevopsz (core, core->addr + p->cur);
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

static void visual_windows(RCore *core) {
	// TODO add more formats
	// hud for all modes from visual
	//int pidx = core->visual.printidx;
	//int mode = core->visual.hexMode; // MODE_PX
	//int mode = core->visual.disMode; // MODE_DB/PD
	//int mode = core->visual.currentFormat; // MODE_OV / CD
	RList *pmodes = r_list_newf (free);
	r_list_append (pmodes, strdup ("0:0 standard hexdump"));
	r_list_append (pmodes, strdup ("0:1 hexdump with flag names and colors"));
	r_list_append (pmodes, strdup ("0:2 pxr recursive hexdump regsize word"));
	r_list_append (pmodes, strdup ("0:5 hexdump with st32"));
	r_list_append (pmodes, strdup ("0:7 hexdump with ut16"));
	r_list_append (pmodes, strdup ("0:8 hexdump with ut32"));
	r_list_append (pmodes, strdup ("0:6 bit viewer at byte level hexdump"));
	r_list_append (pmodes, strdup ("1:0 standard disassembly view"));
	r_list_append (pmodes, strdup ("1:2 disassembly with esil expressions"));
	r_list_append (pmodes, strdup ("1:2 pseudo disassembly"));
	r_list_append (pmodes, strdup ("2:0 standard debugger"));
	r_list_append (pmodes, strdup ("3:0 raw byte image pixel view"));
	r_list_append (pmodes, strdup ("3:5 entropy bars"));
	r_list_append (pmodes, strdup ("4:0 code dump"));
	r_list_append (pmodes, strdup ("4:1 assembly code"));
	r_list_append (pmodes, strdup ("4:2 hex bytes"));
	char *res = r_cons_hud (core->cons, pmodes, NULL);
	if (R_STR_ISNOTEMPTY (res)) {
		int a, b;
		sscanf (res, "%d:%d", &a, &b);
		core->visual.printidx = a;
		switch (core->visual.printidx) {
		case R_CORE_VISUAL_MODE_PD:
		case R_CORE_VISUAL_MODE_DB:
			core->visual.disMode = b;
			applyDisMode (core);
			break;
		case R_CORE_VISUAL_MODE_PX:
			core->visual.hexMode = b;
			applyHexMode (core);
			core->visual.currentFormat = b;
			printfmtSingle[0] = printHexFormats[R_ABS (core->visual.hexMode) % PRINT_HEX_FORMATS];
			break;
		case R_CORE_VISUAL_MODE_OV:
			// core->visual.hexMode = b;
			core->visual.current4format = b;
			core->visual.currentFormat = b;
			break;
		case R_CORE_VISUAL_MODE_CD:
			// core->visual.hexMode = b;
			core->visual.current5format = b;
		//	core->visual.currentFormat = b;
			core->visual.currentFormat = R_ABS (core->visual.current5format) % PRINT_5_FORMATS;
			printfmtSingle[4] = print5Formats[core->visual.currentFormat];
			break;
		}
	}
	r_list_free (pmodes);
	free (res);
}

static bool insert_mode_enabled(RCore *core) {
	if (!core->visual.ime) {
		return false;
	}
	char ch = (ut8)r_cons_readchar (core->cons);
	if ((ut8)ch == KEY_ALTQ) {
		(void)r_cons_readchar (core->cons);
		core->visual.ime = false;
		return true;
	}
	if (core->visual.imes) {
		if (ch == 0x1b) {
			core->visual.ime = false;
			core->visual.imes = false;
			return true;
		}
		if (ch == 9) {
			core->visual.textedit_mode = !core->visual.textedit_mode;
			return true;
		}
		if (ch == 0x7f) { // backspace
			if (core->visual.textedit_mode) {
				if (core->print->cur_enabled && core->print->cur > 0) {
					r_core_cmdf (core, "r-1@ 0x%08"PFMT64x" + %d", core->addr, core->print->cur - 1);
					core->print->cur--;
				}
				return true;
			} else {
				core->print->cur--;
			}
			ch = 0;
		}
		if (ch == 0xd) {
			ch = '\n';
		}
		if (core->visual.textedit_mode) {
			r_core_cmdf (core, "r+1@ 0x%08"PFMT64x" + %d", core->addr, core->print->cur);
		}
		r_core_cmdf (core, "wx %02x @ 0x%08"PFMT64x" + %d", ch, core->addr, core->print->cur);
		core->print->cur ++;
		if (ch == 0) { // backspace
			core->print->cur--;
		}
		return true;
	}
	char arrows = r_cons_arrow_to_hjkl (core->cons, ch);
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
		core->print->cur++;
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
		if (core->visual.nib != -1) {
			r_core_cmdf (core, "wx %c%c @ $$+%d", core->visual.nib, ch, core->print->cur);
			core->print->cur++;
			core->visual.nib = -1;
		} else {
			r_core_cmdf (core, "wx %c @ $$+%d", ch, core->print->cur);
			core->visual.nib = ch;
		}
		break;
	case 'u':
		r_core_cmd_call (core, "wcu");
		break;
	case 'U':
		r_core_cmd_call (core, "wcU");
		break;
	case 'r':
		r_core_cmdf (core, "r-1 @ 0x%08"PFMT64x, core->addr + core->print->cur);
		break;
	case 'R':
		r_core_cmdf (core, "r+1 @ 0x%08"PFMT64x, core->addr + core->print->cur);
		break;
	case 'h':
		core->print->cur = R_MAX (0, core->print->cur - 1);
		break;
	case 'l':
		core->print->cur++;
		break;
	case 'j':
		cursor_nextrow (core, false);
		break;
	case 'k':
		cursor_prevrow (core, false);
		break;
	case 'Q':
	case 'q':
		core->visual.ime = false;
		break;
	case '?':
		r_cons_less_str (core->cons, "\nVisual Insert Mode:\n\n"
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
		"# Browse stuff:\n"
		" _  hud mode (V_)\n"
		" 1  bit editor (vd1)\n"
		" a  anal classes\n"
		" b  blocks\n"
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
		" l  same as VT\n"
		" L  same as TT\n"
		" m  maps\n"
		" M  mountpoints\n"
		" p  pids/threads\n"
		" q  quit\n"
		" r  ROP gadgets\n"
		" s  symbols\n"
		" t  types\n"
		" T  themes\n"
		" v  vars\n"
		" w  window panels\n"
		" x  xrefs\n"
		" X  refs\n"
		" z  browse function zignatures\n"
		" :  run command\n"
	;
	for (;;) {
		r_cons_clear00 (core->cons);
		r_cons_printf (core->cons, "%s\n", browsemsg);
		r_cons_flush (core->cons);
		char ch = 0;
		if (R_STR_ISNOTEMPTY (input)) {
			ch = *input;
			input++;
		} else {
			ch = r_cons_readchar (core->cons);
		}
		ch = r_cons_arrow_to_hjkl (core->cons, ch);
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
		case 'w': // "vbw"
			visual_windows (core);
			return;
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
			// r_core_cmd0 (core, "s $(CC~...)");
			break;
		case 't': // "vbt"
			r_core_visual_types (core);
			break;
		case 'T': // "vbT"
			r_core_cmd0 (core, "eco $(eco~...)");
			break;
		case 'l': // previously VT "vbl"
			r_core_cmd0 (core, "VT");
			break;
		case 'L': // "vbL" - alias for TT
			if (r_sandbox_enable (0)) {
				R_LOG_WARN ("sandbox not enabled");
			} else {
				if (r_cons_is_interactive (core->cons)) {
					r_core_cmd_call (core, "TT");
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

#define R_INCLUDE_BEGIN 1
#include "visual_tabs.inc.c"
#undef R_INCLUDE_BEGIN

static bool isNumber(RCore *core, int ch) {
	if (ch > '0' && ch <= '9') {
		return true;
	}
	if (core->print->cur_enabled) {
		return ch == '0';
	}
	return false;
}

static void numbuf_append(RCore *core, int ch) {
	if (core->visual.numbuf_i >= sizeof (core->visual.numbuf) - 1) {
		core->visual.numbuf_i = 0;
	}
	core->visual.numbuf[core->visual.numbuf_i++] = ch;
	core->visual.numbuf[core->visual.numbuf_i] = 0;
}

static int numbuf_pull(RCore *core) {
	int distance = 1;
	if (core->visual.numbuf_i) {
		core->visual.numbuf[core->visual.numbuf_i] = 0;
		distance = atoi (core->visual.numbuf);
		if (!distance) {
			distance = 1;
		}
		core->visual.numbuf_i = 0;
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
			R_WARN_IF_REACHED ();
		}
		return true;
	} else {
		r_config_toggle (core->config, "asm.cmt.fold");
	}
	return false;
}

static int process_get_click(RCore *core, int ch) {
	int x, y;
	if (r_cons_get_click (core->cons, &x, &y)) {
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

static void handle_space_key(RCore *core, int force) {
	if (force == 0) {
		switch (core->visual.printidx) {
		case R_CORE_VISUAL_MODE_PX: // hex
			if (core->visual.hexMode % 2) {
				printFormat (core, -1);
			} else {
				printFormat (core, 1);
			}
			applyHexMode (core);
			break;
		case R_CORE_VISUAL_MODE_PD:
		case R_CORE_VISUAL_MODE_DB:
			force = 'V';
			break;
		case R_CORE_VISUAL_MODE_OV: // hex
		case R_CORE_VISUAL_MODE_CD: // hex
			break;
		}
	}
	if (force == 'V') {
		RAnalFunction *fun = r_anal_get_fcn_in (core->anal, core->addr, R_ANAL_FCN_TYPE_NULL);
		if (!fun) {
			r_cons_message (core->cons, "Not in a function. Type 'df' to define it here");
		} else if (r_list_empty (fun->bbs)) {
			r_cons_message (core->cons, "No basic blocks in this function. You may want to use 'afb+'.");
		} else {
			const int ocolor = r_config_get_i (core->config, "scr.color");
			reset_print_cur (core->print);
			eprintf ("\rRendering graph...");
			r_core_visual_graph (core, NULL, NULL, true);
			r_config_set_i (core->config, "scr.color", ocolor);
		}
	}
}

R_API int r_core_visual_cmd(RCore *core, const char *arg) {
	ut8 och = arg[0];
	ut64 offset = core->addr;
	char buf[4096]; // TODO: remove this var, use local ones for each specific case
	const char *key_s;
	int i, cols = core->print->cols;
	int wheelspeed;
	int ch = och;
	r_cons_set_raw (core->cons, true);
	if ((ut8)ch == KEY_ALTQ) {
		r_cons_readchar (core->cons);
		ch = 'q';
	}
	ch = r_cons_arrow_to_hjkl (core->cons, ch);
	ch = visual_nkey (core, ch);
	if (ch < 2) {
		ch = process_get_click (core, ch);
		if (!ch) {
			return 1;
		}
	}
	if (core->visual.imes) {
		// TODO: support arrow keys to move around without losing insert mode
		// TODO: implement append mode
		core->visual.ime = true;
		setcursor (core, true);
		if (ch == 9 || ch == 0x1b) {
			core->visual.ime = false;
			core->visual.imes = false;
			return 1;
		}
		if (ch == 0x7f) { // backspace
			core->print->cur--;
			ch = 0;
		}
		r_core_cmdf (core, "wx %02x @ 0x%08"PFMT64x" + %d", ch, core->addr, core->print->cur);
		core->print->cur ++;
		och = 0;
		ch = 0;
		return 1;
	}
	if (core->cons->mouse_event) {
		wheelspeed = r_config_get_i (core->config, "scr.wheel.speed");
	} else {
		wheelspeed = 1;
	}
	RCoreVisual *v = &core->visual;
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
		if (isDisasmPrint (v->printidx)) {
			if (r_config_get_i (core->config, "asm.hints") && (r_config_get_i (core->config, "asm.hint.jmp")
			|| r_config_get_i (core->config, "asm.hint.lea") || r_config_get_i (core->config, "asm.hint.emu")
			|| r_config_get_i (core->config, "asm.hint.imm")
			|| r_config_get_i (core->config, "asm.hint.call"))) {
				r_core_visual_jump (core, ch);
			} else {
				numbuf_append (core, ch);
			}
		} else {
			numbuf_append (core, ch);
		}
	} else {
		switch (ch) {
#if R2__WINDOWS__
		case 0xf5:
			SetWindow (81, 25);
			break;
		case 0xcf5:
			SetWindow (81, 40);
			break;
#endif
		case 0x0d: // "enter" "\\n" "newline"
			if (r_config_get_b (core->config, "scr.cursor")) {
				RConsCursorPos cpos = core->cons->cpos;
				r_cons_set_click (core->cons, cpos.x, cpos.y);
				char buf[10];
				int ch = process_get_click (core, 0);
				buf[0] = ch;
				buf[1] = 0;
				r_core_visual_cmd (core, buf);
			} else {
				RAnalOp *op;
				int wheel = r_config_get_i (core->config, "scr.wheel");
				if (wheel) {
					r_cons_enable_mouse (core->cons, true);
				}
				do {
					op = r_core_anal_op (core, core->addr + core->print->cur, R_ARCH_OP_MASK_BASIC);
					if (op) {
						if (op->type == R_ANAL_OP_TYPE_JMP ||
								op->type == R_ANAL_OP_TYPE_CJMP ||
								op->type == R_ANAL_OP_TYPE_CALL ||
								op->type == R_ANAL_OP_TYPE_CCALL) {
							if (core->print->cur_enabled) {
								int delta = R_ABS ((st64) op->jump - (st64) offset);
								if (op->jump < core->addr || op->jump >= core->print->screen_bounds) {
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
			prevPrintFormat (core);
			break;
		case 9: // tab TAB
			r_core_visual_toggle_decompiler_disasm (core, false, true);
			if (core->visual.splitView) {
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
					if (v->printidx == R_CORE_VISUAL_MODE_DB) {
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
					nextPrintFormat (core);
				}
			}
			break;
		case '&':
			// cache current disasm/hexdump, work in a canvas to freely scroll :?
			if (core->print->cur_enabled) {
				core->visual.autoblocksize = !core->visual.autoblocksize;
				if (core->visual.autoblocksize) {
					core->visual.obs = core->blocksize;
				} else {
					r_core_block_size (core, core->visual.obs);
				}
				r_cons_clear (core->cons);
			} else {
				rotate_asm_bits (core);
			}
			break;
		case 'a':
		{
			{
				ut64 addr = core->addr;
				if (PIDX == 2) {
					if (core->seltab == 0) {
						addr = r_debug_reg_get (core->dbg, "SP");
					}
				}
				if (!canWrite (core, addr)) {
					r_cons_printf (core->cons, "\nFile has been opened in read-only mode. Use -w flag, oo+ or e io.cache=true\n");
					r_cons_any_key (core->cons, NULL);
					return true;
				}
			}
			r_cons_printf (core->cons, "Enter assembler opcodes separated with ';':\n");
			r_core_visual_showcursor (core, true);
			r_cons_flush (core->cons);
			r_cons_set_raw (core->cons, false);
			strcpy (buf, "\"wa ");
			r_line_set_prompt (core->cons->line, "> ");
			r_cons_enable_mouse (core->cons, false);
			if (r_cons_fgets (core->cons, buf + 4, sizeof (buf) - 4, 0, NULL) < 0) {
				buf[0] = '\0';
			}
			strcat (buf, "\"");
			int wheel = r_config_get_i (core->config, "scr.wheel");
			if (wheel) {
				r_cons_enable_mouse (core->cons, true);
			}
			if (*buf) {
				ut64 off = core->addr;
				if (core->print->cur_enabled) {
					ut64 t = off + core->print->cur;
					r_core_seek (core, t, false);
				}
				r_core_cmd (core, buf, true);
				if (core->print->cur_enabled) {
					r_core_seek (core, off, true);
				}
			}
			r_core_visual_showcursor (core, false);
			r_cons_set_raw (core->cons, true);
		}
		break;
		case '=':
		{ // TODO: edit
			r_core_visual_showcursor (core, true);
			const char *buf = NULL;
			#define I core->cons
			const char *cmd = r_config_get (core->config, "cmd.vprompt");
			r_line_set_prompt (core->cons->line, "cmd.vprompt> ");
			core->cons->line->contents = strdup (cmd);
			buf = r_line_readline (core->cons);
			core->cons->line->contents = NULL;
			(void)r_config_set (core->config, "cmd.vprompt", buf);
			r_core_visual_showcursor (core, false);
		}
		break;
		case '|':
		{ // TODO: edit
			r_core_visual_showcursor (core, true);
			#define I core->cons
			const char *cmd = r_config_get (core->config, "cmd.cprompt");
			r_line_set_prompt (core->cons->line, "cmd.cprompt> ");
			I->line->contents = strdup (cmd);
			const char *buf = r_line_readline (core->cons);
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
			if (0) {
				r_core_cmd0 (core, "wx 9090");
			} else {
				const int oce = core->print->cur_enabled;
				const int oco = core->print->ocur;
				const int occ = core->print->cur;
				ut64 off = oce? core->addr + core->print->cur: core->addr;
				core->print->cur_enabled = 0;
				r_cons_enable_mouse (core->cons, false);
				r_core_visual_asm (core, off);
				core->print->cur_enabled = oce;
				core->print->cur = occ;
				core->print->ocur = oco;
				if (r_config_get_b (core->config, "scr.wheel")) {
					r_cons_enable_mouse (core->cons, true);
				}
			}
			break;
		case '\\':
			if (core->visual.splitPtr == UT64_MAX) {
				core->visual.splitPtr = core->addr;
			}
			core->visual.splitView = !core->visual.splitView;
			setcursor (core, core->visual.splitView);
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
				if (prompt_read (core, "cursor at:", buf, sizeof (buf))) {
					core->print->cur = (st64) r_num_math (core->num, buf);
				}
			}
			break;
		case 'C':
			if (++core->visual.color > 3) {
				core->visual.color = 0;
			}
			r_config_set_i (core->config, "scr.color", core->visual.color);
			break;
		case 'd': {
			bool mouse_state = __holdMouseState (core);
			r_core_visual_showcursor (core, true);
			int distance = numbuf_pull (core);
			r_core_visual_define (core, arg + 1, distance - 1);
			r_core_visual_showcursor (core, false);
			r_cons_enable_mouse (core->cons, mouse_state && r_config_get_i (core->config, "scr.wheel"));
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
			r_line_set_prompt (core->cons->line, "flag name: ");
			r_core_visual_showcursor (core, true);
			if (r_cons_fgets (core->cons, name, sizeof (name), 0, NULL) >= 0 && *name) {
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
					r_flag_unset_addr (core->flags, core->addr + core->print->cur);
				} else if (*n == '.') {
					if (n[1] == '-') {
						//unset
						r_core_cmdf (core, "f.-%s@0x%"PFMT64x, n + 1, core->addr + min);
					} else {
						r_core_cmdf (core, "f.%s@0x%"PFMT64x, n + 1, core->addr + min);
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
							core->addr + min, range);
					}
				}
			}
			r_cons_enable_mouse (core->cons, mouse_state && r_config_get_i (core->config, "scr.wheel"));
		}
			r_core_visual_showcursor (core, false);
			break;
		case ',':
			visual_comma (core);
			break;
		case 't':
			{
				r_cons_gotoxy (core->cons, 0, 0);
				if (core->visual.tabs) {
					r_cons_printf (core->cons, "[tnp:=+-] ");
				} else {
					r_cons_printf (core->cons, "[t] ");
				}
				r_cons_flush (core->cons);
				r_cons_set_raw (core->cons, true);
				int ch = r_cons_readchar (core->cons);
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
							r_cons_fgets (core->cons, tab->name + 1, sizeof (tab->name) - 1, 0, NULL);
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
		case 'T': // "VT"
			visual_textlogs (core);
			break;
		case 'n': // "Vn"
			r_core_seek_next (core, r_config_get (core->config, "scr.nkey"));
			break;
		case 'N': // "VN"
			r_core_seek_previous (core, r_config_get (core->config, "scr.nkey"));
			break;
		case 'i':
		case 'I':
			{
			ut64 oaddr = core->addr;
			int delta = (core->print->ocur != -1)? R_MIN (core->print->cur, core->print->ocur): core->print->cur;
			ut64 addr = core->addr + delta;
			char buf[128];
			*buf = 0;
			if (!canWrite (core, addr)) {
				R_LOG_ERROR ("File is read-only. Use `r2 -w` or run `oo+` or `e io.cache=true`");
				r_cons_any_key (core->cons, NULL);
				return true;
			}
			if (PIDX == 0) {
				if (strstr (printfmtSingle[0], "pxb")) {
					r_core_visual_define (core, "1", 1);
					return true;
				}
				if (core->print->ocur == -1) {
					core->visual.ime = true;
					core->print->cur_enabled = true;
					return true;
				}
			} else if (PIDX == 4) {
				core->visual.ime = true;
				core->visual.imes = true;
			} else if (PIDX == 2) {
				if (core->seltab == 0) {
					addr = r_debug_reg_get (core->dbg, "SP") + delta;
				} else if (core->seltab == 1) {
					if (prompt_read (core, "new-reg-value> ", buf, sizeof (buf))) {
						const char *creg = core->dbg->creg;
						if (creg) {
							r_core_cmdf (core, "dr %s = %s", creg, buf);
						}
					}
					return true;
				}
			}
			r_core_visual_showcursor (core, true);
			r_cons_flush (core->cons);
			r_cons_set_raw (core->cons, 0);
			if (ch == 'I') {
				strcpy (buf, "wow ");
				r_line_set_prompt (core->cons->line, "insert hexpair block: ");
				if (r_cons_fgets (core->cons, buf + 4, sizeof (buf) - 4, 0, NULL) < 0) {
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
				r_line_set_prompt (core->cons->line, "insert string: ");
				if (r_cons_fgets (core->cons, buf + 3, sizeof (buf) - 3, 0, NULL) < 0) {
					buf[0] = '\0';
				}
				strcat (buf, "\"");
			} else if (PIDX != 4) {
				r_line_set_prompt (core->cons->line, "insert hex: ");
				if (core->print->ocur != -1) {
					int bs = R_ABS (core->print->cur - core->print->ocur) + 1;
					core->blocksize = bs;
					strcpy (buf, "wow ");
				} else {
					strcpy (buf, "wx ");
				}
				if (r_cons_fgets (core->cons, buf + strlen (buf), sizeof (buf) - strlen (buf), 0, NULL) < 0) {
					buf[0] = '\0';
				}
			}
			if (core->print->cur_enabled) {
				r_core_seek (core, addr, false);
			}
			if (*buf) {
				r_core_cmd (core, buf, 1);
			}
			if (core->print->cur_enabled) {
				r_core_seek (core, addr, true);
			}
			r_cons_set_raw (core->cons, true);
			r_core_visual_showcursor (core, false);
			r_core_seek (core, oaddr, true);
			}
			break;
		case 'R':
			if (r_config_get_i (core->config, "scr.randpal")) {
				r_core_cmd_call (core, "ecr");
			} else {
				r_core_cmd_call (core, "ecn");
			}
			break;
		case 'e':
			r_core_visual_config (core);
			break;
		case '^':
			{
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->addr, 0);
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
			if (r_config_get_b (core->config, "asm.hint.call")) {
				r_core_cmd_call (core, "e!asm.hint.call");
				r_core_cmd_call (core, "e asm.hint.jmp=true");
			} else if (r_config_get_b (core->config, "asm.hint.jmp")) {
				r_core_cmd_call (core, "e!asm.hint.jmp");
				r_core_cmd_call (core, "e asm.hint.imm=true");
			} else if (r_config_get_b (core->config, "asm.hint.imm")) {
				r_core_cmd_call (core, "e!asm.hint.imm");
				r_core_cmd_call (core, "e asm.hint.emu=true");
			} else if (r_config_get_b (core->config, "asm.hint.emu")) {
				r_core_cmd_call (core, "e!asm.hint.emu");
				r_core_cmd_call (core, "e asm.hint.lea=true");
			} else if (r_config_get_b (core->config, "asm.hint.lea")) {
				r_core_cmd_call (core, "e!asm.hint.lea");
				r_core_cmd_call (core, "e asm.hint.call=true");
			} else {
				r_core_cmd_call (core, "e asm.hint.call=true");
			}
			visual_refresh (core);
			break;
		case ' ':
			handle_space_key (core, 0);
			break;
		case 'V':
			handle_space_key (core, 'V');
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
				int h, w = r_cons_get_size (core->cons, &h);
				if (core->cons->cpos.x >= w) {
					core->cons->cpos.x = w;
				}
			} else {
				int distance = numbuf_pull (core);
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
				int distance = numbuf_pull (core);
				core->cons->cpos.x += (ch == 'h' || ch == 'H')? -distance: distance;
				if (core->cons->cpos.x < 1) {
					core->cons->cpos.x = 0;
				}
				int h, w = r_cons_get_size (core->cons, &h);
				if (core->cons->cpos.x >= w) {
					core->cons->cpos.x = w;
				}
			} else {
				int distance = numbuf_pull (core);
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
				(void)r_cons_get_size (core->cons, &h);
				if (core->cons->cpos.y >= h) {
					core->cons->cpos.y = h;
				}
			} else if (core->print->cur_enabled) {
				int distance = numbuf_pull (core);
				for (i = 0; i < distance; i++) {
					cursor_nextrow (core, false);
				}
				if (r_config_get_b (core->config, "scr.cursor.limit")) {
					/* Clamp cursor within the loaded block boundaries */
					if (core->print->cur < 0) {
						core->print->cur = 0;
					}
					int clamp = core->blocksize - 32;
					if ((ut64)core->print->cur >= clamp) {
						core->print->cur = clamp > 0 ? clamp - 1 : 0;
					}
				}
			} else {
				if (r_config_get_b (core->config, "scr.wheel.nkey")) {
					int i, distance = numbuf_pull (core);
					if (distance < 1)  {
						distance =  1;
					}
					for (i = 0; i < distance; i++) {
						r_core_cmd_call (core, "sn");
					}
				} else {
					int times = R_MAX (1, wheelspeed);
					ut64 amisize = 0;
					RIntervalNode *in = r_meta_get_in (core->anal, core->addr, R_META_TYPE_DATA);
					RAnalMetaItem *ami = NULL; // r_meta_get_in (core->anal, core->addr, R_META_TYPE_DATA); // , &amisize);
					if (in) {
						ami = in->data;
						amisize = r_meta_item_size (in->start, in->end);
					}

					// RAnalMetaItem *ami = r_meta_get_at (core->anal, core->addr, R_META_TYPE_DATA, &amisize);
					if (!ami) {
						ami = r_meta_get_at (core->anal, core->addr, R_META_TYPE_STRING, &amisize);
					}
					if (ami) {
						const int hexcols = r_config_get_i (core->config, "hex.cols");
						if (amisize > hexcols) {
							int pad = core->addr % hexcols;
							amisize = hexcols - pad;
						}
						r_core_seek_delta (core, amisize);
					} else {
						int distance = numbuf_pull (core);
						if (distance > 1) {
							times = distance;
						}
						while (times--) {
							RAnalOp op;
							if (isDisasmPrint (v->printidx)) {
								r_core_visual_disasm_down (core, &op, &cols);
								r_asm_op_fini (&op);
							} else if (!strcmp (__core_visual_print_command (core),
									"prc")) {
								cols = r_config_get_i (core->config, "hex.cols");
							}
							r_core_seek (core, core->addr + cols, true);
						}
					}
				}
			}
			break;
		case 'J':
			if (r_config_get_b (core->config, "scr.cursor")) {
				const int distance = 4; // numbuf_pull (core);
				core->cons->cpos.y += distance;
				int h;
				(void)r_cons_get_size (core->cons, &h);
				if (core->cons->cpos.y >= h) {
					core->cons->cpos.y = h;
				}
			} else if (core->print->cur_enabled) {
				const int distance = numbuf_pull (core);
				for (i = 0; i < distance; i++) {
					cursor_nextrow (core, true);
				}
				if (r_config_get_b (core->config, "scr.cursor.limit")) {
					/* Clamp cursor within the loaded block boundaries */
					if (core->print->cur < 0) {
						core->print->cur = 0;
					}
					if ((ut64)core->print->cur >= core->blocksize) {
						core->print->cur = core->blocksize > 0 ? core->blocksize - 1 : 0;
					}
				}
			} else {
				if (core->print->screen_bounds > 1 && core->print->screen_bounds >= core->addr) {
					RAnalOp op;
					ut64 addr = UT64_MAX;
					if (isDisasmPrint (v->printidx)) {
						if (core->print->screen_bounds == core->addr) {
							r_asm_disassemble (core->rasm, &op, core->block, 32);
							r_asm_op_fini (&op);
						}
						if (addr == core->addr || addr == UT64_MAX) {
							addr = core->addr + 48;
						}
					} else {
						int h;
						int hexCols = r_config_get_i (core->config, "hex.cols");
						if (hexCols < 1) {
							hexCols = 16;
						}
						(void)r_cons_get_size (core->cons, &h);
						int delta = hexCols * (h / 4);
						addr = core->addr + delta;
					}
					r_core_seek (core, addr, true);
				} else {
					r_core_seek (core, core->addr + core->visual.obs, true);
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
       	const int distance = numbuf_pull (core);
       	for (i = 0; i < distance; i++) {
       		cursor_prevrow (core, false);
       	}
       	if (r_config_get_b (core->config, "scr.cursor.limit")) {
       		/* Clamp cursor within the loaded block boundaries */
       		if (core->print->cur < 0) {
       			core->print->cur = 0;
       		}
       		if ((ut64)core->print->cur >= core->blocksize) {
       			core->print->cur = core->blocksize > 0 ? core->blocksize - 1 : 0;
       		}
       	}
       } else {
				if (r_config_get_b (core->config, "scr.wheel.nkey")) {
					int i, distance = numbuf_pull (core);
					if (distance < 1)  {
						distance =  1;
					}
					for (i = 0; i < distance; i++) {
						r_core_cmd_call (core, "sp");
					}
				} else {
					int times = wheelspeed;
					if (times < 1) {
						times = 1;
					}
					const int distance = numbuf_pull (core);
					if (distance > 1) {
						times = distance;
					}
					while (times--) {
						if (isDisasmPrint (v->printidx)) {
							r_core_visual_disasm_up (core, &cols);
						} else if (!strcmp (__core_visual_print_command (core), "prc")) {
							cols = r_config_get_i (core->config, "hex.cols");
						}
						if (cols != 0) {
							r_core_seek_delta (core, -cols);
						}
					}
				}
			}
			break;
		case 'K':
			if (r_config_get_b (core->config, "scr.cursor")) {
				int distance = 4;// numbuf_pull (core);
				core->cons->cpos.y -= distance;
				if (core->cons->cpos.y < 1) {
					core->cons->cpos.y = 0;
				}
       } else if (core->print->cur_enabled) {
       	int distance = numbuf_pull (core);
       	for (i = 0; i < distance; i++) {
       		cursor_prevrow (core, true);
       	}
       	if (r_config_get_b (core->config, "scr.cursor.limit")) {
       		/* Clamp cursor within the loaded block boundaries */
       		if (core->print->cur < 0) {
       			core->print->cur = 0;
       		}
       		if ((ut64)core->print->cur >= core->blocksize) {
       			core->print->cur = core->blocksize > 0 ? core->blocksize - 1 : 0;
       		}
       	}
			} else {
				if (core->print->screen_bounds > 1 && core->print->screen_bounds > core->addr) {
					int delta = (core->print->screen_bounds - core->addr);
					const ut64 addr = (core->addr >= delta)? core->addr - delta: 0;
					r_core_seek (core, addr, true);
				} else {
					ut64 at = (core->addr > core->visual.obs)? core->addr - core->visual.obs: 0;
					const ut64 addr = (core->addr > core->visual.obs)? at: 0;
					r_core_seek (core, addr, true);
				}
			}
			break;
		case '[':
			// comments column
			if (core->print->cur_enabled &&
				(v->printidx == R_CORE_VISUAL_MODE_PD ||
				(v->printidx == R_CORE_VISUAL_MODE_DB && core->seltab == 2))) {
				int cmtcol = r_config_get_i (core->config, "asm.cmt.col");
				if (cmtcol > 2) {
					r_config_set_i (core->config, "asm.cmt.col", cmtcol - 2);
				}
			}
			// hex column
			if ((v->printidx != R_CORE_VISUAL_MODE_PD && v->printidx != R_CORE_VISUAL_MODE_DB) ||
				(v->printidx == R_CORE_VISUAL_MODE_DB && core->seltab != 2)) {
				int scrcols = r_config_get_i (core->config, "hex.cols");
				if (scrcols > 1) {
					r_config_set_i (core->config, "hex.cols", scrcols - 1);
				}
			}
			break;
		case ']':
			// comments column
			if (core->print->cur_enabled &&
				(v->printidx == R_CORE_VISUAL_MODE_PD ||
				(v->printidx == R_CORE_VISUAL_MODE_DB && core->seltab == 2))) {
				int cmtcol = r_config_get_i (core->config, "asm.cmt.col");
				r_config_set_i (core->config, "asm.cmt.col", cmtcol + 2);
			}
			// hex column
			if ((v->printidx != R_CORE_VISUAL_MODE_PD && v->printidx != R_CORE_VISUAL_MODE_DB) ||
				(v->printidx == R_CORE_VISUAL_MODE_DB && core->seltab != 2)) {
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
			if (R_STR_ISNOTEMPTY (key_s)) {
				r_core_cmd0 (core, key_s);
			} else {
				// r_core_cmd0 (core, "dsb");
				__core_visual_step_over (core);
			}
			break;
		case '"':
			r_config_toggle (core->config, "scr.dumpcols");
			break;
		case 'p':
			r_core_visual_toggle_decompiler_disasm (core, false, true);
			if (v->printidx == R_CORE_VISUAL_MODE_DB && core->print->cur_enabled) {
				nextPrintCommand (core);
			} else {
				setprintmode (core, 1);
			}
			break;
		case 'P':
			if (v->printidx == R_CORE_VISUAL_MODE_DB && core->print->cur_enabled) {
				prevPrintCommand (core);
			} else {
				setprintmode (core, -1);
			}
			break;
		case '%':
			if (core->print->cur_enabled) {
				findPair (core);
			} else {
				r_core_visual_find (core, NULL);
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
				r_cons_gotoxy (core->cons, 0, 0);
				r_cons_printf (core->cons, R_CONS_CLEAR_LINE"Set shortcut key for 0x%"PFMT64x"\n", core->addr);
				r_cons_flush (core->cons);
				const int ch = r_cons_readchar (core->cons);
				r_core_vmark (core, ch);
			}
			break;
		case 'M':
			{
				r_cons_gotoxy (core->cons, 0, 0);
				if (r_core_vmark_dump (core, 'v')) {
					r_cons_printf (core->cons, R_CONS_CLEAR_LINE"Remove a shortcut key from the list\n");
					r_cons_flush (core->cons);
					const int ch = r_cons_readchar (core->cons);
					r_core_vmark_del (core, ch);
				}
			}
			break;
		case '\'':
			{
				r_cons_gotoxy (core->cons, 0, 2);
				if (r_core_vmark_dump (core, 'v')) {
					r_cons_flush (core->cons);
					const int ch = r_cons_readchar (core->cons);
					r_core_vmark_seek (core, ch, NULL);
				}
			}
			break;
		case 'y':
			if (core->print->ocur == -1) {
				r_core_yank (core, core->addr + core->print->cur, 1);
			} else {
				r_core_yank (core, core->addr + ((core->print->ocur < core->print->cur) ?
					core->print->ocur: core->print->cur), R_ABS (core->print->cur - core->print->ocur) + 1);
			}
			break;
		case 'Y':
			if (!core->yank_buf) {
				r_cons_print (core->cons, "Cannot paste, clipboard is empty.\n");
				r_cons_flush (core->cons);
				r_cons_any_key (core->cons, NULL);
				r_cons_clear00 (core->cons);
			} else {
				r_core_yank_paste (core, core->addr + core->print->cur, 0);
			}
			break;
		case '0':
			core->visual.current0format = 0;
			core->visual.current0format = 0;
			core->visual.currentFormat = core->visual.current0format;
			setprintmode (core, 0);
			break;
		case '-':
			if (core->print->cur_enabled) {
				if (core->seltab < 2 && v->printidx == R_CORE_VISUAL_MODE_DB) {
					if (core->seltab) {
						const char *creg = core->dbg->creg;
						if (creg) {
							r_core_cmdf (core, "dr %s = %s-1", creg, creg);
						}
					} else {
						int w = r_config_get_i (core->config, "hex.cols");
						r_config_set_i (core->config, "stack.size",
							r_config_get_i (core->config, "stack.size") - w);
					}
				} else {
					if (!canWrite (core, core->addr)) {
						r_cons_printf (core->cons, "\nFile has been opened in read-only mode. Use -w flag, oo+ or e io.cache=true\n");
						r_cons_any_key (core->cons, NULL);
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
				if (!core->visual.autoblocksize) {
					r_core_block_size (core, core->blocksize - 1);
				}
			}
			break;
		case '+':
			if (core->print->cur_enabled) {
				if (core->seltab < 2 && v->printidx == R_CORE_VISUAL_MODE_DB) {
					if (core->seltab) {
						const char *creg = core->dbg->creg;
						if (creg) {
							r_core_cmdf (core, "dr %s = %s+1", creg, creg);
						}
					} else {
						int w = r_config_get_i (core->config, "hex.cols");
						r_config_set_i (core->config, "stack.size",
							r_config_get_i (core->config, "stack.size") + w);
					}
				} else {
					if (!canWrite (core, core->addr)) {
						r_cons_printf (core->cons, "\nFile has been opened in read-only mode. Use -w flag, oo+ or e io.cache=true\n");
						r_cons_any_key (core->cons, NULL);
						return true;
					}
					if (core->print->ocur == -1) {
						r_core_cmdf (core, "woa 01 @ $$+%i!1", core->print->cur);
					} else {
						r_core_cmdf (core, "woa 01 @ $$+%i!%i", core->print->cur < core->print->ocur
							? core->print->cur : core->print->ocur,
							R_ABS (core->print->ocur - core->print->cur) + 1);
					}
				}
			} else {
				if (!core->visual.autoblocksize) {
					r_core_block_size (core, core->blocksize + 1);
				}
			}
			break;
		case '/': {
			bool mouse_state = __holdMouseState (core);
			if (core->print->cur_enabled) {
				if (core->seltab < 2 && v->printidx == R_CORE_VISUAL_MODE_DB) {
					if (core->seltab) {
						const char *creg = core->dbg->creg;
						if (creg) {
							int delta = core->rasm->config->bits / 8;
							r_core_cmdf (core, "dr %s = %s-%d", creg, creg, delta);
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
				if (core->visual.autoblocksize) {
					r_core_cmd0 (core, "?i highlight;e scr.highlight=`yp`");
				} else {
					r_core_block_size (core, core->blocksize - cols);
				}
			}
			r_cons_enable_mouse (core->cons, mouse_state && r_config_get_i (core->config, "scr.wheel"));
		}	break;
		case '(':
			core->visual.snowMode = !core->visual.snowMode;
			if (!core->visual.snowMode) {
				r_list_free (core->visual.snows);
				core->visual.snows = NULL;
			}
			break;
		case ')':
			rotateAsmemu (core);
			break;
		case '#':
			if (v->printidx == 1) {
				r_core_visual_toggle_decompiler_disasm (core, false, false);
			} else {
				// do nothing for now :?, px vs pxa?
			}
			break;
		case '*':
			if (core->print->cur_enabled) {
				if (core->seltab < 2 && v->printidx == R_CORE_VISUAL_MODE_DB) {
					if (core->seltab) {
						const char *creg = core->dbg->creg;
						if (creg) {
							int delta = core->rasm->config->bits / 8;
							r_core_cmdf (core, "dr %s = %s+%d", creg, creg, delta);
						}
					} else {
						int w = r_config_get_i (core->config, "hex.cols");
						const int newstacksize = r_config_get_i (core->config, "stack.size") + w;
						r_config_set_i (core->config, "stack.size", newstacksize);
					}
				} else {
					r_core_cmdf (core, "dr PC=0x%08"PFMT64x, core->addr + core->print->cur);
				}
			} else if (!core->visual.autoblocksize) {
				r_core_block_size (core, core->blocksize + cols);
			}
			break;
		case '>':
			if (core->print->cur_enabled) {
				if (core->print->ocur == -1) {
					R_LOG_ERROR ("No range selected. Use HJKL");
					r_cons_any_key (core->cons, NULL);
					break;
				}
				char buf[128];
				// TODO autocomplete filenames
				if (prompt_read (core, "dump to file: ", buf, sizeof (buf))) {
					ut64 from = core->addr + core->print->ocur;
					ut64 size = R_ABS (core->print->cur - core->print->ocur) + 1;
					r_core_dump (core, buf, from, size, false);
				}
			} else {
				r_core_seek (core, core->addr + core->blocksize, false);
				r_io_sundo_push (core->io, core->addr, r_print_get_cursor (core->print));
			}
			break;
		case '<': // "V<"
			if (core->print->cur_enabled) {
				char buf[128];
				// TODO autocomplete filenames
				if (prompt_read (core, "load from file: ", buf, sizeof (buf))) {
					size_t sz;
					char *data = r_file_slurp (buf, &sz);
					if (data) {
						int cur;
						if (core->print->ocur != -1) {
							cur = R_MIN (core->print->cur, core->print->ocur);
						} else {
							cur = core->print->cur;
						}
						ut64 from = core->addr + cur;
						ut64 size = R_ABS (core->print->cur - core->print->ocur) + 1;
						ut64 s = R_MIN (size, (ut64)sz);
						r_io_write_at (core->io, from, (const ut8*)data, s);
					}
				}
			} else {
				r_core_seek (core, core->addr - core->blocksize, false);
				r_io_sundo_push (core->io, core->addr, r_print_get_cursor (core->print));
			}
			break;
		case '.': // "V."
			r_io_sundo_push (core->io, core->addr, r_print_get_cursor (core->print));
			if (core->print->cur_enabled) {
				r_config_set_i (core->config, "stack.delta", 0);
				r_core_seek (core, core->addr + core->print->cur, true);
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
									((RIOMapRef *)r_list_last (bank->maprefs))->id);
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
		case ';': // "V;"
			visual_add_comment (core, UT64_MAX);
			break;
		case 'b':
			r_core_visual_browse (core, arg + 1);
			break;
		case 'B':
			{
			ut64 addr = core->print->cur_enabled? core->addr + core->print->cur: core->addr;
			r_core_cmdf (core, "dbs 0x%08"PFMT64x, addr);
			}
			break;
		case 'u':
		{
			RIOUndos *undo = r_io_sundo (core->io, core->addr);
			if (undo) {
				r_core_visual_seek_animation (core, undo->off);
				core->print->cur = undo->cursor;
			} else {
				R_LOG_ERROR ("Cannot undo");
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
			ut64 at = core->addr;
			if (core->print->cur_enabled) {
				at += core->print->cur;
			}
			toggle_bb (core, at);
		}
		break;
		case 'Z': // Z=90 shift-tab SHIFT-TAB
			if (och == 27) { // shift-tab
				if (core->print->cur_enabled && v->printidx == R_CORE_VISUAL_MODE_DB) {
					core->print->cur = 0;
					core->seltab--;
					if (core->seltab < 0) {
						core->seltab = 2;
					}
				} else {
					prevPrintFormat (core);
				}
			} else { // "Z"
				prevPrintFormat (core);
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
		core->visual.numbuf_i = 0;
	}
	r_core_block_read (core);
	return true;
}

static void visual_title(RCore *core, int color) {
	bool showDelta = r_config_get_b (core->config, "asm.slow");
	core->visual.oldpc = 0;
	const char *BEGIN = core->cons->context->pal.prompt;
	const char *filename;
	char pos[512], bar[512], pcs[32];
	if (!core->visual.oldpc) {
		core->visual.oldpc = r_debug_reg_get (core->dbg, "PC");
	}
	/* automatic block size */
	int pc, hexcols = r_config_get_i (core->config, "hex.cols");
	if (core->visual.autoblocksize) {
		switch (core->visual.printidx) {
		case R_CORE_VISUAL_MODE_PX: // x
			if (core->visual.currentFormat == 3 || core->visual.currentFormat == 9 || core->visual.currentFormat == 5) { // prx
				r_core_block_size (core, (int)(core->cons->rows * hexcols * 4));
			} else if ((R_ABS (core->visual.hexMode) % 3) == 0) { // prx
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
				int new_sz = core->print->screen_bounds - core->addr + 32;
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
		if (curpc && curpc != UT64_MAX && curpc != core->visual.oldpc) {
			// check dbg.follow here
			int follow = (int) (st64) r_config_get_i (core->config, "dbg.follow");
			if (follow > 0) {
				if ((curpc < core->addr) || (curpc > (core->addr + follow))) {
					r_core_seek (core, curpc, true);
				}
			} else if (follow < 0) {
				r_core_seek (core, curpc + follow, true);
			}
			core->visual.oldpc = curpc;
		}
	}
	RIOMap *map = r_io_map_get_at (core->io, core->addr);
	RIODesc *desc = map ? r_io_desc_get (core->io, map->fd) : core->io->desc;
	filename = desc? desc->name: "";

	{ /* get flag with delta */
		ut64 addr = core->addr + (core->print->cur_enabled? core->print->cur: 0);
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
			if (f->addr == addr || !f->addr) {
				snprintf (pos, sizeof (pos), "@ %s", f->name);
			} else {
				snprintf (pos, sizeof (pos), "@ %s+%d # 0x%"PFMT64x,
					f->name, (int) (addr - f->addr), addr);
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
		r_cons_print (core->cons, BEGIN);
	}
	const char *cmd_visual = r_config_get (core->config, "cmd.visual");
	if (R_STR_ISNOTEMPTY (cmd_visual)) {
		r_str_ncpy (bar, cmd_visual, sizeof (bar) - 1);
		bar[10] = '.'; // chop cmdfmt
		bar[11] = '.'; // chop cmdfmt
		bar[12] = 0; // chop cmdfmt
	} else {
		const char *cmd = __core_visual_print_command (core);
		if (R_STR_ISNOTEMPTY (cmd)) {
			r_str_ncpy (bar, cmd, sizeof (bar) - 1);
			bar[10] = '.'; // chop cmdfmt
			bar[11] = '.'; // chop cmdfmt
			bar[12] = 0; // chop cmdfmt
		}
	}
	{
		ut64 sz = r_io_size (core->io);
		ut64 pa = core->addr;
		{
			RIOMap *map = r_io_map_get_at (core->io, core->addr);
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
			snprintf (pcs, sizeof (pcs), "%d%% ", pc);
		}
	}
	{
		char *title;
		char *address = (core->print->wide_offsets && R_SYS_BITS_CHECK (core->dbg->bits, 64))
			? r_str_newf ("0x%016"PFMT64x, core->addr)
			: r_str_newf ("0x%08"PFMT64x, core->addr);
		if (core->visual.ime) {
			const char *text = core->visual.textedit_mode? "EDITOR MODE": "INSERT MODE";
			title = r_str_newf ("[%s + %d> * %s * (press ESC to leave, TAB to toggle mode)\n",
				address, core->print->cur, text);
		} else {
			char pm[32] = "[XADVC]";
			int i;
			for (i = 0; i < 6; i++) {
				if (core->visual.printidx == i) {
					pm[i + 1] = toupper ((unsigned char)pm[i + 1]);
				} else {
					pm[i + 1] = tolower ((unsigned char)pm[i + 1]);
				}
			}
			if (core->print->cur_enabled) {
				if (core->print->ocur == -1) {
					title = r_str_newf ("[%s *0x%08"PFMT64x" %s%d ($$+0x%x)]> %s %s\n",
						address, core->addr + core->print->cur,
						pm, core->visual.currentFormat, core->print->cur,
						bar, pos);
				} else {
					title = r_str_newf ("[%s 0x%08"PFMT64x" %s%d [0x%x..0x%x] %d]> %s %s\n",
						address, core->addr + core->print->cur,
						pm, core->visual.currentFormat, core->print->ocur, core->print->cur,
						R_ABS (core->print->cur - core->print->ocur) + 1,
						bar, pos);
				}
			} else {
				title = r_str_newf ("[%s %s%d %s%d %s]> %s %s\n",
					address, pm, core->visual.currentFormat, pcs, core->blocksize, filename, bar, pos);
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
		r_cons_print (core->cons, title);
		free (title);
		free (address);
	}
	if (color) {
		r_cons_print (core->cons, Color_RESET);
	}
}

static int visual_responsive(RCore *core) {
	int h, w = r_cons_get_size (core->cons, &h);
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
			r_config_set_b (core->config, "asm.addr", false);
		} else {
			r_config_set_b (core->config, "asm.addr", true);
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
	int i, h, w = r_cons_get_size (core->cons, &h);

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
	} else if (r_config_get_b (core->config, "io.va")) {
		from = r_num_math (core->num, "$S");
		to = r_num_math (core->num, "$S+$SS");
	} else {
		to = r_num_math (core->num, "$s");
	}
	char *s = r_str_newf ("[0x%08"PFMT64x"]", from);
	r_cons_gotoxy (core->cons, w - strlen (s) + 1, 2);
	r_cons_print (core->cons, s);
	free (s);

	ut64 block = (to - from) / h;

	RList *words = r_flag_zone_barlist (core->flags, from, block, h);

	bool hadMatch = false;
	RCons *cons = core->cons;
	for (i = 0; i < h ; i++) {
		const char *word = r_list_pop_head (words);
		if (word && *word) {
			r_cons_gotoxy (cons, w - strlen (word) - 1, i + 3);
			r_cons_printf (cons, "%s>", word);
		}
		r_cons_gotoxy (core->cons, w, i + 3);
		if (hadMatch) {
			r_cons_printf (cons, "|");
		} else {
			ut64 cur = from + (block * i);
			ut64 nex = from + (block * (i + 1));
			if (R_BETWEEN (cur, core->addr, nex)) {
				r_cons_printf (cons, Color_INVERT"|"Color_RESET);
				hadMatch = true;
			} else {
				r_cons_printf (cons, "|");
			}
		}
	}
	s = r_str_newf ("[0x%08"PFMT64x"]", to);
	if (s) {
		r_cons_gotoxy (core->cons, w - strlen (s) + 1, h + 1);
		r_cons_print (core->cons, s);
		free (s);
	}
	r_list_free (words);
	r_cons_flush (core->cons);
}

R_API void r_core_print_scrollbar_bottom(RCore *core) {
	RCons *cons = core->cons;
	int i, h, w = r_cons_get_size (cons, &h);

	if (w < 10 || h < 4) {
		return;
	}
	ut64 from = 0;
	ut64 to = UT64_MAX;
	if (r_config_get_b (core->config, "cfg.debug")) {
		from = r_num_math (core->num, "$D");
		to = r_num_math (core->num, "$D+$DD");
	} else if (r_config_get_b (core->config, "io.va")) {
		from = r_num_math (core->num, "$S");
		to = r_num_math (core->num, "$S+$SS");
	} else {
		to = r_num_math (core->num, "$s");
	}
	char *s = r_str_newf ("[0x%08"PFMT64x"]", from);
	int slen = strlen (s) + 1;
	r_cons_gotoxy (cons, 0, h + 1);
	r_cons_print (cons, s);
	free (s);

	int linew = (w - (slen * 2)) + 1;
	ut64 block = (to - from) / linew;

	RList *words = r_flag_zone_barlist (core->flags, from, block, h);

	bool hadMatch = false;
	for (i = 0; i < linew + 1; i++) {
		r_cons_gotoxy (cons, i + slen, h + 1);
		if (hadMatch) {
			r_cons_print (cons, "-");
		} else {
			ut64 cur = from + (block * i);
			ut64 nex = from + (block * (i + 2));
			if (R_BETWEEN (cur, core->addr, nex)) {
				r_cons_print (cons, Color_INVERT"-"Color_RESET);
				hadMatch = true;
			} else {
				r_cons_print (cons, "-");
			}
		}
	}
	for (i = 0; i < linew; i++) {
		const char *word = r_list_pop_head (words);
		if (word && *word) {
			ut64 cur = from + (block * i);
			ut64 nex = from + (block * (i + strlen (word) + 1));
			r_cons_gotoxy (cons, i + slen - 1, h);
			if (R_BETWEEN (cur, core->addr, nex)) {
				r_cons_printf (cons, Color_INVERT"{%s}"Color_RESET, word);
			} else {
				r_cons_printf (cons, "{%s}", word);
			}
		}
	}
	s = r_str_newf ("[0x%08"PFMT64x"]", to);
	if (s) {
		r_cons_gotoxy (cons, linew + slen + 1, h + 1);
		r_cons_print (cons, s);
		free (s);
	}
	r_list_free (words);
	r_cons_flush (cons);
}

static void show_cursor(RCore *core) {
	const bool keyCursor = r_config_get_b (core->config, "scr.cursor");
	if (keyCursor) {
		RCons *cons = core->cons;
		r_cons_gotoxy (cons, cons->cpos.x, cons->cpos.y);
		r_cons_show_cursor (cons, 1);
		r_cons_flush (cons);
	}
}

R_IPI void visual_refresh(RCore *core) {
	R_RETURN_IF_FAIL (core);
	RCons *cons = core->cons;
	char *cmd_str = NULL;
	r_print_set_cursor (core->print, core->print->cur_enabled, core->print->ocur, core->print->cur);
	cons->blankline = true;
	int notch = r_config_get_i (core->config, "scr.notch");
	int w = visual_responsive (core);
	if (core->visual.autoblocksize) {
		r_cons_gotoxy (cons, 0, 0);
	} else {
		r_cons_clear (cons);
	}
	r_cons_flush (cons);
	r_cons_print_clear (cons);
	r_cons_print (cons, cons->context->pal.bgprompt);
	cons->context->noflush = true;

	int hex_cols = r_config_get_i (core->config, "hex.cols");
	int split_w = 12 + 4 + hex_cols + (hex_cols * 3);
	bool ce = core->print->cur_enabled;

	const char *vi = r_config_get (core->config, "cmd.cprompt");
	bool vsplit = R_STR_ISNOTEMPTY (vi);

	if (vsplit) {
		// XXX: slow
		cons->blankline = false;
		{
			int hex_cols = r_config_get_i (core->config, "hex.cols");
			int split_w = 12 + 4 + hex_cols + (hex_cols * 3);
			if (split_w > w) {
				// do not show column contents
			} else {
				r_cons_printf (cons, "[cmd.cprompt=%s]\n", vi);
				if (core->visual.oseek != UT64_MAX) {
					r_core_seek (core, core->visual.oseek, true);
				}
				r_core_cmd0 (core, vi);
				r_cons_column (cons, split_w);
				if (r_str_startswith (vi, "p=") && core->print->cur_enabled) {
					core->visual.oseek = core->addr;
					core->print->cur_enabled = false;
					r_core_seek (core, core->num->value, true);
				} else {
					core->visual.oseek = UT64_MAX;
				}
			}
		}
		r_cons_gotoxy (cons, 0, 0);
	}
	int i;
	for (i = 0; i < notch; i++) {
		r_cons_printf (cons, R_CONS_CLEAR_LINE"\n");
	}
	vi = r_config_get (core->config, "cmd.vprompt");
	if (R_STR_ISNOTEMPTY (vi)) {
		r_core_cmd0 (core, vi);
	}
	visual_title (core, core->visual.color);
	const char *vi2 = r_config_get (core->config, "cmd.vprompt2");
	if (R_STR_ISNOTEMPTY (vi2)) {
		r_core_cmd0 (core, vi2);
	}
	const char *vcmd = r_config_get (core->config, "cmd.visual");
	if (R_STR_ISNOTEMPTY (vcmd)) {
		// disable screen bounds when it's a user-defined command
		// because it can cause some issues
		core->print->screen_bounds = 0;
		cmd_str = strdup (vcmd);
	} else {
		if (core->visual.splitView) {
			const char *pxw = NULL;
			int h = r_num_get (core->num, "$r");
			int size = (h * 16) / 2;
			switch (core->visual.printidx) {
			case 1:
				size = (h - 2) / 2;
				pxw = "pd";
				break;
			default:
				pxw = stackPrintCommand (core);
				break;
			}
			core->print->screen_bounds = 1LL;
			cmd_str = r_str_newf (
					"?t0;%s %d @ %"PFMT64d";cl;"
					"?t1;%s %d @ %"PFMT64d";",
					pxw, size, core->visual.splitPtr,
					pxw, size, core->addr);
		} else {
			core->print->screen_bounds = 1LL;
			cmd_str = strdup ((core->visual.zoom ? "pz" : __core_visual_print_command (core)));
		}
	}
	if (R_STR_ISNOTEMPTY (cmd_str)) {
		char *res = r_core_cmd_str (core, cmd_str);
		if (vsplit) {
			res = r_str_ansi_crop (res, 0, 0, split_w, -1);
		}
		r_cons_print (cons, res);
		free (res);
	}
	free (cmd_str);
	core->print->cur_enabled = ce;
	core->visual.blocksize = core->num->value? core->num->value: core->blocksize;
	cons->context->noflush = false;

	RConsMark *mark = r_cons_mark_at (cons, 0, "cursor");
	if (mark) {
		int x = 60;
		r_cons_gotoxy (cons, x, mark->row - 2); r_cons_print (cons, "   .-------------.");
		r_cons_gotoxy (cons, x, mark->row - 1); r_cons_print (cons, "   |             |");
		r_cons_gotoxy (cons, x, mark->row);     r_cons_print (cons, "--<  Hello world |");
		r_cons_gotoxy (cons, x, mark->row + 1); r_cons_print (cons, "   |             |");
		r_cons_gotoxy (cons, x, mark->row + 2); r_cons_print (cons, "   `-------------'");
	}

	/* this is why there's flickering */
	if (core->print->vflush) {
		r_cons_visual_flush (cons);
	} else {
		r_cons_reset (cons);
	}
	if (core->scr_gadgets) {
		r_core_cmd_call (core, "pg");
		r_cons_flush (cons);
	}
	cons->blankline = false;
	cons->blankline = true;
	core->curtab = 0; // which command are we focusing
	//core->seltab = 0; // user selected tab

	if (core->visual.snowMode) {
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

static int varcount(RCore *core, RAnalFunction *f) {
	int mode = r_config_get_i (core->config, "asm.var.summary");
	if (mode != 0) {
		return 0;
	}
	RAnalFcnVarsCache vars_cache;
	if (!f) {
		f = r_anal_get_function_at (core->anal, core->addr);
		if (!f) {
			return 0;
		}
	}
	r_anal_function_vars_cache_init (core->anal, &vars_cache, f);
	int len = r_list_length (vars_cache.rvars);
	len += r_list_length (vars_cache.bvars);
	len += r_list_length (vars_cache.svars);
	r_anal_function_vars_cache_fini (&vars_cache);
	return len;
}

R_API void r_core_visual_disasm_up(RCore *core, int *cols) {
	RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->addr, R_ANAL_FCN_TYPE_NULL);
	if (f && f->folded) {
		*cols = core->addr - f->addr;
		if (*cols < 1) {
			*cols = 4;
		}
	} else {
		if (f && core->addr == f->addr) {
			if (core->skiplines > 0) {
				core->skiplines--;
				*cols = 0;
			} else {
				int delta = r_core_visual_prevopsz (core, core->addr);
				*cols = delta;
			}
			return;
		}
		int delta = r_core_visual_prevopsz (core, core->addr);
		if (f && core->addr - delta == f->addr) {
			int nvars = varcount (core, f);
			if (nvars < 20) {
				core->skiplines = nvars;
				if (core->skiplines > 0) {
					core->skiplines--;
				}
			}
			*cols = delta;
		} else {
			*cols = delta;
			// *cols = 0;
		}
	}
}

R_API void r_core_visual_disasm_down(RCore *core, RAnalOp *op, int *cols) {
	int midflags = r_config_get_i (core->config, "asm.flags.middle");
	const bool midbb = r_config_get_i (core->config, "asm.bbmiddle");
	RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->addr, 0);
	ut64 orig = core->addr;
	op->size = 1;
	if (f && f->folded) {
		*cols = core->addr - r_anal_function_max_addr (f);
	} else {
		r_asm_set_pc (core->rasm, core->addr);
		int maxopsize = r_anal_archinfo (core->anal,
			R_ARCH_INFO_MAXOP_SIZE);
		size_t bufsize = maxopsize > -1? R_MAX (maxopsize, 32): 32;
		ut8 *buf = calloc (bufsize, sizeof (ut8));
		if (!buf) {
			R_LOG_ERROR ("Cannot allocate %d byte(s)", (int)bufsize);
			return;
		};
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
		*cols = r_asm_disassemble (core->rasm, op, buf, bufsize);
		free (buf);

		if (midflags || midbb) {
			int skip_bytes_flag = 0, skip_bytes_bb = 0;
			if (midflags >= R_MIDFLAGS_REALIGN) {
				skip_bytes_flag = r_core_flag_in_middle (core, core->addr, *cols, &midflags);
			}
			if (midbb) {
				skip_bytes_bb = r_core_bb_starts_in_middle (core, core->addr, *cols);
			}
			if (skip_bytes_flag) {
				*cols = skip_bytes_flag;
			}
			if (skip_bytes_bb && skip_bytes_bb < *cols) {
				*cols = skip_bytes_bb;
			}
		}
	}
	int nvars = varcount (core, f);
	if (f && f->addr == orig && nvars < 20) {
		// skip line by line here
		if (nvars <= core->skiplines) {
			*cols = op->size > 1 ? op->size : 1;
			core->skiplines = 0;
		} else {
			core->skiplines ++;
			*cols = 0;
		}
	} else if (*cols < 1) {
		*cols = op->size > 1 ? op->size : 1;
	}
}


static bool is_mintty(RCons *cons) {
#ifdef R2__WINDOWS__
	return cons->term_xterm;
#else
	return false;
#endif
}

static void flush_stdin(RCons *cons) {
#if R2__WINDOWS__
	while (r_cons_readchar_timeout (cons, 1) != -1) ;
#else
#ifndef __wasi__
	tcflush (STDIN_FILENO, TCIFLUSH);
#endif
#endif
}

R_API int r_core_visual(RCore *core, const char *input) {
	RStrBuf *highlight_sb = NULL;
	RCons *cons = core->cons;
	const char *teefile;
	int flags, ch;
	bool skip;
	char arg[2] = {
		input[0], 0
	};

	core->visual.splitPtr = UT64_MAX;

	if (r_cons_get_size (cons, &ch) < 1 || ch < 1) {
		R_LOG_ERROR ("Cannot create Visual context. Use scr.fix_{columns|rows}");
		return 0;
	}

	int ovtmode = r_config_get_i (core->config, "scr.vtmode");
	r_config_set_i (core->config, "scr.vtmode", 2);
	core->visual.obs = core->blocksize;
	//r_cons_set_cup (true);
	if (strchr (input, '?')) {
		// show V? help message, disables oneliner to open visual help
		r_config_set_i (core->config, "scr.vtmode", ovtmode);
		return 0;
	}
	core->vmode = false;
	/* honor vim */
	if (r_str_startswith (input, "im")) {
		char *cmd = r_str_newf ("!v%s", input);
		int ret = r_core_cmd0 (core, cmd);
		free (cmd);
		r_config_set_i (core->config, "scr.vtmode", ovtmode);
		return ret;
	}
	while (*input) {
		int len = *input == 'd'? 2: 1;
		if (!r_core_visual_cmd (core, input)) {
			r_config_set_i (core->config, "scr.vtmode", ovtmode);
			return 0;
		}
		input += len;
	}
	bool highlight_mode = false;
	core->vmode = true;
	// disable tee in cons
	teefile = cons->teefile;
	cons->teefile = "";

	core->print->flags |= R_PRINT_FLAGS_ADDRMOD;
	do {
dodo:
		r_core_visual_tab_update (core);
		// update the cursor when it's not visible anymore
		skip = fix_cursor (core);
		r_cons_show_cursor (cons, false);
		r_cons_set_raw (cons, true);
		const int ref = r_config_get_i (core->config, "dbg.slow");
#if 1
		// This is why multiple debug views dont work
		if (core->visual.printidx == R_CORE_VISUAL_MODE_DB) {
			const bool pxa = r_config_get_b (core->config, "stack.annotated");
			const char *reg = r_config_get (core->config, "stack.reg");
			const int size = r_config_get_i (core->config, "stack.size");
			const int delta = r_config_get_i (core->config, "stack.delta");
			const char *cmdvhex = r_config_get (core->config, "cmd.stack");
			char *dr1 = r_core_cmd_str (core, "dr 1~?");
			bool have_flags = false;
			if (dr1) {
				have_flags = (*dr1 != '0');
				free (dr1);
			}

			if (R_STR_ISNOTEMPTY (cmdvhex)) {
				snprintf (core->visual.debugstr, sizeof (core->visual.debugstr),
					"?t0;f tmp;sr %s;%s;?t1;%s;%s?t1;"
					"ss tmp;f-tmp;pd $r", reg, cmdvhex,
					ref? "drr": "dr=", have_flags?"drcq;": "");
				core->visual.debugstr[sizeof (core->visual.debugstr) - 1] = 0;
			} else {
				const bool cfg_debug = r_config_get_b (core->config, "cfg.debug");
				const char *pxw = stackPrintCommand (core);
				const char sign = (delta < 0)? '+': '-';
				const int absdelta = R_ABS (delta);
				snprintf (core->visual.debugstr, sizeof (core->visual.debugstr),
					"%s?t0;f tmp;sr %s;%s %d@$$%c%d;"
					"?t1;%s%s;"
					"?t1;ss tmp;f-tmp;afal;pd $r",
					cfg_debug? "diq;":"",
					reg, pxa? "pxa": pxw, size, sign, absdelta,
					have_flags? "drcq;": "",
					ref? "drr": "dr=");
			}
			printfmtSingle[2] = core->visual.debugstr;
		}
#endif
		r_cons_show_cursor (core->cons, false);
		r_cons_enable_mouse (core->cons, r_config_get_b (core->config, "scr.wheel"));
		core->cons->event_resize = NULL; // avoid running old event with new data
		core->cons->event_data = core;
		core->cons->event_resize = (RConsEvent) visual_refresh_oneshot;
		flags = core->print->flags;
		core->visual.color = r_config_get_i (core->config, "scr.color");
		if (core->visual.color) {
			flags |= R_PRINT_FLAGS_COLOR;
		}
		flags |= R_PRINT_FLAGS_ADDRMOD | R_PRINT_FLAGS_HEADER;
		r_print_set_flags (core->print, flags);
		if (r_config_get_b (core->config, "cfg.debug")) {
			r_core_cmd (core, ".dr*", 0);
		}
#if 0
		cmdprompt = r_config_get (core->config, "cmd.vprompt");
		if (cmdprompt && *cmdprompt) {
			r_core_cmd (core, cmdprompt, 0);
		}
#endif
		if (highlight_mode && highlight_sb) {
			char *s = r_strbuf_tostring (highlight_sb);
			r_config_set (core->config, "scr.highlight", s);
			free (s);
		}
		core->print->vflush = !skip;
		visual_refresh (core);
		if (highlight_mode && highlight_sb) {
			r_cons_gotoxy (core->cons, 0, 0);
			char *s = r_strbuf_tostring (highlight_sb);
			r_cons_printf (core->cons, "%s[Highlight] %s|", R_CONS_CLEAR_LINE, s);
			r_cons_flush (core->cons);
			free (s);
		}
		if (insert_mode_enabled (core)) {
			goto dodo;
		}
		if (!skip) {
			if (core->visual.snowMode) {
				ch = r_cons_readchar_timeout (core->cons, 300);
				if (ch == -1) {
					skip = 1;
					continue;
				}
			} else {
				ch = r_cons_readchar (core->cons);
			}
			if (highlight_mode) {
				switch (ch) {
				case 0:
				case '\r':
				case '\n':
					r_strbuf_free (highlight_sb);
					highlight_sb = NULL;
					highlight_mode = false;
					break;
				case 27: // escape
					r_config_set (core->config, "scr.highlight", "");
					r_strbuf_free (highlight_sb);
					highlight_sb = NULL;
					highlight_mode = false;
					goto dodo;
				case 127: // backspace
					if (r_strbuf_length (highlight_sb) > 0) {
						char *s = r_strbuf_drain (highlight_sb);
						s[strlen (s) - 1] = 0;
						highlight_sb = r_strbuf_new (s);
						free (s);
					} else {
						r_config_set (core->config, "scr.highlight", "");
						r_strbuf_free (highlight_sb);
						highlight_sb = NULL;
						highlight_mode = false;
					}
					break;
				default:
					if (IS_PRINTABLE (ch)) {
						r_strbuf_append_n (highlight_sb, (const char*)&ch, 1);
						char *s = r_strbuf_tostring (highlight_sb);
						r_config_set (core->config, "scr.highlight", s);
						free (s);
					}
					break;
				}
				// r_cons_visual_flush ();
				goto dodo;
			} else if (ch == '/') {
				highlight_mode = true;
				r_strbuf_free (highlight_sb);
				highlight_sb = r_strbuf_new (NULL);
				// r_cons_visual_flush ();
				goto dodo;
				continue;
			}
			if (I->vtmode == 2 && !is_mintty (core->cons)) {
				// Prevent runaway scrolling
				if (IS_PRINTABLE (ch) || ch == '\t' || ch == '\n') {
					flush_stdin (core->cons);
				} else if (ch == 0x1b) {
					char chrs[3];
					int chrs_read = 1;
					chrs[0] = r_cons_readchar (core->cons);
					if (chrs[0] == '[') {
						chrs[1] = r_cons_readchar (core->cons);
						chrs_read++;
						int ch56 = chrs[1] == '5' || chrs[1] == '6';
						if ((chrs[1] >= 'A' && chrs[1] <= 'D') || ch56) { // arrow keys
							if (!ch56 || (chrs[2] = r_cons_readchar (core->cons)) == '~') {
								chrs_read += ch56;
								flush_stdin (core->cons);
#ifndef R2__WINDOWS__
								// Following seems to fix an issue where scrolling slows
								// down to a crawl for some terminals after some time
								// mashing the up and down arrow keys
								r_cons_set_raw (core->cons, false);
								r_cons_set_raw (core->cons, true);
#endif
							}
						}
					}
					(void)r_cons_readpush (core->cons, chrs, chrs_read);
				}
			}
			if (r_cons_is_breaked (core->cons)) {
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

	r_cons_enable_mouse (core->cons, false);
	if (core->visual.color) {
		r_cons_print (core->cons, Color_RESET);
	}
	r_config_set_i (core->config, "scr.color", core->visual.color);
	core->print->cur_enabled = false;
	if (core->visual.autoblocksize) {
		r_core_block_size (core, core->visual.obs);
	}
	core->cons->teefile = teefile;
	r_cons_set_cup (false);
	r_cons_clear00 (core->cons);
	core->vmode = false;
	core->cons->event_resize = NULL;
	core->cons->event_data = NULL;
	r_cons_show_cursor (core->cons, true);
	r_config_set_i (core->config, "scr.vtmode", ovtmode);
	return 0;
}
