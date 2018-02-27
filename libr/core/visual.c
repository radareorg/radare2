/* radare - LGPL - Copyright 2009-2018 - pancake */

#include <r_core.h>

static int obs = 0;
static int blocksize = 0;
static int autoblocksize = 1;
static int disMode = 0;
static void visual_refresh(RCore *core);


static bool snowMode = false;
static RList *snows = NULL;
typedef struct {
	int x;
	int y;
} Snow;

#define KEY_ALTQ 0xc5

static const char *printfmtSingle[] = {
	"xc", "pd $r",
	"pxw 64@r:SP;dr=;pd $r",
	"pxw", "pxx", "pxA", "pss", "prc", "pxa"
};

static const char *printfmtColumns[] = {
	"pCx", "pCd $r-1",
	"pCD",
	"pCw", "pCc", "pCA", "pss", "prc", "pCa"
};

static const char **printfmt = printfmtSingle;

static bool splitView = false;
static ut64 splitPtr = UT64_MAX;

#undef USE_THREADS
#define USE_THREADS 1

#if USE_THREADS
static int visual_repeat_thread_anykey(RThread *th) {
	RCore *core = th->user;
	r_cons_any_key (NULL);
	eprintf ("^C  \n");
	core->cons->breaked = true;
	return 0;
}

static int visual_repeat_thread(RThread *th) {
	RCore *core = th->user;
	int i = 0;
	r_cons_break_push (NULL, NULL);
	for (;;) {
		if (r_cons_is_breaked ()) {
			break;
		}
		visual_refresh (core);
		r_cons_flush ();
		r_cons_gotoxy (0, 0);
		r_cons_printf ("[@%d] ", i++);
		r_cons_flush ();
		r_sys_sleep (1);
	}
	r_cons_break_pop ();
	core->cons->breaked = true;
	r_th_wait (th);
	return 0;
}

static void rotateAsmBits(RCore *core) {
	RAnalHint *hint = r_anal_hint_get (core->anal, core->offset);
	// const char *arch = r_config_get_i (core->config, "asm.arch");
	int bits = hint? hint->bits : r_config_get_i (core->config, "asm.bits");
	int retries = 4;
	while (retries > 0) {
		int nb = bits == 64 ? 8:
			bits == 32 ? 64:
			bits == 16 ? 32:
			bits == 8 ? 16: bits;
		if ((core->assembler->cur->bits & nb) == nb) {
			r_core_cmdf (core, "ahb %d", nb);
			break;
		}
		bits = nb;
		retries--;
	}
}

static void rotateAsmemu(RCore *core) {
	const bool isEmuStr = r_config_get_i (core->config, "asm.emu.str");
	const bool isEmu = r_config_get_i (core->config, "asm.emu");
	if (isEmu) {
		if (isEmuStr) {
			r_config_set (core->config, "asm.emu.str", "false");
		} else {
			r_config_set (core->config, "asm.emu", "false");
		}
	} else {
		r_config_set (core->config, "asm.emu.str", "true");
	}
}

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

static void visual_repeat(RCore *core) {
	int atport = r_config_get_i (core->config, "scr.atport");
	if (atport) {
#if __UNIX__ && !__APPLE__
// TODO: Add support for iterm2 and terminal for mac, see rarop source for more info
		int port = r_config_get_i (core->config, "http.port");
		if (!r_core_rtr_http (core, '&', NULL)) {
			const char *xterm = r_config_get (core->config, "cmd.xterm");
			// TODO: this must be configurable
			r_sys_cmdf ("%s 'r2 -C http://localhost:%d/cmd/V;sleep 1' &", xterm, port);
			//xterm -bg black -fg gray -e 'r2 -C http://localhost:%d/cmd/;sleep 1' &", port);
		} else {
			r_cons_any_key (NULL);
		}
#else
		eprintf ("Unsupported on this platform\n");
		r_cons_any_key (NULL);
#endif
	} else {
		RThread *th = r_th_new (visual_repeat_thread_anykey, core, 0);
		if (!th) {
			return;
		}

		visual_repeat_thread (th);
/*
		r_th_start (th, 1);
*/
		//	r_cons_break_push (NULL, NULL);
		r_th_wait (th);
		//	r_cons_break_pop ();
	}
}
#endif

static void showcursor(RCore *core, int x) {
	if (core && core->vmode) {
		r_cons_show_cursor (x);
		if (x) {
			// TODO: cache this
			int wheel = r_config_get_i (core->config, "scr.wheel");
			if (wheel) {
				r_cons_enable_mouse (true);
			} else {
				r_cons_enable_mouse (false);
			}
		} else {
			r_cons_enable_mouse (false);
		}
	} else {
		r_cons_enable_mouse (false);
	}
	r_cons_flush ();
}

static int color = 1;
static int debug = 1;
static int zoom = 0;

R_API int r_core_visual_hud(RCore *core) {
	const char *c = r_config_get (core->config, "hud.path");
	char *f = r_str_newf ("%s/share/radare2/" R2_VERSION "/hud/main",
		r_config_get (core->config, "dir.prefix"));
	int use_color = core->print->flags & R_PRINT_FLAGS_COLOR;
	char *homehud = r_str_home (R2_HOMEDIR "/hud");
	char *res = NULL;
	char *p = 0;
	r_cons_singleton ()->color = use_color;

	showcursor (core, true);
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
		p = strchr (res, '\t');
		r_cons_println (res);
		r_cons_flush ();
		if (p) {
			r_core_cmd0 (core, p + 1);
		}
		free (res);
	}
	showcursor (core, false);
	r_cons_flush ();
	free (homehud);
	free (f);
	return (int) (size_t) p;
}

static int visual_help() {
	r_cons_clear00 ();
	return r_cons_less_str (
		"Visual mode help:\n"
		" ?        show this help\n"
		" ??       show the user-friendly hud\n"
		" %        in cursor mode finds matching pair, otherwise toggle autoblocksz\n"
		" @        redraw screen every 1s (multi-user view), in cursor set position\n"
		" ^        seek to the begining of the function\n"
		" !        enter into the visual panels mode\n"
		" _        enter the flag/comment/functions/.. hud (same as VF_)\n"
		" =        set cmd.vprompt (top row)\n"
		" |        set cmd.cprompt (right column)\n"
		" .        seek to program counter\n"
		" \\        toggle visual split mode\n"
		" \"        toggle the column mode (uses pC..)\n"
		" /        in cursor mode search in current block\n"
		" (        toggle snow\n"
		" )        toggle asm.emu.str\n"
		" :cmd     run radare command\n"
		" ;[-]cmt  add/remove comment\n"
		" 0        seek to beginning of current function\n"
		" [1-9]    follow jmp/call identified by shortcut (like ;[1])\n"
		" ,file    add a link to the text file\n"
		" /*+-[]   change block size, [] = resize hex.cols\n"
		" </>      seek aligned to block size (seek cursor in cursor mode)\n"
		" a/A      (a)ssemble code, visual (A)ssembler\n"
		" b        browse symbols, flags, configurations, classes, ...\n"
		" B        toggle breakpoint\n"
		" c/C      toggle (c)ursor and (C)olors\n"
		" d[f?]    define function, data, code, ..\n"
		" D        enter visual diff mode (set diff.from/to)\n"
		" e        edit eval configuration variables\n"
		" f/F      set/unset or browse flags. f- to unset, F to browse, ..\n"
		" gG       go seek to begin and end of file (0-$s)\n"
		" hjkl     move around (or HJKL) (left-down-up-right)\n"
		" i        insert hex or string (in hexdump) use tab to toggle\n"
		" mK/'K    mark/go to Key (any key)\n"
		" M        walk the mounted filesystems\n"
		" n/N      seek next/prev function/flag/hit (scr.nkey)\n"
		" o        go/seek to given offset\n"
		" O        toggle asm.pseudo and asm.esil\n"
		" p/P      rotate print modes (hex, disasm, debug, words, buf)\n"
		" q        back to radare shell\n"
		" r        refresh screen / in cursor mode browse comments\n" // browse anal info and comments / in cursor mode = remove byte\n"
		" R        randomize color palette (ecr)\n"
		" sS       step / step over\n"
		" t        browse types\n"
		" T        enter textlog chat console (TT)\n"
		" uU       undo/redo seek\n"
		" v        visual function/vars code analysis menu\n"
		" V        (V)iew graph using cmd.graph (agv?)\n"
		" wW       seek cursor to next/prev word\n"
		" xX       show xrefs/refs of current function from/to data/code\n"
		" yY       copy and paste selection\n"
		" z        fold/unfold comments in disassembly\n"
		" Z        toggle zoom mode\n"
		" Enter    follow address of jump/call\n"
		"Function Keys: (See 'e key.'), defaults to:\n"
		"  F2      toggle breakpoint\n"
		"  F4      run to cursor\n"
		"  F7      single step\n"
		"  F8      step over\n"
		"  F9      continue\n",
		"?");
}

static void prompt_read(const char *p, char *buf, int buflen) {
	if (!buf || buflen < 1) {
		return;
	}
	*buf = 0;
	r_line_set_prompt (p);
	showcursor (NULL, true);
	r_cons_fgets (buf, buflen, 0, NULL);
	showcursor (NULL, false);
}

R_API void r_core_visual_prompt_input(RCore *core) {
	int ret;
	ut64 addr = core->offset;
	ut64 bsze = core->blocksize;
	int h;
	(void) r_cons_get_size (&h);
	r_cons_enable_mouse (false);
	r_cons_gotoxy (0, h - 2);
	r_cons_reset_colors ();
	r_cons_printf ("\nPress <enter> to return to Visual mode.\n");
	r_cons_show_cursor (true);
	core->vmode = false;
	ut64 newaddr = addr;
	if (core->print->cur_enabled) {
		if (core->print->ocur != -1) {
			int newsz = core->print->cur - core->print->ocur;
			newaddr = core->offset + core->print->ocur;
			r_core_block_size (core, newsz);
		} else {
			newaddr = core->offset + core->print->cur;
		}
		r_core_seek (core, newaddr, 1);
	}
	do {
		ret = r_core_visual_prompt (core);
		if (core->offset != newaddr) {
			// do not restore seek anymore
			newaddr = addr;
		}
	} while (ret);
	if (core->print->cur_enabled) {
		if (addr != newaddr) {
			r_core_seek (core, addr, 1);
			r_core_block_size (core, bsze);
		}
	}
	r_cons_show_cursor (false);
	core->vmode = true;
	r_cons_enable_mouse (true);
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
	showcursor (core, true);
	r_cons_fgets (buf, sizeof (buf), 0, NULL);
	if (!strcmp (buf, "q")) {
		ret = false;
	} else if (*buf) {
		r_line_hist_add (buf);
		r_core_cmd (core, buf, 0);
		r_cons_flush ();
		ret = true;
	} else {
		ret = false;
		//r_cons_any_key (NULL);
		r_cons_clear00 ();
		showcursor (core, false);
	}
	return ret;
}

static void visual_single_step_in(RCore *core) {
	if (r_config_get_i (core->config, "cfg.debug")) {
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

static void visual_single_step_over(RCore *core) {
	if (r_config_get_i (core->config, "cfg.debug")) {
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
}

static void visual_breakpoint(RCore *core) {
	r_core_cmd (core, "dbs $$", 0);
}

static void visual_continue(RCore *core) {
	r_core_cmd (core, "dc", 0);
}

static int visual_nkey(RCore *core, int ch) {
	const char *cmd;
	ut64 oseek = UT64_MAX;
	if (core->print->ocur == -1) {
		oseek = core->offset;
		r_core_seek (core, core->offset + core->print->cur, 0);
	}

	switch (ch) {
	case R_CONS_KEY_F1:
		cmd = r_config_get (core->config, "key.f1");
		if (cmd && *cmd) {
			ch = r_core_cmd0 (core, cmd);
		} else {
			visual_help ();
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
			visual_single_step_over (core);
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
		r_core_seek (core, oseek, 0);
	}
	return ch;
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
		showcursor (core, true);
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
				showcursor (core, true);
			} else {
				r_core_seek (core, core->offset + i + 1, 1);
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
				showcursor (core, true);
			} else {
				// r_core_seek (core, core->offset + i + 1, 1);
			}
			break;
		}
	}
}

// TODO: integrate in '/' command with search.inblock ?
static void visual_search(RCore *core) {
	const ut8 *p;
	int len, d = core->print->cur;
	char str[128], buf[258];

	r_line_set_prompt ("search byte/string in block: ");
	r_cons_fgets (str, sizeof (str), 0, NULL);
	len = r_hex_str2bin (str, (ut8 *) buf);
	if (*str == '"') {
		char *e = strncpy (buf + 1, str + 1, sizeof (buf) - 1);
		if (e) {
			e--;
			if (*e == '"') {
				*e = 0;
			}
		}
		len = strlen (buf);
	} else if (len < 1) {
		strncpy (buf, str, sizeof (buf) - 1);
		len = strlen (str);
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
		showcursor (core, true);
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
	r_core_seek (core, addr, 1);
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
	case 0:
		core->inc = 16;
		break;
	case 1:
	case 2:
		core->inc = r_asm_disassemble (core->assembler,
			&op, core->block, 32);
		break;
	case 5: // "pxA"
		core->inc = 256;
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
			return res;
		}
	}
	// if we anal info didn't help then fallback to the dumb solution.
	target = addr;
	base = target - OPDELTA;
	r_core_read_at (core, base, buf, sizeof (buf));
	for (i = 0; i < sizeof (buf); i++) {
		ret = r_anal_op (core->anal, &op, base + i,
			buf + i, sizeof (buf) - i);
		if (!ret) {
			continue;
		}
		len = op.size;
		r_anal_op_fini (&op); // XXX
		if (len < 1) {
			continue;
		}
		if (target == base + i + len) {
			return base + i;
		}
		i += len - 1;
	}
	return target - 4;
}

//  Returns true if we can use analysis to find the previous operation address,
//  sets prev_addr to the value of the instruction numinstrs back.
//  If we can't use the anal, then set prev_addr to UT64_MAX and return false;
R_API bool r_core_prevop_addr(RCore *core, ut64 start_addr, int numinstrs, ut64 *prev_addr) {
	RAnalBlock *bb;
	int i;
	// Check that we're in a bb, otherwise this prevop stuff won't work.
	bb = r_anal_bb_from_offset (core->anal, start_addr);
	if (bb) {
		if (r_anal_bb_opaddr_at (bb, start_addr) != UT64_MAX) {
			// Do some anal looping.
			for (i = 0; i < numinstrs; ++i) {
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
	for (i = 0; i < numinstrs; ++i) {
		start_addr = prevop_addr (core, start_addr);
	}
	return start_addr;
}

static void reset_print_cur(RPrint *p) {
	p->cur = 0;
	p->ocur = -1;
}

static void visual_offset(RCore *core) {
	char buf[256];
	r_line_set_prompt ("[offset]> ");
	strcpy (buf, "s ");
	if (r_cons_fgets (buf + 2, sizeof (buf) - 3, 0, NULL) > 0) {
		if (buf[2] == '.') {
			buf[1] = '.';
		}
		r_core_cmd0 (core, buf);
		reset_print_cur (core->print);
	}
}

static int prevopsz(RCore *core, ut64 addr) {
	ut64 prev_addr = prevop_addr (core, addr);
	return addr - prev_addr;
}

R_API int r_core_visual_refs(RCore *core, bool xref) {
	int ret = 0;
#if FCN_OLD
	char ch;
	int count = 0;
	RList *xrefs = NULL;
	RAnalRef *refi;
	RListIter *iter;
	RAnalFunction *fun;
	int skip = 0;
	int idx = 0;
	char cstr[32];
	ut64 addr = core->offset;
		int printMode = 0;
		int lastPrintMode = 3;
	if (core->print->cur_enabled) {
		addr += core->print->cur;
	}

repeat:
	if (xref) {
		xrefs = r_anal_xrefs_get (core->anal, addr);
	} else {
		xrefs = r_anal_refs_get (core->anal, addr);
	}

	if (xrefs) {
		bool asm_bytes = r_config_get_i (core->config, "asm.bytes");
		r_config_set_i (core->config, "asm.bytes", false);
		r_cons_clear00 ();
		r_cons_gotoxy (1, 1);
		r_cons_printf ("[GOTO %cREF]> 0x%08"PFMT64x "  ", xref ? 'X':' ', addr);
		r_core_cmd0 (core, "fd");
		if (r_list_empty (xrefs)) {
			r_cons_printf ("No %cREF found at 0x%"PFMT64x "\n", xref ? 'X':' ', addr);
			r_cons_any_key (NULL);
			r_cons_clear00 ();
		} else {
			int maxcount = 9;
			int rows, cols = r_cons_get_size (&rows);
			idx = 0;
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
					fun = r_anal_get_fcn_in (core->anal, refi->addr, R_ANAL_FCN_TYPE_NULL);
					char *name;
					if (fun) {
						name = strdup (fun->name);
					} else {
						RFlagItem *f = r_flag_get_at (core->flags, refi->addr, true);
						if (f) {
							name = r_str_newf ("%s + %d", f->name, refi->addr - f->offset);
						} else {
							name = strdup ("unk");
						}
					}
					r_cons_printf (" %d [%s] 0x%08"PFMT64x " %s %cREF (%s)\n",
						idx, cstr, refi->addr,
						refi->type == R_ANAL_REF_TYPE_CODE? "CODE (JMP)" :
						refi->type == R_ANAL_REF_TYPE_CALL? "CODE (CALL)": "DATA",
						xref ? 'X':' ',
						name);
					free (name);
					if (idx == skip) {
						free (dis);
						curat = refi->addr;
						// TODO: show disasm with context. not seek addr
						// dis = r_core_cmd_strf (core, "pd $r-4 @ 0x%08"PFMT64x, refi->addr);
						switch (printMode) {
						case 0:
							dis = r_core_cmd_strf (core, "pd $r-4 @ 0x%08"PFMT64x, refi->addr);
							break;
						case 1:
							dis = r_core_cmd_strf (core, "pd @ 0x%08"PFMT64x"-32", refi->addr);
							break;
						case 2:
							dis = r_core_cmd_strf (core, "px @ 0x%08"PFMT64x, refi->addr);
							break;
						case 3:
							dis = r_core_cmd_strf (core, "pds @ 0x%08"PFMT64x, refi->addr);
							break;
						}
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
				if (ats) {
					(void) r_config_set (core->config, "scr.highlight", ats);
				}
				/* print disasm */
				char *d = r_str_ansi_crop (dis, 0, 0, cols, rows - 9);
				r_cons_printf ("%s", d);
				free (d);
				/* flush and restore highlight */
				r_cons_flush ();
				r_config_set (core->config, "scr.highlight", cmd);
				free (ats);
				free (cmd);
				free (dis);
				dis = NULL;
			}
		}
		r_config_set_i (core->config, "asm.bytes", asm_bytes);
	} else {
		xrefs = NULL;
	}
	if (!xrefs || !r_list_length (xrefs)) {
		r_list_free (xrefs);
		return 0;
	}
	r_cons_flush ();
	ch = r_cons_readchar ();
	if (ch == ':') {
		r_core_visual_prompt_input (core);
	} else if (ch == '?') {
		r_cons_clear00 ();
		r_cons_printf ("Usage: Visual Xrefs\n"
		" jk  - select next or previous item (use arrows)\n"
		" pP  - rotate between various print modes\n"
		" :   - run r2 command\n"
		" ?   - show this help message\n"
		" \\n  - seek to this xref");
		r_cons_flush ();
		r_cons_any_key (NULL);
		goto repeat;
	} else if (ch == 'p') {
		printMode++;
		if (printMode > lastPrintMode) {
			printMode = 0;
		}
		goto repeat;
	} else if (ch == 'P') {
		printMode--;
		if (printMode<0) {
			printMode = lastPrintMode;
		}
		goto repeat;
	} else if (r_cons_arrow_to_hjkl (ch) == 'j') {
		skip++;
		goto repeat;
	} else if (r_cons_arrow_to_hjkl (ch) == 'k') {
		skip--;
		if (skip < 0) {
			skip = 0;
		}
		goto repeat;
	} else if (ch == ' ' || ch == '\n' || ch == '\r') {
		refi = r_list_get_n (xrefs, skip);
		if (refi) {
			r_core_cmdf (core, "s 0x%"PFMT64x, refi->addr);
			ret = 1;
		}
	} else if (IS_DIGIT (ch)) {
		refi = r_list_get_n (xrefs, ch - 0x30);
		if (refi) {
			r_core_cmdf (core, "s 0x%"PFMT64x, refi->addr);
			ret = 1;
		}
	}
	r_list_free (xrefs);
#else
	eprintf ("TODO: sdbize xrefs here\n");
#endif
	return ret;
}

#if __WINDOWS__ && !__CYGWIN__
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
	ut64 addr = core->offset + (core->print->cur_enabled? core->print->cur: 0);
	char *comment, *cwd, *cmtfile;
	comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
	cmtfile = r_str_between (comment, ",(", ")");
	cwd = getcommapath (core);
	if (!cmtfile) {
		char *fn;
		showcursor (core, true);
		fn = r_cons_input ("<comment-file> ");
		showcursor (core, false);
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
		char *data = r_core_editor (core, NULL, odata);
		r_file_dump (cwf, (const ut8 *) data, -1, 0);
		free (data);
		free (odata);
		free (cwf);
	} else {
		eprintf ("No commafile found.\n");
	}
	free (comment);
}

static bool isDisasmPrint(int mode) {
	return (mode == 1 || mode == 2);
}

static void cursor_ocur(RCore *core, bool use_ocur) {
	RPrint *p = core->print;
	if (use_ocur && p->ocur == -1) {
		p->ocur = p->cur;
	} else if (!use_ocur) {
		p->ocur = -1;
	}
}

static void cursor_nextrow(RCore *core, bool use_ocur) {
	RPrint *p = core->print;
	ut32 roff, next_roff;
	int row, sz, delta;
	RAsmOp op;

	cursor_ocur (core, use_ocur);
	if (PIDX == 7 || !strcmp ("prc", r_config_get (core->config, "cmd.visual"))) {
		//int cols = r_config_get_i (core->config, "hex.cols") * 3.5;
		int cols = r_config_get_i (core->config, "hex.cols") + r_config_get_i (core->config, "hex.pcols");
		cols /= 2;
		p->cur += cols > 0? cols: 0;
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
	if (PIDX == 2 && core->seltab == 1) {
		const int cols = core->dbg->regcols;
		p->cur += cols > 0? cols: 3;
		return;
	}
	if (core->seltab == 0 && core->printidx == R_CORE_VISUAL_MODE_PDDBG) {
		int w = r_config_get_i (core->config, "hex.cols");
		if (w < 1) {
			w = 16;
		}
		r_config_set_i (core->config, "stack.delta",
			r_config_get_i (core->config, "stack.delta") - w);
		return;
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
		if (next_roff == -1) {
			p->cur++;
			return;
		}
		if (next_roff + 32 < core->blocksize) {
			sz = r_asm_disassemble (core->assembler, &op,
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

	if (PIDX == 7 || !strcmp ("prc", r_config_get (core->config, "cmd.visual"))) {
		int cols = r_config_get_i (core->config, "hex.cols") + r_config_get_i (core->config, "hex.pcols");
		cols /= 2;
		p->cur -= R_MAX (cols, 0);
		return;
	}
	if (PIDX == 2 && core->seltab == 1) {
		const int cols = core->dbg->regcols;
		p->cur -= cols > 0? cols: 4;
		return;
	}
	cursor_ocur (core, use_ocur);

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
	if (core->seltab == 0 && core->printidx == R_CORE_VISUAL_MODE_PDDBG) {
		int w = r_config_get_i (core->config, "hex.cols");
		if (w < 1) {
			w = 16;
		}
		r_config_set_i (core->config, "stack.delta",
			r_config_get_i (core->config, "stack.delta") + w);
		return;
	}

	if (p->row_offsets != NULL) {
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
				r_core_seek (core, prev_addr, 1);
				prev_sz = r_asm_disassemble (core->assembler, &op,
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
			int sz = r_asm_disassemble (core->assembler,
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
		r_core_seek (core, core->offset + p->cols, 1);
		p->cur -= p->cols;
		if (p->ocur != -1) {
			p->ocur -= p->cols;
		}
	}

	if (p->cur < 0) {
		int sz = p->cols;

		if (isDisasmPrint (core->printidx)) {
			sz = prevopsz (core, core->offset + p->cur);
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
	case 127:
		core->print->cur = R_MAX (0, core->print->cur - 1);
		return true;
	case 9: // tab "tab"
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
		if (IS_PRINTABLE (ch)) {
			r_core_cmdf (core, "\"w %c\" @ $$+%d", ch, core->print->cur);
			core->print->cur++;
		}
		return true;
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

static void visual_browse(RCore *core) {
	const char *browsemsg = \
		"Browse stuff:\n"
		"-------------\n"
		" _  hud mode (V_)\n"
		" b  blocks\n"
		" c  classes\n"
		" C  comments\n"
		" e  eval var configurations\n"
		" f  flags\n"
		" F  functions\n"
		" h  history\n"
		" i  imports\n"
		" m  maps\n"
		" p  pids/threads\n"
		" q  quit\n"
		" s  symbols\n"
		" t  types\n"
		" T  themes\n"
		" v  vars\n"
		" x  xrefs\n"
		" X  refs\n"
	;
	for (;;) {
		r_cons_clear00 ();
		r_cons_printf ("%s\n", browsemsg);
		r_cons_flush ();
		char ch = r_cons_arrow_to_hjkl (r_cons_readchar ());
		switch (ch) {
		case 'f':
			r_core_visual_trackflags (core);
			break;
		case 'F':
			r_core_cmd0 (core, "s $(afl~...)");
			break;
		case 'c':
			r_core_visual_classes (core);
			break;
		case 'C':
			r_core_cmd0 (core, "s $(CC~...)");
			break;
		case 't':
			r_core_visual_types (core);
			break;
		case 'T':
			r_core_cmd0 (core, "eco $(eco~...)");
			break;
		case 'e':
			r_core_visual_config (core);
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
			r_core_visual_refs (core, true);
			break;
		case 'X':
			r_core_visual_refs (core, false);
			break;
		case 'h': // seek history
			r_core_cmdf (core, "s!~...");
			break;
		case 'v':
			r_core_visual_anal (core);
			break;
		case '_':
			r_core_visual_hudstuff (core);
			break;
		case 'q':
			return;
		}
	}
}

static void applyDisMode(RCore *core) {
	switch (disMode) {
	case 0:
		r_config_set (core->config, "asm.pseudo", "false");
		r_config_set (core->config, "asm.esil", "false");
		break;
	case 1:
		r_config_set (core->config, "asm.pseudo", "true");
		r_config_set (core->config, "asm.esil", "false");
		break;
	case 2:
		r_config_set (core->config, "asm.pseudo", "false");
		r_config_set (core->config, "asm.esil", "true");
		break;
	}
}

R_API int r_core_visual_cmd(RCore *core, const char *arg) {
	ut8 ch = arg[0];
	RAsmOp op;
	ut64 offset = core->offset;
	char buf[4096];
	const char *key_s;
	int i, ret, cols = core->print->cols, delta = 0;
	int wheelspeed;
	if ((ut8)ch == KEY_ALTQ) {
		r_cons_readchar ();
		ch = 'q';
	}
	ch = r_cons_arrow_to_hjkl (ch);
	ch = visual_nkey (core, ch);
	if (ch < 2) {
		return 1;
	}
	if (r_cons_singleton ()->mouse_event) {
		wheelspeed = r_config_get_i (core->config, "scr.wheel.speed");
	} else {
		wheelspeed = 1;
	}

	// do we need hotkeys for data references? not only calls?
	// '0' is handled to seek at the beginning of the function
	if (ch > '0' && ch <= '9') {
		char chbuf[2];
		ut64 off;

		chbuf[0] = ch;
		chbuf[1] = '\0';
		off = r_core_get_asmqjmps (core, chbuf);
		if (off != UT64_MAX) {
			int delta = R_ABS ((st64) off - (st64) offset);
			r_io_sundo_push (core->io, offset, r_print_get_cursor (core->print));
			if (core->print->cur_enabled && delta < 100) {
				core->print->cur = delta;
			} else {
				r_core_visual_seek_animation (core, off);
				core->print->cur = 0;
			}
			r_core_block_read (core);
		}
	} else {
		switch (ch) {
#if __WINDOWS__ && !__CYGWIN__
		case 0xf5:
			SetWindow (81,25);
			break;
		case 0xcf5:
			SetWindow (81,40);
			break;
#endif
		case 0x0d: // "enter" "\\n" "newline"
		{
			RAnalOp *op;
			int wheel = r_config_get_i (core->config, "scr.wheel");
			if (wheel) {
				r_cons_enable_mouse (true);
			}
			do {
				op = r_core_anal_op (core, core->offset + core->print->cur);
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
		case 9: // tab
			if (splitView) {
				core->print->cur = 0;
				core->curtab = 0;
				core->seltab++;
				if (core->seltab > 1) {
					core->seltab = 0;
				}
			} else {
				core->curtab = 0;
				if (core->printidx == R_CORE_VISUAL_MODE_PDDBG) {
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
					} else {
						ut64 delta = offset - f;
						r_core_seek (core, t + delta, 1);
						r_config_set_i (core->config, "diff.from", t);
						r_config_set_i (core->config, "diff.to", f);
					}
				}
			}
			break;
		case '&':
			rotateAsmBits (core);
			break;
		case 'a':
		{
			if (core->file && core->io && !(r_io_desc_get (core->io, core->file->fd)->flags & 2)) {
				r_cons_printf ("\nFile has been opened in read-only mode. Use -w flag\n");
				r_cons_any_key (NULL);
				return true;
			}
			r_cons_printf ("Enter assembler opcodes separated with ';':\n");
			showcursor (core, true);
			r_cons_flush ();
			r_cons_set_raw (false);
			strcpy (buf, "wa ");
			r_line_set_prompt (":> ");
			r_cons_enable_mouse (false);
			if (r_cons_fgets (buf + 3, 1000, 0, NULL) < 0) {
				buf[0] = '\0';
			}
			int wheel = r_config_get_i (core->config, "scr.wheel");
			if (wheel) {
				r_cons_enable_mouse (true);
			}
			if (*buf) {
				if (core->print->cur_enabled) {
					int t = core->offset + core->print->cur;
					r_core_seek (core, t, 0);
				}
				r_core_cmd (core, buf, true);
				if (core->print->cur_enabled) {
					int t = core->offset - core->print->cur;
					r_core_seek (core, t, 1);
				}
			}
			showcursor (core, false);
			r_cons_set_raw (true);
		}
		break;
		case '=':
		{ // TODO: edit
			const char *buf = NULL;
			#define I core->cons
			const char *cmd = r_config_get (core->config, "cmd.vprompt");
			r_line_set_prompt ("cmd.vprompt> ");
			I->line->contents = strdup (cmd);
			buf = r_line_readline ();
//		if (r_cons_fgets (buf, sizeof (buf)-4, 0, NULL) <0) buf[0]='\0';
			I->line->contents = NULL;
			(void)r_config_set (core->config, "cmd.vprompt", buf);
		}
		break;
		case '|':
		{ // TODO: edit
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
				//		if (r_cons_fgets (buf, sizeof (buf)-4, 0, NULL) <0) buf[0]='\0';
				R_FREE (I->line->contents);
				(void)r_config_set (core->config, "cmd.cprompt", buf? buf: "");
			}
		}
		break;
		case '!':
			r_core_visual_panels (core);
			break;
		case 'o':
		{
			r_cons_enable_mouse (false);
			visual_offset (core);
			int wheel = r_config_get_i (core->config, "scr.wheel");
			if (wheel) {
				r_cons_enable_mouse (true);
			}
		}
		break;
		case 'A':
		{
			int oc = core->print->cur_enabled;
			ut64 off = oc? core->offset + core->print->cur: core->offset;
			core->print->cur_enabled = 0;
			r_cons_enable_mouse (false);
			r_core_visual_asm (core, off);
			core->print->cur_enabled = oc;
			int wheel = r_config_get_i (core->config, "scr.wheel");
			if (wheel) {
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
		case '@':
			if (core->print->cur_enabled) {
				char buf[128];
				prompt_read ("cursor at:", buf, sizeof (buf));
				core->print->cur = (st64) r_num_math (core->num, buf);
			} else {
				visual_repeat (core);
			}
			break;
		case 'C':
			color = color? 0: 1;
			r_config_set_i (core->config, "scr.color", color);
			break;
		case 'd':
			if (r_config_get_i (core->config, "asm.esil")) {
				r_core_visual_esil (core);
			} else {
				int wheel = r_config_get_i (core->config, "scr.wheel");
				if (wheel) {
					r_cons_enable_mouse (false);
				}
				r_core_visual_define (core, arg + 1);
				if (wheel) {
					r_cons_enable_mouse (true);
				}
			}
			break;
		case 'D':
			setdiff (core);
			break;
		case 'f':
		{
			int range, min, max;
			char name[256], *n;
			r_line_set_prompt ("flag name: ");
			showcursor (core, true);
			if (r_cons_fgets (name, sizeof (name), 0, NULL) >= 0 && *name) {
				n = r_str_trim (name);
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
		}
			showcursor (core, false);
			break;
		case ',':
			visual_comma (core);
			break;
		case 'T':
			if (r_sandbox_enable (0)) {
				eprintf ("sandbox not enabled\n");
			} else {
				if (r_config_get_i (core->config, "scr.interactive")) {
					r_core_cmd0 (core, "TT");
				}
			}
			break;
		case 'n':
			r_core_seek_next (core, r_config_get (core->config, "scr.nkey"));
			break;
		case 'N':
			r_core_seek_previous (core, r_config_get (core->config, "scr.nkey"));
			break;
		case 'i':
		case 'I':
			if (PIDX == 0) {
				if (core->print->ocur == -1) {
					__ime = true;
					core->print->cur_enabled = true;
					return true;
				}
			}
			if (PIDX == 2 && core->seltab == 1) {
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
			if (core->file && core->io && !(r_io_desc_get (core->io, core->file->fd)->flags & 2)) {
				r_cons_printf ("\nFile has been opened in read-only mode. Use -w flag\n");
				r_cons_any_key (NULL);
				return true;
			}
			showcursor (core, true);
			r_cons_flush ();
			r_cons_set_raw (0);
			if (ch == 'I') {
				strcpy (buf, "wow ");
				r_line_set_prompt ("insert hexpair block: ");
				if (r_cons_fgets (buf + 4, sizeof (buf) - 5, 0, NULL) < 0) {
					buf[0] = '\0';
				}
				char *p = strdup (buf);
				int cur = core->print->cur;
				if (cur >= core->blocksize) {
					cur = core->print->cur - 1;
				}
				snprintf (buf, sizeof (buf), "%s @ $$0!%i", p,
					core->blocksize - core->print->cur);
				r_core_cmd (core, buf, 0);
				free (p);
				break;
			}
			delta = (core->print->ocur != -1)? R_MIN (core->print->cur, core->print->ocur): core->print->cur;
			if (core->print->col == 2) {
				strcpy (buf, "\"w ");
				r_line_set_prompt ("insert string: ");
				if (r_cons_fgets (buf + 3, sizeof (buf) - 4, 0, NULL) < 0) {
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
				r_core_seek (core, core->offset + delta, 0);
			}
			r_core_cmd (core, buf, 1);
			if (core->print->cur_enabled) {
				r_core_seek (core, offset, 1);
			}
			r_cons_set_raw (1);
			showcursor (core, false);
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
					  r_core_seek (core, fcn->addr, 0);
				  }
			  }
			  break;
		case 'E':
			r_core_visual_colors (core);
			break;
		case 'M':
			if (!r_list_empty (core->fs->roots)) {
				r_core_visual_mounts (core);
			}
			break;
		case 'x':
			r_core_visual_refs (core, true);
			break;
		case 'X':
			r_core_visual_refs (core, false);
			break;
		case 'r':
			if (core->print->ocur != -1) {
				r_core_visual_comments (core);
			} else {
				visual_refresh (core);
			}
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
			r_core_visual_anal (core);
			break;
		case 'g':
			if (core->io->va) {
				ut64 offset = r_io_section_get_paddr_at (core->io, 0LL);
				if (offset == -1) {
					offset = 0;
				}
				r_core_seek (core, offset, 1);
			} else {
				r_core_seek (core, 0, 1);
			}
			r_io_sundo_push (core->io, core->offset, r_print_get_cursor (core->print));
			break;
		case 'G':
			ret = 0;
			int scols = r_config_get_i (core->config, "hex.cols");
			if (core->file) {
				if (core->io->va) {
					RIOSection *sec = r_io_section_get (core->io, 0LL);
					ut64 offset;
					if (!sec) {
						offset = r_io_fd_size (core->io, core->file->fd)
						- core->blocksize + 2 * scols;
						ret = r_core_seek (core, offset, 1);
					} else {
						offset = r_io_fd_size (core->io, core->file->fd)
						- core->blocksize + 2 * scols;
						ret = r_core_seek (core, offset, 1);
					}
				} else {
					ret = r_core_seek (core,
						r_io_fd_size (core->io, core->file->fd)
						- core->blocksize + 2 * scols, 1);
				}
			} else {
				ret = -1;
			}
			if (ret != -1) {
				r_io_sundo_push (core->io, core->offset, r_print_get_cursor (core->print));
			}
			break;
		case 'h':
			if (core->print->cur_enabled) {
				cursor_left (core, false);
			} else {
				r_core_seek_delta (core, -1);
			}
			break;
		case 'H':
			if (core->print->cur_enabled) {
				cursor_left (core, true);
			} else {
				r_core_seek_delta (core, -2);
			}
			break;
		case 'l':
			if (core->print->cur_enabled) {
				cursor_right (core, false);
			} else {
				r_core_seek_delta (core, 1);
			}
			break;
		case 'L':
			if (core->print->cur_enabled) {
				cursor_right (core, true);
			} else {
				r_core_seek_delta (core, 2);
			}
			break;
		case 'j':
			if (core->print->cur_enabled) {
				cursor_nextrow (core, false);
			} else {
				if (r_config_get_i (core->config, "scr.wheel.nkey")) {
					r_core_cmd0 (core, "sn");
				} else {
					int times = R_MAX (1, wheelspeed);
					// Check if we have a data annotation.
					RAnalMetaItem *ami = r_meta_find (core->anal,
							core->offset, R_META_TYPE_DATA,
							R_META_WHERE_HERE);
					if (!ami) {
						ami = r_meta_find (core->anal,
								core->offset, R_META_TYPE_STRING,
								R_META_WHERE_HERE);
					}
					if (ami) {
						r_core_seek_delta (core, ami->size);
					} else {
						while (times--) {
							if (isDisasmPrint (core->printidx)) {
								RAnalFunction *f = NULL;
								if (true) {
									f = r_anal_get_fcn_in (core->anal, core->offset, 0);
								}
								op.size = 1;
								if (f && f->folded) {
									cols = core->offset - f->addr + r_anal_fcn_size (f);
								} else {
									r_asm_set_pc (core->assembler, core->offset);
									cols = r_asm_disassemble (core->assembler,
											&op, core->block, 32);
								}
								if (cols < 1) {
									cols = op.size;
								}
								if (cols < 1) {
									cols = 1;
								}
							}
							r_core_seek (core, core->offset + cols, 1);
						}
					}
				}
			}
			break;
		case 'J':
			if (core->print->cur_enabled) {
				cursor_nextrow (core, true);
			} else {
				if (core->print->screen_bounds > 1 && core->print->screen_bounds >= core->offset) {
					ut64 addr = core->print->screen_bounds;
					if (core->print->screen_bounds == core->offset) {
						addr += r_asm_disassemble (core->assembler, &op, core->block, 32);
					}
					r_core_seek (core, addr, 1);
				} else {
					r_core_seek (core, core->offset + obs, 1);
				}
			}
			break;
		case 'k':
			if (core->print->cur_enabled) {
				cursor_prevrow (core, false);
			} else {
				if (r_config_get_i (core->config, "scr.wheel.nkey")) {
					r_core_cmd0 (core, "sp");
				} else {
					int times = wheelspeed;
					if (times < 1) {
						times = 1;
					}
					while (times--) {
						if (isDisasmPrint (core->printidx)) {
							RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
							if (f && f->folded) {
								cols = core->offset - f->addr; // + f->size;
								if (cols < 1) {
									cols = 4;
								}
							} else {
								cols = prevopsz (core, core->offset);
							}
						}
						r_core_seek_delta (core, -cols);
					}
				}
			}
			break;
		case 'K':
			if (core->print->cur_enabled) {
				cursor_prevrow (core, true);
			} else {
				if (core->print->screen_bounds > 1 && core->print->screen_bounds > core->offset) {
					int delta = (core->print->screen_bounds - core->offset);
					if (core->offset >= delta) {
						r_core_seek (core, core->offset - delta, 1);
					} else {
						r_core_seek (core, 0, 1);
					}
				} else {
					ut64 at = (core->offset > obs)? core->offset - obs: 0;
					if (core->offset > obs) {
						r_core_seek (core, at, 1);
					} else {
						r_core_seek (core, 0, 1);
					}
				}
			}
			break;
		case '[':
			// comments column
			if (core->print->cur_enabled &&
				(core->printidx == R_CORE_VISUAL_MODE_PD ||
				(core->printidx == R_CORE_VISUAL_MODE_PDDBG && core->seltab == 2))) {
				int cmtcol = r_config_get_i (core->config, "asm.cmt.col");
				if (cmtcol > 2) {
					r_config_set_i (core->config, "asm.cmt.col", cmtcol - 2);
				}
			}
			// hex column
			if ((core->printidx != R_CORE_VISUAL_MODE_PD && core->printidx != R_CORE_VISUAL_MODE_PDDBG) ||
				(core->printidx == R_CORE_VISUAL_MODE_PDDBG && core->seltab != 2)) {
				int scrcols = r_config_get_i (core->config, "hex.cols");
				if (scrcols > 2) {
					r_config_set_i (core->config, "hex.cols", scrcols - 2);
				}
			}
			break;
		case ']':
			// comments column
			if (core->print->cur_enabled &&
				(core->printidx == R_CORE_VISUAL_MODE_PD ||
				(core->printidx == R_CORE_VISUAL_MODE_PDDBG && core->seltab == 2))) {
				int cmtcol = r_config_get_i (core->config, "asm.cmt.col");
				r_config_set_i (core->config, "asm.cmt.col", cmtcol + 2);
			}
			// hex column
			if ((core->printidx != R_CORE_VISUAL_MODE_PD && core->printidx != R_CORE_VISUAL_MODE_PDDBG) ||
				(core->printidx == R_CORE_VISUAL_MODE_PDDBG && core->seltab != 2)) {
				int scrcols = r_config_get_i (core->config, "hex.cols");
				r_config_set_i (core->config, "hex.cols", scrcols + 2);
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
				visual_single_step_over (core);
			}
			break;
		case '"':
			if (printfmt == printfmtSingle) {
				printfmt = printfmtColumns;
			} else {
				printfmt = printfmtSingle;
			}
			break;
		case 'p':
			setprintmode (core, 1);
			break;
		case 'P':
			setprintmode (core, -1);
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
			r_core_visual_mark (core, r_cons_readchar ());
			break;
		case '\'':
			r_core_visual_mark_seek (core, r_cons_readchar ());
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
				r_core_seek (core, fcn->addr, 1);
			}
		}
		break;
		case '-':
			if (core->print->cur_enabled) {
				if (core->seltab == 0 && core->printidx == R_CORE_VISUAL_MODE_PDDBG) {
					int w = r_config_get_i (core->config, "hex.cols");
					r_config_set_i (core->config, "stack.size",
						r_config_get_i (core->config, "stack.size") - w);

				} else {
					if (core->print->ocur == -1) {
						sprintf (buf, "wos 01 @ $$+%i!1",core->print->cur);
					} else {
						sprintf (buf, "wos 01 @ $$+%i!%i", core->print->cur < core->print->ocur
							? core->print->cur
							: core->print->ocur,
							R_ABS (core->print->ocur - core->print->cur) + 1);
					}
					r_core_cmd (core, buf, 0);
				}
			} else {
				if (!autoblocksize) {
					r_core_block_size (core, core->blocksize - 1);
				}
			}
			break;
		case '+':
			if (core->print->cur_enabled) {
				if (core->seltab == 0 && core->printidx == R_CORE_VISUAL_MODE_PDDBG) {
					int w = r_config_get_i (core->config, "hex.cols");
					r_config_set_i (core->config, "stack.size",
						r_config_get_i (core->config, "stack.size") + w);

				} else {
					if (core->print->ocur == -1) {
						sprintf (buf, "woa 01 @ $$+%i!1", core->print->cur);
					} else {
						sprintf (buf, "woa 01 @ $$+%i!%i", core->print->cur < core->print->ocur
							? core->print->cur
							: core->print->ocur,
							R_ABS (core->print->ocur - core->print->cur) + 1);
					}
					r_core_cmd (core, buf, 0);
				}
			} else {
				if (!autoblocksize) {
					r_core_block_size (core, core->blocksize + 1);
				}
			}
			break;
		case '/':
			if (core->print->cur_enabled) {
				visual_search (core);
			} else {
				if (autoblocksize) {
					r_core_cmd0 (core, "?i highlight;e scr.highlight=`?y`");
				} else {
					r_core_block_size (core, core->blocksize - cols);
				}
			}
			break;
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
		case '*':
			if (core->print->cur_enabled) {
				r_core_cmdf (core, "dr PC=0x%08"PFMT64x, core->offset + core->print->cur);
			} else if (!autoblocksize) {
				r_core_block_size (core, core->blocksize + cols);
			}
			break;
		case '>':
			if (core->print->cur_enabled) {
				char buf[128];
				prompt_read ("inc cursor:", buf, sizeof (buf));
				core->print->cur += (st64) r_num_math (core->num, buf);
			} else {
				r_core_seek_align (core, core->blocksize, 1);
				r_io_sundo_push (core->io, core->offset, r_print_get_cursor (core->print));
			}
			break;
		case '<': // "V<"
			if (core->print->cur_enabled) {
				char buf[128];
				prompt_read ("dec cursor:", buf, sizeof (buf));
				core->print->cur -= (st64) r_num_math (core->num, buf);
			} else {
				r_core_seek_align (core, core->blocksize, -1);
				r_core_seek_align (core, core->blocksize, -1);
				r_io_sundo_push (core->io, core->offset, r_print_get_cursor (core->print));
			}
			break;
		case '.': // "V."
			r_io_sundo_push (core->io, core->offset, r_print_get_cursor (core->print));
			if (core->print->cur_enabled) {
				r_config_set_i (core->config, "stack.delta", 0);
				r_core_seek (core, core->offset + core->print->cur, 1);
				core->print->cur = 0;
			} else {
				ut64 addr = r_debug_reg_get (core->dbg, "PC");
				if (addr && addr != UT64_MAX) {
					r_core_seek (core, addr, 1);
					r_core_cmdf (core, "ar `arn PC`=0x%"PFMT64x, addr);
				} else {
					ut64 entry = r_num_get (core->num, "entry0");
					if (!entry || entry == UT64_MAX) {
						RIOSection *s = r_io_section_vget (core->io, core->offset);
						if (s) {
							entry = s->vaddr;
						} else {
							RIOMap *map = ls_pop (core->io->maps);
							if (map) {
								entry = map->itv.addr;
							} else {
								entry = r_config_get_i (core->config, "bin.baddr");
							}
							ls_prepend (core->io->maps, map);
						}
					}
					if (entry != UT64_MAX) {
						r_core_seek (core, entry, 1);
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
			r_cons_gotoxy (0, 0);
			r_cons_printf ("Enter a comment: ('-' to remove, '!' to use $EDITOR)\n");
			showcursor (core, true);
			r_cons_flush ();
			r_cons_set_raw (false);
			r_line_set_prompt ("comment: ");
			strcpy (buf, "\"CC ");
			i = strlen (buf);
			if (r_cons_fgets (buf + i, sizeof (buf) - i - 1, 0, NULL) > 0) {
				ut64 addr, orig;
				addr = orig = core->offset;
				if (core->print->cur_enabled) {
					addr += core->print->cur;
					r_core_seek (core, addr, 0);
					r_core_cmdf (core, "s 0x%"PFMT64x, addr);
				}
				if (!strcmp (buf + i, "-")) {
					strcpy (buf, "CC-");
				} else {
					switch (buf[i]) {
					case '-':
						memcpy (buf, "\"CC-\x00", 5);
						break;
					case '!':
						memcpy (buf, "\"CC!\x00", 5);
						break;
					default:
						memcpy (buf, "\"CC ", 4);
						break;
					}
					strcat (buf, "\"");
				}
				if (buf[3] == ' ') {
					// have to escape any quotes.
					int j, len = strlen (buf);
					char *duped = strdup (buf);
					i = 4, j = 4;
					for (i = 4, j = 4; i < len; ++i,++j) {
						char c = duped[i];
						if (c == '"' && i != (len - 1)) {
							buf[j] = '\\';
							++j;
							buf[j] = '"';
						} else {
							buf[j] = c;
						}
					}
					free (duped);
				}
				r_core_cmd (core, buf, 1);
				if (core->print->cur_enabled) {
					r_core_seek (core, orig, 1);
				}
			}
			r_cons_set_raw (true);
			showcursor (core, false);
			break;
		case 'b':
			visual_browse (core);
			break;
		case 'B':
			{
			ut64 addr = core->print->cur_enabled? core->offset + core->print->cur: core->offset;
			r_core_cmdf (core, "dbs 0x%08"PFMT64x, addr);
			}
			break;
		case 'O':
			disMode++;
			if (disMode > 2) {
				disMode = 0;
			}
			applyDisMode (core);
			// r_core_cmd0 (core, "e!asm.pseudo");
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
		case 'Z':
			if (zoom && core->print->cur) {
				ut64 from = r_config_get_i (core->config, "zoom.from");
				ut64 to = r_config_get_i (core->config, "zoom.to");
				r_core_seek (core, from + ((to - from) / core->blocksize) * core->print->cur, 1);
			}
			zoom = !zoom;
			break;
		case '?':
			if (visual_help () == '?') {
				r_core_visual_hud (core);
			}
			break;
		case 0x1b:
		case 'q':
		case 'Q':
			setcursor (core, false);
			return false;
		}
	}
	r_core_block_read (core);
	return true;
}

R_API void r_core_visual_title(RCore *core, int color) {
	bool showDelta = r_config_get_i (core->config, "scr.slow");
	static ut64 oldpc = 0;
	const char *BEGIN = core->cons->pal.prompt;
	const char *filename;
	char pos[512], foo[512], bar[512], pcs[32];
	if (!oldpc) {
		oldpc = r_debug_reg_get (core->dbg, "PC");
	}
	/* automatic block size */
	int pc, hexcols = r_config_get_i (core->config, "hex.cols");
	if (autoblocksize) {
		switch (core->printidx) {
		case R_CORE_VISUAL_MODE_PRC: // prc
			r_core_block_size (core, (int)(core->cons->rows * hexcols * 3.5));
			break;
		case R_CORE_VISUAL_MODE_PX: // x
		case R_CORE_VISUAL_MODE_PXa: // pxa
			r_core_block_size (core, (int)(core->cons->rows * hexcols * 3.5));
			break;
		case R_CORE_VISUAL_MODE_PW: // XXX pw
			r_core_block_size (core, (int)(core->cons->rows * hexcols));
			break;
		case R_CORE_VISUAL_MODE_PC: // XXX pc
			r_core_block_size (core, (int)(core->cons->rows * hexcols * 4));
			break;
		case R_CORE_VISUAL_MODE_PD: // pd
		case R_CORE_VISUAL_MODE_PDDBG: // pd+dbg
		{
			int bsize = core->cons->rows * 5;

			if (core->print->screen_bounds > 1) {
				// estimate new blocksize with the size of the last
				// printed instructions
				int new_sz = core->print->screen_bounds - core->offset + 32;
				if (new_sz > bsize) {
					bsize = new_sz;
				}
			}
			r_core_block_size (core, bsize);
			break;
		}
		case R_CORE_VISUAL_MODE_PXA: // pxA
			r_core_block_size (core, hexcols * core->cons->rows * 8);
			break;
		}
	}
	if (r_config_get_i (core->config, "scr.zoneflags")) {
		r_core_cmd (core, "fz:", 0);
	}
	if (r_config_get_i (core->config, "cfg.debug")) {
		ut64 curpc = r_debug_reg_get (core->dbg, "PC");
		if (curpc && curpc != UT64_MAX && curpc != oldpc) {
			// check dbg.follow here
			int follow = (int) (st64) r_config_get_i (core->config, "dbg.follow");
			if (follow > 0) {
				if ((curpc < core->offset) || (curpc > (core->offset + follow))) {
					r_core_seek (core, curpc, 1);
				}
			} else if (follow < 0) {
				r_core_seek (core, curpc + follow, 1);
			}
			oldpc = curpc;
		}
	}

	RIODesc *desc = r_io_desc_get (core->io, core->file->fd);
	filename = desc? desc->name: "";
	{ /* get flag with delta */
		ut64 addr = core->offset + (core->print->cur_enabled? core->print->cur: 0);
#if 1
		/* TODO: we need a helper into r_flags to do that */
		bool oss = core->flags->space_strict;
		int osi = core->flags->space_idx;
		RFlagItem *f = NULL;
		core->flags->space_strict = true;
		core->anal->flb.set_fs (core->flags, "symbols");
		if (core->flags->space_idx != -1) {
			f = core->anal->flb.get_at (core->flags, addr, showDelta);
		}
		core->flags->space_strict = oss;
		core->flags->space_idx = osi;
		if (!f) {
			f = r_flag_get_at (core->flags, addr, showDelta);
		}
#else
		RFlagItem *f = r_flag_get_at (core->flags, addr, false);
#endif
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
		strncpy (bar, cmd_visual, sizeof (bar) - 1);
		bar[10] = '.'; // chop cmdfmt
		bar[11] = '.'; // chop cmdfmt
		bar[12] = 0; // chop cmdfmt
	} else {
		strncpy (bar, printfmt[PIDX], sizeof (bar) - 1);
		bar[sizeof (bar) - 1] = 0; // '\0'-terminate bar
		bar[10] = '.'; // chop cmdfmt
		bar[11] = '.'; // chop cmdfmt
		bar[12] = 0; // chop cmdfmt
	}
	{
		ut64 sz = r_io_size (core->io);
		ut64 pa;
		{
			RIOSection *s = r_io_section_vget (core->io, core->offset); 
			pa =  s ? core->offset - s->vaddr + s->paddr : core->offset;
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
	if (__ime) {
		snprintf (foo, sizeof (foo), "[0x%08"PFMT64x " + %d> * INSERT MODE *\n",
			core->offset, core->print->cur);
	} else {
		if (core->print->cur_enabled) {
			snprintf (foo, sizeof (foo), "[0x%08"PFMT64x " %s%d (0x%x:%d=%d)]> %s %s\n",
				core->offset, pcs, core->blocksize,
				core->print->cur, core->print->ocur, core->print->ocur == -1 ?
				1: R_ABS (core->print->cur - core->print->ocur) + 1,
				bar, pos);
		} else {
			snprintf (foo, sizeof (foo), "[0x%08"PFMT64x " %s%d %s]> %s %s\n",
				core->offset, pcs, core->blocksize, filename, bar, pos);
		}
	}
	r_cons_print (foo);
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
			r_config_set_i (core->config, "hex.cols", w / 5.2);
		} else {
			r_config_set_i (core->config, "hex.cols", 16);
		}
		if (w < 25) {
			r_config_set_i (core->config, "asm.offset", 0);
		} else {
			r_config_set_i (core->config, "asm.offset", 1);
		}
		if (w > 80) {
			r_config_set_i (core->config, "asm.lineswidth", 14);
			r_config_set_i (core->config, "asm.lineswidth", w - (w / 1.2));
			r_config_set_i (core->config, "asm.cmt.col", w - (w / 2.5));
		} else {
			r_config_set_i (core->config, "asm.lineswidth", 7);
		}
		if (w < 70) {
			r_config_set_i (core->config, "asm.lineswidth", 1);
			r_config_set_i (core->config, "asm.bytes", 0);
		} else {
			r_config_set_i (core->config, "asm.bytes", 1);
		}
	}
	return w;
}

static void visual_refresh(RCore *core) {
	static ut64 oseek = UT64_MAX;
	const char *vi, *vcmd;
	if (!core) {
		return;
	}
	r_print_set_cursor (core->print, core->print->cur_enabled, core->print->ocur, core->print->cur);
	core->cons->blankline = true;

	int w = visual_responsive (core);

	if (autoblocksize) {
		r_cons_gotoxy (0, 0);
	} else {
		r_cons_clear ();
	}
	r_cons_flush ();
	r_cons_print_clear ();

	vi = r_config_get (core->config, "cmd.cprompt");
	bool ce = core->print->cur_enabled;
	if (vi && *vi) {
		// XXX: slow
		core->cons->blankline = false;
		r_cons_clear00 ();
		{
			int hc = r_config_get_i (core->config, "hex.cols");
			int nw = 12 + 4 + hc + (hc * 3);
			if (nw > w) {
				// do not show column contents
			} else {
				r_cons_printf ("[cmd.cprompt=%s]\n", vi);
				if (oseek != UT64_MAX) {
					r_core_seek (core, oseek, 1);
				}
				r_core_cmd0 (core, vi);
				r_cons_column (nw);
				r_cons_flush ();
				if (!strncmp (vi, "p=", 2) && core->print->cur_enabled) {
					oseek = core->offset;
					core->print->cur_enabled = false;
					r_core_seek (core, core->num->value, 1);
				} else {
					oseek = UT64_MAX;
				}
			}
		}
		r_cons_gotoxy (0, 0);
		r_core_visual_title (core, color);
		vi = r_config_get (core->config, "cmd.vprompt");
		if (vi) {
			r_core_cmd (core, vi, 0);
		}
	} else {
		vi = r_config_get (core->config, "cmd.vprompt");
		if (vi) {
			r_core_cmd (core, vi, 0);
		}
		r_core_visual_title (core, color);
	}

	vcmd = r_config_get (core->config, "cmd.visual");
	if (vcmd && *vcmd) {
		// disable screen bounds when it's a user-defined command
		// because it can cause some issues
		core->print->screen_bounds = 0;
		r_core_cmd (core, vcmd, 0);
	} else {
		if (splitView) {
			static char debugstr[512];
			const int ref = r_config_get_i (core->config, "dbg.slow");
			const int bytes = r_config_get_i (core->config, "stack.bytes");
			char *pxw = NULL;
			int h = r_num_get (core->num, "$r");
			int size = (h * 16) / 2;
			switch (core->printidx) {
			case 1:
				size = (h - 2) / 2;
				pxw = "pd";
				break;
			default:
				if (ref) {
					pxw = "pxr";
				} else if (bytes) {
					pxw = "px";
				} else {
					switch (core->assembler->bits) {
					case 64: pxw = "pxq"; break;
					case 32: pxw = "pxw"; break;
					default: pxw = "px"; break;
					}
				}
			}
			snprintf (debugstr, sizeof (debugstr),
					"?0;%s %d @ %"PFMT64d";cl;"
					"?1;%s %d @ %"PFMT64d";",
					pxw, size, splitPtr,
					pxw, size, core->offset);
			core->print->screen_bounds = 1LL;
			r_core_cmd0 (core, debugstr);
		} else {
			core->print->screen_bounds = 1LL;
			r_core_cmd0 (core, zoom? "pz": printfmt[PIDX]);
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

	/* this is why there's flickering */
	if (core->print->vflush) {
		r_cons_visual_flush ();
	} else {
		r_cons_reset ();
	}
	core->cons->blankline = true;
	core->curtab = 0; // which command are we focusing
	//core->seltab = 0; // user selected tab

	if (snowMode) {
		printSnow (core);
	}
}

R_API int r_core_visual(RCore *core, const char *input) {
	const char *cmdprompt, *teefile;
	ut64 scrseek;
	int wheel, flags, ch;
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
		// update the cursor when it's not visible anymore
		skip = fix_cursor (core);
		const int ref = r_config_get_i (core->config, "dbg.slow");
		const int bytes = r_config_get_i (core->config, "stack.bytes");

		if (printfmt == printfmtSingle && core->printidx == R_CORE_VISUAL_MODE_PDDBG) {
			const int pxa = r_config_get_i (core->config, "stack.anotated"); // stack.anotated
			const int size = r_config_get_i (core->config, "stack.size");
			const int delta = r_config_get_i (core->config, "stack.delta");
			const char *cmdvhex = r_config_get (core->config, "cmd.stack");

			if (cmdvhex && *cmdvhex) {
				snprintf (debugstr, sizeof (debugstr),
					"?0;f tmp;ssr SP;%s;?1;%s;?1;"
					"ss tmp;f-tmp;pd $r", cmdvhex,
					ref? "drr": "dr=");
				debugstr[sizeof (debugstr) - 1] = 0;
			} else {
				const char *pxw;
				if (ref) {
					pxw = "pxr";
				} else if (bytes) {
					pxw = "px";
				} else {
					switch (core->assembler->bits) {
					case 64: pxw = "pxq"; break;
					case 32: pxw = "pxw"; break;
					default: pxw = "px"; break;
					}
				}
				const char sign = (delta < 0)? '+': '-';
				const int absdelta = R_ABS (delta);
				snprintf (debugstr, sizeof (debugstr),
					"?0;f tmp;ssr SP;%s %d@$$%c%d;"
					"?1;%s;"
					"?1;ss tmp;f-tmp;afal;pd $r",
					pxa? "pxa": pxw, size, sign, absdelta,
					ref? "drr": "dr=");
			}
			printfmt[2] = debugstr;
		}
		wheel = r_config_get_i (core->config, "scr.wheel");
		r_cons_show_cursor (false);
		if (wheel) {
			r_cons_enable_mouse (true);
		}
		core->cons->event_data = core;
		core->cons->event_resize = (RConsEvent) visual_refresh;
		flags = core->print->flags;
		color = r_config_get_i (core->config, "scr.color");
		if (color) {
			flags |= R_PRINT_FLAGS_COLOR;
		}
		debug = r_config_get_i (core->config, "cfg.debug");
		flags |= R_PRINT_FLAGS_ADDRMOD | R_PRINT_FLAGS_HEADER;
		r_print_set_flags (core->print, core->print->flags);
		scrseek = r_num_math (core->num,
			r_config_get (core->config, "scr.seek"));
		if (scrseek != 0LL) {
			r_core_seek (core, scrseek, 1);
		}
		if (debug) {
			r_core_cmd (core, ".dr*", 0);
		}
		cmdprompt = r_config_get (core->config, "cmd.vprompt");
		if (cmdprompt && *cmdprompt) {
			r_core_cmd (core, cmdprompt, 0);
		}
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
	} while (skip || r_core_visual_cmd (core, arg));

	r_cons_enable_mouse (false);
	if (color) {
		r_cons_printf (Color_RESET);
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
