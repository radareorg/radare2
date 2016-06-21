/* radare - LGPL - Copyright 2009-2015 - pancake */

#include <r_core.h>

#include <string.h>

#define NPF 7
static int obs = 0;
static int blocksize = 0;
static int autoblocksize = 1;
static ut64 last_printed_address = 0LL;
static void r_core_visual_refresh (RCore *core);

#define debugfmt_default "f tmp;sr SP;pxw 64;dr=;s-;s tmp;f-tmp;pd $r"
static const char *printfmt[] = {
	"x", "pd $r",
	debugfmt_default,
	"pxw", "pc", "pxA", "pxa"
};

#undef USE_THREADS
#define USE_THREADS 1

#if USE_THREADS
static int visual_repeat_thread(RThread *th) {
	RCore *core = th->user;
	int i = 0;
	for (;;) {
		if (core->cons->breaked)
			break;
		r_core_visual_refresh (core);
		r_cons_flush ();
		r_cons_gotoxy (0, 0);
		r_cons_printf ("[@%d] ", i++);
		r_cons_flush ();
		r_sys_sleep (1);
	}
	r_th_kill (th, 1);
	return 0;
}

static void visual_repeat(RCore *core) {
	int atport = r_config_get_i (core->config, "scr.atport");
	if (atport) {
#if __UNIX__ && !__APPLE__
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
		RThread *th = r_th_new (visual_repeat_thread, core, 0);
		r_th_start (th, 1);
		r_cons_break (NULL, NULL);
		r_cons_any_key (NULL);
		eprintf ("^C  \n");
		core->cons->breaked = true;
		r_th_wait (th);
		r_cons_break_end ();
	}
}
#endif

static void showcursor(RCore *core, int x) {
	if (core && core->vmode) {
		r_cons_show_cursor (x);
		if (x) {
			// TODO: cache this
			int wheel = r_config_get_i (core->config, "scr.wheel");
			if (wheel) r_cons_enable_mouse (true);
			else r_cons_enable_mouse (false);
		} else {
			r_cons_enable_mouse (false);
		}
	} else r_cons_enable_mouse (false);
	r_cons_flush ();
}

// XXX: use core->print->cur_enabled instead of curset/cursor/ocursor
static int curset = 0, cursor = 0, ocursor=-1;
static int color = 1;
static int debug = 1;
static int zoom = 0;

R_API int r_core_visual_hud(RCore *core) {
	const char *c = r_config_get (core->config, "hud.path");
	const char *f = R2_LIBDIR"/radare2/"R2_VERSION"/hud/main";
	char *homehud = r_str_home (R2_HOMEDIR"/hud");
	char *res = NULL;
	char *p = 0;

	showcursor (core, true);
	if (c && *c && r_file_exists (c))
		res = r_cons_hud_file (c);
	if (!res && homehud)
		res = r_cons_hud_file (homehud);
	if (!res && r_file_exists (f))
		res = r_cons_hud_file (f);
	if (!res)
		r_cons_message ("Cannot find hud file");

	r_cons_clear ();
	if (res) {
		p = strchr (res, '\t');
		r_cons_printf ("%s\n", res);
		r_cons_flush ();
		if (p) r_core_cmd0 (core, p+1);
		free (res);
	}
	showcursor (core, false);
	r_cons_flush ();
	free (homehud);
	return (int)(size_t)p;
}

static int visual_help() {
	r_cons_clear00 ();
	return r_cons_less_str (
	"Visual mode help:\n"
	" ?        show this help or enter the userfriendly hud\n"
	" &        rotate asm.bits between supported 8, 16, 32, 64\n"
	" %        in cursor mode finds matching pair, otherwise toggle autoblocksz\n"
	" @        set cmd.vprompt to run commands before the visual prompt\n"
	" !        enter into the visual panels mode\n"
	" _        enter the flag/comment/functions/.. hud (same as VF_)\n"
	" =        set cmd.vprompt (top row)\n"
	" |        set cmd.cprompt (right column)\n"
	" .        seek to program counter\n"
	" /        in cursor mode search in current block\n"
	" :cmd     run radare command\n"
	" ;[-]cmt  add/remove comment\n"
	" /*+-[]   change block size, [] = resize hex.cols\n"
	" >||<     seek aligned to block size\n"
	" a/A      (a)ssemble code, visual (A)ssembler\n"
	" b        toggle breakpoint\n"
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
	" O        toggle asm.esil\n"
	" p/P      rotate print modes (hex, disasm, debug, words, buf)\n"
	" q        back to radare shell\n"
	" r        browse anal info and comments\n"
	" R        randomize color palette (ecr)\n"
	" sS       step / step over\n"
	" T        enter textlog chat console (TT)\n"
	" uU       undo/redo seek\n"
	" v        visual code analysis menu\n"
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
	r_cons_flush ();
	r_cons_clear00 ();
}

static void prompt_read (const char *p, char *buf, int buflen) {
	r_line_set_prompt (p);
	showcursor (NULL, true);
	r_cons_fgets (buf, buflen, 0, NULL);
	showcursor (NULL, false);
}

R_API void r_core_visual_prompt_input (RCore *core) {
	int ret;
	ut64 addr = core->offset;
	ut64 bsze = core->blocksize;
	int h;
	(void)r_cons_get_size (&h);
	r_cons_gotoxy (0, h-2);
	r_cons_reset_colors ();
	r_cons_printf ("\nPress <enter> to return to Visual mode.\n");
	r_cons_show_cursor (true);
	core->vmode = false;
	ut64 newaddr = addr;
	if (curset) {
		if (ocursor != -1) {
			newaddr = core->offset + ocursor;
			r_core_block_size (core, cursor-ocursor);
		} else newaddr = core->offset + cursor;
		r_core_seek (core, newaddr, 1);
	}
	do {
		ret = r_core_visual_prompt (core);
		if (core->offset != newaddr) {
			// do not restore seek anymore
			newaddr = addr;
		}
	} while (ret);
	if (curset) {
		if (addr != newaddr) {
			r_core_seek (core, addr, 1);
			r_core_block_size (core, bsze);
		}
	}
	r_cons_show_cursor (false);
	core->vmode = true;
}

R_API int r_core_visual_prompt (RCore *core) {
	char buf[1024];
	int ret;
#if __UNIX__
	r_line_set_prompt (Color_RESET":> ");
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

static int visual_nkey(RCore *core, int ch) {
	const char *cmd;
	ut64 oseek = UT64_MAX;
	if (ocursor == -1) {
		oseek = core->offset;
		r_core_seek (core, core->offset + cursor, 0);
	}

	switch (ch) {
	case R_CONS_KEY_F1:
		cmd = r_config_get (core->config, "key.f1");
		if (cmd && *cmd) ch = r_core_cmd0 (core, cmd);
		else ch = '?';
		break;
	case R_CONS_KEY_F2:
		cmd = r_config_get (core->config, "key.f2");
		if (cmd && *cmd) ch = r_core_cmd0 (core, cmd);
		break;
	case R_CONS_KEY_F3:
		cmd = r_config_get (core->config, "key.f3");
		if (cmd && *cmd) ch = r_core_cmd0 (core, cmd);
		break;
	case R_CONS_KEY_F4:
		cmd = r_config_get (core->config, "key.f4");
		if (cmd && *cmd) ch = r_core_cmd0 (core, cmd);
		else {
			if (curset) {
				// dcu 0xaddr
				r_core_cmdf (core, "dcu 0x%08"PFMT64x, core->offset + cursor);
				curset = 0;
			}
		}
		break;
	case R_CONS_KEY_F5:
		cmd = r_config_get (core->config, "key.f5");
		if (cmd && *cmd) ch = r_core_cmd0 (core, cmd);
		break;
	case R_CONS_KEY_F6:
		cmd = r_config_get (core->config, "key.f6");
		if (cmd && *cmd) ch = r_core_cmd0 (core, cmd);
		break;
	case R_CONS_KEY_F7:
		cmd = r_config_get (core->config, "key.f7");
		if (cmd && *cmd) ch = r_core_cmd0 (core, cmd);
		else ch = 's';
		break;
	case R_CONS_KEY_F8:
		cmd = r_config_get (core->config, "key.f8");
		if (cmd && *cmd) ch = r_core_cmd0 (core, cmd);
		break;
	case R_CONS_KEY_F9:
		cmd = r_config_get (core->config, "key.f9");
		if (cmd && *cmd) ch = r_core_cmd0 (core, cmd);
		else r_core_cmd0 (core, "dc");
		break;
	case R_CONS_KEY_F10:
		cmd = r_config_get (core->config, "key.f10");
		if (cmd && *cmd) ch = r_core_cmd0 (core, cmd);
		break;
	case R_CONS_KEY_F11:
		cmd = r_config_get (core->config, "key.f11");
		if (cmd && *cmd) ch = r_core_cmd0 (core, cmd);
		break;
	case R_CONS_KEY_F12:
		cmd = r_config_get (core->config, "key.f12");
		if (cmd && *cmd) ch = r_core_cmd0 (core, cmd);
		break;
	}
	if (oseek != UT64_MAX)
		r_core_seek (core, oseek, 0);
	return ch;
}

static void setcursor (RCore *core, int cur) {
	int flags = core->print->flags; // wtf
	curset = cur;
	if (curset) flags |= R_PRINT_FLAGS_CURSOR;
	else flags &= ~(R_PRINT_FLAGS_CURSOR);
	core->print->cur_enabled = cur;
	r_print_set_flags (core->print, flags);
	core->print->col = curset? 1: 0;
}

static void setdiff (RCore *core) {
	char from[64], to[64];
	prompt_read ("diff from: ", from, sizeof (from));
	r_config_set (core->config, "diff.from", from);
	prompt_read ("diff to: ", to, sizeof (to));
	r_config_set (core->config, "diff.to", to);
}

static void findPair (RCore *core) {
	ut8 buf[256];
	int i, len, d = cursor+1;
	int delta = 0;
	const ut8 *p, *q = NULL;
	const char *keys = "{}[]()<>";
	ut8 ch = core->block[cursor];

	p = (const ut8*)strchr (keys, ch);
	if (p) {
		delta = (size_t)(p-(const ut8*)keys);
		ch = (delta%2 && p != (const ut8*)keys)? p[-1]: p[1];
	}
	len = 1;
	buf[0] = ch;

	if (p && (delta%2)) {
		for (i = d-1; i>=0; i--) {
			if (core->block[i] == ch) {
				q = core->block + i;
				break;
			}
		}
	} else {
		q = r_mem_mem (core->block+d, core->blocksize-d,
				(const ut8*)buf, len);
		if (!q) {
			q = r_mem_mem (core->block, R_MIN (core->blocksize, d),
					(const ut8*)buf, len);
		}
	}
	if (q) {
		cursor = (int)(size_t)(q-core->block);
		ocursor = -1;
		showcursor (core, true);
	}
}

static void findNextWord (RCore *core) {
	int i, d = curset? cursor: 0;
	for (i = d+1; i<core->blocksize; i++) {
		switch (core->block[i]) {
		case ' ':
		case '.':
		case '\t':
		case '\n':
			if (curset) {
				cursor = i+1;
				ocursor = -1;
				showcursor (core, true);
			} else {
				r_core_seek (core, core->offset + i + 1, 1);
			}
			return;
		}
	}
}

static int isSpace (char ch) {
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

static void findPrevWord (RCore *core) {
	int i = curset? cursor: 0;
	while (i>1) {
		if (isSpace (core->block[i]))
			i--;
		else if (isSpace (core->block[i-1]))
			i-=2;
		else break;
	}
	for (; i>=0; i--) {
		if (isSpace (core->block[i])) {
			if (curset) {
				cursor = i+1;
				ocursor = -1;
				showcursor (core, true);
			} else {
				// r_core_seek (core, core->offset + i + 1, 1);
			}
			break;
		}
	}
}

// TODO: integrate in '/' command with search.inblock ?
static void visual_search (RCore *core) {
	const ut8 *p;
	int len, d = cursor;
	char str[128], buf[258];

	r_line_set_prompt ("search byte/string in block: ");
	r_cons_fgets (str, sizeof (str), 0, NULL);
	len = r_hex_str2bin (str, (ut8*)buf);
	if (*str=='"') {
		char *e = strncpy (buf, str+1, sizeof (buf)-1);
		if (e) { --e; if (*e=='"') *e=0; }
		len = strlen (buf);
	} else
	if (len<1) {
		strncpy (buf, str, sizeof (buf)-1);
		len = strlen (str);
	}
	p = r_mem_mem (core->block+d, core->blocksize-d,
		(const ut8*)buf, len);
	if (p) {
		cursor = (int)(size_t)(p-core->block);
		if (len>1) {
			ocursor = cursor+len-1;
		} else ocursor = -1;
		showcursor (core, true);
		eprintf ("FOUND IN %d\n", cursor);
		r_cons_any_key (NULL);
	} else {
		eprintf ("Cannot find bytes\n");
		r_cons_any_key (NULL);
		r_cons_clear00 ();
	}
}

R_API void r_core_visual_show_char (RCore *core, char ch) {
	if (r_config_get_i (core->config, "scr.feedback")<2)
		return;
	if (!IS_PRINTABLE (ch))
		return;
	r_cons_gotoxy (1, 2);
	r_cons_printf (".---.\n");
	r_cons_printf ("| %c |\n", ch);
	r_cons_printf ("'---'\n");
	r_cons_flush ();
	r_sys_sleep (1);
}

R_API void r_core_visual_seek_animation (RCore *core, ut64 addr) {
	r_core_seek (core, addr, 1);
	if (r_config_get_i (core->config, "scr.feedback")<1)
		return;
	if (core->offset == addr)
		return;
	r_cons_gotoxy (1, 2);
	if (addr>core->offset) {
		r_cons_printf (".----.\n");
		r_cons_printf ("| \\/ |\n");
		r_cons_printf ("'----'\n");
	} else {
		r_cons_printf (".----.\n");
		r_cons_printf ("| /\\ |\n");
		r_cons_printf ("'----'\n");
	}
	r_cons_flush();
	r_sys_usleep (90000);
}

static void setprintmode (RCore *core, int n) {
	RAsmOp op;
	if (n>0) {
		core->printidx = R_ABS ((core->printidx+1)%NPF);
	} else {
		if (core->printidx)
			core->printidx--;
		else core->printidx = NPF-1;
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
static int prevopsz (RCore *core, ut64 addr) {
	ut64 target = addr;
	ut64 base = target-OPDELTA;
	int len, ret, i;
	ut8 buf[OPDELTA*2];
	RAnalOp op;

	r_core_read_at (core, base, buf, sizeof (buf));
	for (i=0; i<sizeof (buf); i++) {
		ret = r_anal_op (core->anal, &op, base+i,
			buf+i, sizeof (buf)-i);
		if (!ret) continue;
		len = op.size;
		r_anal_op_fini (&op); // XXX
		if (len<1) continue;
		i += len-1;
		if (target == base+i+1)
			return len;
	}
	return 4;
}
static void visual_offset (RCore *core) {
	char buf[256];
	r_line_set_prompt ("[offset]> ");
	strcpy (buf, "s ");
	if (r_cons_fgets (buf+2, sizeof (buf)-3, 0, NULL) >0) {
		if (buf[2]=='.')buf[1]='.';
		r_core_cmd0 (core, buf);
	}
}

R_API int r_core_visual_xrefs_x (RCore *core) {
	int ret = 0;
#if FCN_OLD
	char ch;
	int count = 0;
	RList *xrefs = NULL;
	RAnalRef *refi;
	RListIter *iter;
	RAnalFunction *fun;

	if ((xrefs = r_anal_xref_get (core->anal, core->offset))) {
		r_cons_gotoxy (1, 1);
		r_cons_printf ("[GOTO XREF]> \n");
		if (r_list_empty (xrefs)) {
			r_cons_printf ("\tNo XREF found at 0x%"PFMT64x"\n", core->offset);
			r_cons_any_key (NULL);
			r_cons_clear00 ();
		} else {
			r_list_foreach (xrefs, iter, refi) {
				fun = r_anal_get_fcn_in (core->anal, refi->addr, R_ANAL_FCN_TYPE_NULL);
				r_cons_printf (" [%i] 0x%08"PFMT64x" %s XREF 0x%08"PFMT64x" (%s)                      \n", count,
					refi->at,
					      refi->type==R_ANAL_REF_TYPE_CODE?"CODE (JMP)":
					      refi->type==R_ANAL_REF_TYPE_CALL?"CODE (CALL)":"DATA", refi->addr,
					      fun?fun->name:"unk");
				if (++count > 9) break;
			}
		}
	} else xrefs = NULL;
	if (!xrefs || !r_list_length (xrefs)) {
		r_list_free (xrefs);
		return 0;
	}
	r_cons_flush ();
	ch = r_cons_readchar ();
	if (ch >= '0' && ch <= '9') {
		refi = r_list_get_n (xrefs, ch-0x30);
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

R_API int r_core_visual_xrefs_X (RCore *core) {
	int ret = 0;
#if FCN_OLD
	char ch;
	int count = 0;
	RAnalRef *refi;
	RListIter *iter;
	RAnalFunction *fun;

	fun = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
	if (fun) {
		r_cons_gotoxy (1, 1);
		r_cons_printf ("[GOTO REF]> \n");
		if (r_list_empty (fun->refs)) {
			r_cons_printf ("\tNo REF found at 0x%"PFMT64x"\n", core->offset);
			r_cons_any_key (NULL);
			r_cons_clear00 ();
		} else {
			r_list_foreach (fun->refs, iter, refi) {
				r_cons_printf (" [%i] 0x%08"PFMT64x" %s XREF 0x%08"PFMT64x" (%s)  \n", count,
					refi->at,
					      refi->type==R_ANAL_REF_TYPE_CODE?"CODE (JMP)":
					      refi->type==R_ANAL_REF_TYPE_CALL?"CODE (CALL)":"DATA", refi->addr, fun->name);
				if (++count > 9) break;
			}
		}
	}
	r_cons_flush ();
	if (!count)
		return 0;
	ch = r_cons_readchar ();
	if (fun && fun->refs) {
		if (ch >= '0' && ch <= '9') {
			refi = r_list_get_n (fun->refs, ch-0x30);
			if (refi) {
				r_core_cmdf (core, "s 0x%"PFMT64x, refi->addr);
				ret = 1;
			}
		}
	}
#else
	eprintf ("TODO: sdbize this\n");
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

	HANDLE Handle = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleScreenBufferSize(Handle, coord);
	SetConsoleWindowInfo(Handle, TRUE, &Rect);
}
#endif

// unnecesarily public
char *getcommapath(RCore *core) {
	char *cwd;
	const char *dir = r_config_get (core->config, "dir.projects");
	const char *prj = r_config_get (core->config, "file.project");
	if (dir && *dir && prj && *prj) {
		char *abspath = r_file_abspath (dir);
		/* use prjdir as base directory for comma-ent files */
		cwd = r_str_newf ("%s"R_SYS_DIR"%s.d", abspath, prj);
		free (abspath);
	} else {
		/* use cwd as base directory for comma-ent files */
		cwd = r_sys_getdir ();
	}
	return cwd;
}

static void visual_comma(RCore *core) {
	ut64 addr = core->offset + curset? cursor: 0;
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
		char *cwf = r_str_newf ("%s"R_SYS_DIR"%s", cwd, cmtfile);
		char *odata = r_file_slurp (cwf, NULL);
		char *data = r_core_editor (core, NULL, odata);
		r_file_dump (cwf, (const ut8*)data, -1, 0);
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

R_API int r_core_visual_cmd(RCore *core, int ch) {
	RAsmOp op;
	ut64 offset = core->offset;
	char buf[4096];
	const char *key_s;
	int i, ret, offscreen, cols = core->print->cols, delta = 0;
	int wheelspeed;
	ch = r_cons_arrow_to_hjkl (ch);
	ch = visual_nkey (core, ch);
	if (ch<2) return 1;

	if (r_cons_singleton()->mouse_event) {
		wheelspeed = r_config_get_i (core->config, "scr.wheelspeed");
	} else {
		wheelspeed = 1;
	}

	// do we need hotkeys for data references? not only calls?
	if (ch >= '0'&& ch <= '9') {
		char chbuf[2];
		ut64 off;

		chbuf[0] = ch;
		chbuf[1] = '\0';
		off = r_core_get_asmqjmps (core, chbuf);
		if (off != UT64_MAX) {
			int delta = R_ABS ((st64)off-(st64)offset);
			r_io_sundo_push (core->io, offset);
			if (curset && delta<100) {
				cursor = delta;
			} else {
				r_core_visual_seek_animation (core, off);
				cursor = 0;
			}
			r_core_block_read (core, 1);
		}
	} else
	switch (ch) {
#if __WINDOWS__ && !__CYGWIN__
	case 0xf5:
		SetWindow(81,25);
		break;
	case 0xcf5:
		SetWindow(81,40);
		break;
#endif
	case 0x0d: // "enter" "\\n" "newline"
		{
			RAnalOp *op;
			int wheel = r_config_get_i (core->config, "scr.wheel");
			if (wheel)
				r_cons_enable_mouse (true);
			do {
				op = r_core_anal_op (core, core->offset+cursor);
				if (op) {
					if (op->type == R_ANAL_OP_TYPE_JMP	||
							op->type == R_ANAL_OP_TYPE_CJMP ||
							op->type == R_ANAL_OP_TYPE_CALL ||
							op->type == R_ANAL_OP_TYPE_CCALL) {
						if (curset) {
							int delta = R_ABS ((st64)op->jump-(st64)offset);
							if ( op->jump < core->offset || op->jump > last_printed_address) {
								r_io_sundo_push (core->io, offset);
								r_core_visual_seek_animation (core, op->jump);
								cursor = 0;
							} else {
								cursor = delta;
							}
						} else {
							r_io_sundo_push (core->io, offset);
							r_core_visual_seek_animation (core, op->jump);
						}
					}
				}
				r_anal_op_free (op);
			} while (--wheelspeed>0);
		}
		break;
	case 9: // tab
		{ // XXX: unify diff mode detection
		ut64 f = r_config_get_i (core->config, "diff.from");
		ut64 t = r_config_get_i (core->config, "diff.to");
		if (f == t && f == 0) {
			core->print->col = core->print->col==1? 2: 1;
		} else {
			ut64 delta = offset - f;
			r_core_seek (core, t+delta, 1);
			r_config_set_i (core->config, "diff.from", t);
			r_config_set_i (core->config, "diff.to", f);
		}
		}
		break;
	case 'a':
		if (core->file && core->file->desc && !(core->file->desc->flags & 2)) {
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
		if (r_cons_fgets (buf+3, 1000, 0, NULL) <0) buf[0]='\0';
		if (*buf) {
			if (curset) r_core_seek (core, core->offset + cursor, 0);
			r_core_cmd (core, buf, true);
			if (curset) r_core_seek (core, core->offset - cursor, 1);
		}
		showcursor (core, false);
		r_cons_set_raw (true);
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
		r_config_set (core->config, "cmd.vprompt", buf);
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
//		if (r_cons_fgets (buf, sizeof (buf)-4, 0, NULL) <0) buf[0]='\0';
		I->line->contents = NULL;
		r_config_set (core->config, "cmd.cprompt", buf);
		}
		break;
	case '!':
		r_core_visual_panels (core);
		break;
	case 'o':
		visual_offset (core);
		break;
	case 'A':
		{ int oc = curset;
		ut64 off = curset? core->offset+cursor : core->offset;
		curset = 0;
		r_core_visual_asm (core, off);
		curset = oc;
		}
		break;
	case 'c':
		setcursor (core, curset?0:1);
		break;
	case '@':
		visual_repeat (core);
		break;
	case 'C':
		color = color? 0: 1;
		r_config_set_i (core->config, "scr.color", color);
		break;
	case 'd':
		{
			int wheel = r_config_get_i (core->config, "scr.wheel");
			if (wheel) r_cons_enable_mouse (false);
			r_core_visual_define (core);
			if (wheel) r_cons_enable_mouse (true);
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
		if (r_cons_fgets (name, sizeof (name), 0, NULL) >=0 && *name) {
			n = r_str_chop (name);
			if (ocursor != -1) {
				min = R_MIN (cursor, ocursor);
				max = R_MAX (cursor, ocursor);
			} else {
				min = max = cursor;
			}
			range = max-min+1;
			if (!strcmp (n, "-")) {
				r_flag_unset_i (core->flags, core->offset + cursor, NULL);
			} else if (*n=='.') {
				if (n[1]=='-') {
					//unset
					r_core_cmdf (core, "f.-%s@0x%"PFMT64x, n+1, core->offset+min);
				} else {
					r_core_cmdf (core, "f.%s@0x%"PFMT64x, n+1, core->offset+min);
				}
			} else if (*n=='-') {
				if (*n) r_flag_unset (core->flags, n+1, NULL);
			} else {
				if (range<1) range = 1;
				if (*n) r_flag_set (core->flags, n,
					core->offset + min, range, 1);
			}
		} }
		showcursor (core, false);
		break;
	case ',':
		visual_comma (core);
		break;
	case 'T':
		if (r_sandbox_enable (0)) {
			eprintf ("sandbox not enabled\n");
		} else {
			if (r_config_get_i (core->config, "scr.interactive"))
				r_core_cmd0 (core, "TT");
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
		if (core->file && core->file->desc &&!(core->file->desc->flags & 2)) {
			r_cons_printf ("\nFile has been opened in read-only mode. Use -w flag\n");
			r_cons_any_key (NULL);
			return true;
		}
		showcursor (core, true);
		r_cons_flush ();
		r_cons_set_raw (0);
		if (ch=='I') {
			strcpy (buf, "wow ");
			r_line_set_prompt ("insert hexpair block: ");
			if (r_cons_fgets (buf+4, sizeof (buf)-5, 0, NULL) <0)
				buf[0]='\0';
			char *p = strdup (buf);
			int cur = core->print->cur;
			if (cur>=core->blocksize)
				cur = core->print->cur-1;
			snprintf (buf, sizeof (buf), "%s @ $$0!%i", p,
				core->blocksize-cursor);
			r_core_cmd (core, buf, 0);
			free (p);
			break;
		}
		delta = (ocursor!=-1)? R_MIN (cursor, ocursor): cursor;
		if (core->print->col==2) {
			strcpy (buf, "\"w ");
			r_line_set_prompt ("insert string: ");
			if (r_cons_fgets (buf+3, sizeof (buf)-4, 0, NULL) <0)
				buf[0]='\0';
			strcat (buf, "\"");
		} else {
			r_line_set_prompt ("insert hex: ");
			if (ocursor != -1) {
				int bs = R_ABS (cursor-ocursor)+1;
				core->blocksize = bs;
				strcpy (buf, "wow ");
			} else {
				strcpy (buf, "wx ");
			}
			if (r_cons_fgets (buf+strlen (buf), sizeof (buf)-strlen (buf), 0, NULL) <0)
				buf[0]='\0';
		}
		if (curset) r_core_seek (core, core->offset + delta, 0);
		r_core_cmd (core, buf, 1);
		if (curset) r_core_seek (core, offset, 1);
		r_cons_set_raw (1);
		showcursor (core, false);
		break;
	case 'R':
		r_core_cmd0 (core, "ecr");
		break;
	case 'e':
		r_core_visual_config (core);
		break;
	case 'E':
		r_core_visual_colors (core);
		break;
	case 'M':
		r_core_visual_mounts (core);
		break;
	case '&':
		switch (core->assembler->bits) {
		case 8:
			r_config_set_i (core->config, "asm.bits", 16);
			if (core->assembler->bits!=16) {
				r_config_set_i (core->config, "asm.bits", 32);
				if (core->assembler->bits!=32) {
					r_config_set_i (core->config, "asm.bits", 64);
				}
			}
			break;
		case 16:
			r_config_set_i (core->config, "asm.bits", 32);
			if (core->assembler->bits!=32) {
				r_config_set_i (core->config, "asm.bits", 64);
				if (core->assembler->bits!=64) {
					r_config_set_i (core->config, "asm.bits", 8);
				}
			}
			break;
		case 32:
			r_config_set_i (core->config, "asm.bits", 64);
			if (core->assembler->bits!=64) {
				r_config_set_i (core->config, "asm.bits", 8);
				if (core->assembler->bits!=8) {
					r_config_set_i (core->config, "asm.bits", 16);
				}
			}
			break;
		case 64:
			r_config_set_i (core->config, "asm.bits", 8);
			if (core->assembler->bits!=8) {
				r_config_set_i (core->config, "asm.bits", 16);
				if (core->assembler->bits!=16) {
					r_config_set_i (core->config, "asm.bits", 32);
				}
			}
			break;
		}
		break;
	case 't':
		r_core_visual_types (core);
		break;
	case 'B':
		r_core_visual_classes (core);
		break;
	case 'F':
		r_core_visual_trackflags (core);
		break;
	case 'x':
		r_core_visual_xrefs_x (core);
		break;
	case 'X':
		r_core_visual_xrefs_X (core);
		break;
	case 'r':
		r_core_visual_comments (core);
		break;
	case ' ':
	case 'V':
		if (r_config_get_i (core->config, "graph.web")) {
			r_core_cmd0 (core, "agv $$");
		} else {
			RAnalFunction *fun = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
			int ocolor;

			if (!fun) {
				r_cons_message("Not in a function. Type 'df' to define it here");
				break;
			} else if (r_list_empty (fun->bbs)) {
				r_cons_message("No basic blocks in this function. You may want to use 'afb+'.");
				break;
			}
			ocolor = r_config_get_i (core->config, "scr.color");
			r_core_visual_graph (core, NULL, NULL, true);
			r_config_set_i (core->config, "scr.color", ocolor);
		}
		break;
	case 'v':
		r_core_visual_anal (core);
		break;
	case 'g':
		if (core->io->va) {
			ut64 offset = r_io_section_get_vaddr (core->io, 0);
			if (offset == -1)
				offset = 0;
			r_core_seek (core, offset, 1);
		} else r_core_seek (core, 0, 1);
		r_io_sundo_push (core->io, core->offset);
		break;
	case 'G':
		ret = 0;
		int scols = r_config_get_i (core->config, "hex.cols");
		if (core->file) {
			if (core->io->va) {
				ut64 offset = r_io_section_get_vaddr (core->io, 0);
				if (offset == UT64_MAX) {
					offset = r_io_desc_size (core->file->desc)
						- core->blocksize + 2*scols;
					ret = r_core_seek (core, offset, 1);
				} else {
					offset += r_io_desc_size (core->file->desc)
						- core->blocksize + 2 * scols;
					ret = r_core_seek (core, offset, 1);
				}
			} else {
				ret = r_core_seek (core,
						r_io_desc_size (core->file->desc)
						- core->blocksize + 2 * scols, 1);
			}
		} else {
			ret = -1;
		}
		if (ret != -1)
			r_io_sundo_push (core->io, core->offset);
		break;
	case 'h':
		if (curset) {
			cursor--;
			ocursor=-1;
			if (cursor<0) {
				r_core_seek_delta (core, -cols);
				cursor ++;
			}
		} else r_core_seek_delta (core, -1);
		break;
	case 'H':
		if (curset) {
			if (ocursor==-1) ocursor = cursor;
			cursor--;
			if (cursor<0) {
				r_core_seek (core, core->offset-cols, 1);
				cursor += cols;
				ocursor += cols;
			}
		} else r_core_seek_delta (core, -2);
		break;
	case 'l':
		if (curset) {
			cursor++;
			ocursor=-1;
			{
				int offscreen = (core->cons->rows-3)*cols;
				if (cursor>=offscreen) {
					r_core_seek (core, core->offset+cols, 1);
					cursor-=cols;
				}
			}
		} else r_core_seek_delta (core, 1);
		break;
	case 'L':
		if (curset) {
			if (ocursor==-1) ocursor = cursor;
			cursor++;
			offscreen = (core->cons->rows-3)*cols;
			if (cursor>=offscreen) {
				r_core_seek (core, core->offset+cols, 1);
				cursor -= cols;
				ocursor -= cols;
			}
		} else r_core_seek_delta (core, 2);
		break;
	case 'j':
		if (curset) {
			if (isDisasmPrint (core->printidx)) {
				// we read the size of the current mnemonic
				cols = r_asm_disassemble (core->assembler,
					&op, core->block+cursor, 32);
				if (cols<1) cols = 1;
				cursor += cols; // we move the cursor sizeof the current mnemonic
				ocursor = -1;
				if (cursor + core->offset > last_printed_address) {
					// we seek with the size of the first mnemo
					cols = r_asm_disassemble (core->assembler,
							&op, core->block, 32);
					r_core_seek (core, core->offset+cols, 1);
					cursor -= cols;
				}
			} else { // every other printmode
				if (cols<1) cols = 1;
				cursor += cols;
				ocursor = -1;
				offscreen = (core->cons->rows - 3) * cols;
				if (cursor > offscreen) {
					r_core_seek (core, core->offset+cols, 1);
					cursor -= cols;
				}
			}
		} else {
			int times = wheelspeed;
			if (times<1) times = 1;
			while (times--) {
				if (isDisasmPrint(core->printidx)) {
					RAnalFunction *f = NULL;
					if (true) {
						f = r_anal_get_fcn_in (core->anal, core->offset, 0);
					}
					if (f && f->folded) {
						cols = core->offset - f->addr + f->size;
					} else {
						r_asm_set_pc (core->assembler, core->offset);
						cols = r_asm_disassemble (core->assembler,
								&op, core->block, 32);
					}
					if (cols<1) cols = op.size;
					if (cols<1) cols = 1;
				}
				r_core_seek (core, core->offset + cols, 1);
			}
		}
		break;
	case 'J':
		if (curset) {
			if (isDisasmPrint (core->printidx)) {
				cols = r_asm_disassemble (core->assembler,
					&op, core->block+cursor, 32);
				if (cols<1) cols = 1;
			}
			if (ocursor==-1) ocursor = cursor;
			cursor += cols;
			if (isDisasmPrint (core->printidx)) {
				if (cursor + core->offset > last_printed_address) {
					// we seek with the size of the first mnemo
					cols = r_asm_disassemble (core->assembler,
							&op, core->block, 32);
					r_core_seek (core, core->offset+cols, 1);
					cursor-=cols;
					ocursor-=cols;
				}
			}
		} else {
			if (last_printed_address && last_printed_address > core->offset) {
				r_core_seek (core, last_printed_address, 1);
			} else {
				r_core_seek (core, core->offset+obs, 1);
			}
		}
		break;
	case 'k':
		if (curset) {
			if (isDisasmPrint (core->printidx)) {
				cols = prevopsz (core, core->offset + cursor);
			}
			cursor -= cols;
			ocursor = -1;
			if (cursor<0) {
				if (core->offset >= cols) {
					r_core_seek (core, core->offset - cols, 1);
					cursor += cols;
				}
			}
		} else {
			int times = wheelspeed;
			if (times<1) times = 1;
			while (times--) {
				if (isDisasmPrint (core->printidx)) {
					RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
					if (f && f->folded) {
						cols = core->offset - f->addr; // + f->size;
						if (cols<1) {
							cols = 4;
						}
					} else {
						cols = prevopsz (core, core->offset);
					}
				}
				r_core_seek (core, core->offset - cols, 1);
			}
		}
		break;
	case 'K':
		if (curset) {
			if (ocursor==-1) ocursor = cursor;
			if (isDisasmPrint (core->printidx)) {
				cols = prevopsz (core, core->offset+cursor);
			}
			cursor -= cols;
			if (cursor<0) {
				if (core->offset>=cols) {
					r_core_seek (core, core->offset-cols, 1);
					ocursor += cols;
					cursor += cols;
				} else {
					r_core_seek (core, 0, 1);
					cursor = 0;
				}
			}
		} else {
			if (last_printed_address > core->offset) {
				int delta = (last_printed_address - core->offset);
				if (core->offset >delta)
					r_core_seek (core, core->offset-delta, 1);
				else
					r_core_seek (core, 0, 1);
			} else {
				ut64 at = (core->offset>obs)?core->offset-obs:0;
				if (core->offset >obs)
					r_core_seek (core, at, 1);
				else
					r_core_seek (core, 0, 1);
			}
		}
		break;
	case '[':
		{
			int scrcols = r_config_get_i (core->config, "hex.cols");
			if (scrcols>2)
				r_config_set_i (core->config, "hex.cols", scrcols-2);
		}
		break;
	case ']':
		{
			int scrcols = r_config_get_i (core->config, "hex.cols");
			r_config_set_i (core->config, "hex.cols", scrcols+2);
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
			if (r_config_get_i (core->config, "cfg.debug")) {
				if (curset) {
					// dcu 0xaddr
					r_core_cmdf (core, "dcu 0x%08"PFMT64x, core->offset + cursor);
					curset = 0;
				} else {
					r_core_cmd (core, "ds", 0);
					r_core_cmd (core, ".dr*", 0);
				}
			} else {
				r_core_cmd (core, "aes", 0);
				r_core_cmd (core, ".ar*", 0);
			}
		}
		break;
	case 'S':
		key_s = r_config_get (core->config, "key.S");
		if (key_s && *key_s) {
			r_core_cmd0 (core, key_s);
		} else {
			if (r_config_get_i (core->config, "cfg.debug")) {
				if (curset) {
					r_core_cmd (core, "dcr", 0);
					curset = 0;
				} else {
					r_core_cmd (core, "dso", 0);
					r_core_cmd (core, ".dr*", 0);
				}
			} else {
				r_core_cmd (core, "aeso", 0);
				r_core_cmd (core, ".ar*", 0);
			}
		}
		break;
	case 'p':
		setprintmode (core, 1);
		break;
	case 'P':
		setprintmode (core, -1);
		break;
	case '%':
		if (curset) {
			findPair (core);
		} else {
			/* do nothing? */
			autoblocksize = !autoblocksize;
			if (autoblocksize)
				obs = core->blocksize;
			else r_core_block_size (core, obs);
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
		if (ocursor==-1) r_core_yank (core, core->offset+cursor, 1);
		else r_core_yank (core, core->offset+((ocursor<cursor)?
			ocursor:cursor), R_ABS (cursor-ocursor)+1);
		break;
	case 'Y':
		if (!core->yank_buf) {
			r_cons_strcat ("Cannot paste, clipboard is empty.\n");
			r_cons_flush ();
			r_cons_any_key (NULL);
			r_cons_clear00 ();
		} else r_core_yank_paste (core, core->offset+cursor, 0);
		break;
	case '-':
		if (core->print->cur_enabled) {
			int cur = core->print->cur;
			if (cur>=core->blocksize)
				cur = core->print->cur-1;
			if (ocursor==-1) sprintf (buf, "wos 01 @ $$+%i!1",cursor);
			else sprintf (buf, "wos 01 @ $$+%i!%i", cursor<ocursor?
				cursor:ocursor, R_ABS (ocursor-cursor)+1);
			r_core_cmd (core, buf, 0);
		} else {
			if (!autoblocksize)
				r_core_block_size (core, core->blocksize-1);
		}
		break;
	case '+':
		if (core->print->cur_enabled) {
			int cur = core->print->cur;
			if (cur>=core->blocksize)
				cur = core->print->cur-1;
			if (ocursor==-1) sprintf (buf, "woa 01 @ $$+%i!1", cursor);
			else sprintf (buf, "woa 01 @ $$+%i!%i",
				cursor<ocursor? cursor: ocursor, R_ABS (ocursor-cursor)+1);
			r_core_cmd (core, buf, 0);
		} else {
			if (!autoblocksize)
				r_core_block_size (core, core->blocksize+1);
		}
		break;
	case '/':
		if (curset) {
			visual_search (core);
		} else {
			if (autoblocksize) {
				r_core_cmd0 (core, "?i highlight;e scr.highlight=`?y`");
			} else {
				r_core_block_size (core, core->blocksize-cols);
			}
		}
		break;
	case '*':
		if (!autoblocksize)
			r_core_block_size (core, core->blocksize+cols);
		break;
	case '>':
		r_core_seek_align (core, core->blocksize, 1);
		r_io_sundo_push (core->io, core->offset);
		break;
	case '<':
		r_core_seek_align (core, core->blocksize, -1);
		r_core_seek_align (core, core->blocksize, -1);
		r_io_sundo_push (core->io, core->offset);
		break;
	case '.':
		r_io_sundo_push (core->io, core->offset);
		if (curset) {
			r_core_seek (core, core->offset+cursor, 1);
			cursor = 0;
		} else {
			ut64 addr = r_debug_reg_get (core->dbg, "PC");
			if (addr) {
				r_core_seek (core, addr, 1);
				r_core_cmdf (core, "ar `arn PC`=0x%"PFMT64x, addr);
			} else {
				r_core_seek (core, r_num_get (core->num, "entry0"), 1);
				//r_core_cmd (core, "s entry0", 0);
			}
		}
		break;
#if 0
	case 'n': r_core_seek_delta (core, core->blocksize); break;
	case 'N': r_core_seek_delta (core, 0-(int)core->blocksize); break;
#endif
	case ':':
		r_core_visual_prompt_input (core);
		break;
	case '_':
		r_core_visual_hudstuff (core);
		break;
	case ';':
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
			if (curset) {
				addr += cursor;
				r_core_seek (core, addr, 0);
				r_core_cmdf (core, "s 0x%"PFMT64x, addr);
			}
			if (!strcmp (buf + i, "-")) {
				strcpy (buf, "CC-");
			} else {
				switch (buf[i]) {
				case '-':
					memcpy (buf, "\"CC-", 4);
					break;
				case '!':
					memcpy (buf, "\"CC!", 4);
					break;
				default:
					memcpy (buf, "\"CC ", 4);
					break;
				}
				strcat (buf, "\"");
			}
			r_core_cmd (core, buf, 1);
			if (curset) r_core_seek (core, orig, 1);
		}
		r_cons_set_raw (true);
		showcursor (core, false);
		break;
	case 'b':
		{
 		ut64 addr = curset? core->offset + cursor : core->offset;
		RBreakpointItem *bp = r_bp_get_at (core->dbg->bp, addr);
		if (bp) {
			r_bp_del (core->dbg->bp, addr);
		} else {
			r_bp_add_sw (core->dbg->bp, addr, 1, R_BP_PROT_EXEC);
		}
		}
		break;
	case 'O':
		r_core_cmd0 (core, "e!asm.esil");
		break;
	case 'u':
		{
		ut64 off = r_io_sundo (core->io, core->offset);
		if (off != UT64_MAX) {
			r_core_visual_seek_animation (core, off);
		} else {
			eprintf ("Cannot undo\n");
		}
		}
		break;
	case 'U':
		{
		ut64 off = r_io_sundo_redo (core->io);
		if (off != UT64_MAX) {
			r_core_visual_seek_animation (core, off);
		}
		}
		break;
	case 'z':
		{
		RAnalFunction *fcn;
		if (curset) {
			fcn = r_anal_get_fcn_in (core->anal,
				core->offset+cursor, R_ANAL_FCN_TYPE_NULL);
		} else {
			fcn = r_anal_get_fcn_in (core->anal,
				core->offset, R_ANAL_FCN_TYPE_NULL);
		}
		if (fcn) {
			fcn->folded = !fcn->folded;
		} else {
			r_config_toggle (core->config, "asm.cmtfold");
		}
		}
		break;
	case 'Z':
		if (zoom && cursor) {
			ut64 from = r_config_get_i (core->config, "zoom.from");
			ut64 to = r_config_get_i (core->config, "zoom.to");
			r_core_seek (core, from + ((to-from)/core->blocksize)*cursor, 1);
		}
		zoom = !zoom;
		break;
	case '?':
		if (visual_help ()=='?')
			r_core_visual_hud (core);
		break;
	case 0x1b:
	case 'q':
	case 'Q':
		setcursor (core, 0);
		return false;
	}
	r_core_block_read (core, 0);
	return true;
}

#define PIDX (R_ABS(core->printidx%NPF))
R_API void r_core_visual_title (RCore *core, int color) {
	static ut64 oldpc = 0;
	const char *BEGIN = core->cons->pal.prompt;
	const char *filename;
	char pos[512], foo[512], bar[512], pcs[32];
	if (!oldpc) oldpc = core->offset;
	/* automatic block size */
	int pc, hexcols = r_config_get_i (core->config, "hex.cols");
	if (autoblocksize)
	switch (core->printidx) {
	case 0: // x"
	case 6: // pxa
		r_core_block_size (core, core->cons->rows * hexcols);
		break;
	case 3: // XXX pw
		r_core_block_size (core, core->cons->rows * hexcols);
		break;
	case 4: // XXX pc
		r_core_block_size (core, core->cons->rows * 5);
		break;
	case 1: // pd
	case 2: // pd+dbg
		r_core_block_size (core, core->cons->rows * 5); // this is hacky
		break;
	case 5: // pxA
		r_core_block_size (core, hexcols * core->cons->rows * 8);
		break;
	}

	if (r_config_get_i (core->config, "cfg.debug")) {
		ut64 curpc = r_debug_reg_get (core->dbg, "PC");
		if (curpc && curpc != UT64_MAX && curpc != oldpc) {
			// check dbg.follow here
			int follow = (int)(st64)r_config_get_i (core->config, "dbg.follow");
			if (follow>0) {
				if ((curpc<core->offset) || (curpc> (core->offset+follow)))
					r_core_seek (core, curpc, 1);
			} else if (follow<0) {
				r_core_seek (core, curpc+follow, 1);
			}
			oldpc = curpc;
		}
	}

	filename = (core->file && core->file->desc && core->file->desc->name)? core->file->desc->name: "";
	{ /* get flag with delta */
		ut64 addr = core->offset + (curset? cursor: 0);
		RFlagItem *f = r_flag_get_at (core->flags, addr);
		if (f) {
			if (f->offset == addr || !f->offset)
				snprintf (pos, sizeof (pos), "@ %s", f->name);
			else snprintf (pos, sizeof (pos), "@ %s+%d # 0x%"PFMT64x,
				f->name, (int)(addr-f->offset), addr);
		} else pos[0] = 0;
	}

	if (cursor<0) cursor = 0;

	if (color) r_cons_strcat (BEGIN);
	strncpy (bar, printfmt[PIDX], sizeof (bar)-1);

	bar[sizeof (bar)-1] = 0; // '\0'-terminate bar
	bar[10] = '.'; // chop cmdfmt
	bar[11] = '.'; // chop cmdfmt
	bar[12] = 0; // chop cmdfmt
	{
		ut64 sz = r_io_size (core->io);
		ut64 pa = r_io_section_vaddr_to_maddr_try (core->io, core->offset);
		if (sz == UT64_MAX) {
			pcs[0] = 0;
		} else {
			if (!sz || pa>sz) {
				pc = 0;
			} else {
				pc = ( pa * 100 ) / sz;
			}
			sprintf (pcs, "%d%% ", pc);
		}
	}
	if (curset)
		snprintf (foo, sizeof (foo), "[0x%08"PFMT64x" %s%d (0x%x:%d=%d)]> %s %s\n",
				core->offset, pcs, core->blocksize,
				cursor, ocursor, ocursor==-1?1:R_ABS (cursor-ocursor)+1,
				bar, pos);
	else
		snprintf (foo, sizeof (foo), "[0x%08"PFMT64x" %s%d %s]> %s %s\n",
			core->offset, pcs, core->blocksize, filename, bar, pos);
	r_cons_printf ("%s", foo);
	if (color) r_cons_strcat (Color_RESET);
}

static int r_core_visual_responsive (RCore *core) {
	int h, w = r_cons_get_size (&h);
	if (r_config_get_i (core->config, "scr.responsive")) {
		if (w<110) {
			r_config_set_i (core->config, "asm.cmtright", 0);
		} else {
			r_config_set_i (core->config, "asm.cmtright", 1);
		}
		if (w<68) {
			r_config_set_i (core->config, "hex.cols", w/5.2);
		} else {
			r_config_set_i (core->config, "hex.cols", 16);
		}
		if (w<25) {
			r_config_set_i (core->config, "asm.offset", 0);
		} else {
			r_config_set_i (core->config, "asm.offset", 1);
		}
		if (w>80) {
			r_config_set_i (core->config, "asm.lineswidth", 14);
			r_config_set_i (core->config, "asm.lineswidth", w-(w/1.2));
			r_config_set_i (core->config, "asm.cmtcol", w-(w/2.5));
		} else {
			r_config_set_i (core->config, "asm.lineswidth", 7);
		}
		if (w<70) {
			r_config_set_i (core->config, "asm.lineswidth", 1);
			r_config_set_i (core->config, "asm.bytes", 0);
		} else {
			r_config_set_i (core->config, "asm.bytes", 1);
		}
	}
	return w;
}

static void r_core_visual_refresh (RCore *core) {
	int w;
	const char *vi, *vcmd;
	if (!core) return;
	r_print_set_cursor (core->print, curset, ocursor, cursor);
	core->cons->blankline = true;

	w = r_core_visual_responsive (core);

	if (autoblocksize) {
		r_cons_gotoxy (0, 0);
	} else {
		r_cons_clear ();
	}
	r_cons_flush ();
	r_cons_print_clear ();

	vi = r_config_get (core->config, "cmd.cprompt");
	if (vi && *vi) {
		// XXX: slow
		core->cons->blankline = false;
		r_cons_clear00 ();
		r_cons_flush ();
		{
		       int hc = r_config_get_i (core->config, "hex.cols");
		       int nw = 12 + 4 + hc + (hc*3);
		       if (nw>w) {
				// do not show column contents
			} else {
				r_cons_printf ("[cmd.cprompt=%s]\n", vi);
				r_core_cmd0 (core, vi);
				r_cons_column (nw);
				r_cons_flush ();
			}
		}
		r_cons_gotoxy (0, 0);
		r_core_visual_title (core, color);
		vi = r_config_get (core->config, "cmd.vprompt");
		if (vi) r_core_cmd (core, vi, 0);
	} else {
		vi = r_config_get (core->config, "cmd.vprompt");
		if (vi) r_core_cmd (core, vi, 0);
		r_core_visual_title (core, color);
	}

	core->screen_bounds = 1LL;
	vcmd = r_config_get (core->config, "cmd.visual");
	if (vcmd && *vcmd) {
		r_core_cmd (core, vcmd, 0);
	} else {
		if (zoom) r_core_cmd0 (core, "pz");
		else r_core_cmd0 (core, printfmt[PIDX]);
	}
// TODO: rename screen_bounds to offset_last ?
	if (core->screen_bounds != 1LL) {
		last_printed_address = core->screen_bounds;
		r_cons_printf ("[0x%08"PFMT64x"..0x%08"PFMT64x"]\n",
			core->offset, core->screen_bounds);
	}
	core->screen_bounds = 0LL; // disable screen bounds
	blocksize = core->num->value? core->num->value : core->blocksize;

	/* this is why there's flickering */
	r_cons_visual_flush ();
	core->cons->blankline = true;
}

R_API int r_core_visual(RCore *core, const char *input) {
	const char *cmdprompt, *teefile;
	ut64 scrseek;
	int wheel, flags, ch;

	if (r_cons_get_size (&ch)<1 || ch<1) {
		eprintf ("Cannot create Visual context. Use scr.fix_{columns|rows}\n");
		return 0;
	}

	obs = core->blocksize;
	//r_cons_set_cup (true);

	core->vmode = false;
	while (*input) {
		if (!r_core_visual_cmd (core, input[0]))
			return 0;
		input++;
	}
	core->vmode = true;

	// disable tee in cons
	teefile = r_cons_singleton ()->teefile;
	r_cons_singleton ()->teefile = "";

	core->print->flags |= R_PRINT_FLAGS_ADDRMOD;
	do {
		if (core->printidx == 2) {
			static char debugstr[512];
			const char *cmdvhex = r_config_get (core->config, "cmd.stack");
			const int ref = r_config_get_i (core->config, "dbg.slow");
			const int pxa = r_config_get_i (core->config, "stack.anotated"); // stack.anotated
			const int size = r_config_get_i (core->config, "stack.size");
			const int delta = r_config_get_i (core->config, "stack.delta");
			const int bytes = r_config_get_i (core->config, "stack.bytes");
			if (cmdvhex && *cmdvhex) {
				snprintf (debugstr, sizeof(debugstr),
					"f tmp;sr SP;%s;%s;s-;"
					"s tmp;f-tmp;pd $r", cmdvhex,
					ref? "drr": "dr=");
				debugstr[sizeof(debugstr)-1]=0;
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
				snprintf (debugstr, sizeof (debugstr),
					"f tmp;sr SP;%s %d@$$-%d;%s;s-;"
					"s tmp;f-tmp;pd $r",
					pxa? "pxa": pxw, size, delta,
					ref? "drr": "dr=");
			}
			printfmt[2] = debugstr;
		}
		wheel = r_config_get_i (core->config, "scr.wheel");
		r_cons_show_cursor (false);
		if (wheel) r_cons_enable_mouse (true);
		core->cons->event_data = core;
		core->cons->event_resize = (RConsEvent)r_core_visual_refresh;
		flags = core->print->flags;
		color = r_config_get_i (core->config, "scr.color");
		if (color) flags |= R_PRINT_FLAGS_COLOR;
		debug = r_config_get_i (core->config, "cfg.debug");
		flags |= R_PRINT_FLAGS_ADDRMOD | R_PRINT_FLAGS_HEADER;
		r_print_set_flags (core->print, core->print->flags);
		scrseek = r_num_math (core->num,
			r_config_get (core->config, "scr.seek"));
		if (scrseek != 0LL)
			r_core_seek (core, scrseek, 1);
		if (debug)
			r_core_cmd (core, ".dr*", 0);
		cmdprompt = r_config_get (core->config, "cmd.vprompt");
		if (cmdprompt && *cmdprompt)
			r_core_cmd (core, cmdprompt, 0);
		r_core_visual_refresh (core);
		ch = r_cons_readchar ();
		r_core_visual_show_char (core, ch);
		if (ch==-1 || ch==4) break; // error or eof
	} while (r_core_visual_cmd (core, ch));

	r_cons_enable_mouse (false);
	if (color)
		r_cons_printf (Color_RESET);
	r_config_set_i (core->config, "scr.color", color);
	core->print->cur_enabled = false;
	if (autoblocksize)
		r_core_block_size (core, obs);
	r_cons_singleton ()->teefile = teefile;
	r_cons_set_cup (false);
	r_cons_clear00 ();
	core->vmode = false;
	core->cons->event_resize = NULL;
	core->cons->event_data = NULL;
	r_cons_show_cursor (true);
	return 0;
}
