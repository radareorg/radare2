/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

#include "r_core.h"

#define NPF 6
static int blocksize = 0;
static const char *printfmt[] = { "x", "pd", "f tmp;sr sp;pw 64;dr=;s-;s tmp;f-tmp;pd", "p8", "pc", "ps" };
static int autoblocksize = 1;
static int obs = 0;

// XXX: use core->print->cur_enabled instead of curset/cursor/ocursor
static int curset = 0, cursor = 0, ocursor=-1;
static int color = 1;
static int debug = 1;
static int flags = R_PRINT_FLAGS_ADDRMOD;
static int zoom = 0;

static int marks_init = 0;
static ut64 marks[UT8_MAX+1];

static void r_core_visual_mark_seek(RCore *core, ut8 ch) {
	if (!marks_init) {
		int i;
		for (i=0;i<UT8_MAX;i++)
			marks[i] = 0;
		marks_init = 1;
	}
	if (marks[ch])
		r_core_seek (core, marks[ch], 1);
}

static void r_core_visual_mark(RCore *core, ut8 ch) {
	if (!marks_init) {
		int i;
		for (i=0;i<UT8_MAX;i++)
			marks[i] = 0;
		marks_init = 1;
	}
	marks[ch] = core->offset;
}

R_API void r_core_visual_prompt (RCore *core) {
	char buf[1024];
	ut64 oseek = core->offset;
	r_line_set_prompt (":> ");
	r_cons_fgets (buf, sizeof (buf), 0, NULL);
	r_core_cmd (core, buf, 0);
	r_cons_any_key ();
	if (curset) r_core_seek (core, oseek, 1);
}

static int visual_fkey(RCore *core, int ch) {
	const char *cmd;
	switch (ch) {
	case R_CONS_KEY_F1:
		cmd = r_config_get (core->config, "key.f1");
		if (cmd && *cmd) return r_core_cmd0 (core, cmd); 
		ch = '?';
		break;
	case R_CONS_KEY_F2:
		cmd = r_config_get (core->config, "key.f2");
		if (cmd && *cmd) return r_core_cmd0 (core, cmd);
		// TODO: toggle breakpoint
		break;
	case R_CONS_KEY_F3:
		cmd = r_config_get (core->config, "key.f3");
		if (cmd && *cmd) return r_core_cmd0 (core, cmd);
		// TODO: F3
		break;
	case R_CONS_KEY_F4:
		cmd = r_config_get (core->config, "key.f4");
		if (cmd && *cmd) return r_core_cmd0 (core, cmd);
		// TODO: F4
	case R_CONS_KEY_F5:
		cmd = r_config_get (core->config, "key.f5");
		if (cmd && *cmd) return r_core_cmd0 (core, cmd);
		// TODO: F5
	case R_CONS_KEY_F6:
		cmd = r_config_get (core->config, "key.f6");
		if (cmd && *cmd) return r_core_cmd0 (core, cmd);
		// TODO: F6
		break;
	case R_CONS_KEY_F7:
		cmd = r_config_get (core->config, "key.f7");
		if (cmd && *cmd) return r_core_cmd0 (core, cmd);
		ch = 's';
		break;
	case R_CONS_KEY_F8:
		cmd = r_config_get (core->config, "key.f8");
		if (cmd && *cmd) return r_core_cmd0 (core, cmd);
		// TODO: F8
		break;
	case R_CONS_KEY_F9:
		cmd = r_config_get (core->config, "key.f9");
		if (cmd && *cmd) return r_core_cmd0 (core, cmd);
		r_core_cmd0 (core, "dc");
		break;
	case R_CONS_KEY_F10:
		cmd = r_config_get (core->config, "key.f10");
		if (cmd && *cmd) return r_core_cmd0 (core, cmd);
		break;
	case R_CONS_KEY_F11:
		cmd = r_config_get (core->config, "key.f11");
		if (cmd && *cmd) return r_core_cmd0 (core, cmd);
		break;
	case R_CONS_KEY_F12:
		cmd = r_config_get (core->config, "key.f12");
		if (cmd && *cmd) return r_core_cmd0 (core, cmd);
		break;
	}
	return ch;
}

/* TODO: use r_cmd here in core->vcmd..optimize over 255 table */ 
R_API int r_core_visual_cmd(RCore *core, int ch) {
	RAsmOp op;
	char buf[4096];
	int i, cols = core->print->cols;
	ch = r_cons_arrow_to_hjkl (ch);
	ch = visual_fkey (core, ch);
	if (ch<2) return 1;

	// do we need hotkeys for data references? not only calls?
	if (ch>='0'&&ch<='9') {
		r_core_seek (core, core->asmqjmps[ch-'0'], 1);
		r_io_sundo_push (core->io);
	} else
	switch (ch) {
	case 'c':
		// XXX dupped flag imho
		curset ^= 1;
		if (curset) flags|=R_PRINT_FLAGS_CURSOR; 
		else flags &= ~(flags&R_PRINT_FLAGS_CURSOR);
		r_print_set_flags (core->print, flags);
		break;
	case 'd':
		r_core_visual_define (core);
		break;
	case 'C':
		color ^= 1;
		if (color) flags |= R_PRINT_FLAGS_COLOR;
		else flags &= ~(flags&R_PRINT_FLAGS_COLOR);
		r_config_set_i (core->config, "scr.color", color);
		r_print_set_flags (core->print, flags);
		break;
	case 'f':
		r_core_seek_next (core, r_config_get (core->config, "scr.fkey"));
		break;
	case 'F':
		r_core_seek_previous (core, r_config_get (core->config, "scr.fkey"));
		break;
	case 'a':
		r_cons_printf ("Enter assembler opcodes separated with ';':\n");
		r_cons_flush ();
		r_cons_set_raw (R_FALSE);
		strcpy (buf, "wa ");
		r_line_set_prompt (":> ");
		if (r_cons_fgets (buf+3, 1000, 0, NULL) <0) buf[0]='\0';
		if (*buf) {
			if (curset) r_core_seek (core, core->offset + cursor, 0);
			r_core_cmd (core, buf, R_TRUE);
			if (curset) r_core_seek (core, core->offset - cursor, 1);
		}
		r_cons_set_raw (R_TRUE);
		break;
	case 'w':
		r_cons_printf ("Enter hexpair string to write:\n");
		r_cons_flush ();
		r_cons_set_raw (0);
		strcpy (buf, "wx ");
		r_line_set_prompt ("hex: ");
		if (r_cons_fgets (buf+3, 1000, 0, NULL) <0) buf[0]='\0';
		if (*buf) {
			if (curset) r_core_seek (core, core->offset + cursor, 0);
			r_core_cmd (core, buf, 1);
			if (curset) r_core_seek (core, core->offset - cursor, 1);
		}
		r_cons_set_raw (1);
		break;
	case 'e':
		r_core_visual_config (core);
		break;
	case 'M':
		r_core_visual_mounts (core);
		break;
	case 't':
		r_core_visual_trackflags (core);
		break;
	case 'T':
		r_core_visual_comments (core);
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
		} else
			r_core_cmd (core, "s 0", 0);
		r_io_sundo_push (core->io);
		break;
	case 'G':
{
		int ret = 0;
		if (core->io->va) {
			ut64 offset = r_io_section_get_vaddr (core->io, 0);
			//ut64 offset = r_io_section_get_vaddr (core->io,
			//	core->file->size-core->blocksize);
			if (offset == UT64_MAX) {
				ret = r_core_seek (core, offset, 1);
				memset (core->block, 0xff, core->blocksize);
			} else {
				offset += core->file->size - core->blocksize;
				ret = r_core_seek (core, offset, 1);
				memset (core->block, 0xff, core->blocksize);
			}
		} else ret = r_core_seek (core, core->file->size-core->blocksize, 1);
		if (ret != -1)
			r_io_sundo_push (core->io);
}
		break;
	case 'h':
		if (curset) {
			cursor--;
			ocursor=-1;
			if (cursor<0) {
				r_core_seek (core, core->offset-cols, 1);
				cursor ++;
			}
		} else r_core_cmd (core, "s-1", 0);
		break;
	case 'H':
		if (curset) {
			if (ocursor==-1) ocursor=cursor;
			cursor--;
			if (cursor<0) {
				r_core_seek (core, core->offset-cols, 1);
				cursor += cols;
				ocursor += cols;
			}
		} else r_core_cmd (core, "s-2", 0);
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
		} else r_core_cmd (core, "s+1", 0);
		break;
	case 'L':
		if (curset) {
			if (ocursor==-1) ocursor=cursor;
			cursor++;
			{
				int offscreen = (core->cons->rows-3)*cols;
				if (cursor>=offscreen) {
					r_core_seek (core, core->offset+cols, 1);
					cursor-=cols;
					ocursor-=cols;
				}
			}
		} else r_core_cmd (core, "s+2", 0);
		break;
	case 'j':
		if (curset) {
			if (core->printidx == 1 || core->printidx == 2)
				cols = r_asm_disassemble (core->assembler, &op, core->block+cursor, 32);
			cursor += cols;
			ocursor = -1;
			{
				int offscreen = (core->cons->rows-3)*cols;
				if (cursor>=offscreen) {
					r_core_seek (core, core->offset+cols, 1);
					cursor-=cols;
				}
			}
		} else {
			if (core->printidx == 1 || core->printidx == 2) {
				cols = core->inc;
				core->asmsteps[core->curasmstep].offset = core->offset+cols;
				core->asmsteps[core->curasmstep].cols = cols;
				if (core->curasmstep < R_CORE_ASMSTEPS-1)
					core->curasmstep++;
				else core->curasmstep = 0;
			}
			r_core_seek (core, core->offset+cols, 1);
		}
		break;
	case 'J':
		if (curset) {
			if (ocursor==-1) ocursor = cursor;
			cursor += cols;
			{
				int offscreen = (core->cons->rows-3)*cols;
				if (cursor>=offscreen) {
					r_core_seek (core, core->offset+cols, 1);
					cursor-=cols;
					ocursor-=cols;
				}
			}
		} else r_core_seek (core, core->offset+obs, 1);
		break;
	case 'k':
		if (curset) {
			if (core->printidx == 1 || core->printidx == 2)
				cols = 4; //r_asm_disassemble (core->assembler, &op, core->block, 32);
			cursor -= cols;
			ocursor = -1;
			if (cursor<0) {
				if (core->offset>=cols)
					r_core_seek (core, core->offset-cols, 1);
				cursor += cols;
			}
		} else {
			if (core->printidx == 1 || core->printidx == 2) {
				int i;
				cols = core->inc;
				for (i = 0; i < R_CORE_ASMSTEPS; i++)
					if (core->offset == core->asmsteps[i].offset)
						cols = core->asmsteps[i].cols;
			}
			if (core->offset >= cols)
				r_core_seek (core, core->offset-cols, 1);
			else r_core_seek (core, 0, 1);
		}
		break;
	case 'K':
		if (curset) {
			if (ocursor==-1) ocursor=cursor;
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
			ut64 at = (core->offset>obs)?core->offset-obs:0;
			r_core_seek (core, at, 1);
		}
		break;
	case '[':
		{
			int scrcols = r_config_get_i (core->config, "scr.cols");
			if (scrcols>2)
				r_config_set_i (core->config, "scr.cols", scrcols-2);
		}
		break;
	case ']':
		{
			int scrcols = r_config_get_i (core->config, "scr.cols");
			//if (scrcols<32)
				r_config_set_i (core->config, "scr.cols", scrcols+2);
		}
		break;
	case 's':
		r_core_cmd (core, "ds", 0);
		r_core_cmd (core, ".dr*", 0);
		//r_core_cmd(core, "s eip", 0);
		break;
	case 'S':
		r_core_cmd (core, "dso", 0);
		r_core_cmd (core, ".dr*", 0);
		//r_core_cmd(core, "s eip", 0);
		break;
	case 'p':
		core->printidx = (core->printidx+1)%NPF;
		break;
	case 'P':
		core->printidx = (core->printidx-1)%NPF;
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
		if (!core->yank) {
			r_cons_strcat ("Can't paste, clipboard is empty.\n");
			r_cons_flush ();
			r_cons_any_key ();
		} else r_core_yank_paste (core, core->offset+cursor, 0);
		break;
	case '-':
		if (core->print->cur_enabled) {
			int cur = core->print->cur;
			if (cur>=core->blocksize)
				cur = core->print->cur-1;
			if (ocursor==-1) sprintf (buf, "wos 01 @ $$+%i:1",cursor);
			else sprintf (buf, "wos 01 @ $$+%i:%i", cursor<ocursor?
				cursor:ocursor, R_ABS (ocursor-cursor)+1);
			r_core_cmd (core, buf, 0);
		} else r_core_block_size (core, core->blocksize-1);
		break;
	case '+':
		if (core->print->cur_enabled) {
			int cur = core->print->cur;
			if (cur>=core->blocksize)
				cur = core->print->cur-1;
			if (ocursor==-1) sprintf (buf, "woa 01 @ $$+%i:1", cursor);
			else sprintf (buf, "woa 01 @ $$+%i:%i",
				cursor<ocursor? cursor: ocursor, R_ABS (ocursor-cursor)+1);
			r_core_cmd (core, buf, 0);
		} else r_core_block_size (core, core->blocksize+1);
		break;
	case '/':
		r_core_block_size (core, core->blocksize-cols);
		break;
	case '*':
		r_core_block_size (core, core->blocksize+cols);
		break;
	case '>':
		r_core_seek_align (core, core->blocksize, 1);
		r_io_sundo_push (core->io);
		break;
	case '<':
		r_core_seek_align (core, core->blocksize, -1);
		r_core_seek_align (core, core->blocksize, -1);
		r_io_sundo_push (core->io);
		break;
	case '.':
		r_core_cmd (core, "sr pc", 0); // XXX
		break;
	case 'n':
		r_core_seek (core, core->offset + (core->num->value/4), 1);
		break;
	case 'N':
		r_core_seek (core, core->offset - (core->num->value/4), 1);
		break;
	case ':':
		r_core_visual_prompt (core);
		break;
	case ';':
		r_cons_printf ("Enter a comment: ('-' to remove, '!' to use $EDITOR)\n");
		r_cons_flush ();
		r_cons_set_raw (R_FALSE);
		strcpy (buf, "CC ");
		r_line_set_prompt ("comment: ");
		i = strlen (buf);
		if (r_cons_fgets (buf+i, sizeof (buf)-i-1, 0, NULL) >1) {
			ut64 orig = core->offset;
			ut64 addr = core->offset;
			if (curset) {
				addr += cursor;
				r_core_seek (core, addr, 0);
			}
			switch (buf[i]) {
			case '-':
				strcpy (buf, "CC-");
				break;
			case '!':
				strcpy (buf, "CC!");
				break;
			}
			r_core_cmd (core, buf, 1);
			if (curset) r_core_seek (core, orig, 1);
		}
		r_cons_set_raw (R_TRUE);
		break;
	case 'B':
		autoblocksize = !autoblocksize;
		if (autoblocksize)
			obs = core->blocksize;
		else r_core_block_size (core, obs);
		break;
	case 'u':
		if (r_io_sundo (core->io))
			r_core_seek (core, core->io->off, 1);
		break;
	case 'U':
		if (r_io_sundo_redo (core->io))
			r_core_seek (core, core->io->off, 1);
		break;
	case 'x':
		r_core_cmdf (core, "./a 0x%08llx @ entry0", core->offset);
		break;
	case 'z':
		if (zoom && cursor) {
			ut64 from = r_config_get_i (core->config, "zoom.from");
			ut64 to = r_config_get_i (core->config, "zoom.to");
			r_core_seek (core, from + ((to-from)/core->blocksize)*cursor, 1);
		}
		zoom = !zoom;
		break;
	case '?':
		r_cons_clear00 ();
		r_cons_printf (
		"\nVisual mode help:\n\n"
		" >||<    - seek aligned to block size\n"
		" hjkl    - move around\n"
		" HJKL    - move around faster\n"
		" pP      - rotate print modes\n"
		" /*+-[]  - change block size, [] = resize scr.cols\n"
		" cC      - toggle cursor and colors\n"
		" gG      - go seek to begin and end of file (0-$s)\n"
		" d[f?]   - define function, data, code, ..\n"
		" x       - find xrefs for current offset\n"
		" sS      - step / step over\n"
		" e       - edit eval configuration variables\n"
		" t       - track flags (browse symbols, functions..)\n"
		" T       - browse anal info and comments\n"
		" v       - visual code analysis menu\n"
		" fF      - seek next/prev function/flag/hit (scr.fkey)\n"
		" B       - toggle automatic block size\n"
		" uU      - undo/redo seek\n"
		" yY      - copy and paste selection\n"
		" mK/'K   - mark/go to Key (any key)\n"
		" M       - show mount points\n"
		" :cmd    - run radare command\n"
		" ;[-]cmt - add/remove comment\n"
		" .       - seek to program counter\n"
		" z       - toggle zoom mode\n"
		" q       - back to radare shell\n");
		r_cons_flush ();
		r_cons_any_key ();
		break;
	case 'q':
	case 'Q':
		return R_FALSE;
	}
	return R_TRUE;
}

// TODO: simplify R_ABS(printidx%NPF) into a macro, or just control negative values..
R_API void r_core_visual_title (RCore *core, int color) {
	const char *filename;
	char pos[512];
	/* automatic block size */
	if (autoblocksize)
	switch (core->printidx) {
	case 0:
		{
		int scrcols = r_config_get_i (core->config, "scr.cols");
		r_core_block_size (core, core->cons->rows * scrcols);
		}
		break;
	case 1: // pd
	case 2: // pd+dbg
		r_core_block_size (core, core->cons->rows * 5); // this is hacky
		break;
	}

	if (core->file && core->file->filename)
		filename = core->file->filename;
	else filename = "";
	{ /* get flag with delta */
		RFlagItem *f = r_flag_get_at (core->flags, core->offset);
		if (f) {
			if (f->offset == core->offset) snprintf (pos, sizeof (pos), "@ %s", f->name);
			else snprintf (pos, sizeof (pos), "@ %s+%d ((%llx))", f->name, (int)(core->offset-f->offset), f->offset);
		} else pos[0] = 0;
	}

	if (cursor<0) cursor = 0;
	if (color) r_cons_strcat (Color_YELLOW);
	if (curset) r_cons_printf ("[0x%08"PFMT64x" %d %s(%d:%d=%d)]> %s\n", core->offset,
		core->blocksize, core->file->filename, cursor, ocursor,
		ocursor==-1?1:R_ABS (cursor-ocursor)+1, printfmt[R_ABS (core->printidx%NPF)]);
	else r_cons_printf ("[0x%08"PFMT64x" %d %s]> %s %s\n", core->offset, core->blocksize,
		filename, printfmt[R_ABS (core->printidx%NPF)], pos);
	//r_cons_printf (" %d %d %d\n", core->printidx, core->cons->rows, core->blocksize);
	if (color) r_cons_strcat (Color_RESET);
}

static void r_core_visual_refresh (RCore *core) {
	const char *vi;
	r_cons_get_size (NULL);
	r_print_set_cursor (core->print, curset, ocursor, cursor);
	r_cons_clear00 ();

	vi = r_config_get (core->config, "cmd.vprompt");
	if (vi) r_core_cmd (core, vi, 0);
	r_core_visual_title (core, color);

	vi = r_config_get (core->config, "cmd.cprompt");
	if (vi && *vi) {
		r_cons_printf ("\n[cmd.cprompt] %s\n", vi);
		r_core_cmd (core, vi, 0);
		r_cons_column (80);
	}

	if (zoom) r_core_cmd (core, "pZ", 0);
	else r_core_cmd (core, printfmt[R_ABS (core->printidx%NPF)], 0);
	blocksize = core->num->value? core->num->value : core->blocksize;
	r_cons_visual_flush ();
}

R_API int r_core_visual(RCore *core, const char *input) {
	const char *cmdprompt, *teefile;
	ut64 scrseek;
	int ch;
	obs = core->blocksize;

	core->visual = R_TRUE;
	r_cons_singleton ()->data = core;
	r_cons_singleton ()->event_resize = (RConsEvent)r_core_visual_refresh;
	r_cons_set_cup (R_TRUE);

	while (*input) {
		if (!r_core_visual_cmd (core, input[0])) {
			r_cons_clear00 ();
			r_core_cmd (core, printfmt[R_ABS (core->printidx%NPF)], 0);
			r_cons_visual_flush ();
			r_cons_any_key ();
			r_cons_set_cup (R_FALSE);
			return 0;
		}
		input++;
	}

	// disable tee in cons
	teefile = r_cons_singleton ()->teefile;
	r_cons_singleton ()->teefile = "";

	color = r_config_get_i (core->config, "scr.color");
	debug = r_config_get_i (core->config, "cfg.debug");
	flags = R_PRINT_FLAGS_ADDRMOD | R_PRINT_FLAGS_HEADER;
	if (color) flags |= R_PRINT_FLAGS_COLOR;
	do {
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
	} while (r_core_visual_cmd (core, ch));

	if (color)
		r_cons_printf (Color_RESET);
	core->print->cur_enabled = R_FALSE;
	if (autoblocksize)
		r_core_block_size (core, obs);
	r_cons_singleton ()->teefile = teefile;
	r_cons_set_cup (R_FALSE);
	core->visual = R_FALSE;
	return 0;
}
