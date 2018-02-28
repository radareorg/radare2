/* radare - LGPL - Copyright 2009-2018 - nibble, pancake, dso */

#include "r_core.h"
#include "r_cons.h"

#define HASRETRY 1
#define HAVE_LOCALS 1
#define DEFAULT_NARGS 4

#define R_MIDFLAGS_SHOW 1
#define R_MIDFLAGS_REALIGN 2
#define R_MIDFLAGS_SYMALIGN 3

#define COLOR(ds, field) (ds->show_color ? ds->field : "")
#define COLOR_CONST(ds, color) (ds->show_color ? Color_ ## color : "")
#define COLOR_RESET(ds) COLOR_CONST(ds, RESET)

// ugly globals but meh
static ut64 emustack_min = 0LL;
static ut64 emustack_max = 0LL;

static const char* r_vline_a[] = {
	"|",  // LINE_VERT
	"|-", // LINE_CROSS
	"-",  // LINE_HORIZ
	":",  // LINE_UP
	",",  // LUP_CORNER
	"\\", // RDWN_CORNER
	"/",  // RUP_CORNER
	"`",  // LDWN_CORNER
	"->", // ARROW_RIGHT
	"=<", // ARROW_LEFT
};

static const char* r_vline_u[] = {
	"│", // LINE_VERT
	"├", // LINE_CROSS
	"─", // LINE_HORIZ
	"⁝", // LINE_UP
	// "↑", // LINE_UP
	//"┌", // LUP_CORNER
	"┘", // LUP_CORNER
	"└", // RDWN_CORNER
	"┌", // RUP_CORNER
	"┐", // LDWN_CORNER
	">", // ARROW_RIGHT
	"<", // ARROW_LEFT
};

static const char* r_vline_uc[] = {
	"│", // LINE_VERT
	"├", // LINE_CROSS
	"─", // LINE_HORIZ
	"↑", // LINE_UP
	//"┌", // LUP_CORNER
	"╯", // LUP_CORNER
	"╰", // RDWN_CORNER
	"╭", // RUP_CORNER
	"╮", // LDWN_CORNER
	">", // ARROW_RIGHT
	"<", // ARROW_LEFT
};


#define DS_PRE_NONE         0
#define DS_PRE_EMPTY        1
#define DS_PRE_FCN_HEAD     2
#define DS_PRE_FCN_MIDDLE   3
#define DS_PRE_FCN_TAIL     4

// TODO: what about using bit shifting and enum for keys? see libr/util/bitmap.c
// the problem of this is that the fields will be more opaque to bindings, but we will earn some bits
typedef struct {
	RCore *core;
	char str[1024], strsub[1024];
	bool immtrim;
	bool immstr;
	bool use_esil;
	bool show_color;
	bool show_color_bytes;
	int colorop;
	int acase;
	bool capitalize;
	bool show_flgoff;
	bool hasMidflag;
	int atabs;
	int atabsonce;
	int atabsoff;
	int decode;
	bool pseudo;
	int filter;
	int interactive;
	bool jmpsub;
	bool varsub;
	bool show_lines;
	bool show_lines_ret;
	bool show_lines_call;
	int linesright;
	int tracespace;
	int cyclespace;
	int cmtfold;
	int show_indent;
	bool show_dwarf;
	bool show_size;
	bool show_trace;
	bool highlight;
	bool show_family;
	bool asm_describe;
	int linesout;
	int adistrick;
	int asm_demangle;
	bool show_offset;
	bool show_offdec; // dupe for r_print->flags
	bool show_bbline;
	bool show_emu;
	bool pre_emu;
	bool show_emu_str;
	bool show_asm_bbinfo;
	bool show_emu_stroff;
	bool show_emu_stack;
	bool show_emu_write;
	bool show_section;
	int show_section_col;
	bool show_symbols;
	int show_symbols_col;
	bool show_offseg;
	bool show_flags;
	bool bblined;
	bool show_bytes;
	bool show_reloff;
	bool show_reloff_flags;
	bool show_comments;
	bool show_jmphints;
	bool show_leahints;
	bool show_slow;
	int cmtcol;
	bool show_fcnlines;
	bool show_calls;
	bool show_cmtflgrefs;
	bool show_cycles;
	bool show_stackptr;
	int stackFd;
	bool show_xrefs;
	bool show_cmtrefs;
	const char *show_cmtoff;
	bool show_functions;
	bool show_fcncalls;
	bool show_hints;
	bool show_marks;
	bool show_asciidot;
	RStrEnc strenc;
	int cursor;
	int show_comment_right_default;
	int flagspace_ports;
	int show_flag_in_bytes;
	int lbytes;
	int show_comment_right;
	int pre;
	char *ocomment;
	int linesopts;
	int lastfail;
	int ocols;
	int lcols;
	int nb, nbytes;
	int show_utf8;
	int lines;
	int oplen;
	bool show_varxs;
	bool show_vars;
	int show_varsum;
	int midflags;
	bool midcursor;
	bool show_noisy_comments;
	const char *pal_comment;
	const char *color_comment;
	const char *color_usrcmt;
	const char *color_fname;
	const char *color_floc;
	const char *color_fline;
	const char *color_flow;
	const char *color_flow2;
	const char *color_flag;
	const char *color_label;
	const char *color_other;
	const char *color_nop;
	const char *color_bin;
	const char *color_math;
	const char *color_btext;
	const char *color_jmp;
	const char *color_cjmp;
	const char *color_call;
	const char *color_cmp;
	const char *color_swi;
	const char *color_trap;
	const char *color_ret;
	const char *color_push;
	const char *color_pop;
	const char *color_reg;
	const char *color_num;
	const char *color_mov;
	const char *color_invalid;
	const char *color_gui_cflow;
	const char *color_gui_dataoffset;
	const char *color_gui_background;
	const char *color_gui_alt_background;
	const char *color_gui_border;

	RFlagItem *lastflag;
	RAnalHint *hint;
	RPrint *print;

	ut64 esil_old_pc;
	ut8* esil_regstate;
	bool esil_likely;

	int l;
	int middle;
	int indent_level;
	int indent_space;
	char *line;
	char *refline, *refline2;
	char *comment;
	char *opstr;
	char *osl, *sl;
	int stackptr, ostackptr;
	int index;
	ut64 at, vat, addr, dest;
	int tries, cbytes, idx;
	char chref;
	bool retry;
	bool mi_found;
	RAsmOp asmop;
	RAnalOp analop;
	RAnalFunction *fcn;
	const ut8 *buf;
	int len;
	int maxrefs;
	char *prev_ins;
	bool prev_ins_eq;
	int prev_ins_count;
	bool show_nodup;
	bool has_description;
	// caches
	char *_tabsbuf;
	int _tabsoff;
	bool dwarfFile;
	bool dwarfAbspath;
	bool showpayloads;
	bool showrelocs;
	int cmtcount;
	int shortcut_pos;
	bool asm_anal;
	ut64 printed_str_addr;
	ut64 printed_flag_addr;
	ut64 min_ref_addr;

	bool use_json;
	bool first_line;
	const char *strip;
} RDisasmState;

static void ds_setup_print_pre(RDisasmState *ds, bool tail, bool middle);
static void ds_setup_pre(RDisasmState *ds, bool tail, bool middle);
static void ds_print_pre(RDisasmState *ds);
static void ds_beginline(RDisasmState *ds);
static void ds_begin_json_line(RDisasmState *ds);
static void ds_newline(RDisasmState *ds);
static void ds_print_esil_anal(RDisasmState *ds);
static void ds_reflines_init(RDisasmState *ds);
static void ds_align_comment(RDisasmState *ds);
static RDisasmState * ds_init(RCore * core);
static void ds_build_op_str(RDisasmState *ds, bool print_color);
static void ds_pre_xrefs(RDisasmState *ds, bool no_fcnlines);
static void ds_show_xrefs(RDisasmState *ds);
static void ds_atabs_option(RDisasmState *ds);
static void ds_show_functions(RDisasmState *ds);
static void ds_show_comments_right(RDisasmState *ds);
static void ds_show_flags(RDisasmState *ds);
static void ds_update_ref_lines(RDisasmState *ds);
static int ds_disassemble(RDisasmState *ds, ut8 *buf, int len);
static void ds_control_flow_comments(RDisasmState *ds);
static void ds_print_lines_right(RDisasmState *ds);
static void ds_print_lines_left(RDisasmState *ds);
static void ds_print_cycles(RDisasmState *ds);
static void ds_print_family(RDisasmState *ds);
static void ds_print_stackptr(RDisasmState *ds);
static void ds_print_offset(RDisasmState *ds);
static void ds_print_op_size(RDisasmState *ds);
static void ds_print_trace(RDisasmState *ds);
static void ds_adistrick_comments(RDisasmState *ds);
static int ds_print_meta_infos(RDisasmState *ds, ut8* buf, int len, int idx );
static void ds_print_opstr(RDisasmState *ds);
static void ds_print_color_reset(RDisasmState *ds);
static int ds_print_middle(RDisasmState *ds, int ret);
static bool ds_print_labels(RDisasmState *ds, RAnalFunction *f);
static void ds_print_import_name(RDisasmState *ds);
static void ds_print_sysregs(RDisasmState *ds);
static void ds_print_fcn_name(RDisasmState *ds);
static void ds_print_as_string(RDisasmState *ds);
static void ds_print_core_vmode(RDisasmState *ds, int pos);
static void ds_print_dwarf(RDisasmState *ds);
static void ds_print_asmop_payload(RDisasmState *ds, const ut8 *buf);
static char *ds_esc_str(RDisasmState *ds, const char *str, int len, const char **prefix_out);
static void ds_print_comments_right(RDisasmState *ds);
static void ds_print_ptr(RDisasmState *ds, int len, int idx);
static void ds_print_str(RDisasmState *ds, const char *str, int len, ut64 refaddr);
static char *ds_sub_jumps(RDisasmState *ds, char *str);

static ut64 p2v(RDisasmState *ds, ut64 addr) {
#if 0
	if (ds->core->io->pava) {
		ut64 at = r_io_section_get_vaddr (ds->core->io, addr);
		if (at == UT64_MAX || (!at && ds->at)) {
			addr = ds->at;
		} else {
			addr = at + addr;
		}
	}
#endif
	return addr;
}

static RAnalFunction *fcnIn(RDisasmState *ds, ut64 at, int type) {
	if (ds->fcn && r_tinyrange_in (&ds->fcn->bbr, at)) {
		return ds->fcn;
	}
	return r_anal_get_fcn_in (ds->core->anal, at, type);
}

static int cmpaddr(const void *_a, const void *_b) {
	const RAnalBlock *a = _a, *b = _b;
	return (a->addr > b->addr);
}

static void get_bits_comment(RCore *core, RAnalFunction *f, char *cmt, int cmt_size) {
	if (core && f && cmt && cmt_size > 0 && f->bits && f->bits != core->assembler->bits) {
		const char *asm_arch = r_config_get (core->config, "asm.arch");
		if (asm_arch && *asm_arch && strstr (asm_arch, "arm")) {
			switch (f->bits) {
			case 16: strcpy (cmt, " (thumb)"); break;
			case 32: strcpy (cmt, " (arm)"); break;
			case 64: strcpy (cmt, " (aarch64)"); break;
			}
		} else {
			snprintf (cmt, cmt_size, " (%d bits)", f->bits);
		}
	} else {
		if (cmt) {
			cmt[0] = 0;
		}
	}
}

static const char * get_section_name(RCore *core, ut64 addr) {
	static char section[128] = "";
	static ut64 oaddr = UT64_MAX;
	RIOSection *s;
	if (oaddr == addr) {
		return section;
	}
	s = r_io_section_vget (core->io, addr);
	if (s) {
		snprintf (section, sizeof (section)-1, "%10s ", s->name);
	} else {
		RListIter *iter;
		RDebugMap *map;
		*section = 0;
		r_list_foreach (core->dbg->maps, iter, map) {
			if (addr >= map->addr && addr < map->addr_end) {
				const char *mn = r_str_lchr (map->name, '/');
				if (mn) {
					strncpy (section, mn + 1, sizeof (section) - 1);
				} else {
					strncpy (section, map->name, sizeof (section) - 1);
				}
				break;
			}
		}
	}
	oaddr = addr;
	return section;
}

// up means if this lines go up, it controls whether to insert `_
// nl if we have to insert new line, it controls whether to insert \n
static void _ds_comment_align_(RDisasmState *ds, bool up, bool nl) {
	ds->cmtcount ++;
	if (ds->show_comment_right) {
		if (ds->show_color) {
			r_cons_printf (ds->pal_comment);
		}
		return;
	}
	//XXX fix this generate many dupes with section name
	const char *sn = ds->show_section ? get_section_name (ds->core, ds->at) : "";
	// if (ds->cmtcount == 0) {
		ds_align_comment (ds);
	// }
	sn = ds->show_section ? get_section_name (ds->core, ds->at) : "";
	ds_align_comment (ds);
	r_cons_print (COLOR_RESET (ds));
	ds_print_pre (ds);
	r_cons_printf ("%s%s%s%s%s  %s %s", nl? "\n": "", sn,
			COLOR (ds, color_flow),ds->refline, COLOR_RESET (ds),
			up? "": ".-", COLOR (ds, color_comment));
#if 0
// r_cons_printf ("(%d)", ds->cmtcount);
	if (ds->cmtcount == 1) {
		ds_align_comment (ds);
		r_cons_printf ("%s%s%s%s%s%s%s  %s %s", nl? "\n": "",
			COLOR_RESET (ds), COLOR (ds, color_fline),
			ds->pre, sn, ds->refline, COLOR_RESET (ds),
			up? "": ".v", COLOR (ds, color_comment));
	} else {
		r_cons_printf ("%s%s", COLOR (ds, color_comment), " "); //nl? "\n": "");
	}
#if 0
	if (!up || ds->cmtcount > 1) {
		r_cons_printf ("%s%s", COLOR (ds, color_comment), nl? "\n": "");
	} else {
		ds_align_comment (ds);
		r_cons_printf ("%s%s%s%s%s%s%s  %s %s", nl? "\n": "",
			COLOR_RESET (ds), COLOR (ds, color_fline),
			ds->pre, sn, ds->refline, COLOR_RESET (ds),
			up? "": "`-", COLOR (ds, color_comment));
	}
#endif
#endif
}
#define ALIGN _ds_comment_align_ (ds, true, false)

static void ds_comment_lineup(RDisasmState *ds) {
	_ds_comment_align_ (ds, true, false);
}

static void ds_begin_comment(RDisasmState *ds) {
	if (ds->show_comment_right) {
		ALIGN;
	} else {
		if (ds->use_json) {
			ds_begin_json_line (ds);
		}
		ds_pre_xrefs (ds, false);
	}
}

static void ds_comment(RDisasmState *ds, bool align, const char *format, ...) {
	va_list ap;
	va_start (ap, format);

	if (ds->show_comments) {
		if (ds->show_comment_right && align) {
			ds_align_comment (ds);
		} else if (!ds->use_json) {
			r_cons_printf ("%s", COLOR (ds, color_comment));
		}
	}

	if (!ds->use_json) {
		r_cons_printf_list (format, ap);
	} else {
		char buffer[4096];
		vsnprintf (buffer, sizeof(buffer), format, ap);
		char *escstr = ds_esc_str (ds, (const char *)buffer, (int)strlen (buffer), NULL);
		if (escstr) {
			r_cons_printf ("%s", escstr);
			free (escstr);
		}
	}

	if (!ds->show_comment_right && align) {
		ds_newline (ds);
	}

	va_end (ap);
}

static void ds_comment_esil(RDisasmState *ds, bool up, bool end, const char *format, ...) {
	va_list ap;
	va_start (ap, format);
	if (ds->show_comments && up) {
		ds->show_comment_right ? ds_align_comment (ds) : ds_comment_lineup (ds);
	}
	r_cons_printf_list (format, ap);
	va_end (ap);

	if (ds->show_comments && !ds->show_comment_right) {
		if (end) {
			ds_newline (ds);
		}
	}
}

static RDisasmState * ds_init(RCore *core) {
	RDisasmState *ds = R_NEW0 (RDisasmState);
	if (!ds) {
		return NULL;
	}
	ds->shortcut_pos = r_config_get_i (core->config, "asm.shortcut");
	ds->core = core;
	ds->strip = r_config_get (core->config, "asm.strip");
	ds->pal_comment = core->cons->pal.comment;
	#define P(x) (core->cons && core->cons->pal.x)? core->cons->pal.x
	ds->color_comment = P(comment): Color_CYAN;
	ds->color_usrcmt = P(usercomment): Color_CYAN;
	ds->color_fname = P(fname): Color_RED;
	ds->color_floc = P(floc): Color_MAGENTA;
	ds->color_fline = P(fline): Color_CYAN;
	ds->color_flow = P(flow): Color_CYAN;
	ds->color_flow2 = P(flow2): Color_CYAN;
	ds->color_flag = P(flag): Color_CYAN;
	ds->color_label = P(label): Color_CYAN;
	ds->color_other = P(other): Color_WHITE;
	ds->color_nop = P(nop): Color_BLUE;
	ds->color_bin = P(bin): Color_YELLOW;
	ds->color_math = P(math): Color_YELLOW;
	ds->color_btext = P(btext): Color_YELLOW;
	ds->color_jmp = P(jmp): Color_GREEN;
	ds->color_cjmp = P(cjmp): Color_GREEN;
	ds->color_call = P(call): Color_BGREEN;
	ds->color_cmp = P(cmp): Color_MAGENTA;
	ds->color_swi = P(swi): Color_MAGENTA;
	ds->color_trap = P(trap): Color_BRED;
	ds->color_ret = P(ret): Color_RED;
	ds->color_push = P(push): Color_YELLOW;
	ds->color_pop = P(pop): Color_BYELLOW;
	ds->color_reg = P(reg): Color_YELLOW;
	ds->color_num = P(num): Color_CYAN;
	ds->color_mov = P(mov): Color_WHITE;
	ds->color_invalid = P(invalid): Color_BRED;
	ds->color_gui_cflow = P(gui_cflow): Color_YELLOW;
	ds->color_gui_dataoffset = P(gui_dataoffset): Color_YELLOW;
	ds->color_gui_background = P(gui_background): Color_BLACK;
	ds->color_gui_alt_background = P(gui_alt_background): Color_GRAY;
	ds->color_gui_border = P(gui_border): Color_BGGRAY;

	ds->immstr = r_config_get_i (core->config, "asm.immstr");
	ds->immtrim = r_config_get_i (core->config, "asm.immtrim");
	ds->use_esil = r_config_get_i (core->config, "asm.esil");
	ds->pre_emu = r_config_get_i (core->config, "asm.emu.pre");
	ds->show_flgoff = r_config_get_i (core->config, "asm.flgoff");
	ds->show_nodup = r_config_get_i (core->config, "asm.nodup");
	ds->asm_anal = r_config_get_i (core->config, "asm.anal");
	ds->show_color = r_config_get_i (core->config, "scr.color");
	ds->show_color_bytes = r_config_get_i (core->config, "scr.color.bytes"); // maybe rename to asm.color.bytes
	ds->colorop = r_config_get_i (core->config, "scr.color.ops"); // XXX confusing name // asm.color.inst (mnemonic + operands) ?
	ds->show_utf8 = r_config_get_i (core->config, "scr.utf8");
	ds->acase = r_config_get_i (core->config, "asm.ucase");
	ds->capitalize = r_config_get_i (core->config, "asm.capitalize");
	ds->atabs = r_config_get_i (core->config, "asm.tabs");
	ds->atabsonce = r_config_get_i (core->config, "asm.tabsonce");
	ds->atabsoff = r_config_get_i (core->config, "asm.tabsoff");
	ds->midflags = r_config_get_i (core->config, "asm.midflags");
	ds->midcursor = r_config_get_i (core->config, "asm.midcursor");
	ds->decode = r_config_get_i (core->config, "asm.decode");
	ds->pseudo = r_config_get_i (core->config, "asm.pseudo");
	if (ds->pseudo) {
		ds->atabs = 0;
	}
	ds->filter = r_config_get_i (core->config, "asm.filter");
	ds->interactive = r_config_get_i (core->config, "scr.interactive");
	ds->jmpsub = r_config_get_i (core->config, "asm.jmpsub");
	ds->varsub = r_config_get_i (core->config, "asm.varsub");
	core->parser->relsub = r_config_get_i (core->config, "asm.relsub");
	core->parser->localvar_only = r_config_get_i (core->config, "asm.varsub_only");
	core->parser->retleave_asm = NULL;
	ds->show_vars = r_config_get_i (core->config, "asm.vars");
	ds->show_varsum = r_config_get_i (core->config, "asm.varsum");
	ds->show_varxs = r_config_get_i (core->config, "asm.varxs");
	ds->maxrefs = r_config_get_i (core->config, "asm.maxrefs");
	ds->show_lines = r_config_get_i (core->config, "asm.lines");
	ds->linesright = r_config_get_i (core->config, "asm.linesright");
	ds->show_indent = r_config_get_i (core->config, "asm.indent");
	ds->indent_space = r_config_get_i (core->config, "asm.indentspace");
	ds->tracespace = r_config_get_i (core->config, "asm.tracespace");
	ds->cyclespace = r_config_get_i (core->config, "asm.cyclespace");
	ds->show_dwarf = r_config_get_i (core->config, "asm.dwarf");
	ds->dwarfFile = r_config_get_i (ds->core->config, "asm.dwarf.file");
	ds->dwarfAbspath = r_config_get_i (ds->core->config, "asm.dwarf.abspath");
	ds->show_lines_call = r_config_get_i (core->config, "asm.lines.call");
	ds->show_lines_ret = r_config_get_i (core->config, "asm.lines.ret");
	ds->show_size = r_config_get_i (core->config, "asm.size");
	ds->show_trace = r_config_get_i (core->config, "asm.trace");
	ds->linesout = r_config_get_i (core->config, "asm.linesout");
	ds->adistrick = r_config_get_i (core->config, "asm.middle"); // TODO: find better name
	ds->asm_demangle = r_config_get_i (core->config, "asm.demangle");
	ds->asm_describe = r_config_get_i (core->config, "asm.describe");
	ds->show_offset = r_config_get_i (core->config, "asm.offset");
	ds->show_offdec = r_config_get_i (core->config, "asm.decoff");
	ds->show_bbline = r_config_get_i (core->config, "asm.bbline");
	ds->show_section = r_config_get_i (core->config, "asm.section");
	ds->show_section_col = r_config_get_i (core->config, "asm.section.col");
	ds->show_symbols = r_config_get_i (core->config, "asm.symbol");
	ds->show_symbols_col = r_config_get_i (core->config, "asm.symbol.col");
	ds->show_emu = r_config_get_i (core->config, "asm.emu");
	ds->show_emu_str = r_config_get_i (core->config, "asm.emu.str");
	ds->show_asm_bbinfo = r_config_get_i (core->config, "asm.bbinfo");
	ds->show_emu_stroff = r_config_get_i (core->config, "asm.emu.stroff");
	ds->show_emu_write = r_config_get_i (core->config, "asm.emu.write");
	ds->show_emu_stack = r_config_get_i (core->config, "asm.emu.stack");
	ds->stackFd = -1;
	if (ds->show_emu_stack) {
		// TODO: initialize fake stack in here
		const char *uri = "malloc://32K";
		ut64 size = r_num_get (core->num, "32K");
		ut64 addr = r_reg_getv (core->anal->reg, "SP") - (size / 2);
		emustack_min = addr;
		emustack_max = addr + size;
		ds->stackFd = r_io_fd_open (core->io, uri, R_IO_RW, 0);
		RIOMap *map = r_io_map_add (core->io, ds->stackFd, R_IO_RW, 0LL, addr, size, true);
		if (!map) {
			r_io_fd_close (core->io, ds->stackFd);
			eprintf ("Cannot create map for tha stack, fd %d got closed again\n", ds->stackFd);
			ds->stackFd = -1;
		} else {
			r_io_map_set_name (map, "fake.stack");
		}
	}
	ds->stackptr = core->anal->stackptr;
	ds->show_offseg = r_config_get_i (core->config, "asm.segoff");
	ds->show_flags = r_config_get_i (core->config, "asm.flags");
	ds->show_bytes = r_config_get_i (core->config, "asm.bytes");
	ds->show_reloff = r_config_get_i (core->config, "asm.reloff");
	ds->show_reloff_flags = r_config_get_i (core->config, "asm.reloff.flags");
	ds->show_fcnlines = r_config_get_i (core->config, "asm.fcnlines");
	ds->show_comments = r_config_get_i (core->config, "asm.comments");
	ds->show_jmphints = r_config_get_i (core->config, "asm.jmphints");
	ds->show_leahints = r_config_get_i (core->config, "asm.leahints");
	ds->show_slow = r_config_get_i (core->config, "asm.slow");
	ds->show_calls = r_config_get_i (core->config, "asm.calls");
	ds->show_family = r_config_get_i (core->config, "asm.family");
	ds->cmtcol = r_config_get_i (core->config, "asm.cmt.col");
	ds->show_cmtflgrefs = r_config_get_i (core->config, "asm.cmt.flgrefs");
	ds->show_cycles = r_config_get_i (core->config, "asm.cycles");
	ds->show_stackptr = r_config_get_i (core->config, "asm.stackptr");
	ds->show_xrefs = r_config_get_i (core->config, "asm.xrefs");
	ds->show_cmtrefs = r_config_get_i (core->config, "asm.cmt.refs");
	ds->cmtfold = r_config_get_i (core->config, "asm.cmt.fold");
	ds->show_cmtoff = r_config_get (core->config, "asm.cmt.off");
	ds->show_functions = r_config_get_i (core->config, "asm.functions");
	ds->show_fcncalls = r_config_get_i (core->config, "asm.fcncalls");
	ds->nbytes = r_config_get_i (core->config, "asm.nbytes");
	ds->show_asciidot = !strcmp (core->print->strconv_mode, "asciidot");
	const char *strenc_str = r_config_get (core->config, "asm.strenc");
	if (!strcmp (strenc_str, "latin1")) {
		ds->strenc = R_STRING_ENC_LATIN1;
	} else if (!strcmp (strenc_str, "utf8")) {
		ds->strenc = R_STRING_ENC_UTF8;
	} else if (!strcmp (strenc_str, "utf16le")) {
		ds->strenc = R_STRING_ENC_UTF16LE;
	} else if (!strcmp (strenc_str, "utf32le")) {
		ds->strenc = R_STRING_ENC_UTF32LE;
	} else {
		ds->strenc = R_STRING_ENC_GUESS;
	}
	core->print->bytespace = r_config_get_i (core->config, "asm.bytespace");
	ds->cursor = 0;
	ds->nb = 0;
	ds->flagspace_ports = r_flag_space_get (core->flags, "ports");
	ds->lbytes = r_config_get_i (core->config, "asm.lbytes");
	ds->show_comment_right_default = r_config_get_i (core->config, "asm.cmt.right");
	ds->show_comment_right = ds->show_comment_right_default;
	ds->show_flag_in_bytes = r_config_get_i (core->config, "asm.flagsinbytes");
	ds->show_hints = r_config_get_i (core->config, "asm.hints");
	ds->show_marks = r_config_get_i (core->config, "asm.marks");
	ds->show_noisy_comments = r_config_get_i (core->config, "asm.noisy");
	ds->pre = DS_PRE_NONE;
	ds->ocomment = NULL;
	ds->linesopts = 0;
	ds->lastfail = 0;
	ds->ocols = 0;
	ds->lcols = 0;
	ds->printed_str_addr = UT64_MAX;
	ds->printed_flag_addr = UT64_MAX;

	ds->esil_old_pc = UT64_MAX;
	ds->esil_regstate = NULL;
	ds->esil_likely = false;

	ds->showpayloads = r_config_get_i (ds->core->config, "asm.payloads");
	ds->showrelocs = r_config_get_i (core->config, "bin.relocs");
	ds->min_ref_addr = r_config_get_i (core->config, "asm.minvalsub");

	if (ds->show_flag_in_bytes) {
		ds->show_flags = 0;
	}
	if (r_config_get_i (core->config, "asm.lineswide")) {
		ds->linesopts |= R_ANAL_REFLINE_TYPE_WIDE;
	}
	if (core->cons->vline) {
		if (ds->show_utf8) {
			ds->linesopts |= R_ANAL_REFLINE_TYPE_UTF8;
		}
	}
	if (ds->show_lines) {
		ds->ocols += 10; // XXX
	}
	if (ds->show_offset) {
		ds->ocols += 14;
	}
	ds->lcols = ds->ocols + 2;
	if (ds->show_bytes) {
		ds->ocols += 20;
	}
	if (ds->show_trace) {
		ds->ocols += 8;
	}
	if (ds->show_stackptr) {
		ds->ocols += 4;
	}
	/* disasm */ ds->ocols += 20;
	ds->nb = ds->nbytes? (1 + ds->nbytes * 2): 0;
	ds->tries = 3;
	if (core->print->cur_enabled) {
		if (core->print->cur < 0) {
			core->print->cur = 0;
		}
		ds->cursor = core->print->cur;
	} else {
		ds->cursor = -1;
	}
	if (r_config_get_i (core->config, "asm.lineswide")) {
		ds->linesopts |= R_ANAL_REFLINE_TYPE_WIDE;
	}
	if (core->cons->vline) {
		if (ds->show_utf8) {
			ds->linesopts |= R_ANAL_REFLINE_TYPE_UTF8;
		}
	}
	return ds;
}

static ut64 lastaddr = UT64_MAX;

static void ds_reflines_fini(RDisasmState *ds) {
	RAnal *anal = ds->core->anal;
	r_list_free (anal->reflines);
	r_list_free (anal->reflines2);
	anal->reflines = NULL;
	anal->reflines2 = NULL;
	R_FREE (ds->refline);
	R_FREE (ds->refline2);
}

static void ds_reflines_init(RDisasmState *ds) {
	RAnal *anal = ds->core->anal;

	lastaddr = UT64_MAX;

	if (ds->show_lines) {
		ds_reflines_fini (ds);
		anal->reflines = r_anal_reflines_get (anal,
			ds->addr, ds->buf, ds->len, ds->l,
			ds->linesout, ds->show_lines_call);
		anal->reflines2 = r_anal_reflines_get (anal,
			ds->addr, ds->buf, ds->len, ds->l,
			ds->linesout, 1);
	} else {
		r_list_free (anal->reflines);
		r_list_free (anal->reflines2);
		anal->reflines = anal->reflines2 = NULL;
	}
}

static void ds_reflines_fcn_init(RDisasmState *ds,  RAnalFunction *fcn, const ut8* buf) {
	RCore *core = ds->core;
	RAnal *anal = core->anal;
	if (ds->show_lines) {
		// TODO: make anal->reflines implicit
		free (anal->reflines); // TODO: leak
		anal->reflines = r_anal_reflines_fcn_get (anal, fcn, -1, ds->linesout, ds->show_lines_call);
		free (anal->reflines2); // TODO: leak
		anal->reflines2 = r_anal_reflines_fcn_get (anal, fcn, -1, ds->linesout, 1);
	} else {
		r_list_free (anal->reflines);
		r_list_free (anal->reflines2);
		anal->reflines = anal->reflines2 = NULL;
	}
}

static void ds_free(RDisasmState *ds) {
	if (!ds) {
		return;
	}
	if (ds->show_emu_stack) {
		// TODO: destroy fake stack in here
		eprintf ("Free fake stack\n");
		if (ds->stackFd != -1) {
			r_io_fd_close (ds->core->io, ds->stackFd);
		}
	}
	r_anal_op_fini (&ds->analop);
	r_anal_hint_free (ds->hint);
	free (ds->comment);
	free (ds->line);
	free (ds->refline);
	free (ds->refline2);
	free (ds->opstr);
	free (ds->osl);
	free (ds->sl);
	free (ds->_tabsbuf);
	R_FREE (ds);
}

/* XXX move to r_print */
static char *colorize_asm_string(RCore *core, RDisasmState *ds, bool print_color) {
	char *spacer = NULL;
	char *source = ds->opstr? ds->opstr: ds->asmop.buf_asm;
	char *hlstr = r_meta_get_string (ds->core->anal, R_META_TYPE_HIGHLIGHT, ds->at);
	bool partial_reset = hlstr ? (*hlstr?true:false):false;

	if (!ds->show_color || !ds->colorop) {
		return strdup (source);
	}

	if (print_color) {
		r_cons_strcat (r_print_color_op_type (core->print, ds->analop.type));
	}


	// workaround dummy colorizer in case of paired commands (tms320 & friends)

	spacer = strstr (source, "||");
	if (spacer) {
		char *scol1, *s1 = r_str_ndup (source, spacer - source);
		char *scol2, *s2 = strdup (spacer + 2);

		scol1 = r_print_colorize_opcode (ds->core->print, s1, ds->color_reg, ds->color_num, partial_reset);
		free (s1);
		scol2 = r_print_colorize_opcode (ds->core->print, s2, ds->color_reg, ds->color_num, partial_reset);
		free (s2);
		if (!scol1) {
			scol1 = strdup ("");
		}
		if (!scol2) {
			scol2 = strdup ("");
		}

		source = malloc (strlen (scol1) + strlen (scol2) + 2 + 1); // reuse source variable
		sprintf (source, "%s||%s", scol1, scol2);
		free (scol1);
		free (scol2);
		return source;
	}

	return r_print_colorize_opcode (ds->core->print, source, ds->color_reg, ds->color_num, partial_reset);
}

static bool ds_must_strip(RDisasmState *ds) {
	if (ds && ds->strip && *ds->strip) {
		const char * optype = r_anal_optype_to_string (ds->analop.type);
		if (optype && *optype) {
			return strstr (ds->strip, optype);
		}
	}
	return false;
}

static void ds_highlight_word(RDisasmState * ds, char *word, char *color) {
	char *source = ds->opstr? ds->opstr: ds->asmop.buf_asm;
	char * asm_str = r_str_highlight (source, word, color);
	ds->opstr = asm_str? asm_str:source;
}

static void ds_build_op_str(RDisasmState *ds, bool print_color) {
	RCore *core = ds->core;
	if (!ds->opstr) {
		ds->opstr = strdup (ds->asmop.buf_asm);
	}
	/* initialize */
	core->parser->hint = ds->hint;
	core->parser->relsub = r_config_get_i (core->config, "asm.relsub");
	core->parser->relsub_addr = 0;
	if (ds->varsub && ds->opstr) {
		ut64 at = ds->vat;
		RAnalFunction *f = fcnIn (ds, at, R_ANAL_FCN_TYPE_NULL);
		core->parser->varlist = r_anal_var_list_dynamic;
		r_parse_varsub (core->parser, f, at, ds->analop.size,
			ds->opstr, ds->strsub, sizeof (ds->strsub));
		if (*ds->strsub) {
			free (ds->opstr);
			ds->opstr = strdup (ds->strsub);
		}
		if (core->parser->relsub) {
			RList *list = r_anal_refs_get (core->anal, at);
			RListIter *iter;
			RAnalRef *ref;
			r_list_foreach (list, iter, ref) {
				if ((ref->type == R_ANAL_REF_TYPE_DATA
					|| ref->type == R_ANAL_REF_TYPE_STRING)
					&& ds->analop.type == R_ANAL_OP_TYPE_LEA) {
					core->parser->relsub_addr = ref->addr;
					break;
				}
			}
			r_list_free (list);
		}
	}
	char *asm_str = colorize_asm_string (core, ds, print_color);
	asm_str = ds_sub_jumps (ds, asm_str);
	if (ds->immtrim) {
		r_parse_immtrim (ds->opstr);
		free (asm_str);
		return;
	}
	if (ds->decode) {
		char *tmpopstr = r_anal_op_to_string (core->anal, &ds->analop);
		// TODO: Use data from code analysis..not raw ds->analop here
		// if we want to get more information
		ds->opstr = tmpopstr? tmpopstr: asm_str? strdup (asm_str): strdup ("");
	} else {
		if (ds->hint && ds->hint->opcode) {
			free (ds->opstr);
			ds->opstr = strdup (ds->hint->opcode);
		}
		if (ds->filter) {
			int ofs = core->parser->flagspace;
			int fs = ds->flagspace_ports;
			if (ds->analop.type == R_ANAL_OP_TYPE_IO) {
				core->parser->notin_flagspace = -1;
				core->parser->flagspace = fs;
			} else {
				if (fs != -1) {
					core->parser->notin_flagspace = fs;
					core->parser->flagspace = fs;
				} else {
					core->parser->notin_flagspace = -1;
					core->parser->flagspace = -1;
				}
			}
			if (ds->analop.refptr) {
				if (core->parser->relsub_addr == 0) {
					ut64 killme = UT64_MAX;
					const int be = core->assembler->big_endian;
					r_io_read_i (core->io, ds->analop.ptr, &killme, ds->analop.refptr, be);
					core->parser->relsub_addr = (int)killme;
				}
			}
			r_parse_filter (core->parser, core->flags, asm_str,
				ds->str, sizeof (ds->str), core->print->big_endian);
			core->parser->flagspace = ofs;
			free (ds->opstr);
			ds->opstr = strdup (ds->str);
		} else {
			free (ds->opstr);
			ds->opstr = strdup (asm_str? asm_str: "");
		}
	}
	if (ds->show_color) {
		int i = 0;
		char *word = NULL;
		char *bgcolor = NULL;
		char *wcdata = r_meta_get_string (ds->core->anal, R_META_TYPE_HIGHLIGHT, ds->at);
		int argc = 0;
		char **wc_array = r_str_argv (wcdata, &argc);
		for (i = 0; i < argc; i++) {
			bgcolor = strchr (wc_array[i], '\x1b');
			word = r_str_newlen (wc_array[i], bgcolor - wc_array[i]);
			ds_highlight_word (ds, word, bgcolor);
		}
	}
	if (ds->use_esil) {
		if (*R_STRBUF_SAFEGET (&ds->analop.esil)) {
			free (ds->opstr);
			ds->opstr = strdup (R_STRBUF_SAFEGET (&ds->analop.esil));
		} else {
			char *p = malloc (strlen (ds->opstr) + 6); /* What's up '\0' ? */
			if (p) {
				strcpy (p, "TODO,");
				strcpy (p + 5, ds->opstr);
				free (ds->opstr);
				ds->opstr = p;
			}
		}
	}
	free (asm_str);
}

//removed hints bits from since r_anal_build_range_on_hints along with
//r_core_seek_archbits will be used instead. The ranges are built from hints
R_API RAnalHint *r_core_hint_begin(RCore *core, RAnalHint* hint, ut64 at) {
	static char *hint_arch = NULL;
	static char *hint_syntax = NULL;
	r_anal_hint_free (hint);
	hint = r_anal_hint_get (core->anal, at);
	if (hint_arch) {
		r_config_set (core->config, "asm.arch", hint_arch);
		hint_arch = NULL;
	}
	if (hint_syntax) {
		r_config_set (core->config, "asm.syntax", hint_syntax);
		hint_syntax = NULL;
	}
	if (hint) {
		/* arch */
		if (hint->arch) {
			if (!hint_arch) {
				hint_arch = strdup (r_config_get (core->config, "asm.arch"));
			}
			r_config_set (core->config, "asm.arch", hint->arch);
		}
		/* arch */
		if (hint->syntax) {
			if (!hint_syntax) {
				hint_syntax = strdup (r_config_get (core->config, "asm.syntax"));
			}
			r_config_set (core->config, "asm.syntax", hint->syntax);
		}
		if (hint->high) {
		}
	}
	return hint;
}

static void ds_beginline(RDisasmState *ds) {
	ds_setup_pre (ds, false, false);
	ds_print_pre (ds);
	char *tmp = ds->line;
	ds->line = ds->refline2;
	ds_print_lines_left (ds);
	ds->line = tmp;
}

static void ds_begin_json_line(RDisasmState *ds) {
	if (!ds->use_json) {
		return;
	}
	if (!ds->first_line) {
		r_cons_print (",");
	}
	ds->first_line = false;
	r_cons_printf ("{\"offset\":%"PFMT64d",\"text\":\"", ds->vat);
}

static void ds_newline(RDisasmState *ds) {
	if (ds->use_json) {
		r_cons_printf ("\"}");
	} else {
		r_cons_newline ();
	}
}

static void ds_pre_xrefs(RDisasmState *ds, bool no_fcnlines) {
	ds_setup_pre (ds, false, false);
	if (ds->pre != DS_PRE_NONE && ds->pre != DS_PRE_EMPTY) {
		ds->pre = no_fcnlines ? DS_PRE_EMPTY : DS_PRE_FCN_MIDDLE;
	}
	ds_print_pre (ds);
	char *tmp = ds->line;
	ds->line = ds->refline2;
	ds_print_lines_left (ds);
	ds->line = tmp;
}

static void ds_show_refs(RDisasmState *ds) {
	RList *list;
	RAnalRef *ref;
	RListIter *iter;
	RFlagItem *flagi, *flagat;
	char *cmt;

	if (!ds->show_cmtrefs) {
		return;
	}
	list = r_anal_xrefs_get_from (ds->core->anal, ds->at);
	r_list_foreach (list, iter, ref) {
		cmt = r_meta_get_string (ds->core->anal, R_META_TYPE_COMMENT, ref->addr);
		flagi = r_flag_get_i (ds->core->flags, ref->addr);
		flagat = r_flag_get_at (ds->core->flags, ref->addr, false);
		// ds_align_comment (ds);
		if (ds->show_color) {
			r_cons_strcat (ds->color_comment);
		}
		if (flagi && flagat && (strcmp (flagi->name, flagat->name) != 0)) {
			_ds_comment_align_ (ds, true, false);
			ds_comment (ds, true, "; (%s)", flagi->name);
		}
		if (cmt) {
			_ds_comment_align_ (ds, true, false);
			ds_comment (ds, true, "; (%s)", cmt);
		}
		if (ref->type & R_ANAL_REF_TYPE_CALL) {
			RAnalOp aop;
			ut8 buf[12];
			r_core_read_at (ds->core, ref->at, buf, sizeof (buf));
			r_anal_op (ds->core->anal, &aop, ref->at, buf, sizeof (buf));
			if ((aop.type & R_ANAL_OP_TYPE_MASK) == R_ANAL_OP_TYPE_UCALL) {
				RAnalFunction * fcn = r_anal_get_fcn_at (ds->core->anal,
					ref->addr, R_ANAL_FCN_TYPE_NULL);
				_ds_comment_align_ (ds, true, false);
				if (fcn) {
					ds_comment (ds, true, "; %s", fcn->name);
				} else {
					ds_comment (ds, true, "; 0x%" PFMT64x"", ref->addr);
				}
			}
		}
		ds_print_color_reset (ds);
	}
}

static void ds_show_xrefs(RDisasmState *ds) {
	RAnalRef *refi;
	RListIter *iter;
	RCore *core = ds->core;
	bool demangle = r_config_get_i (core->config, "bin.demangle");
	const char *lang = demangle ? r_config_get (core->config, "bin.lang") : NULL;
	char *name, *tmp;
	int count = 0;
	if (!ds->show_xrefs || !ds->show_comments) {
		return;
	}
	/* show xrefs */
	RList *xrefs = r_anal_xref_get (core->anal, ds->at);
	if (!xrefs) {
		return;
	}
	if (ds->maxrefs < 1) {
		ds_pre_xrefs (ds, false);
		ds_comment (ds, false, "   %s; XREFS(%d)\n",
			ds->show_color? ds->pal_comment: "",
			r_list_length (xrefs));
		r_list_free (xrefs);
		return;
	}
	if (r_list_length (xrefs) > ds->maxrefs) {
		int cols = r_cons_get_size (NULL);
		cols -= 15;
		cols /= 23;
		ds_pre_xrefs (ds, false);
		ds_comment (ds, false, "   %s; XREFS: ", ds->show_color? ds->pal_comment: "");
		r_list_foreach (xrefs, iter, refi) {
			ds_comment (ds, false, "%s 0x%08"PFMT64x"  ",
				r_anal_xrefs_type_tostring (refi->type), refi->addr);
			if (count == cols) {
				if (iter->n) {
					ds_print_color_reset (ds);
					ds_newline (ds);
					ds_pre_xrefs (ds, false);
					ds_comment (ds, false, "   %s; XREFS: ", ds->show_color? ds->pal_comment: "");
				}
				count = 0;
			} else {
				count++;
			}
		}
		ds_print_color_reset (ds);
		ds_newline (ds);
		r_list_free (xrefs);
		return;
	}

	r_list_foreach (xrefs, iter, refi) {
		if (refi->at == ds->at) {
			RAnalFunction *fun = fcnIn (ds, refi->addr, -1); //r_anal_get_fcn_in (core->anal, refi->addr, -1);
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
			if (demangle) {
				tmp = r_bin_demangle (core->bin->cur, lang, name, refi->addr);
				if (tmp) {
					free (name);
					name = tmp;
				}
			}
			ds_begin_json_line (ds);
			ds_pre_xrefs (ds, false);
			//those extra space to align
			ds_comment (ds, false, "   %s; %s XREF from 0x%08"PFMT64x" (%s)%s",
				COLOR (ds, pal_comment), r_anal_xrefs_type_tostring (refi->type),
				refi->addr, name, COLOR_RESET (ds));
			ds_newline (ds);
			R_FREE (name);
		} else {
			eprintf ("Corrupted database?\n");
		}
	}
	r_list_free (xrefs);
}

static void ds_atabs_option(RDisasmState *ds) {
	int n, i = 0, comma = 0, word = 0;
	int size, brackets = 0;
	char *t, *b;
	if (!ds || !ds->atabs) {
		return;
	}
	size = strlen (ds->asmop.buf_asm) * (ds->atabs + 1) * 4;
	if (size < 1 || size < strlen (ds->asmop.buf_asm)) {
		return;
	}
	free (ds->opstr);
	ds->opstr = b = malloc (size + 1);
	strncpy (b, ds->asmop.buf_asm, R_MIN (size, R_ASM_BUFSIZE));
	b[size] = 0;
	for (; *b; b++, i++) {
		if (*b == '(' || *b == '[') {
			brackets++;
		}
		if (*b == ')' || *b == ']') {
			brackets--;
		}
		if (*b == ',') {
			comma = 1;
		}
		if (*b != ' ') {
			continue;
		}
		if (word > 0 && !comma) {
			continue; //&& b[1]=='[') continue;
		}
		if (brackets > 0) {
			continue;
		}
		comma = 0;
		brackets = 0;
		n = (ds->atabs-i);
		t = strdup (b + 1); //XXX slow!
		if (n < 1) {
			n = 1;
		}
		memset (b, ' ', n);
		b += n;
		strcpy (b, t);
		free (t);
		i = 0;
		word++;
		if (ds->atabsonce) {
			break;
		}
	}
}

static int handleMidFlags(RCore *core, RDisasmState *ds, bool print) {
	int i;

	ds->hasMidflag = false;
	if (ds->midcursor && core->print->cur != -1) {
		ut64 cur = core->offset + core->print->cur;
		ut64 from = ds->at;
		ut64 to = ds->at + ds->oplen;
		if (cur > from && cur < to) {
			return cur - from;
		}
	}
	for (i = 1; i < ds->oplen; i++) {
		RFlagItem *fi = r_flag_get_i (core->flags, ds->at + i);
		if (fi && fi->name) {
			if (ds->midflags == 2 && ((fi->name[0] == '$') || (fi->realname && fi->realname[0] == '$'))) {
				i = 0;
			} else if (!strncmp (fi->name, "hit.", 4)) { // use search.prefix ?
				i = 0;
			} else if (!strncmp (fi->name, "str.", 4)) {
				ds->midflags = R_MIDFLAGS_REALIGN;
			} else if (!strncmp (fi->name, "reloc.", 6)) {
				if (print) {
					ds_begin_json_line (ds);
					r_cons_printf ("(%s)", fi->name);
					ds_newline (ds);
				}
				continue;
			} else if (ds->midflags == R_MIDFLAGS_SYMALIGN) {
				if (strncmp (fi->name, "sym.", 4)) {
					continue;
				}
			}
			ds->hasMidflag = true;
			return i;
		}
	}
	return 0;
}

static void ds_print_show_cursor(RDisasmState *ds) {
	RCore *core = ds->core;
	char res[] = "     ";
	void *p;
	if (!ds->show_marks) {
		return;
	}
	int q = core->print->cur_enabled &&
		ds->cursor >= ds->index &&
		ds->cursor < (ds->index + ds->asmop.size);
	p = r_bp_get_at (core->dbg->bp, ds->at);
	if (ds->midflags) {
		(void)handleMidFlags (core, ds, false);
	}
	if (p) {
		res[0] = 'b';
	}
	if (ds->hasMidflag) {
		res[1] = '~';
	}
	if (q) {
		if (ds->cursor == ds->index) {
			res[2] = '*';
		} else {
			int i = 2, diff = ds->cursor - ds->index;
			if (diff > 9) {
				res[i++] = '0' + (diff / 10);
			}
			res[i] = '0' + (diff % 10);
		}
	}
	r_cons_strcat (res);
}

static int var_comparator(const RAnalVar *a, const RAnalVar *b){
	if (a && b) {
		return a->delta > b->delta;
	}
	return false;
}

//TODO: this function is a temporary fix. All analysis should be based on realsize. However, now for same architectures realisze is not used
static ut32 tmp_get_realsize (RAnalFunction *f) {
	ut32 size = r_anal_fcn_realsize (f);
	return (size > 0) ? size : r_anal_fcn_size (f);
}

static void ds_show_functions_argvar(RDisasmState *ds, RAnalVar *var, const char *base, bool is_var, char sign) {
	int delta = sign == '+' ? var->delta : -var->delta;
	const char *arg_or_var = is_var ? "var" : "arg";
	r_cons_printf ("%s %s %s @ %s%c0x%x", arg_or_var, var->type, var->name,
		base, sign, delta);
}

static void printVarSummary(RDisasmState *ds, RList *list) {
	const char *numColor = ds->core->cons->pal.num;
	RAnalVar *var;
	RListIter *iter;
	int bp_vars = 0;
	int sp_vars = 0;
	int rg_vars = 0;
	int bp_args = 0;
	int sp_args = 0;
	int rg_args = 0;
	const char *bp_vars_color = COLOR_RESET (ds);
	const char *sp_vars_color = COLOR_RESET (ds);
	const char *rg_vars_color = COLOR_RESET (ds);
	const char *bp_args_color = COLOR_RESET (ds);
	const char *sp_args_color = COLOR_RESET (ds);
	const char *rg_args_color = COLOR_RESET (ds);
	r_list_foreach (list, iter, var) {
		if (var->delta > 0) {
			switch (var->kind) {
			case 'b':
				bp_args++;
				break;
			case 's':
				sp_args++;
				break;
			case 'r':
				rg_args++;
				break;
			}
		} else {
			switch (var->kind) {
			case 'b':
				bp_vars++;
				break;
			case 's':
				sp_vars++;
				break;
			case 'r':
				rg_vars++;
				break;
			}
		}
	}
	if (bp_vars) { bp_vars_color = numColor; }
	if (sp_vars) { sp_vars_color = numColor; }
	if (rg_vars) { rg_vars_color = numColor; }
	if (bp_args) { bp_args_color = numColor; }
	if (sp_args) { sp_args_color = numColor; }
	if (rg_args) { rg_args_color = numColor; }
	if (ds->show_varsum == 2) {
		ds_begin_json_line (ds);
		ds_print_pre (ds);
		r_cons_printf ("vars: %s%d%s %s%d%s %s%d%s",
				bp_vars_color, bp_vars, COLOR_RESET (ds),
				sp_vars_color, sp_vars, COLOR_RESET (ds),
				rg_vars_color, rg_vars, COLOR_RESET (ds));
		ds_newline (ds);
		ds_begin_json_line (ds);
		ds_print_pre (ds);
		r_cons_printf ("args: %s%d%s %s%d%s %s%d%s",
				bp_args_color, bp_args, COLOR_RESET (ds),
				sp_args_color, sp_args, COLOR_RESET (ds),
				rg_args_color, rg_args, COLOR_RESET (ds));
		ds_newline (ds);
		return;
	}
	ds_begin_json_line (ds);
	ds_print_pre (ds);
	r_cons_printf ("bp: %s%d%s (vars %s%d%s, args %s%d%s)",
			bp_args || bp_vars ? numColor : COLOR_RESET (ds), bp_args + bp_vars, COLOR_RESET (ds),
			bp_vars_color, bp_vars, COLOR_RESET (ds),
			bp_args_color, bp_args, COLOR_RESET (ds));
	ds_newline (ds);
	ds_begin_json_line (ds);
	ds_print_pre (ds);
	r_cons_printf ("sp: %s%d%s (vars %s%d%s, args %s%d%s)",
			sp_args || sp_vars ? numColor : COLOR_RESET (ds), sp_args+sp_vars, COLOR_RESET (ds),
			sp_vars_color, sp_vars, COLOR_RESET (ds),
			sp_args_color, sp_args, COLOR_RESET (ds));
	ds_newline (ds);
	ds_begin_json_line (ds);
	ds_print_pre (ds);
	r_cons_printf ("rg: %s%d%s (vars %s%d%s, args %s%d%s)",
			rg_args || rg_vars ? numColor : COLOR_RESET (ds), rg_args+rg_vars, COLOR_RESET (ds),
			rg_vars_color, rg_vars, COLOR_RESET (ds),
			rg_args_color, rg_args, COLOR_RESET (ds));
	ds_newline (ds);
}

static void ds_show_functions(RDisasmState *ds) {
	RAnalFunction *f;
	RCore *core = ds->core;
	bool demangle, call;
	const char *lang;
	char *fcn_name;
	char *sign;

	if (!ds->show_functions) {
		return;
	}
	demangle = r_config_get_i (core->config, "bin.demangle");
	call = r_config_get_i (core->config, "asm.calls");
	lang = demangle ? r_config_get (core->config, "bin.lang") : NULL;
	f = r_anal_get_fcn_in (core->anal, ds->at, R_ANAL_FCN_TYPE_NULL);
	if (!f || (f->addr != ds->at)) {
		return;
	}
	if (demangle) {
		fcn_name = r_bin_demangle (core->bin->cur, lang, f->name, f->addr);
		if (!fcn_name) {
			fcn_name = strdup (f->name);
		}
	} else {
		fcn_name = f->name;
	}
	ds_begin_json_line (ds);
	sign = r_anal_fcn_to_string (core->anal, f);
	if (f->type == R_ANAL_FCN_TYPE_LOC) {
		r_cons_printf ("%s%s ", COLOR (ds, color_fline),
			core->cons->vline[LINE_CROSS]); // |-
		r_cons_printf ("%s%s%s %d", COLOR (ds, color_floc),
			fcn_name, COLOR_RESET (ds), r_anal_fcn_size (f));
	} else {
		const char *fcntype;
		char cmt[32];
		get_bits_comment (core, f, cmt, sizeof (cmt));

		switch (f->type) {
		case R_ANAL_FCN_TYPE_FCN:
		case R_ANAL_FCN_TYPE_SYM:
			fcntype = "fcn"; break;
		case R_ANAL_FCN_TYPE_IMP:
			fcntype = "imp"; break;
		default:
			fcntype = "loc"; break;
		}
#if SLOW_BUT_OK
		int corner = (f->size <= ds->analop.size) ? RDWN_CORNER : LINE_VERT;
		corner = LINE_VERT; // 99% of cases
		RFlagItem *item = r_flag_get_i (core->flags, f->addr);
		corner = item ? LINE_VERT : RDWN_CORNER;
		if (item) {
			corner = 0;
		}
#endif
		//ds_set_pre (ds, core->cons->vline[CORNER_TL]);
		if (ds->show_fcnlines) {
			ds->pre = DS_PRE_FCN_HEAD;
		}
		ds_print_pre (ds);
		if (ds->show_flgoff) {
			ds_print_lines_left (ds);
			ds_print_offset (ds);
		}
		r_cons_printf ("%s(%s) %s%s%s %d",
					   COLOR (ds, color_fname),
					   fcntype, fcn_name, cmt, COLOR_RESET (ds), tmp_get_realsize (f));
	}
	ds_newline (ds);
	if (sign) {
		ds_begin_json_line (ds);
		r_cons_printf ("// %s", sign);
		ds_newline (ds);
	}
	R_FREE (sign);
	if (ds->show_fcnlines) {
		ds->pre = DS_PRE_FCN_MIDDLE;
	}
	ds->stackptr = core->anal->stackptr;
	if (ds->show_vars && ds->show_varsum) {
		RList *vars = r_anal_var_list (core->anal, f, 'b');
		r_list_join(vars, r_anal_var_list (core->anal, f, 'r'));
		r_list_join(vars, r_anal_var_list (core->anal, f, 's'));
		printVarSummary(ds, vars);
		r_list_free (vars);
	} else if (ds->show_vars) {
		char spaces[32];
		RAnalVar *var;
		RListIter *iter;
		RList *args = r_anal_var_list (core->anal, f, 'b');
		RList *regs = r_anal_var_list (core->anal, f, 'r');
		RList *sp_vars = r_anal_var_list (core->anal, f, 's');
		r_list_sort (args, (RListComparator)var_comparator);
		r_list_sort (regs, (RListComparator)var_comparator);
		r_list_sort (sp_vars, (RListComparator)var_comparator);
		if (call) {
			ds_begin_json_line (ds);
			r_cons_print (COLOR (ds, color_fline));
			ds_print_pre (ds);
			r_cons_printf ("%s %s %s%s (",
				COLOR_RESET (ds), COLOR (ds, color_fname),
				fcn_name, COLOR_RESET (ds));
			bool comma = true;
			bool arg_bp = false;
			int tmp_len;
			r_list_foreach (regs, iter, var) {
				tmp_len = strlen (var->type);
				r_cons_printf ("%s%s%s%s", var->type,
					tmp_len && var->type[tmp_len - 1] == '*' ? "" : " ",
					var->name, iter->n ? ", " : "");
			}
			r_list_foreach (args, iter, var) {
				if (var->delta > 0) {
					if (!r_list_empty (regs) && comma) {
						r_cons_printf (", ");
						comma = false;
					}
					arg_bp = true;
					tmp_len = strlen (var->type);
					r_cons_printf ("%s%s%s%s", var->type,
						tmp_len && var->type[tmp_len - 1] =='*' ? "" : " ",
						var->name, iter->n ? ", " : "");
				}
			}
			comma = true;
			r_list_foreach (sp_vars, iter, var) {
				if (var->delta > f->maxstack) {
					if ((arg_bp || !r_list_empty (regs)) && comma) {
						comma = false;
						r_cons_printf (", ");
					}
					tmp_len = strlen (var->type);
					r_cons_printf ("%s%s%s%s", var->type,
						tmp_len && var->type[tmp_len - 1] =='*' ? "" : " ",
						var->name, iter->n ? ", " : "");
				}
			}
			r_cons_printf (");");
			ds_newline (ds);
		}
		r_list_join (args, sp_vars);
		r_list_join (args, regs);
		r_list_foreach (args, iter, var) {
			ds_begin_json_line (ds);
			char *tmp;
			int idx;
			RAnal *anal = ds->core->anal;
			memset (spaces, ' ', sizeof(spaces));
			idx = 12 - strlen (var->name);
			if (idx < 0) {
				idx = 0;
			}
			spaces[idx] = 0;
			ds_setup_print_pre (ds, false, true);

			tmp = ds->line;
			ds->line = ds->refline2;
			ds_print_lines_left (ds);
			ds->line = tmp;

			if (ds->show_flgoff) {
				ds_print_offset (ds);
				r_cons_printf ("     ");
			}
			r_cons_printf ("%s; ", COLOR (ds, color_other));
			switch (var->kind) {
			case 'b': {
				char sign = var->delta > 0 ? '+' : '-';
				bool is_var = var->delta <= 0;
				ds_show_functions_argvar (ds, var,
					anal->reg->name[R_REG_NAME_BP], is_var, sign);
				}
				break;
			case 'r': {
				RRegItem *i = r_reg_index_get (anal->reg, var->delta);
				if (!i) {
					eprintf("Register not found");
					break;
				}
				r_cons_printf ("reg %s %s @ %s",
					var->type, var->name, i->name);
				}
				break;
			case 's': {
				bool is_var = var->delta < f->maxstack;
				ds_show_functions_argvar (ds, var,
					anal->reg->name[R_REG_NAME_SP],
					is_var, '+');
				}
				break;
			}
			char *comment = r_meta_get_var_comment (anal, var->kind, var->delta, f->addr);
			if (comment) {
				char *comment_esc = NULL;
				if (ds->use_json) {
					comment = comment_esc = ds_esc_str (ds, comment, (int)strlen (comment), NULL);
				}

				if (comment) {
					r_cons_printf ("    %s; %s", COLOR (ds, color_comment), comment);
				}
				if (comment_esc) {
					free (comment_esc);
				}
			}
			r_cons_print (COLOR_RESET (ds));
			ds_newline (ds);
		}
		r_list_free (regs);
		// it's already empty, but rlist instance is still there
		r_list_free (args);
		r_list_free (sp_vars);
	}
	if (demangle) {
		free (fcn_name);
	}
}

static void ds_setup_print_pre(RDisasmState *ds, bool tail, bool middle) {
	ds_setup_pre (ds, tail, middle);
	ds_print_pre (ds);
}

static void ds_setup_pre(RDisasmState *ds, bool tail, bool middle) {
	ds->cmtcount = 0;
	if (!ds->show_functions || !ds->show_fcnlines) {
		ds->pre = DS_PRE_NONE;
		return;
	}
	ds->pre = DS_PRE_EMPTY;
	RAnalFunction *f = fcnIn (ds, ds->at, R_ANAL_FCN_TYPE_NULL);
	if (f) {
		if (f->addr == ds->at) {
			if (ds->analop.size == r_anal_fcn_size (f) && !middle) {
				ds->pre = DS_PRE_FCN_TAIL;
			} else {
				ds->pre = DS_PRE_FCN_MIDDLE;
			}
		} else if (f->addr + r_anal_fcn_size (f) - ds->analop.size == ds->at) {
			ds->pre = DS_PRE_FCN_TAIL;
		} else if (r_anal_fcn_is_in_offset (f, ds->at)) {
			ds->pre = DS_PRE_FCN_MIDDLE;
		}
		if (tail) {
			if (ds->pre == DS_PRE_FCN_TAIL) {
				ds->pre = DS_PRE_EMPTY;
			}
			if (ds->pre == DS_PRE_FCN_MIDDLE) {
				ds->pre = DS_PRE_FCN_TAIL;
			}
		}
	}
}

static void ds_print_pre(RDisasmState *ds) {
	RCore *core = ds->core;

	const char *c = NULL;
	switch(ds->pre) {
	case DS_PRE_FCN_HEAD:
		c = core->cons->vline[CORNER_TL];
		break;
	case DS_PRE_FCN_MIDDLE:
		c = core->cons->vline[LINE_VERT];
		break;
	case DS_PRE_FCN_TAIL:
		c = core->cons->vline[CORNER_BL];
		break;
	case DS_PRE_EMPTY:
		r_cons_print ("  ");
	case DS_PRE_NONE:
	default:
		return;
	}

	char *c_esc = NULL;
	if (ds->use_json) {
		c = c_esc = r_str_escape (c);
	}
	r_cons_printf ("%s%s%s ",
		COLOR (ds, color_fline), c,
		COLOR_RESET (ds));
	free (c_esc);
}

//XXX review this with asm.cmt.right
static void ds_show_comments_right(RDisasmState *ds) {
	int linelen, maxclen ;
	RCore *core = ds->core;
	RFlagItem *item;
	/* show comment at right? */
	int scr = ds->show_comment_right;
	if (!ds->show_comments) {
		return;
	}
	//RAnalFunction *f = r_anal_get_fcn_in (core->anal, ds->at, R_ANAL_FCN_TYPE_NULL);
	item = r_flag_get_i (core->flags, ds->at);
	ds->comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, ds->at);
	if (!ds->comment && item && item->comment && *item->comment) {
		ds->ocomment = item->comment;
		ds->comment = strdup (item->comment);
	}
	if (!ds->comment) {
		return;
	}
	maxclen = strlen (ds->comment) + 5;
	linelen = maxclen;
	if (ds->show_comment_right_default) {
		if (ds->ocols + maxclen < core->cons->columns) {
			if (ds->comment && *ds->comment && strlen (ds->comment) < maxclen) {
				if (!strchr (ds->comment, '\n')) { // more than one line?
					ds->show_comment_right = 1;
				}
			}
		}
	}
	if (!ds->show_comment_right) {
		ds_begin_json_line (ds);
		int mycols = ds->lcols;
		if ((mycols + linelen + 10) > core->cons->columns) {
			mycols = 0;
		}
		mycols /= 2;
		if (ds->show_color) {
			r_cons_strcat (ds->pal_comment);
		}
		/* print multiline comment */
		if (ds->cmtfold) {
			char *p = strdup (ds->comment);
			char *q = strchr (p, '\n');
			if (q) {
				*q = 0;
				r_cons_strcat (p);
				r_cons_strcat (" ; [z] unfold");
			}
			free (p);
		} else {
			ds->comment = r_str_prefix_all (ds->comment, "; ");
			if (ds->show_comment_right) {
				ALIGN;
			} else {
				ds_pre_xrefs (ds, false);
			}
			if (ds->show_color) {
				r_cons_strcat (ds->color_usrcmt);
			}
			ds_comment (ds, false, "%s", ds->comment);
		}
		if (ds->show_color) {
			ds_print_color_reset (ds);
		}
		R_FREE (ds->comment);
		ds_newline (ds);
		/* flag one */
		if (item && item->comment && ds->ocomment != item->comment) {
			ds_begin_json_line (ds);
			if (ds->show_color) {
				r_cons_strcat (ds->pal_comment);
			}
			ds_newline (ds);
			ds_begin_json_line (ds);
			r_cons_strcat ("  ;  ");
			r_cons_strcat_justify (item->comment, mycols, ';');
			ds_newline (ds);
			if (ds->show_color) {
				ds_print_color_reset (ds);
			}
		}
	}
	ds->show_comment_right = scr;
}

static int flagCmp(const void *a, const void *b) {
	const RFlagItem *fa = a;
	const RFlagItem *fb = b;
	if (fa->realname && fb->realname) {
		return !strcmp (fa->realname, fb->realname);
	}
	return !strcmp (fa->name, fb->name);
}

static void ds_show_flags(RDisasmState *ds) {
	//const char *beginch;
	RFlagItem *flag;
	RListIter *iter;
	RAnalFunction *f;
	const RList /*RFlagList*/ *flaglist;
	if (!ds->show_flags) {
		return;
	}
	RCore *core = ds->core;
	// f = r_anal_get_fcn_in (core->anal, ds->at, R_ANAL_FCN_TYPE_NULL);
	f = fcnIn (ds, ds->at, R_ANAL_FCN_TYPE_NULL);
	flaglist = r_flag_get_list (core->flags, ds->at);
	RList *uniqlist = r_list_uniq (flaglist, flagCmp);
	r_list_foreach (uniqlist, iter, flag) {
		if (f && f->addr == flag->offset && !strcmp (flag->name, f->name)) {
			// do not show flags that have the same name as the function
			continue;
		}
		ds_begin_json_line (ds);
		if (ds->show_flgoff) {
			ds_beginline (ds);
			ds_print_offset (ds);
			r_cons_printf (" ");
		} else {
			ds_pre_xrefs (ds, true);
			r_cons_printf (";-- ");
		}
		if (ds->show_color) {
			bool hasColor = false;
			if (flag->color) {
				char *color = r_cons_pal_parse (flag->color, NULL);
				if (color) {
					r_cons_strcat (color);
					free (color);
					ds->lastflag = flag;
					hasColor = true;
				}
			}
			if (!hasColor) {
				r_cons_strcat (ds->color_flag);
			}
		}
		if (ds->asm_demangle && flag->realname) {
			const char *lang = r_config_get (core->config, "bin.lang");
			char *name = r_bin_demangle (core->bin->cur, lang, flag->realname, flag->offset);
			r_cons_printf ("%s:", name? name: flag->realname);
			R_FREE (name);
		} else {
			r_cons_printf ("%s:", flag->name);
		}
		if (ds->show_color) {
			r_cons_strcat (Color_RESET);
		}
		ds_newline (ds);
	}
	r_list_free (uniqlist);
}

static void ds_update_ref_lines(RDisasmState *ds) {
	if (ds->show_lines) {
		ds->line = r_anal_reflines_str (ds->core, ds->at, ds->linesopts);
		{
			const char *col = ds->show_utf8? r_vline_u[LINE_UP] : r_vline_a[LINE_UP];
			char *newstr = ds->show_color
				? r_str_newf ("%s%s%s", ds->color_flow, col, ds->color_flow)
				: strdup (col);
			ds->line = r_str_replace (ds->line, r_vline_a[LINE_UP], newstr, true);
			free (newstr);
		}
		free (ds->refline);
		ds->refline = ds->line? strdup (ds->line): NULL;
		free (ds->refline2);
		ds->refline2 = r_anal_reflines_str (ds->core, ds->at,
			ds->linesopts | R_ANAL_REFLINE_TYPE_MIDDLE);
		if (ds->line) {
			if (strchr (ds->line, '<')) {
				ds->indent_level++;
			}
			if (strchr (ds->line, '>')) {
				ds->indent_level--;
			}
		} else {
			ds->indent_level = 0;
		}
	} else {
		R_FREE (ds->line);
		free (ds->refline);
		free (ds->refline2);
		ds->refline = strdup ("");
		ds->refline2 = strdup ("");
	}
}

static int ds_disassemble(RDisasmState *ds, ut8 *buf, int len) {
	RCore *core = ds->core;
	int ret;
	const char *info;
	Sdb *s = core->anal->sdb_meta;
	char key[100];
	ut64 mt_sz = UT64_MAX;

	//handle meta info to fix ds->oplen
	snprintf (key, sizeof (key) - 1, "meta.0x%"PFMT64x, ds->at);
	info = sdb_const_get (s, key, 0);
	if (info) {
		for (;*info; info++) {
			switch (*info) {
			case R_META_TYPE_DATA:
			case R_META_TYPE_STRING:
			case R_META_TYPE_FORMAT:
			case R_META_TYPE_MAGIC:
			case R_META_TYPE_HIDE:
				snprintf (key, sizeof (key) - 1,
						"meta.%c.0x%"PFMT64x, *info, ds->at);
				sdb_const_get (s, key, 0);
				mt_sz = sdb_array_get_num (s, key, 0, 0);
				//if (mt_sz) { break; }
				break;
			}
		}
	}

	if (ds->hint && ds->hint->size) {
		ds->oplen = ds->hint->size;
	}
	if (ds->hint && ds->hint->opcode) {
		free (ds->opstr);
		ds->opstr = strdup (ds->hint->opcode);
		return true;
	}
	ret = r_asm_disassemble (core->assembler, &ds->asmop, buf, len);
	if (ds->asmop.size < 1) {
		ds->asmop.size = 1;
	}

	if (ds->show_nodup) {
		const char *opname = (ret < 1)? "invalid": ds->asmop.buf_asm;
		if (ds->prev_ins && !strcmp (ds->prev_ins, opname)) {
			if (!ds->prev_ins_eq) {
				ds->prev_ins_eq = true;
				r_cons_printf ("...");
			}
			ds->prev_ins_count++;
			return -31337;
		}
		if (ds->prev_ins_eq) {
			r_cons_printf ("dup (%d)\n", ds->prev_ins_count);
		}
		ds->prev_ins_count = 0;
		ds->prev_ins_eq = false;
		if (ds->prev_ins) {
			R_FREE (ds->prev_ins);
		}
		ds->prev_ins = strdup (ds->asmop.buf_asm);
	}
	ds->oplen = ds->asmop.size;

	if (ret < 1) {
		ret = -1;
#if HASRETRY
		if (!ds->cbytes && ds->tries > 0) {
			ds->addr = core->assembler->pc;
			ds->tries--;
			ds->idx = 0;
			ds->retry = true;
			return ret;
		}
#endif
		ds->lastfail = 1;
		ds->asmop.size = (ds->hint && ds->hint->size) ? ds->hint->size : 1;
		ds->oplen = ds->asmop.size;
	} else {
		ds->lastfail = 0;
		ds->asmop.size = (ds->hint && ds->hint->size)
				? ds->hint->size
				: r_asm_op_get_size (&ds->asmop);
		ds->oplen = ds->asmop.size;
	}
	if (ds->pseudo) {
		r_parse_parse (core->parser, ds->opstr
				? ds->opstr
				: ds->asmop.buf_asm,
				ds->str);
		free (ds->opstr);
		ds->opstr = strdup (ds->str);
	}
	if (ds->acase) {
		r_str_case (ds->asmop.buf_asm, 1);
	} else if (ds->capitalize) {
		ds->asmop.buf_asm[0] = toupper (ds->asmop.buf_asm[0]);
	}
	if (info && mt_sz != UT64_MAX) {
		ds->oplen = mt_sz;
	}
	return ret;
}

static void ds_control_flow_comments(RDisasmState *ds) {
	if (ds->show_comments && ds->show_cmtflgrefs) {
		RFlagItem *item;
		if (ds->asm_anal) {
			switch (ds->analop.type) {
			case R_ANAL_OP_TYPE_CALL:
				r_core_cmdf (ds->core, "af @ 0x%"PFMT64x, ds->analop.jump);
				break;
			}
		}
		switch (ds->analop.type) {
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_CALL:
			item = r_flag_get_i (ds->core->flags, ds->analop.jump);
			if (item && item->comment) {
				if (ds->show_color) {
					r_cons_strcat (ds->pal_comment);
				}
				ds_align_comment (ds);
				r_cons_printf ("  ; ref to %s: %s\n", item->name, item->comment);
				ds_print_color_reset (ds);
			}
			break;
		}
	}
}

static void ds_print_lines_right(RDisasmState *ds){
	if (ds->linesright && ds->show_lines && ds->line) {
		r_cons_printf ("%s%s%s", COLOR (ds, color_flow), ds->line, COLOR_RESET (ds));
	}
}

static void printCol(RDisasmState *ds, char *sect, int cols, const char *color) {
	int pre, post;
	if (cols < 8) cols = 8;
	int outsz = cols + 32;
	char *out = malloc (outsz);
	if (!out) {
		return;
	}
	memset (out, ' ', outsz);
	int sect_len = strlen (sect);

	if (sect_len > cols) {
		sect[cols-2] = '.';
		sect[cols-1] = '.';
		sect[cols] = 0;
	}
	if (ds->show_color) {
		pre = strlen (color) + 1;
		post = strlen (color) + 1 + strlen (Color_RESET);
		snprintf (out, outsz-pre, "%s %s", color, sect);
		strcat (out, Color_RESET);
		out[outsz-1] = 0;
	} else {
		strcpy (out + 1, sect);
		pre = 1;
		post = 0;
	}
	out[strlen (out)] = ' ';
	out[cols + post] = 0;
	r_cons_strcat (out);
	free (out);
}

static void ds_print_lines_left(RDisasmState *ds) {
	RCore *core = ds->core;

	if (ds->show_section) {
		char *sect = strdup (get_section_name (core, ds->at));
		printCol (ds, sect, ds->show_section_col, ds->color_reg);
		free (sect);
	}
	if (ds->show_symbols) {
		static RFlagItem sfi = R_EMPTY;
		const char *name = "";
		int delta = 0;
		if (ds->fcn) {
			sfi.offset = ds->fcn->addr;
			sfi.name = ds->fcn->name;
			ds->lastflag = &sfi;
		} else {
			RFlagItem *fi = r_flag_get_at (core->flags, ds->at, false);
			if (fi) { // && (!ds->lastflag || fi->offset != ds->at))
				sfi.offset = fi->offset;
				sfi.name = fi->name;
				ds->lastflag = &sfi;
			}
		}
		if (ds->lastflag && ds->lastflag->name) {
			name = ds->lastflag->name;
			delta = ds->at - ds->lastflag->offset;
		}
		{
			char * str = r_str_newf ("%s + %-4d", name, delta);
			printCol (ds, str, ds->show_symbols_col, ds->color_num);
			free (str);
		}
	}
	if (ds->line) {
		if (ds->show_color) {
			if (!ds->linesright && ds->show_lines) {
				r_cons_printf ("%s%s%s", COLOR (ds, color_flow), ds->line, COLOR_RESET (ds));
			}
		} else {
			r_cons_printf ("%s", ds->line);
		}
	}
}

static void ds_print_family(RDisasmState *ds) {
	if (ds->show_family) {
		const char *familystr = r_anal_op_family_to_string (ds->analop.family);
		r_cons_printf ("%5s ", familystr);
	}
}

static void ds_print_cycles(RDisasmState *ds) {
	if (ds->show_cycles) {
		if (!ds->analop.failcycles) {
			r_cons_printf ("%3d     ", ds->analop.cycles);
		} else {
			r_cons_printf ("%3d %3d ", ds->analop.cycles, ds->analop.failcycles);
		}
	}
	if (ds->cyclespace) {
		char spaces [32];
		int times = R_MIN (ds->analop.cycles/4, 30); // limit to 30
		memset (spaces, ' ', sizeof (spaces));
		spaces[times] = 0;
		r_cons_strcat (spaces);
	}
}

static void ds_update_stackptr(RDisasmState *ds, RAnalOp *op) {
	//ds->stackptr = ds->core->anal->stackptr;
	ds->ostackptr = ds->stackptr;
	switch (op->stackop) {
	case R_ANAL_STACK_RESET:
		ds->stackptr = 0;
		break;
	case R_ANAL_STACK_SET:
		ds->stackptr = op->stackptr;
		break;
	case R_ANAL_STACK_INC:
		ds->stackptr += op->stackptr;
		break;
	default:
		/* nothing to do here */
		break;
	}
	/* XXX if we reset the stackptr 'ret 0x4' has not effect.
	 * Use RAnalFunction->RAnalOp->stackptr? */
	if (op->type == R_ANAL_OP_TYPE_RET) {
		ds->stackptr = 0;
	}
//	ds->ostackptr = ds->stackptr;
	//ds->core->anal->stackptr = ds->stackptr;
}

static void ds_print_stackptr(RDisasmState *ds) {
	if (ds->show_stackptr) {
		r_cons_printf ("%5d%s", ds->stackptr,
			ds->analop.type == R_ANAL_OP_TYPE_CALL?">":
			ds->analop.stackop == R_ANAL_STACK_ALIGN? "=":
			ds->stackptr > ds->ostackptr? "+":
			ds->stackptr < ds->ostackptr? "-": " ");
		ds_update_stackptr (ds, &ds->analop);
	}
}

static void ds_print_offset(RDisasmState *ds) {
	RCore *core = ds->core;
	ut64 at = ds->vat;

	bool hasCustomColor = false;
	// probably tooslow
	RFlagItem *f = r_flag_get_at (core->flags, at, 1);
	if (ds->show_color && f) { // ds->lastflag) {
		const char *color = f->color;
		if (ds->at >= f->offset && ds->at < f->offset + f->size) {
		//	if (r_itv_inrange (f->itv, ds->at))
			if (color && *color) {
				char *k = r_cons_pal_parse (f->color, NULL);
				if (k) {
					r_cons_printf ("%s", k);
					hasCustomColor = true;
					free (k);
				}
			}
		}
	}
	r_print_set_screenbounds (core->print, at);
	if (ds->show_offset) {
		static RFlagItem sfi = R_EMPTY;
		const char *label = NULL;
		RFlagItem *fi;
		int delta = -1;
		bool show_trace = false;
		if (ds->show_reloff) {
			RAnalFunction *f = r_anal_get_fcn_at (core->anal, at, R_ANAL_FCN_TYPE_NULL);
			if (!f) {
				f = fcnIn (ds, at, R_ANAL_FCN_TYPE_NULL); // r_anal_get_fcn_in (core->anal, at, R_ANAL_FCN_TYPE_NULL);
			}
			if (f) {
				delta = at - f->addr;
				sfi.name = f->name;
				sfi.offset = f->addr;
				ds->lastflag = &sfi;
				label = f->name;
			} else {
				if (ds->show_reloff_flags) {
					/* XXX: this is wrong if starting to disasm after a flag */
					fi = r_flag_get_i (core->flags, at);
					if (fi) {
						ds->lastflag = fi;
					}
					if (ds->lastflag) {
						if (ds->lastflag->offset == at) {
							delta = 0;
						} else {
							delta = at - ds->lastflag->offset;
						}
					} else {
						delta = at - core->offset;
					}
					if (ds->lastflag) {
						label = ds->lastflag->name;
					}
				}
			}
			if (!ds->lastflag) {
				delta = 0;
			}
		}
		if (ds->show_trace) {
			RDebugTracepoint *tp = r_debug_trace_get (ds->core->dbg, ds->at);
			show_trace = (tp? !!tp->count: false);
		}
		if (ds->hint && ds->hint->high) {
			show_trace = true;
		}
		if (hasCustomColor) {
			int of = core->print->flags;
			core->print->flags = 0;
			r_print_offset (core->print, at, (at == ds->dest) || show_trace,
					ds->show_offseg, ds->show_offdec, delta, label);
			core->print->flags = of;
			r_cons_strcat (Color_RESET);
		} else {
			r_print_offset (core->print, at, (at == ds->dest) || show_trace,
					ds->show_offseg, ds->show_offdec, delta, label);
		}
	}
	if (ds->atabsoff > 0) {
		if (ds->_tabsoff != ds->atabsoff) {
			char *b = ds->_tabsbuf;
			// TODO optimize to avoid down resizing
			b = malloc (ds->atabsoff + 1);
			if (b) {
				memset (b, ' ', ds->atabsoff);
				b[ds->atabsoff] = 0;
				free (ds->_tabsbuf);
				ds->_tabsbuf = b;
				ds->_tabsoff = ds->atabsoff;
			}
		}
		r_cons_strcat (ds->_tabsbuf);
	}
}

static void ds_print_op_size(RDisasmState *ds) {
	if (ds->show_size) {
		int size = ds->oplen;
		r_cons_printf ("%d ", size); //ds->analop.size);
	}
}

static void ds_print_trace(RDisasmState *ds) {
	RDebugTracepoint *tp = NULL;
	if (ds->show_trace) {
		tp = r_debug_trace_get (ds->core->dbg, ds->at);
		r_cons_printf ("%02x:%04x ", tp?tp->times:0, tp?tp->count:0);
	}
	if (ds->tracespace) {
		char spaces [32];
		int times;
		if (!tp) {
			tp = r_debug_trace_get (ds->core->dbg, ds->at);
		}
		if (tp) {
			times = R_MIN (tp->times, 30); // limit to 30
			memset (spaces, ' ', sizeof (spaces));
			spaces[times] = 0;
			r_cons_strcat (spaces);
		}
	}
}

static void ds_adistrick_comments(RDisasmState *ds) {
	if (ds->adistrick) {
		ds->middle = r_anal_reflines_middle (ds->core->anal,
			ds->core->anal->reflines, ds->at, ds->analop.size);
	}
}

static bool ds_print_data_type(RDisasmState *ds, const ut8 *buf, int ib, int size) {
	RCore *core = ds->core;
	const char *type = NULL;
	char msg[64];
	const int isSigned = (ib == 1 || ib == 8 || ib == 10)? 1: 0;
	switch (size) {
	case 1: type = isSigned? ".char": ".byte"; break;
	case 2: type = isSigned? ".int16": ".word"; break;
	case 3: type = "htons"; break;
	case 4: type = isSigned? ".int32": ".dword"; break;
	case 8: type = isSigned? ".int64": ".qword"; break;
	default: return false;
	}
	ut64 n = r_read_ble (buf, core->print->big_endian, size * 8);
	{
		int q = core->print->cur_enabled &&
			ds->cursor >= ds->index &&
			ds->cursor < (ds->index + size);
		if (q) {
			if (ds->cursor > ds->index) {
				int diff = ds->cursor - ds->index;
				r_cons_printf ("  %d  ", diff);
			} else if (ds->cursor == ds->index) {
				r_cons_printf ("  *  ");
			} else {
				r_cons_printf ("     ");
			}
		} else {
			r_cons_printf ("     ");
		}
	}

	switch (ib) {
	case 1:
		r_str_bits (msg, buf, size * 8, NULL);
		r_cons_printf ("%s %sb", type, msg);
		break;
	case 3:
		r_cons_printf ("%s %d", type, ntohs (n & 0xFFFF));
		break;
	case 8:
		r_cons_printf ("%s %oo", type, n);
		break;
	case 10:
		r_cons_printf ("%s %d", type, n);
		break;
	default:
		switch (size) {
		case 1:
			r_cons_printf ("%s 0x%02x", type, n);
			break;
		case 2:
			r_cons_printf ("%s 0x%04x", type, n);
			break;
		case 4:
			r_cons_printf ("%s 0x%08x", type, n);
			break;
		case 8:
			r_cons_printf ("%s 0x%016" PFMT64x, type, n);
			break;
		default:
			return false;
		}
	}

	if (size == 4 || size == 8) {
		if (r_str_startswith (r_config_get (core->config, "asm.arch"), "arm")) {
			ut64 bits = r_config_get_i (core->config, "asm.bits");
			//adjust address for arm/thumb address
			if (bits < 64) {
				if (n & 1) {
					n--;
				}
			}
		}
		if (n >= ds->min_ref_addr) {
			const RList *flags = r_flag_get_list (core->flags, n);
			RListIter *iter;
			RFlagItem *fi;
			r_list_foreach (flags, iter, fi) {
				r_cons_printf (" ; %s", fi->name);
			}
		}
	}
	return true;
}

static int ds_print_meta_infos(RDisasmState *ds, ut8* buf, int len, int idx) {
	int ret = 0;
	const char *infos, *metas;
	char key[100];
	RAnalMetaItem MI, *mi = &MI;
	RCore *core = ds->core;
	Sdb *s = core->anal->sdb_meta;

	snprintf (key, sizeof (key), "meta.0x%" PFMT64x, ds->at);
	infos = sdb_const_get (s, key, 0);

	ds->mi_found = false;
	if (infos) {
		for (; *infos; infos++) {
			if (*infos == ',') {
				continue;
			}
			snprintf (key, sizeof (key), "meta.%c.0x%" PFMT64x, *infos, ds->at);
			metas = sdb_const_get (s, key, 0);
			if (!metas) {
				continue;
			}
			if (!r_meta_deserialize_val (mi, *infos, ds->at, metas)) {
				continue;
			}
			// TODO: implement ranged meta find (if not at the begging of function..
			char *out = NULL;
			int hexlen;
			int delta;
			if (mi) {
				switch (mi->type) {
				case R_META_TYPE_STRING:
				{
					char *quote = "\"";
					bool esc_bslash = ds->use_json ? true : core->print->esc_bslash;

					switch (mi->subtype) {
					case R_STRING_ENC_UTF8:
						out = r_str_escape_utf8 (mi->str, false, esc_bslash);
						break;
					case 0:  /* temporary legacy workaround */
						esc_bslash = false;
						/* fallthrough */
					default:
						out = r_str_escape_latin1 (mi->str, false, esc_bslash);
					}
					if (!out) {
						break;
					}
					if (ds->use_json) {
						// escape twice for json
						char *out2 = out;
						out = r_str_escape (out2);
						free (out2);
						if (!out) {
							break;
						}
						quote = "\\\"";
					}

					r_cons_printf ("    .string %s%s%s%s%s ; len=%"PFMT64d,
							COLOR (ds, color_btext), quote, out, quote, COLOR_RESET (ds),
							mi->size);
					free (out);
					delta = ds->at - mi->from;
					ds->oplen = mi->size - delta;
					ds->asmop.size = (int)mi->size;
					//i += mi->size-1; // wtf?
					R_FREE (ds->line);
					R_FREE (ds->refline);
					R_FREE (ds->refline2);
					ds->mi_found = true;
					break;
				}
				case R_META_TYPE_HIDE:
					r_cons_printf ("(%"PFMT64d" bytes hidden)", mi->size);
					ds->asmop.size = mi->size;
					ds->oplen = mi->size;
					ds->mi_found = true;
					break;
				case R_META_TYPE_RUN:
					r_core_cmdf (core, "%s @ 0x%"PFMT64x, mi->str, ds->at);
					ds->asmop.size = mi->size;
					ds->oplen = mi->size;
					ds->mi_found = true;
					break;
				case R_META_TYPE_DATA:
					hexlen = len - idx;
					delta = ds->at - mi->from;
					if (mi->size < hexlen) {
						hexlen = mi->size;
					}
					ds->oplen = mi->size - delta;
					core->print->flags &= ~R_PRINT_FLAGS_HEADER;
					if (!ds_print_data_type (ds, buf + idx, ds->hint? ds->hint->immbase: 0, mi->size)) {
						r_cons_printf ("hex length=%" PFMT64d " delta=%d\n", mi->size , delta);
						r_print_hexdump (core->print, ds->at, buf+idx, hexlen-delta, 16, 1, 1);
					}
					core->inc = 16; // ds->oplen; //
					core->print->flags |= R_PRINT_FLAGS_HEADER;
					ds->asmop.size = ret = (int)mi->size; //-delta;
					R_FREE (ds->line);
					R_FREE (ds->refline);
					R_FREE (ds->refline2);
					ds->mi_found = true;
					break;
				case R_META_TYPE_FORMAT:
					r_cons_printf ("format %s {\n", mi->str);
					r_print_format (core->print, ds->at, buf+idx, len-idx, mi->str, R_PRINT_MUSTSEE, NULL, NULL);
					r_cons_printf ("} %d", mi->size);
					ds->oplen = ds->asmop.size = ret = (int)mi->size;
					R_FREE (ds->line);
					R_FREE (ds->refline);
					R_FREE (ds->refline2);
					ds->mi_found = true;
					break;
				}
			}
			if (MI.str) {
				free (MI.str);
				MI.str = NULL;
			}
		}
	}
	return ret;
}

static void ds_instruction_mov_lea(RDisasmState *ds, int idx) {
	RCore *core = ds->core;
	RAnalValue *src;
	const int addrbytes = core->io->addrbytes;

	switch (ds->analop.type) {
	case R_ANAL_OP_TYPE_LENGTH:
	case R_ANAL_OP_TYPE_CAST:
	case R_ANAL_OP_TYPE_CMOV:
	case R_ANAL_OP_TYPE_MOV:
		src = ds->analop.src[0];
		if (src && src->memref>0 && src->reg && core->anal->reg) {
			const char *pc = core->anal->reg->name[R_REG_NAME_PC];
			RAnalValue *dst = ds->analop.dst;
			if (dst && dst->reg && dst->reg->name) {
				if (src->reg->name && pc && !strcmp (src->reg->name, pc)) {
					RFlagItem *item;
					ut8 b[8];
					ut64 ptr = addrbytes * idx + ds->addr + src->delta + ds->analop.size;
					ut64 off = 0LL;
					r_core_read_at (core, ptr, b, src->memref);
					off = r_mem_get_num (b, src->memref);
					item = r_flag_get_i (core->flags, off);
					//TODO: introduce env for this print?
					r_cons_printf ("; MOV %s = [0x%"PFMT64x"] = 0x%"PFMT64x" %s\n",
							dst->reg->name, ptr, off, item?item->name: "");
					if (ds->asm_anal) {
						if (r_io_is_valid_offset (core->io, off, 0)) {
							r_anal_ref_add (core->anal, ds->addr, off, 'd');
						}
					}
				}
			}
		}
		break;
// TODO: get from meta anal?
	case R_ANAL_OP_TYPE_LEA:
		src = ds->analop.src[0];
		if (src && src->reg && core->anal->reg && *(core->anal->reg->name)) {
			const char *pc = core->anal->reg->name[R_REG_NAME_PC];
			RAnalValue *dst = ds->analop.dst;
			if (dst && dst->reg && src->reg->name && pc && !strcmp (src->reg->name, pc)) {
				int index = 0;
				int memref = core->assembler->bits/8;
				RFlagItem *item;
				ut8 b[64];
				ut64 ptr = index + ds->addr + src->delta + ds->analop.size;
				ut64 off = 0LL;
				r_core_read_at (core, ptr, b, sizeof (b)); //memref);
				off = r_mem_get_num (b, memref);
				item = r_flag_get_i (core->flags, off);
				if (ds->show_leahints) {
					char s[64];
					r_str_ncpy (s, (const char *)b, sizeof (s));
					r_str_filter (s, -1);
					ds_begin_comment (ds);
					ds_comment (ds, true, "; LEA %s = [0x%"PFMT64x"] = 0x%"PFMT64x" \"%s\"",
					            dst->reg->name, ptr, off, item?item->name: s);
					if (ds->asm_anal) {
						if (r_io_is_valid_offset (core->io, off, 0)) {
							r_anal_ref_add (core->anal, ds->addr, ptr, 'd');
						}
					}
				}
			}
		}
	}
}

static st64 revert_cdiv_magic(st64 magic) {
	ut64 amagic = llabs (magic);
	const st64 N = ST64_MAX;
	st64 E, candidate;
	short s;

	if (amagic < 0xFFFFFF || amagic > UT32_MAX) {
		return 0;
	}
	if (magic < 0) {
		magic += 1LL << 32;
	}
	for (s = 0; s < 16; s++) {
		E = 1LL << (32 + s);
		candidate = (E + magic - 1) / magic;
		if (candidate > 0) {
			if ( ((N * magic) >> (32 + s)) == (N / candidate) ) {
				return candidate;
			}
		}
	}
	return 0;
}

static void ds_cdiv_optimization(RDisasmState *ds) {
	char *esil;
	char *end, *comma;
	st64 imm;
	st64 divisor;
	if (!ds->show_hints) {
		return;
	}
	switch (ds->analop.type) {
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_MUL:
		esil = R_STRBUF_SAFEGET (&ds->analop.esil);
		while (esil) {
			comma = strstr (esil, ",");
			if (!comma) {
				break;
			}
			imm = strtol (esil, &end, 10);
			if (comma && comma == end) {
				divisor = revert_cdiv_magic (imm);
				if (divisor) {
					r_cons_printf (" ; CDIV: %lld * 2^n", divisor);
					break;
				}
			}
			esil = comma + 1;
		}
	}
	// /TODO: check following SHR instructions
}

static void ds_print_show_bytes(RDisasmState *ds) {
	RCore* core = ds->core;
	char *nstr, *str = NULL, pad[64];
	char *flagstr = NULL;
	int oldFlags = core->print->flags;
	char extra[128];
	int j, k;

	if (!ds->show_bytes || ds->nb < 1) {
		return;
	}
	if (!ds->show_color_bytes) {
		core->print->flags &= ~R_PRINT_FLAGS_COLOR;
	}
	strcpy (extra, " ");
	if (ds->show_flag_in_bytes) {
		flagstr = r_flag_get_liststr (core->flags, ds->at);
	}
	if (flagstr) {
		str = flagstr;
		if (ds->nb > 0) {
			k = ds->nb-strlen (flagstr) - 1;
			if (k < 0 || k > sizeof(pad)) k = 0;
			for (j = 0; j < k; j++) {
				pad[j] = ' ';
			}
			pad[j] = '\0';
		} else {
			pad[0] = 0;
		}
	} else {
		if (ds->show_flag_in_bytes) {
			k = ds->nb - 1;
			if (k < 0 || k > sizeof (pad)) {
				k = 0;
			}
			for (j = 0; j < k; j++) {
				pad[j] = ' ';
			}
			pad[j] = '\0';
			str = strdup ("");
		} else {
			str = strdup (ds->asmop.buf_hex);
			if (r_str_ansi_len (str) > ds->nb) {
				char *p = (char *)r_str_ansi_chrn (str, ds->nb);
				if (p)  {
					p[0] = '.';
					p[1] = '\0';
				}
			}
			ds->print->cur_enabled = (ds->cursor != -1);
			nstr = r_print_hexpair (ds->print, str, ds->index);
			if (ds->print->bytespace) {
				k = (ds->nb + (ds->nb / 2)) - r_str_ansi_len (nstr) + 2;
			} else {
				k = ds->nb - r_str_ansi_len (nstr) + 1;
			}
			if (k > 0) {
				// setting to sizeof screw up the disasm
				if (k > sizeof (pad)) {
					k = 18;
				}
				for (j = 0; j < k; j++) {
					pad[j] = ' ';
				}
				pad[j] = 0;
				if (ds->lbytes) {
					// hack to align bytes left
					strcpy (extra, pad);
					*pad = 0;
				}
			} else {
				pad[0] = 0;
			}
			free (str);
			str = nstr;
		}
	}
	r_cons_printf ("%s%s %s", pad, str, extra);
	free (str);
	core->print->flags = oldFlags;
}

static void ds_print_indent(RDisasmState *ds) {
	if (ds->show_indent) {
		char indent[128];
		int num = ds->indent_level * ds->indent_space;
		if (num < 0) {
			num = 0;
		}
		if (num >= sizeof (indent)) {
			num = sizeof (indent) - 1;
		}
		memset (indent, ' ', num);
		indent[num] = 0;
		r_cons_strcat (indent);
	}
}

static void ds_print_opstr(RDisasmState *ds) {
	ds_print_indent (ds);
	if (ds->use_json) {
		char *escaped_str = r_str_escape(ds->opstr);
		if (escaped_str) {
			r_cons_strcat(escaped_str);
		}
		free(escaped_str);
	} else {
		r_cons_strcat (ds->opstr);
	}
	ds_print_color_reset (ds);
}

static void ds_print_color_reset(RDisasmState *ds) {
	if (ds->show_color) {
		r_cons_strcat (Color_RESET);
	}
}

static int ds_print_middle(RDisasmState *ds, int ret) {
	if (ds->middle != 0) {
		ret -= ds->middle;
		ds_align_comment (ds);
		if (ds->show_color) {
			r_cons_strcat (ds->pal_comment);
		}
		r_cons_printf (" ; *middle* %d", ret);
		if (ds->show_color) {
			r_cons_strcat (Color_RESET);
		}
	}
	return ret;
}

static bool ds_print_labels(RDisasmState *ds, RAnalFunction *f) {
	RCore *core = ds->core;
	const char *label;
	if (!f) {
		// f = r_anal_get_fcn_in (core->anal, ds->at, 0);
		f = fcnIn (ds, ds->at, 0);
	}
	label = r_anal_fcn_label_at (core->anal, f, ds->at);
	if (!label) {
		return false;
	}
	if (ds->show_color) {
		r_cons_strcat (ds->color_label);
		r_cons_printf (" .%s:\n", label);
		ds_print_color_reset (ds);
	} else {
		r_cons_printf (" .%s:\n", label);
	}
	return true;
}

static void ds_print_import_name(RDisasmState *ds) {
	RListIter *iter = NULL;
	RBinReloc *rel = NULL;
	RCore * core = ds->core;

	switch (ds->analop.type) {
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_CJMP:
	case R_ANAL_OP_TYPE_CALL:
		if (core->bin->cur->o->imports && core->bin->cur->o->relocs) {
			r_list_foreach (core->bin->cur->o->relocs, iter, rel) {
				if ((rel->vaddr == ds->analop.jump) &&
					(rel->import != NULL)) {
					if (ds->show_color) {
						r_cons_strcat (ds->color_fname);
					}
					// TODO: handle somehow ordinals import
					ds_align_comment (ds);
					r_cons_printf ("  ; (imp.%s)", rel->import->name);
					ds_print_color_reset (ds);
				}
			}
		}
	}
}

static void ds_print_sysregs(RDisasmState *ds) {
	RCore *core = ds->core;
	if (!ds->show_comments) {
		return;
	}
	switch (ds->analop.type) {
	// Syscalls first
	case R_ANAL_OP_TYPE_IO:
		{
			const int imm = (int)ds->analop.val;
			RSyscall *sc = core->anal->syscall;
			const char *ioname = r_syscall_get_io (sc, imm);
			if (ioname && *ioname) {
				ALIGN;
				ds_comment (ds, true, "; IO %s", ioname);
				ds->has_description = true;
			}
		}
		break;
	// Then sysregs
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_LEA:
	case R_ANAL_OP_TYPE_LOAD:
	case R_ANAL_OP_TYPE_STORE:
		{
			const int imm = (int)ds->analop.ptr;
			const char *sr = r_syscall_sysreg (core->anal->syscall, "reg", imm);
			if (sr) {
				ALIGN;
				ds_comment (ds, true, "; REG %s - %s", sr, "");
				// TODO: add register description description
				ds->has_description = true;
			}
		}
		break;
	}
}

static void ds_print_fcn_name(RDisasmState *ds) {
	int delta;
	const char *label;
	RAnalFunction *f;
	RCore *core = ds->core;
	if (!ds->show_comments) {
		return;
	}
	switch (ds->analop.type) {
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_CJMP:
	case R_ANAL_OP_TYPE_CALL:
		// f = r_anal_get_fcn_in (core->anal, ds->analop.jump, R_ANAL_FCN_TYPE_NULL);
		f = fcnIn (ds, ds->analop.jump, R_ANAL_FCN_TYPE_NULL);
		if (f && f->name && ds->opstr && !strstr (ds->opstr, f->name)) {
			//beginline (core, ds, f);
			// print label
			delta = ds->analop.jump - f->addr;
			label = r_anal_fcn_label_at (core->anal, f, ds->analop.jump);
			if (label) {
				ALIGN;
				ds_comment (ds, true, "; %s.%s", f->name, label);
			} else {
				RAnalFunction *f2 = fcnIn (ds, ds->at, 0); //r_anal_get_fcn_in (core->anal, ds->at, 0);
				if (f != f2) {
					ALIGN;
					if (delta > 0) {
						ds_comment (ds, true, "; %s+0x%x", f->name, delta);
					} else if (delta < 0) {
						ds_comment (ds, true, "; %s-0x%x", f->name, -delta);
					} else {
						ds_comment (ds, true, "; %s", f->name);
					}
				}
			}
		}
		break;
	}
}

static void ds_print_shortcut(RDisasmState *ds, ut64 addr, int pos) {
	char *shortcut = r_core_add_asmqjmp (ds->core, addr);
	if (!pos && !shortcut) {
		r_cons_printf ("   ");
		return;
	}
	if (pos) {
		ds_align_comment (ds);
	}
	char *ch = pos?  ";": "";
	if (ds->show_color) {
		r_cons_strcat (ds->pal_comment);
	}
	if (shortcut) {
		if (ds->core->is_asmqjmps_letter) {
			r_cons_printf ("%s[g%s]", ch, shortcut);
		} else {
			r_cons_printf ("%s[%s]", ch, shortcut);
		}
		free (shortcut);
	} else {
		r_cons_printf ("%s[?]", ch);
	}
	if (ds->show_color) {
		r_cons_strcat (Color_RESET);
	}
}

static void ds_print_core_vmode(RDisasmState *ds, int pos) {
	RCore *core = ds->core;
	bool gotShortcut = false;

	if (!ds->show_jmphints) {
		return;
	}
	if (core->vmode) {
		switch (ds->analop.type) {
		case R_ANAL_OP_TYPE_LEA:
			if (ds->show_leahints) {
				ds_print_shortcut (ds, ds->analop.ptr, pos);
				gotShortcut = true;
			}
			break;
		case R_ANAL_OP_TYPE_UCALL:
		case R_ANAL_OP_TYPE_UCALL | R_ANAL_OP_TYPE_REG | R_ANAL_OP_TYPE_IND:
		case R_ANAL_OP_TYPE_UCALL | R_ANAL_OP_TYPE_IND:
#if 0
			if (ds->analop.jump == 0 && ds->analop.ptr) {
				ut8 buf[sizeof(ut64)] = {0};
				r_io_read_at (core->io, ds->analop.ptr, buf, sizeof (buf));
				ut32 n32 = r_read_ble32 (buf, 0);
				// is valid address
				// ut32 n64 = r_read_ble32 (buf, 0);
				ds_print_shortcut (ds, n32, pos);
			} else {
				// ds_print_shortcut (ds, ds->analop.jump, pos);
				ds_print_shortcut (ds, ds->analop.ptr, pos);
			}
#endif
			if (ds->analop.jump != UT64_MAX) {
				ds_print_shortcut (ds, ds->analop.jump, pos);
			} else {
				ds_print_shortcut (ds, ds->analop.ptr, pos);
			}
			gotShortcut = true;
			break;
		case R_ANAL_OP_TYPE_RCALL:
			break;
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_CALL:
		case R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_CALL:
			ds_print_shortcut (ds, ds->analop.jump, pos);
			gotShortcut = true;
			break;
		}
		if (!gotShortcut) {
			r_cons_strcat ("   ");
		}
	}
}

// align for comment
static void ds_align_comment(RDisasmState *ds) {
	if (ds->show_comment_right_default) {
		const int cmtcol = ds->cmtcol - 1;
		int cstrlen = 0;
		char *ll = r_cons_lastline (&cstrlen);
		if (ll) {
			int cols, ansilen = r_str_ansi_len (ll);
			int utf8len = r_utf8_strlen ((const ut8*)ll);
			int cells = utf8len - (cstrlen - ansilen);
			if (cstrlen < 20) {
				ds_print_pre (ds);
			}
			cols = ds->interactive ? ds->core->cons->columns : 1024;
			if (cells < cmtcol) {
				int len = cmtcol - cells;
				if (len < cols && len > 0) {
					r_cons_memset (' ', len);
				}
			}
			r_cons_print (" ");
		}
	}
}

static void ds_print_dwarf(RDisasmState *ds) {
	if (ds->show_dwarf) {
		int len = ds->opstr? strlen (ds->opstr): 0;
		if (len < 30) {
			len = 30 - len;
		}
		// TODO: cache value in ds
		int dwarfFile = (int)ds->dwarfFile + (int)ds->dwarfAbspath;
		free (ds->sl);
		ds->sl = r_bin_addr2text (ds->core->bin, ds->at, dwarfFile);
		if (ds->sl) {
			if ((!ds->osl || (ds->osl && strcmp (ds->sl, ds->osl)))) {
				char *chopstr, *line = strdup (ds->sl);
				if (!line) {
					return;
				}
				r_str_replace_char (line, '\t', ' ');
				r_str_replace_char (line, '\x1b', ' ');
				r_str_replace_char (line, '\r', ' ');
				r_str_replace_char (line, '\n', '\x00');
				chopstr = r_str_trim (line);
				if (!*chopstr) {
					free (line);
					return;
				}
				// handle_set_pre (ds, "  ");
				ds_align_comment (ds);
				if (ds->show_color) {
					r_cons_printf ("%s; %s"Color_RESET, ds->pal_comment, chopstr);
				} else {
					r_cons_printf ("; %s", chopstr);
				}
				free (ds->osl);
				ds->osl = ds->sl;
				ds->sl = NULL;
				free (line);
			}
		}
	}
}

static void ds_print_asmop_payload(RDisasmState *ds, const ut8 *buf) {
	if (ds->show_varxs) {
		// XXX asume analop is filled
		//r_anal_op (core->anal, &ds->analop, ds->at, core->block+i, core->blocksize-i);
		int v = ds->analop.ptr;
		switch (ds->analop.stackop) {
		case R_ANAL_STACK_GET:
			if (v < 0) {
				r_cons_printf (" ; local.get %d", -v);
			} else {
				r_cons_printf (" ; arg.get %d", v);
			}
			break;
		case R_ANAL_STACK_SET:
			if (v < 0) {
				r_cons_printf (" ; local.set %d", -v);
			} else {
				r_cons_printf (" ; arg.set %d", v);
			}
			break;
		}
	}
	if (ds->asmop.payload != 0) {
		r_cons_printf ("\n; .. payload of %d byte(s)", ds->asmop.payload);
		if (ds->showpayloads) {
			int mod = ds->asmop.payload % ds->core->assembler->dataalign;
			int x;
			for (x = 0; x < ds->asmop.payload; ++x) {
				r_cons_printf ("\n        0x%02x", buf[ds->oplen + x]);
			}
			for (x = 0; x < mod; ++x) {
				r_cons_printf ("\n        0x%02x ; alignment", buf[ds->oplen + ds->asmop.payload + x]);
			}
		}
	}
}

static char *ds_esc_str(RDisasmState *ds, const char *str, int len, const char **prefix_out) {
	int str_len;
	char *escstr = NULL;
	const char *prefix = "";
	switch (ds->strenc) {
	case R_STRING_ENC_LATIN1:
		escstr = r_str_escape_latin1 (str, ds->show_asciidot, true);
		break;
	case R_STRING_ENC_UTF8:
		escstr = r_str_escape_utf8 (str, ds->show_asciidot, true);
		break;
	case R_STRING_ENC_UTF16LE:
		escstr = r_str_escape_utf16le (str, len, ds->show_asciidot);
		prefix = "u";
		break;
	case R_STRING_ENC_UTF32LE:
		escstr = r_str_escape_utf32le (str, len, ds->show_asciidot);
		prefix = "U";
		break;
	default:
		str_len = strlen (str);
		if ((str_len == 1 && len > 3 && str[2] && !str[3])
		    || (str_len == 3 && len > 5 && !memcmp (str, "\xff\xfe", 2) && str[4] && !str[5])) {
			escstr = r_str_escape_utf16le (str, len, ds->show_asciidot);
			prefix = "u";
		} else if (str_len == 1 && len > 7 && !str[2] && !str[3] && str[4] && !str[5]) {
			RStrEnc enc = R_STRING_ENC_UTF32LE;
			RRune ch;
			const char *ptr, *end;
			end = (const char *)r_mem_mem_aligned ((ut8 *)str, len, (ut8 *)"\0\0\0\0", 4, 4);
			if (!end) {
				end = str + len - 1;
			}
			for (ptr = str; ptr < end; ptr += 4) {
				if (r_utf32le_decode ((ut8 *)ptr, end - ptr, &ch) > 0 && ch > 0x10ffff) {
					enc = R_STRING_ENC_LATIN1;
					break;
				}
			}
			if (enc == R_STRING_ENC_UTF32LE) {
				escstr = r_str_escape_utf32le (str, len, ds->show_asciidot);
				prefix = "U";
			} else {
				escstr = r_str_escape_latin1 (str, ds->show_asciidot, true);
			}
		} else {
			RStrEnc enc = R_STRING_ENC_LATIN1;
			const char *ptr = str, *end = str + str_len;
			for (; ptr < end; ptr++) {
				if (r_utf8_decode ((ut8 *)ptr, end - ptr, NULL) > 1) {
					enc = R_STRING_ENC_UTF8;
					break;
				}
			}
			escstr = (enc == R_STRING_ENC_UTF8 ?
			          r_str_escape_utf8 (str, ds->show_asciidot, true) :
			          r_str_escape_latin1 (str, ds->show_asciidot, true));
		}
	}
	if (prefix_out) {
		*prefix_out = prefix;
	}
	return escstr;
}

static void ds_print_str(RDisasmState *ds, const char *str, int len, ut64 refaddr) {
	const char *prefix;
	if (!r_bin_string_filter (ds->core->bin, str, refaddr)) {
		return;
	}
	char *escstr = ds_esc_str (ds, str, len, &prefix);
	if (escstr) {
		ds_begin_comment (ds);
		ds_comment (ds, true, "; %s\"%s\"", prefix, escstr);
		ds->printed_str_addr = refaddr;
		free (escstr);
	}
}

static inline bool is_filtered_flag(RDisasmState *ds, const char *name) {
	if (ds->show_noisy_comments || strncmp (name, "str.", 4)) {
		return false;
	}
	ut64 refaddr = ds->analop.ptr;
	char *anal_flag = r_meta_get_string (ds->core->anal, R_META_TYPE_STRING, refaddr);
	if (anal_flag) {
		anal_flag = strdup (anal_flag);
		if (anal_flag) {
			r_name_filter (anal_flag, -1);
			if (!strcmp (&name[4], anal_flag)) {
				free (anal_flag);
				return true;
			}
			free (anal_flag);
		}
	}
	return false;
}

/* convert numeric value in opcode to ascii char or number */
static void ds_print_ptr(RDisasmState *ds, int len, int idx) {
	RCore *core = ds->core;
	ut64 p = ds->analop.ptr;
	ut64 v = ds->analop.val;
	ut64 refaddr = p;
	bool aligned = false;
	int refptr = ds->analop.refptr;
	RFlagItem *f;
	if (!ds->show_comments || !ds->show_slow) {
		return;
	}

	ds->chref = 0;
	if ((char)v > 0 && v >= '!') {
		ds->chref = (char)v;
		if (ds->immstr) {
			char *str = r_str_from_ut64 (r_read_ble64 (&v, core->print->big_endian));
			if (str && *str) {
				ALIGN;
				ds_comment (ds, true, "; '%s'", str);
			}
			free (str);
		} else {
			if ((char)v > 0 && v >= '!' && v <= '~') {
				ds_begin_comment (ds);
				aligned = true;
				ds_comment (ds, true, "; '%c'", (char)v);
			}
		}
	}
	RList *list = NULL;
	RListIter *iter;
	RAnalRef *ref;
	list = r_anal_refs_get (core->anal, ds->at);
	r_list_foreach (list, iter, ref) {
		if (ref->type == R_ANAL_REF_TYPE_STRING || ref->type == R_ANAL_REF_TYPE_DATA) {
			if ((f = r_flag_get_i (core->flags, ref->addr))) {
				refaddr = ref->addr;
				break;
			}
		}
	}
	r_list_free (list);
	if (ds->analop.type == (R_ANAL_OP_TYPE_MOV | R_ANAL_OP_TYPE_REG)
	    && ds->analop.stackop == R_ANAL_STACK_SET
	    && ds->analop.val != UT64_MAX && ds->analop.val > 10) {
		const char *arch = r_config_get (core->config, "asm.arch");
		if (arch && !strcmp (arch, "x86")) {
			p = refaddr = ds->analop.val;
			refptr = 0;
		}
	}
	bool flag_printed = false;
	bool refaddr_printed = false;
	bool string_printed = false;
	if (p == UT64_MAX) {
		/* do nothing */
	} else if (((st64)p) > 0 || ((st64)refaddr) > 0) {
		const char *kind;
		char *msg = calloc (sizeof (char), len);
		if (((st64)p) > 0) {
			f = r_flag_get_i (core->flags, p);
			if (f) {
				refaddr = p;
				if (!flag_printed && !is_filtered_flag (ds, f->name)
				    && (!ds->opstr || !strstr (ds->opstr, f->name))) {
					ds_begin_comment (ds);
					ds_comment (ds, true, "; %s", f->name);
					ds->printed_flag_addr = p;
					flag_printed = true;
				}
			}
		}
		r_io_read_at (core->io, refaddr, (ut8*)msg, len - 1);
		if (refptr) {
			ut64 num = r_read_ble (msg, core->print->big_endian, refptr * 8);
			st64 n = (st64)num;
			st32 n32 = (st32)(n & UT32_MAX);
			if (ds->analop.type == R_ANAL_OP_TYPE_LEA) {
				char str[128] = {0};
				f = r_flag_get_i (core->flags, refaddr);
				if (!f && ds->show_slow) {
					r_io_read_at (ds->core->io, ds->analop.ptr,
						      (ut8 *)str, sizeof (str) - 1);
					str[sizeof (str) - 1] = 0;
					if (!string_printed && str[0] && r_str_is_printable_incl_newlines (str)) {
						ds_print_str (ds, str, sizeof (str), ds->analop.ptr);
						string_printed = true;
					}
				}
			} else {
				f = NULL;
				if (n == UT32_MAX || n == UT64_MAX) {
					ds_begin_comment (ds);
					ds_comment (ds, true, "; [0x%" PFMT64x":%d]=-1",
							refaddr, refptr);
				} else if (n == n32 && (n32 > -512 && n32 < 512)) {
					ds_begin_comment (ds);
					ds_comment (ds, true, "; [0x%" PFMT64x
							  ":%d]=%"PFMT64d, refaddr, refptr, n);
				} else {
					const char *kind, *flag = "";
					char *msg2 = NULL;
					f = r_flag_get_i (core->flags, n);
					if (f) {
						flag = f->name;
					} else {
						msg2 = calloc (sizeof (char), len);
						r_io_read_at (core->io, n, (ut8*)msg2, len - 1);
						msg2[len - 1] = 0;
						kind = r_anal_data_kind (core->anal, refaddr, (const ut8*)msg2, len - 1);
						if (kind && !strcmp (kind, "text")) {
							r_str_filter (msg2, 0);
							if (*msg2) {
								char *lala = r_str_newf ("\"%s\"", msg2);
								free (msg2);
								flag = msg2 = lala;
							}
						}
					}
					ds_begin_comment (ds);
					{
						const char *refptrstr = "";
						if (core->print->flags & R_PRINT_FLAGS_SECSUB) {
							RIOSection *s = r_io_section_vget (core->io, n);
							if (s) {
								refptrstr = s->name;
							}
						}
						ds_comment (ds, true, "; [0x%" PFMT64x":%d]=%s%s0x%" PFMT64x "%s%s",
							refaddr, refptr, refptrstr, *refptrstr?".":"",
							n, (flag && *flag) ? " " : "", flag);
					}
					free (msg2);
				}
				refaddr_printed = true;
			}
		}
		if (!strcmp (ds->show_cmtoff, "true")) {
			ds_begin_comment (ds);
			ds_comment (ds, true, "; 0x%" PFMT64x, refaddr);
			refaddr_printed = true;
		} else if (!refaddr_printed && strcmp (ds->show_cmtoff, "false")) {
			char addrstr[sizeof (refaddr) * 2 + 3];
			snprintf (addrstr, sizeof (addrstr), "0x%" PFMT64x, refaddr);
			if (!ds->opstr || !strstr (ds->opstr, addrstr)) {
				snprintf (addrstr, sizeof (addrstr), "0x%08" PFMT64x, refaddr);
				if (!ds->opstr || !strstr (ds->opstr, addrstr)) {
					bool print_refaddr = true;
					if (refaddr < 10) {
						snprintf (addrstr, sizeof (addrstr), "%" PFMT64u, refaddr);
						if (ds->opstr && strstr (ds->opstr, addrstr)) {
							print_refaddr = false;
						}
					}
					if (print_refaddr) {
						if (!aligned) {
							ds_begin_comment (ds);
						}
						ds_comment (ds, true, "; 0x%" PFMT64x, refaddr);
						refaddr_printed = true;
					}
				}
			}
		}
#if 1
		if (!(IS_PRINTABLE (*msg) || ISWHITECHAR (*msg)
		      || (len > 1 && !memcmp (msg, "\xff\xfe", 2)))) {
			*msg = 0;
		} else {
			msg[len - 1] = 0;
		}
#endif
		f = r_flag_get_i (core->flags, refaddr);
		if (f) {
			if (strlen (msg) != 1) {
				char *msg2 = r_str_new (msg);
				if (msg2) {
					r_str_filter (msg2, 0);
					if (!strncmp (msg2, "UH..", 4)) {
						*msg = 0;
					}
					free (msg2);
				}
			}
			if (*msg) {
				if (!string_printed) {
					ds_print_str (ds, msg, len, refaddr);
					string_printed = true;
				}
			} else if (!flag_printed && (!ds->opstr || !strstr (ds->opstr, f->name))) {
				ds_begin_comment (ds);
				ds_comment (ds, true, "; %s", f->name);
				ds->printed_flag_addr = refaddr;
				flag_printed = true;
			}
		} else {
			if (refaddr == UT64_MAX || refaddr == UT32_MAX) {
				ds_begin_comment (ds);
				ds_comment (ds, true, "; -1");
			} else if (((char)refaddr > 0) && refaddr >= '!' && refaddr <= '~') {
				char ch = refaddr;
				ds_begin_comment (ds);
				if (ch != ds->chref) {
					ds_comment (ds, true, "; '%c'", ch);
				}
			} else if (refaddr > 10) {
				if ((st64)refaddr < 0) {
					// resolve local var if possible
					RAnalVar *v = r_anal_var_get (core->anal, ds->at, 'v', 1, (int)refaddr);
					ds_begin_comment (ds);
					if (v) {
						ds_comment (ds, true, "; var %s", v->name);
						r_anal_var_free (v);
					} else {
						ds_comment (ds, true, "; var %d", -(int)refaddr);
					}
				} else {
					if (r_core_anal_address (core, refaddr) & R_ANAL_ADDR_TYPE_ASCII) {
						if (!string_printed && *msg) {
							ds_print_str (ds, msg, len, refaddr);
							string_printed = true;
						}
					}
				}
			}
			//XXX this should be refactored with along the above
			kind = r_anal_data_kind (core->anal, refaddr, (const ut8*)msg, len - 1);
			if (kind) {
				if (!strcmp (kind, "text")) {
					if (!string_printed && *msg) {
						ds_print_str (ds, msg, len, refaddr);
						string_printed = true;
					}
				} else if (!strcmp (kind, "invalid")) {
					int *n = (int*)&refaddr;
					ut64 p = ds->analop.val;
					if (p == UT64_MAX || p == UT32_MAX) {
						p = ds->analop.ptr;
					}
					/* avoid double ; -1 */
					if (p != UT64_MAX && p != UT32_MAX) {
						if (*n > -0xfff && *n < 0xfff) {
							if (!aligned) {
								ds_begin_comment (ds);
							}
							ds_comment (ds, true, "; %"PFMT64d, p);
						}
					}
				} else {
					// r_cons_printf (" ; %s", kind);
				}
				// TODO: check for more data kinds
			}
		}
		free (msg);
	} else {
		ds_print_as_string (ds);
	}
#if 0
	if (!ds->show_comment_right && ds->cmtcount > 0) {
		ds_newline (ds);
	}
#endif
#if DEADCODE
	if (aligned && ds->show_color) {
		r_cons_printf (Color_RESET);
	}
#endif
}

// TODO: Use sdb in rbin to accelerate this
// we shuold use aligned reloc addresses instead of iterating all of them
static RBinReloc *getreloc(RCore *core, ut64 addr, int size) {
	RList *list;
	RBinReloc *r;
	RListIter *iter;
	if (size < 1 || addr == UT64_MAX) {
		return NULL;
	}
	list = r_bin_get_relocs (core->bin);
	r_list_foreach (list, iter, r) {
		if ((r->vaddr >= addr) && (r->vaddr < (addr + size))) {
			return r;
		}
	}
	return NULL;
}

static void ds_print_relocs(RDisasmState *ds) {
	if (!ds->showrelocs || !ds->show_slow) {
		return;
	}
	RCore *core = ds->core;
	RBinReloc *rel = getreloc (core, ds->at, ds->analop.size);

	if (rel) {
		const int cmtcol = ds->cmtcol;
		int cstrlen = 0;
		char *ll = r_cons_lastline (&cstrlen);
		int ansilen = r_str_ansi_len (ll);
		int utf8len = r_utf8_strlen ((const ut8*)ll);
		int cells = utf8len - (cstrlen - ansilen);
		int len = cmtcol - cells;
		r_cons_memset (' ', len);
		if (rel->import) {
			r_cons_printf ("  ; RELOC %d %s", rel->type, rel->import->name);
		} else if (rel->symbol) {
			r_cons_printf ("  ; RELOC %d %s", rel->type, rel->symbol->name);
		} else {
			r_cons_printf ("  ; RELOC %d ", rel->type);
		}
	}
}

static int mymemwrite0(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	return 0;
}

static int mymemwrite1(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	return 1;
}

static int mymemwrite2(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	return (addr >= emustack_min && addr < emustack_max);
}

#define R_DISASM_MAX_STR 512
static int myregwrite(RAnalEsil *esil, const char *name, ut64 *val) {
	char str[64], *msg = NULL;
	ut32 *n32 = (ut32*)str;
	RDisasmState *ds = NULL;
	if (!esil) {
		return 0;
	}
	ds = esil->user;
	if (!ds) {
		return 0;
	}
	ds->esil_likely = true;
	if (!ds->show_slow) {
		return 0;
	}
	memset (str, 0, sizeof (str));
	if (*val) {
		char *type = NULL;
		(void)r_io_read_at (esil->anal->iob.io, *val, (ut8*)str, sizeof (str)-1);
		str[sizeof (str)-1] = 0;
		// support cstring here
		{
			ut64 *cstr = (ut64*) str;
			ut64 addr = cstr[0];
			if (!(*val >> 32)) {
				addr = addr & UT32_MAX;
			}
			if (cstr[0] == 0 && cstr[1] < 0x1000) {
				ut64 addr = cstr[2];
				if (!(*val >> 32)) {
					addr = addr & UT32_MAX;
				}
				(void)r_io_read_at (esil->anal->iob.io, addr,
					(ut8*)str, sizeof (str)-1);
			//	eprintf ("IS CSTRING 0x%llx %s\n", addr, str);
				type = r_str_newf ("(cstr 0x%08"PFMT64x") ", addr);
				ds->printed_str_addr = cstr[2];
			} else if (r_io_is_valid_offset (esil->anal->iob.io, addr, 0)) {
				ds->printed_str_addr = cstr[0];
				type = r_str_newf ("(pstr 0x%08"PFMT64x") ", addr);
				(void)r_io_read_at (esil->anal->iob.io, addr,
					(ut8*)str, sizeof (str)-1);
			//	eprintf ("IS PSTRING 0x%llx %s\n", addr, str);
			}
		}

		if (*str && !r_bin_strpurge (ds->core->bin, str, *val) && r_str_is_printable (str)
		    && (ds->printed_str_addr == UT64_MAX || *val != ds->printed_str_addr)) {
			bool jump_op = false;
			bool ignored = false;
			switch (ds->analop.type) {
			case R_ANAL_OP_TYPE_JMP:
			case R_ANAL_OP_TYPE_UJMP:
			case R_ANAL_OP_TYPE_RJMP:
			case R_ANAL_OP_TYPE_IJMP:
			case R_ANAL_OP_TYPE_IRJMP:
			case R_ANAL_OP_TYPE_CJMP:
			case R_ANAL_OP_TYPE_MJMP:
			case R_ANAL_OP_TYPE_UCJMP:
				jump_op = true;
				break;
			case R_ANAL_OP_TYPE_TRAP:
			case R_ANAL_OP_TYPE_RET:
				ignored = true;
				break;
			}
			if (!jump_op && !ignored) {
				const char *prefix;
				ut32 len = sizeof (str) -1;
#if 0
				RCore *core = ds->core;
				ut32 len = core->blocksize + 256;
				if (len < core->blocksize || len > R_DISASM_MAX_STR) {
					len = R_DISASM_MAX_STR;
				}
#endif
				char *escstr = ds_esc_str (ds, str, (int)len, &prefix);
				if (escstr) {
					if (ds->show_color) {
						msg = r_str_newf ("%s%s"Color_INVERT"\"%s\""Color_RESET, prefix, type? type: "", escstr);
					} else {
						msg = r_str_newf ("%s%s\"%s\"", prefix, type? type: "", escstr);
					}
					free (escstr);
				}
			}
		} else {
			if (!*n32) {
				// msg = strdup ("NULL");
			} else if (*n32 == UT32_MAX) {
				/* nothing */
			} else {
				if (!ds->show_emu_str) {
					msg = r_str_newf ("-> 0x%x", *n32);
				}
			}
		}
		R_FREE (type);
		if (ds->printed_flag_addr == UT64_MAX || *val != ds->printed_flag_addr) {
			RFlagItem *fi = r_flag_get_i (esil->anal->flb.f, *val);
			if (fi && (!ds->opstr || !strstr (ds->opstr, fi->name))) {
				msg = r_str_appendf (msg, "%s%s", msg && *msg ? " " : "", fi->name);
			}
		}
	}
	if (ds->show_emu_str) {
		if (msg && *msg) {
			if (ds->show_emu_stroff && *msg == '"') {
				ds_comment_esil (ds, true, false, "; 0x%"PFMT64x" %s", *val, msg);
			} else {
				ds_comment_esil (ds, true, false, "; %s", msg);
			}
			if (ds->show_comments && !ds->show_comment_right) {
				ds_newline (ds);
			}
		}
	} else {
		if (msg && *msg) {
			ds_comment_esil (ds, true, false, "; %s=0x%"PFMT64x" %s", name, *val, msg);
		} else {
			ds_comment_esil (ds, true, false, "; %s=0x%"PFMT64x, name, *val);
		}
		if (ds->show_comments && !ds->show_comment_right) {
			ds_newline (ds);
		}
	}
	free (msg);
	return 0;
}

static void ds_pre_emulation(RDisasmState *ds) {
	bool do_esil = ds->show_emu;
	if (!ds->pre_emu) {
		return;
	}
	RFlagItem *f = r_flag_get_at (ds->core->flags, ds->core->offset, true);
	if (!f) {
		return;
	}
	ut64 base = f->offset;
	RAnalEsil *esil = ds->core->anal->esil;
	int i, end = ds->core->offset - base;
	int maxemu = 1024 * 1024;
	RAnalEsilHookRegWriteCB orig_cb = esil->cb.hook_reg_write;
	if (end < 0 || end > maxemu) {
		return;
	}
	ds->stackptr = ds->core->anal->stackptr;
	esil->cb.hook_reg_write = NULL;
	for (i = 0; i < end; i++) {
		ut64 addr = base + i;
		RAnalOp* op = r_core_anal_op (ds->core, addr);
		if (op) {
			if (do_esil) {
				r_anal_esil_set_pc (esil, addr);
				r_anal_esil_parse (esil, R_STRBUF_SAFEGET (&op->esil));
				if (op->size > 0) {
					i += op->size - 1;
				}
			}
			ds_update_stackptr (ds, op);
			r_anal_op_free (op);
		}
	}
	esil->cb.hook_reg_write = orig_cb;
}

static void ds_print_esil_anal_init(RDisasmState *ds) {
	RCore *core = ds->core;
	const char *pc = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
	ds->esil_old_pc = r_reg_getv (core->anal->reg, pc);
	if (!ds->esil_old_pc || ds->esil_old_pc == UT64_MAX) {
		ds->esil_old_pc = core->offset;
	}
	if (!ds->show_emu) {
		// XXX. stackptr not computed without asm.emu, when its not required
		return;
	}
	if (!core->anal->esil) {
		int iotrap = r_config_get_i (core->config, "esil.iotrap");
		int esd = r_config_get_i (core->config, "esil.stack.depth");
		if (!(core->anal->esil = r_anal_esil_new (esd, iotrap))) {
			R_FREE (ds->esil_regstate);
			return;
		}
		r_anal_esil_setup (core->anal->esil, core->anal, 0, 0, 1);
	}
	core->anal->esil->user = ds;
	free (ds->esil_regstate);
	R_FREE (core->anal->last_disasm_reg);
	if (core->anal->gp) {
		r_reg_setv (core->anal->reg, "gp", core->anal->gp);
	}
	ds->esil_regstate = r_reg_arena_peek (core->anal->reg);

	// TODO: emulate N instructions BEFORE the current offset to get proper full function emulation
	ds_pre_emulation (ds);
}

static void ds_print_esil_anal_fini(RDisasmState *ds) {
	RCore *core = ds->core;
	if (ds->show_emu && ds->esil_regstate) {
		RCore* core = ds->core;
		core->anal->last_disasm_reg = r_reg_arena_peek (core->anal->reg);
		const char *pc = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
		r_reg_arena_poke (core->anal->reg, ds->esil_regstate);
		r_reg_setv (core->anal->reg, pc, ds->esil_old_pc);
		R_FREE (ds->esil_regstate);
	}
	if (core && core->anal && core->anal->esil) {
		// make sure to remove reference to ds to avoid UAF
		core->anal->esil->user = NULL;
	}
}

static void ds_print_bbline(RDisasmState *ds, bool force) {
	if (ds->show_bbline) {
		RAnalBlock *bb = r_anal_fcn_bbget (ds->fcn, ds->at);
		if (force || (ds->fcn && bb)) {
			if (bb && ds->show_asm_bbinfo) {
				r_cons_printf ("[bb  size:%d ops:%d]\n", bb->size, bb->op_pos_size / sizeof (ut16));
			}
			ds_begin_json_line (ds);
			ds_setup_print_pre (ds, false, false);
			ds_update_ref_lines (ds);
			if (!ds->linesright && ds->show_lines && ds->line) {
				r_cons_printf ("%s%s%s", COLOR (ds, color_flow),
						ds->refline2, COLOR_RESET (ds));
			}
			ds_newline (ds);
		}
	}
}

static void print_fcn_arg(RCore *core, const char *type, const char *name,
			   const char *fmt, const ut64 addr,
			   const int on_stack) {
	//r_cons_newline ();
	r_cons_printf ("%s", type);
	r_core_cmdf (core, "pf %s%s %s @ 0x%08" PFMT64x,
		(on_stack == 1) ? "*" : "", fmt, name, addr);
	r_cons_chop ();
	r_cons_chop ();
}

static void delete_last_comment(RDisasmState *ds) {
	if (ds->show_comment_right_default) {
		int len = 0;
		char *ll = r_cons_lastline (&len);
		if (ll) {
			const char *begin = r_str_nstr (ll, "; ", len);
			if (begin) {
				// const int cstrlen = begin + len - ll;
				// r_cons_drop (cstrlen - (int)(begin - ll));
				r_cons_newline();
			}
		}
	}
}

static char * resolve_fcn_name(RAnal *anal, const char * func_name) {
	const char * name = NULL;
	const char * str = func_name;
	if (r_anal_type_func_exist (anal, func_name)) {
		return strdup (func_name);
	}
	name = func_name;
	while ((str = strchr (str, '.'))) {
		name = str + 1;
		str++;
	}
	if (r_anal_type_func_exist (anal, name)) {
		return strdup (name);
	}
	return r_anal_type_func_guess (anal, (char*)func_name);
}

static bool can_emulate_metadata(RCore * core, ut64 at) {
	const char *infos;
	const char *emuskipmeta = r_config_get (core->config, "asm.emu.skip");
	char key[32];
	Sdb *s = core->anal->sdb_meta;
	snprintf (key, sizeof (key)-1, "meta.0x%"PFMT64x, at);
	infos = sdb_const_get (s, key, 0);
	if (!infos) {
		/* no metadata: let's emulate this */
		return true;
	}
	for (; *infos; infos++) {
		/*
		 * don't emulate if at least one metadata type
		 * can't be emulated
		 */
		if (*infos != ',' && strchr(emuskipmeta, *infos)) {
			return false;
		}
	}
	return true;
}

// modifies anal register state
static void ds_print_esil_anal(RDisasmState *ds) {
	RCore *core = ds->core;
	RAnalEsil *esil = core->anal->esil;
	const char *pc;
	int (*hook_mem_write)(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) = NULL;
	int i, nargs;
	ut64 at = p2v (ds, ds->at);
	RConfigHold *hc = r_config_hold_new (core->config);
	/* apply hint */	
	RAnalHint *hint = r_anal_hint_get (core->anal, at);
	r_anal_op_hint (&ds->analop, hint);
	r_anal_hint_free (hint);
	if (!hc) {
		return;
	}
	if (!esil) {
		ds_print_esil_anal_init (ds);
		esil = core->anal->esil;
	}
	if (!ds->show_emu) {
		goto beach;
	}
	if (!can_emulate_metadata (core, at)) {
		goto beach;
	}
	if (ds->show_color) {
		r_cons_strcat (ds->pal_comment);
	}
	esil = core->anal->esil;
	pc = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
	r_reg_setv (core->anal->reg, pc, at + ds->analop.size);
	esil->cb.user = ds;
	esil->cb.hook_reg_write = myregwrite;
	hook_mem_write = esil->cb.hook_mem_write;
	if (ds->show_emu_stack) {
		esil->cb.hook_mem_write = mymemwrite2;
	} else {
		if (ds->show_emu_write) {
			esil->cb.hook_mem_write = mymemwrite0;
		} else {
			esil->cb.hook_mem_write = mymemwrite1;
		}
	}
	ds->esil_likely = 0;
	r_anal_esil_set_pc (esil, at);
	r_anal_esil_parse (esil, R_STRBUF_SAFEGET (&ds->analop.esil));
	r_anal_esil_stack_free (esil);
	r_config_save_num (hc, "io.cache", NULL);
	r_config_set (core->config, "io.cache", "true");
	if (!ds->show_comments) {
		goto beach;
	}
	switch (ds->analop.type) {
	case R_ANAL_OP_TYPE_SWI: {
		char *s = cmd_syscall_dostr (core, -1);
		if (s) {
			ds_comment_esil (ds, true, true, "; %s", s);
			free (s);
		}
		} break;
	case R_ANAL_OP_TYPE_CJMP:
		ds_comment_esil (ds, true, true, ds->esil_likely? "; likely" : "; unlikely");
		break;
	case R_ANAL_OP_TYPE_UCALL:
	case R_ANAL_OP_TYPE_ICALL:
	case R_ANAL_OP_TYPE_RCALL:
	case R_ANAL_OP_TYPE_IRCALL:
	case R_ANAL_OP_TYPE_CALL:
		{
			RAnalFunction *fcn;
			RAnalFuncArg *arg;
			RListIter *iter;
			RListIter *nextele;
			const char *fcn_name = NULL;
			char *key = NULL;
			ut64 pcv = ds->analop.jump;
			if (pcv == UT64_MAX) {
				pcv = ds->analop.ptr; // call [reloc-addr] // windows style
				if (pcv == UT64_MAX || !pcv) {
					r_anal_esil_reg_read (esil, "$jt", &pcv, NULL);
					if (pcv == UT64_MAX || !pcv) {
						pcv = r_reg_getv (core->anal->reg, pc);
					}
				}
			}
			fcn = r_anal_get_fcn_at (core->anal, pcv, 0);
			if (fcn) {
				fcn_name = fcn->name;
			} else {
				RFlagItem *item = r_flag_get_i (core->flags, pcv);
				if (item) {
					fcn_name = item->name;
				}
			}
			if (fcn_name) {
				key = resolve_fcn_name (core->anal, fcn_name);
			}
			if (key) {
				const char *fcn_type = r_anal_type_func_ret (core->anal, key);
				int nargs = r_anal_type_func_args_count (core->anal, key);
				// remove other comments
				delete_last_comment (ds);
				if (ds->show_color) {
					ds_comment_esil (ds, true, false, ds->pal_comment);
				}
				if (fcn_type) {
					ds_comment_esil (ds, ds->show_color? false : true, false,
							"; %s%s%s(", r_str_get (fcn_type), (*fcn_type &&
							fcn_type[strlen (fcn_type) - 1] == '*') ? "" : " ",
							r_str_get (key));
					if (!nargs) {
						ds_comment_esil (ds, false, true, "void)");
						break;
					}
				}
			}
			ut64 s_width = (core->anal->bits == 64)? 8: 4;
			const char *sp = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
			ut64 spv = r_reg_getv (core->anal->reg, sp);
			r_reg_setv (core->anal->reg, sp, spv + s_width); // temporarily set stack ptr to sync with carg.c
			RList *list = r_core_get_func_args (core, fcn_name);
			if (!r_list_empty (list)) {
				bool warning = false;
				bool on_stack = false;
				r_list_foreach (list, iter, arg) {
					if (arg->cc_source && !strncmp (arg->cc_source, "stack", 5)) {
						on_stack = true;
					}
					if (!arg->size) {
						ds_comment_esil (ds, false, false, "%s: unk_size", arg->c_type);
						warning = true;
					}
					nextele = r_list_iter_get_next (iter);
					if (!arg->fmt) {
						if (!warning) {
							ds_comment_esil (ds, false, false, "%s : unk_format", arg->c_type);
						} else {
							ds_comment_esil (ds, false, false, "_format");
						}
						ds_comment_esil (ds, false, false, nextele?", ":")");
					} else {
						//print_fcn_arg may need ds_comment_esil
						print_fcn_arg (core, arg->orig_c_type,
								arg->name, arg->fmt, arg->src, on_stack);
						ds_comment_esil (ds, false, false, nextele?", ":")");
					}
				}
				break;
				ds_comment_esil (ds, false, true, "");
			} else {
				// function name not resolved
				nargs = DEFAULT_NARGS;
				if (fcn) {
					nargs = fcn->nargs;
				}
				if (nargs > 0) {
					ds_comment_esil (ds, true, false, "; CALL: ");
					for (i = 0; i < nargs; i++) {
						ut64 v = r_debug_arg_get (core->dbg, R_ANAL_CC_TYPE_STDCALL, i);
						ds_comment_esil (ds, false, false, "%s0x%"PFMT64x, i?", ":"", v);
					}
					ds_comment_esil (ds, false, true, "");
				}
			}
			r_reg_setv (core->anal->reg, sp, spv); // reset stack ptr
		}
		break;
	}
	ds_print_color_reset (ds);
beach:
	if (esil) {
		esil->cb.hook_mem_write = hook_mem_write;
	}
	r_config_restore (hc);
	r_config_hold_free (hc);
}

static void ds_print_calls_hints(RDisasmState *ds) {
	int emu = r_config_get_i (ds->core->config, "asm.emu");
	int emuwrite = r_config_get_i (ds->core->config, "asm.emu.write");
	if (emu && emuwrite) {
		// this is done by ESIL
		return;
	}
	RAnal *anal = ds->core->anal;
	// RAnalFunction *fcn = r_anal_get_fcn_in (anal, ds->analop.jump, -1);
	RAnalFunction *fcn = fcnIn (ds, ds->analop.jump, -1);
	char *name;
	if (!fcn) {
		return;
	}
	if (r_anal_type_func_exist (anal, fcn->name)) {
		name = strdup (fcn->name);
	} else if (!(name = r_anal_type_func_guess (anal, fcn->name))) {
		return;
	}
	if (ds->show_color) {
		r_cons_strcat (ds->pal_comment);
	}
	ds_align_comment (ds);
	const char *fcn_type = r_anal_type_func_ret (anal, name);
	if (fcn_type && *fcn_type) {
		r_cons_printf (
			"; %s%s%s(", fcn_type,
			fcn_type[strlen (fcn_type) - 1] == '*' ? "" : " ",
			name);
	}
	int i, arg_max = r_anal_type_func_args_count (anal, name);
	if (!arg_max) {
		r_cons_printf ("void)");
	} else {
		for (i = 0; i < arg_max; i++) {
			char *type = r_anal_type_func_args_type (anal, name, i);
			if (type && *type) {
				r_cons_printf ("%s%s%s%s%s", i == 0 ? "": " ", type,
						type[strlen (type) -1] == '*' ? "": " ",
						r_anal_type_func_args_name (anal, name, i),
						i == arg_max - 1 ? ")": ",");
			}
			free (type);
		}
	}
	ds_print_color_reset (ds);
	free (name);
}

static void ds_print_comments_right(RDisasmState *ds) {
	char *desc = NULL;
	RCore *core = ds->core;
	ds_print_relocs (ds);
	if (ds->asm_describe && !ds->has_description) {
		char *op, *locase = strdup (ds->asmop.buf_asm);
		if (!locase) {
			return;
		}
		op = strchr (locase, ' ');
		if (op) {
			*op = 0;
		}
		r_str_case (locase, 0);
		desc = r_asm_describe (core->assembler, locase);
		free (locase);
	}
	if (ds->show_comments) {
		if (desc && *desc) {
			ds_align_comment (ds);
			if (ds->show_color) {
				r_cons_strcat (ds->color_comment);
			}
			r_cons_strcat ("; ");
			r_cons_strcat (desc);
			ds_print_color_reset (ds);
		}
		if (ds->show_comment_right && ds->comment) {
			char *comment = r_str_trim (ds->comment);
			if (*comment) {
				if (!desc) {
					ds_align_comment (ds);
				}
				if (ds->show_color) {
					// r_cons_strcat (ds->color_comment);
					r_cons_strcat (ds->color_usrcmt);
				}
				if (strchr (comment, '\n')) {
					comment = strdup (comment);
					if (comment) {
						ds_newline (ds);
						ds_begin_json_line (ds);
						int lines_count;
						int *line_indexes = r_str_split_lines (comment, &lines_count);
						if (line_indexes) {
							int i;
							for (i = 0; i < lines_count; i++) {
								char *c = comment + line_indexes[i];
								char *escstr = NULL;
								if (ds->use_json) {
									c = escstr = ds_esc_str (ds, c, (int)strlen (c), NULL);
								}
								ds_print_pre (ds);
								r_cons_printf ("; %s", c);
								ds_newline (ds);
								ds_begin_json_line (ds);
								free (escstr);
							}
						}
						free (line_indexes);
					}
					free (comment);
				} else {
					char *escstr = NULL;
					if (ds->use_json) {
						comment = escstr = ds_esc_str (ds, comment, (int)strlen (comment), NULL);
					}
					if (comment) {
						r_cons_printf ("; %s", comment);
					}
					free (escstr);
				}
			}
			//r_cons_strcat_justify (comment, strlen (ds->refline) + 5, ';');
			ds_print_color_reset (ds);
			R_FREE (ds->comment);
		}
	}
	free (desc);
	if (ds->analop.type == R_ANAL_OP_TYPE_CALL && ds->show_calls) {
		ds_print_calls_hints (ds);
	}
}

static void ds_print_as_string(RDisasmState *ds) {
	char *str = r_num_as_string (NULL, ds->analop.ptr, true);
	if (str) {
		ds_comment (ds, false, "%s; \"%s\"%s", COLOR (ds, pal_comment),
			str, COLOR_RESET (ds));
	}
	free (str);
}

static char *_find_next_number(char *op) {
	char *p = op;
	if (p) {
		while (*p) {
			// look for start of next separator or ANSI sequence
			while (*p && !ISSEPARATOR (*p) && *p != 0x1b) p++;
			if (*p == 0x1b) {
				// skip to end of ANSI sequence (lower or uppercase char)
				while (*p && !(*p >= 'A' && *p <= 'Z') && !(*p >= 'a' && *p <= 'z')) p++;
				if (*p) p++;
			}
			if (ISSEPARATOR (*p)) {
				// skip to end of separator
				while (*p && ISSEPARATOR (*p)) p++;
			}
			if (IS_DIGIT (*p)) {
				// we found the start of the next number
				return p;
			}
		}
	}
	return NULL;
}

static char *ds_sub_jumps(RDisasmState *ds, char *str) {
	RAnal *anal = ds->core->anal;
	RFlag *f = ds->core->flags;
	int optype;
	RAnalFunction *fcn;
	RFlagItem *flag;
	ut64 addr;
	const char *name = 0;

	if (!ds->jmpsub || !anal) {
		return str;
	}

	optype = ds->analop.type & 0xFFFF;
	if (optype < R_ANAL_OP_TYPE_JMP || optype >= R_ANAL_OP_TYPE_RET) {
		return str;
	}
	addr = ds->analop.jump;

	fcn = r_anal_get_fcn_at (anal, addr, 0);
	if (fcn) {
		name = fcn->name;
	} else if (f) {
		flag = r_flag_get_i2 (f, addr);
		if (flag) {
			name = flag->name;
		}
	}

	if (name) {
		char *nptr, *ptr;
		ut64 numval;
		ptr = str;
		while ((nptr = _find_next_number (ptr))) {
			ptr = nptr;
			numval = r_num_get (NULL, ptr);
			if (numval == addr) {
				while (*nptr && !ISSEPARATOR (*nptr) && *nptr != 0x1b) nptr++;
				char* numstr = r_str_ndup (ptr, nptr-ptr);
				str = r_str_replace (str, numstr, name, 0);
				free (numstr);
				break;
			}
		}
	}

	return str;
}

// int l is for lines
R_API int r_core_print_disasm(RPrint *p, RCore *core, ut64 addr, ut8 *buf, int len, int l, int invbreak, int cbytes, bool json) {
	int continueoninvbreak = (len == l) && invbreak;
	RAnalFunction *of = NULL;
	RAnalFunction *f = NULL;
	bool calc_row_offsets = p->calc_row_offsets;
	int ret, i, inc, skip_bytes = 0, idx = 0;
	int dorepeat = 1;
	ut8 *nbuf = NULL;
	const int addrbytes = core->io->addrbytes;

	// TODO: All those ds must be print flags
	RDisasmState *ds = ds_init (core);
	ds->cbytes = cbytes;
	ds->print = p;
	ds->l = l;
	ds->buf = buf;
	ds->len = len;
	ds->addr = addr;
	ds->hint = NULL;
	ds->use_json = json;
	ds->first_line = true;

	// disable row_offsets to prevent other commands to overwrite computed info
	p->calc_row_offsets = false;

	//r_cons_printf ("len =%d l=%d ib=%d limit=%d\n", len, l, invbreak, p->limit);
	// TODO: import values from debugger is possible
	// TODO: allow to get those register snapshots from traces
	// TODO: per-function register state trace
	// XXX - is there a better way to reset a the analysis counter so that
	// when code is disassembled, it can actually find the correct offsets
	{ /* used by asm.emu */
		r_reg_arena_push (core->anal->reg);
	}
	if (core->anal->cur && core->anal->cur->reset_counter) {
		core->anal->cur->reset_counter (core->anal, addr);
	}

	ds_reflines_init (ds);
	core->inc = 0;
	/* reset jmp table if not asked to keep it */
	if (!core->keep_asmqjmps) { // hack
		core->asmqjmps_count = 0;
		core->asmqjmps_size = R_CORE_ASMQJMPS_NUM;
		core->asmqjmps = realloc (core->asmqjmps, core->asmqjmps_size * sizeof (ut64));
		if (core->asmqjmps) {
			for (i = 0; i < R_CORE_ASMQJMPS_NUM; i++) {
				core->asmqjmps[i] = UT64_MAX;
			}
		}
	}
	if (ds->use_json) {
		r_cons_print ("[");
	}
toro:
	// uhm... is this necesary? imho can be removed
	r_asm_set_pc (core->assembler, p2v (ds, ds->addr + idx));
	core->cons->vline = r_config_get_i (core->config, "scr.utf8") ? (r_config_get_i (core->config, "scr.utf8.curvy") ? r_vline_uc : r_vline_u) : r_vline_a;

	if (core->print->cur_enabled) {
		// TODO: support in-the-middle-of-instruction too
		r_anal_op_fini (&ds->analop);
		if (r_anal_op (core->anal, &ds->analop, core->offset + core->print->cur,
			buf + core->print->cur, (int)(len - core->print->cur))) {
			// TODO: check for ds->analop.type and ret
			ds->dest = ds->analop.jump;
		}
	} else {
		/* highlight eip */
		const char *pc = core->anal->reg->name[R_REG_NAME_PC];
		RFlagItem *item = r_flag_get (core->flags, pc);
		if (item) {
			ds->dest = item->offset;
		}
	}

	ds_print_esil_anal_init (ds);
	inc = 0;
	if (!ds->l) {
		len = ds->l = core->blocksize;
	}

	r_cons_break_push (NULL, NULL);
	r_anal_build_range_on_hints (core->anal);
	for (i = idx = ret = 0; addrbytes * idx < len && ds->lines < ds->l; idx += inc, i++, ds->index += inc, ds->lines++) {
		ds->at = ds->addr + idx;
		ds->vat = p2v (ds, ds->at);
		if (r_cons_is_breaked ()) {
			dorepeat = 0;
			R_FREE (nbuf);
			r_cons_break_pop ();
			return 0; //break;
		}
		r_core_seek_archbits (core, ds->at); // slow but safe
		ds->has_description = false;
		ds->hint = r_core_hint_begin (core, ds->hint, ds->at);
		ds->printed_str_addr = UT64_MAX;
		ds->printed_flag_addr = UT64_MAX;
		// XXX. this must be done in ds_update_pc()
		// ds_update_pc (ds, ds->at);
		{
			r_asm_set_pc (core->assembler, ds->at);
			ds_update_ref_lines (ds);
			r_anal_op (core->anal, &ds->analop, ds->at, buf + addrbytes * idx, (int)(len - addrbytes * idx));
		}
		if (ds_must_strip (ds)) {
			inc = ds->analop.size;
			// inc = ds->asmop.payload + (ds->asmop.payload % ds->core->assembler->dataalign);
			continue;
		}
		// f = r_anal_get_fcn_in (core->anal, ds->at, R_ANAL_FCN_TYPE_NULL);
		f = ds->fcn = fcnIn (ds, ds->at, R_ANAL_FCN_TYPE_NULL);
		if (f && f->folded && r_anal_fcn_is_in_offset (f, ds->at)) {
			int delta = (ds->at <= f->addr)? (ds->at - f->addr + r_anal_fcn_size (f)): 0;
			if (of != f) {
				char cmt[32];
				get_bits_comment (core, f, cmt, sizeof (cmt));
				ds_show_comments_right (ds);
				r_cons_printf ("%s%s%s (fcn) %s%s%s\n",
					COLOR (ds, color_fline), core->cons->vline[CORNER_TL],
					COLOR (ds, color_fname), f->name, cmt, COLOR_RESET (ds));
				ds_setup_print_pre (ds, true, false);
				ds_print_lines_left (ds);
				ds_print_offset (ds);
				r_cons_printf ("(%d byte folded function)\n", r_anal_fcn_size (f));
				//r_cons_printf ("%s%s%s\n", COLOR (ds, color_fline), core->cons->vline[RDWN_CORNER], COLOR_RESET (ds));
				if (delta < 0) {
					delta = -delta;
				}
				ds->addr += delta + idx;
				r_io_read_at (core->io, ds->addr, buf, len);
				inc = 0; //delta;
				idx = 0;
				of = f;
				if (len == l) {
					break;
				}
				continue;
			} else {
				ds->lines--;
				ds->addr += 1;
				r_io_read_at (core->io, ds->addr, buf, len);
				inc = 0; //delta;
				idx = 0;
				continue;
			}
		}
		ds_show_comments_right (ds);
		// TRY adding here
		char *link_key = sdb_fmt (-1, "link.%08"PFMT64x, ds->addr + idx);
		const char *link_type = sdb_const_get (core->anal->sdb_types, link_key, 0);
		if (link_type) {
			char *fmt = r_anal_type_format (core->anal, link_type);
			if (fmt) {
				r_cons_printf ("(%s)\n", link_type);
				r_core_cmdf (core, "pf %s @ 0x%08"PFMT64x"\n", fmt, ds->addr + idx);
				inc += r_anal_type_get_size (core->anal, link_type) / 8;
				free (fmt);
				continue;
			}
		} else {
			if (idx >= 0) {
				ret = ds_disassemble (ds, buf + addrbytes * idx, len - addrbytes * idx);
				if (ret == -31337) {
					inc = ds->oplen;
					continue;
				}
			}
		}
		if (ds->retry) {
			ds->retry = false;
			r_cons_break_pop ();
			goto retry;
		}
		ds_atabs_option (ds);
		// TODO: store previous oplen in core->dec
		if (!core->inc) {
			core->inc = ds->oplen;
		}
		// OOPs. double analysis here?
#if 0
		if (ds->analop.mnemonic || !ds->lastfail) {
			r_anal_op_fini (&ds->analop);
		}
		if (!ds->lastfail) {
			r_anal_op (core->anal, &ds->analop, ds->at, buf + addrbytes * idx, (int)(len - addrbytes * idx));
		}
#else
		if (ds->analop.addr != ds->at) {
			r_anal_op_fini (&ds->analop);
			r_anal_op (core->anal, &ds->analop, ds->at, buf + addrbytes * idx, (int)(len - addrbytes * idx));
		}
#endif
		if (ret < 1) {
			r_strbuf_init (&ds->analop.esil);
			ds->analop.type = R_ANAL_OP_TYPE_ILL;
		}
		if (ds->hint) {
			if (ds->hint->size) {
				ds->analop.size = ds->hint->size;
			}
			if (ds->hint->ptr) {
				ds->analop.ptr = ds->hint->ptr;
			}
		}
		ds_print_bbline (ds, false);
		if (ds->at >= addr) {
			r_print_set_rowoff (core->print, ds->lines, ds->at - addr, calc_row_offsets);
		}
		if (ds->midflags) {
			skip_bytes = handleMidFlags (core, ds, true);
			if (skip_bytes && ds->midflags == R_MIDFLAGS_SHOW) {
				ds->at += skip_bytes;
			}
		}
		ds_show_flags (ds);
		if (skip_bytes && ds->midflags == R_MIDFLAGS_SHOW) {
			ds->at -= skip_bytes;
		}
		ds_control_flow_comments (ds);
		ds_adistrick_comments (ds);
		/* XXX: This is really cpu consuming.. need to be fixed */
		ds_show_functions (ds);
		ds_show_xrefs (ds);

		if (ds->show_comments && !ds->show_comment_right) {
			ds_instruction_mov_lea (ds, idx);
			ds_show_refs (ds);
			ds_build_op_str (ds, false);
			ds_print_ptr (ds, len + 256, idx);
			if (!ds->pseudo) {
				R_FREE (ds->opstr);
			}
			ds_print_sysregs (ds);
			ds_print_fcn_name (ds);
			ds_print_color_reset (ds);
			if (ds->show_emu) {
				ds_print_esil_anal (ds);
			}
		}

		ds_begin_json_line (ds);

		ds_setup_print_pre (ds, false, false);
		ds_print_lines_left (ds);
		// f = r_anal_get_fcn_in (core->anal, ds->addr, 0);
		f = fcnIn (ds, ds->addr, 0);
		if (ds_print_labels (ds, f)) {
			ds_show_functions (ds);
			ds_show_xrefs (ds);
			ds_setup_print_pre (ds, false, false);
			ds_print_lines_left (ds);
		}
		ds_print_offset (ds);
		if (ds->shortcut_pos == 0) {
			ds_print_core_vmode (ds, ds->shortcut_pos);
		}
		ds_print_op_size (ds);
		ds_print_trace (ds);
		ds_print_cycles (ds);
		ds_print_family (ds);
		ds_print_stackptr (ds);
		ret = ds_print_meta_infos (ds, buf, len, idx);
		if (!ds->mi_found) {
			/* show cursor */
			ds_print_show_cursor (ds);
			ds_print_show_bytes (ds);
			ds_print_lines_right (ds);
			ds_build_op_str (ds, true);
			ds_print_opstr (ds);
			ds_print_dwarf (ds);
			ret = ds_print_middle (ds, ret);

			ds_print_asmop_payload (ds, buf + addrbytes * idx);
			if (core->assembler->syntax != R_ASM_SYNTAX_INTEL) {
				RAsmOp ao; /* disassemble for the vm .. */
				int os = core->assembler->syntax;
				r_asm_set_syntax (core->assembler, R_ASM_SYNTAX_INTEL);
				r_asm_disassemble (core->assembler, &ao, buf + addrbytes * idx, len - addrbytes * idx + 5);
				r_asm_set_syntax (core->assembler, os);
			}
			if (ds->shortcut_pos > 0) {
				ds_print_core_vmode (ds, ds->shortcut_pos);
			}
			// ds_print_cc_update (ds);

			ds_cdiv_optimization (ds);
			if (ds->show_comments && ds->show_comment_right) {
				ds_instruction_mov_lea (ds, idx);
				ds_print_ptr (ds, len + 256, idx);
				ds_print_sysregs (ds);
				ds_print_fcn_name (ds);
				ds_print_color_reset (ds);
				ds_print_comments_right (ds);
				ds_print_esil_anal (ds);
				ds_show_refs (ds);
			}
		} else {
			if (ds->show_comments && ds->show_comment_right) {
				ds_print_color_reset (ds);
				ds_print_comments_right (ds);
			}
			ds->mi_found = false;
		}

		ds_newline (ds);
		if (ds->show_bbline && !ds->bblined && !ds->fcn) {
			switch (ds->analop.type) {
			case R_ANAL_OP_TYPE_MJMP:
			case R_ANAL_OP_TYPE_UJMP:
			case R_ANAL_OP_TYPE_IJMP:
			case R_ANAL_OP_TYPE_RJMP:
			case R_ANAL_OP_TYPE_IRJMP:
			case R_ANAL_OP_TYPE_CJMP:
			case R_ANAL_OP_TYPE_JMP:
			case R_ANAL_OP_TYPE_RET:
				ds_print_bbline (ds, true);
				break;
			}
		}
		if (ds->line) {
			if (ds->show_lines_ret && ds->analop.type == R_ANAL_OP_TYPE_RET) {
				if (strchr (ds->line, '>')) {
					memset (ds->line, ' ', r_str_len_utf8 (ds->line));
				}
				ds_print_pre (ds);
				r_cons_printf ("%s%s%s; --------------------------------------\n",
					COLOR (ds, color_flow), ds->line, COLOR_RESET (ds));
			}
			R_FREE (ds->line);
			R_FREE (ds->refline);
			R_FREE (ds->refline2);
		}
		R_FREE (ds->opstr);
		inc = ds->oplen;

		if (ds->midflags == R_MIDFLAGS_REALIGN && skip_bytes) {
			inc = skip_bytes;
		}
		if (inc < 1) {
			inc = 1;
		}
		inc += ds->asmop.payload + (ds->asmop.payload % ds->core->assembler->dataalign);
	}

	R_FREE (nbuf);
	r_cons_break_pop ();

#if HASRETRY
	if (!ds->cbytes && ds->lines < ds->l && dorepeat) {
		ds->addr = ds->at + inc;
	retry:
		if (len < 4) {
			len = 4;
		}
		if (nbuf) {
			free (nbuf);
		}
		buf = nbuf = malloc (len);
		if (ds->tries > 0) {
			if (r_core_read_at (core, ds->addr, buf, len)) {
				goto toro;
			}
		}
		if (ds->lines < ds->l) {
			//ds->addr += idx;
			if (!r_core_read_at (core, ds->addr, buf, len)) {
				//ds->tries = -1;
			}
			goto toro;
		}
		if (continueoninvbreak) {
			goto toro;
		}
		R_FREE (nbuf);
	}
#endif
	if (ds->use_json) {
		r_cons_print ("]");
	}
	r_print_set_rowoff (core->print, ds->lines, ds->at - addr, calc_row_offsets);
	r_print_set_rowoff (core->print, ds->lines + 1, UT32_MAX, calc_row_offsets);
	// TODO: this too (must review)
	ds_print_esil_anal_fini (ds);
	ds_reflines_fini (ds);
	ds_free (ds);
	R_FREE (nbuf);
	p->calc_row_offsets = calc_row_offsets;
	/* used by asm.emu */
	r_reg_arena_pop (core->anal->reg);
	return addrbytes * idx; //-ds->lastfail;
}

/* Disassemble either `nb_opcodes` instructions, or
 * `nb_bytes` bytes; both can be negative.
 * Set to 0 the parameter you don't use */
R_API int r_core_print_disasm_instructions(RCore *core, int nb_bytes, int nb_opcodes) {
	RDisasmState *ds = NULL;
	int i, j, ret, len = 0;
	char *tmpopstr;
	const ut64 old_offset = core->offset;
	bool hasanal = false;
	int nbytes = 0;
	const int addrbytes = core->io->addrbytes;

	r_reg_arena_push (core->anal->reg);
	if (!nb_bytes) {
		nb_bytes = core->blocksize;
		if (nb_opcodes < 0) {
			/* Backward disassembly or nb_opcodes opcodes
			 * - We compute the new starting offset
			 * - Read at the new offset */
			nb_opcodes = -nb_opcodes;

			// We have some anal_info.
			if (r_core_prevop_addr (core, core->offset, nb_opcodes, &core->offset)) {
				nbytes = old_offset - core->offset;
			} else {
				// core->offset is modified by r_core_prevop_addr
				core->offset = old_offset;
				r_core_asm_bwdis_len (core, &nbytes, &core->offset, nb_opcodes);
			}
			if (nbytes > core->blocksize) {
				r_core_block_size (core, nbytes);
			}
			r_core_read_at (core, core->offset, core->block, nbytes);
		}
	} else {
		if (nb_bytes < 0) { // Disassemble backward `nb_bytes` bytes
			nb_bytes = -nb_bytes;
			core->offset -= nb_bytes;
			if (nb_bytes > core->blocksize) {
				ut64 obsz = core->blocksize;
				r_core_block_size (core, nb_bytes);
				if (core->blocksize == nb_bytes) {
					r_core_read_at (core, core->offset, core->block, nb_bytes);
				} else {
					eprintf ("Cannot read that much!\n");
					memset (core->block, 0xff, nb_bytes);
				}
				r_core_block_size (core, obsz);
			} else {
				r_core_read_at (core, core->offset, core->block, nb_bytes);
			}
		} else {
			if (nb_bytes > core->blocksize) {
				r_core_block_size (core, nb_bytes);
				r_core_read_at (core, core->offset, core->block, nb_bytes);
			}
		}
	}

	// XXX - is there a better way to reset a the analysis counter so that
	// when code is disassembled, it can actually find the correct offsets
	if (core->anal->cur && core->anal->cur->reset_counter) {
		core->anal->cur->reset_counter (core->anal, core->offset);
	}
	ds = ds_init (core);
	ds->l = nb_opcodes;
	ds->len = nb_opcodes * 8;

	if (ds->len > core->blocksize) {
		if (core->fixedblock) {
			nb_bytes = ds->len = core->blocksize;
		} else {
			r_core_block_size (core, ds->len);
			r_core_block_read (core);
		}
	}
	if (!ds->l) {
		ds->l = ds->len;
	}

	r_cons_break_push (NULL, NULL);
	//build ranges to map addr with bits
	r_anal_build_range_on_hints (core->anal);
#define isNotTheEnd (nb_opcodes ? j < nb_opcodes: addrbytes * i < nb_bytes)
	for (i = j = 0; isNotTheEnd; i += ret, j++) {
		ds->at = core->offset +i;
		ds->vat = p2v (ds, ds->at);
		hasanal = false;
		r_core_seek_archbits (core, ds->at);
		if (r_cons_is_breaked ()) {
			break;
		}
		ds->hint = r_core_hint_begin (core, ds->hint, ds->at);
		ds->has_description = false;
		r_asm_set_pc (core->assembler, ds->at);
		// XXX copypasta from main disassembler function
		// r_anal_get_fcn_in (core->anal, ds->at, R_ANAL_FCN_TYPE_NULL);
		ret = r_asm_disassemble (core->assembler, &ds->asmop,
			core->block + addrbytes * i, core->blocksize - addrbytes * i);
		ds->oplen = ret;
		if (ds->midflags) {
			int skip_bytes = handleMidFlags (core, ds, true);
			if (skip_bytes && ds->midflags > R_MIDFLAGS_SHOW) {
				ret = skip_bytes;
			}
		}
		r_anal_op_fini (&ds->analop);
		if (ds->show_color && !hasanal) {
			r_anal_op (core->anal, &ds->analop, ds->at, core->block + addrbytes * i, core->blocksize - addrbytes * i);
			hasanal = true;
		}
		if (ds_must_strip (ds)) {
			continue;
		}
		
		// r_conf = s_printf ("0x%08"PFMT64x"  ", core->offset+i);
		if (ds->hint && ds->hint->size) {
			ret = ds->hint->size;
			ds->oplen = ret;
			ds->analop.size = ret;
			ds->asmop.size = ret;
		}
		/* fix infinite loop */
		if (ret < 1) {
			ret = 1;
		}
		len += R_MAX (0, ret);
		if (ds->hint && ds->hint->opcode) {
			free (ds->opstr);
			ds->opstr = strdup (ds->hint->opcode);
		} else {
			if (ds->decode && !ds->immtrim) {
				free (ds->opstr);
				if (!hasanal) {
					r_anal_op (core->anal, &ds->analop, ds->at, core->block+i, core->blocksize-i);
					hasanal = true;
				}
				tmpopstr = r_anal_op_to_string (core->anal, &ds->analop);
				ds->opstr = (tmpopstr)? tmpopstr: strdup (ds->asmop.buf_asm);
			} else if (ds->immtrim) {
				ds->opstr = strdup (ds->asmop.buf_asm);
				r_parse_immtrim (ds->opstr);
			} else if (ds->use_esil) {
				if (!hasanal) {
					r_anal_op (core->anal, &ds->analop,
						ds->at, core->block + i,
						core->blocksize - i);
					hasanal = true;
				}
				if (*R_STRBUF_SAFEGET (&ds->analop.esil)) {
					free (ds->opstr);
					ds->opstr = strdup (R_STRBUF_SAFEGET (&ds->analop.esil));
				}
			} else if (ds->filter) {
				char *asm_str;
				int ofs = core->parser->flagspace;
				int fs = ds->flagspace_ports;
				if (ds->analop.type == R_ANAL_OP_TYPE_IO) {
					core->parser->notin_flagspace = -1;
					core->parser->flagspace = fs;
				} else {
					if (fs != -1) {
						core->parser->notin_flagspace = fs;
						core->parser->flagspace = fs;
					} else {
						core->parser->notin_flagspace = -1;
						core->parser->flagspace = -1;
					}
				}
				core->parser->hint = ds->hint;
				r_parse_filter (core->parser, core->flags, ds->asmop.buf_asm, ds->str,
						sizeof (ds->str), core->print->big_endian);
				ds->opstr = strdup (ds->str);
				asm_str = colorize_asm_string (core, ds, true);
				core->parser->flagspace = ofs;
				free (ds->opstr);
				ds->opstr = asm_str;
				core->parser->flagspace = ofs; // ???
			} else {
				ds->opstr = strdup (ds->asmop.buf_asm);
			}
			if (ds->immtrim) {
				ds->opstr = strdup (ds->asmop.buf_asm);
				r_parse_immtrim (ds->opstr);
			}
		}
		{
			const char *opcolor = NULL;
			if (ds->show_color) {
				opcolor = r_print_color_op_type (core->print, ds->analop.type);
				r_cons_printf ("%s%s" Color_RESET "\n", opcolor, ds->opstr);
			} else {
				r_cons_println (ds->opstr);
			}
			R_FREE (ds->opstr);
		}
		if (ds->hint) {
			r_anal_hint_free (ds->hint);
			ds->hint = NULL;
		}
	}
	r_cons_break_pop ();
	ds_free (ds);
	core->offset = old_offset;
	r_reg_arena_pop (core->anal->reg);

	return len;
}

R_API int r_core_print_disasm_json(RCore *core, ut64 addr, ut8 *buf, int nb_bytes, int nb_opcodes) {
	RAsmOp asmop;
	RDisasmState *ds;
	RAnalFunction *f;
	int i, j, k, oplen, ret, line;
	ut64 old_offset = core->offset;
	ut64 at;
	int dis_opcodes = 0;
	//r_cons_printf ("[");
	int limit_by = 'b';
	char str[512];

	if (nb_opcodes != 0) {
		limit_by = 'o';
	}
	if (nb_opcodes) { // Disassemble `nb_opcodes` opcodes.
		if (nb_opcodes < 0) {
			int count, nbytes = 0;

			/* Backward disassembly of `nb_opcodes` opcodes:
			 * - We compute the new starting offset
			 * - Read at the new offset */
			nb_opcodes = -nb_opcodes;

			if (nb_opcodes > 0xffff) {
				eprintf ("Too many backward instructions\n");
				return 0;
			}

			if (r_core_prevop_addr (core, core->offset, nb_opcodes, &addr)) {
				nbytes = old_offset - addr;
			} else if (!r_core_asm_bwdis_len (core, &nbytes, &addr, nb_opcodes)) {
				/* workaround to avoid empty arrays */
#define BWRETRY 0
#if BWRETRY
				nb_opcodes ++;
				if (!r_core_asm_bwdis_len (core, &nbytes, &addr, nb_opcodes)) {
#endif
					r_cons_printf ("]");
					return false;
#if BWRETRY
				}
#endif
				nb_opcodes --;
			}
			count = R_MIN (nb_bytes, nbytes);
			if (count > 0) {
				r_core_read_at (core, addr, buf, count);
				r_core_read_at (core, addr+count, buf+count, nb_bytes-count);
			} else {
				if (nb_bytes > 0) {
					memset (buf, 0xff, nb_bytes);
				}
			}
		} else {
			// If we are disassembling a positive number of lines, enable dis_opcodes
			// to be used to finish the loop
			// If we are disasembling a negative number of lines, we just calculate
			// the equivalent addr and nb_size and scan a positive number of BYTES
			// so keep dis_opcodes = 0;
			dis_opcodes = 1;
			r_core_read_at (core, addr, buf, nb_bytes);
		}
	} else { // Disassemble `nb_bytes` bytes
		if (nb_bytes < 0) {
			//Backward disassembly of `nb_bytes` bytes
			nb_bytes = -nb_bytes;
			addr -= nb_bytes;
			r_core_read_at (core, addr, buf, nb_bytes);
		}
	}
	core->offset = addr;

	// XXX - is there a better way to reset a the analysis counter so that
	// when code is disassembled, it can actually find the correct offsets
	if (core->anal && core->anal->cur && core->anal->cur->reset_counter) {
		core->anal->cur->reset_counter (core->anal, addr);
	}
	// TODO: add support for anal hints
	// If using #bytes i = j
	// If using #opcodes, j is the offset from start address. i is the
	// offset in current disassembly buffer (256 by default)
	i = k = j = line = 0;
	// i = number of bytes
	// j = number of instructions
	// k = delta from addr
	ds = ds_init (core);
	for (;;) {
		bool end_nbopcodes, end_nbbytes;

		at = addr + k;
		ds->hint = r_core_hint_begin (core, ds->hint, ds->at);
		r_asm_set_pc (core->assembler, at);
		// 32 is the biggest opcode length in intel
		// Make sure we have room for it
		if (dis_opcodes == 1 && i >= nb_bytes - 32) {
			// Read another nb_bytes bytes into buf from current offset
			r_core_read_at (core, at, buf, nb_bytes);
			i = 0;
		}

		if (limit_by == 'o') {
			if (j >= nb_opcodes) {
				break;
			}
		} else if (i >= nb_bytes) {
			break;
		}
		ret = r_asm_disassemble (core->assembler, &asmop, buf + i, nb_bytes - i);
		if (ret < 1) {
			r_cons_printf (j > 0 ? ",{" : "{");
			r_cons_printf ("\"offset\":%"PFMT64d, at);
			r_cons_printf (",\"size\":1,\"type\":\"invalid\"}");
			i++;
			k++;
			j++;
			continue;
		}
		char *opstr = strdup (asmop.buf_asm);

		ds->has_description = false;
		r_anal_op_fini (&ds->analop);
		r_anal_op (core->anal, &ds->analop, at, buf + i, nb_bytes - i);

		if (ds->pseudo) {
			r_parse_parse (core->parser, asmop.buf_asm, asmop.buf_asm);
		}

		// f = r_anal_get_fcn_in (core->anal, at, 
		f = fcnIn (ds, at, R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
		if (ds->varsub && f) {
			core->parser->varlist = r_anal_var_list_dynamic;
			r_parse_varsub (core->parser, f, at, ds->analop.size,
				asmop.buf_asm, asmop.buf_asm, sizeof (asmop.buf_asm));
		}
		oplen = r_asm_op_get_size (&asmop);
		ds->oplen = oplen;
		ds->at = at;
		if (ds->midflags) {
			int skip_bytes = handleMidFlags (core, ds, false);
			if (skip_bytes && ds->midflags > R_MIDFLAGS_SHOW) {
				oplen = ds->oplen = ret = skip_bytes;
			}
		}
		{
			ut64 killme = UT64_MAX;
			bool be = core->print->big_endian;
			if (r_io_read_i (core->io, ds->analop.ptr, &killme, ds->analop.refptr, be)) {
				core->parser->relsub_addr = killme;
			}
		}
		r_parse_filter (core->parser, core->flags, asmop.buf_asm, str,
			sizeof (str), core->print->big_endian);

		r_cons_printf (j > 0 ? ",{" : "{");
		r_cons_printf ("\"offset\":%"PFMT64d, at);
		if (ds->analop.ptr != UT64_MAX) {
			r_cons_printf (",\"ptr\":%"PFMT64d, ds->analop.ptr);
		}
		if (ds->analop.val != UT64_MAX) {
			r_cons_printf (",\"val\":%"PFMT64d, ds->analop.val);
		}
		r_cons_printf (",\"esil\":\"%s\"", R_STRBUF_SAFEGET (&ds->analop.esil));
		r_cons_printf (",\"refptr\":%s", r_str_bool (ds->analop.refptr));
		if (f) {
			r_cons_printf (",\"fcn_addr\":%"PFMT64d, f->addr);
			r_cons_printf (",\"fcn_last\":%"PFMT64d, f->addr + r_anal_fcn_size (f) - oplen);
		} else {
			r_cons_printf (",\"fcn_addr\":0");
			r_cons_printf (",\"fcn_last\":0");
		}
		r_cons_printf (",\"size\":%d", ds->analop.size);
		{
			char *escaped_str = r_str_utf16_encode (opstr, -1);
			if (escaped_str) {
				r_cons_printf (",\"opcode\":\"%s\"", escaped_str);
			}
			free (escaped_str);

			escaped_str = r_str_utf16_encode (str, -1);
			if (escaped_str) {
				r_cons_printf (",\"disasm\":\"%s\"", escaped_str);
			}
			free (escaped_str);
		}
		r_cons_printf (",\"bytes\":\"%s\"", asmop.buf_hex);
		r_cons_printf (",\"family\":\"%s\"",
				r_anal_op_family_to_string (ds->analop.family));
		r_cons_printf (",\"type\":\"%s\"", r_anal_optype_to_string (ds->analop.type));
		// wanted the numerical values of the type information
		r_cons_printf (",\"type_num\":%"PFMT64d, ds->analop.type);
		r_cons_printf (",\"type2_num\":%"PFMT64d, ds->analop.type2);
		// handle switch statements
		if (ds->analop.switch_op && r_list_length (ds->analop.switch_op->cases) > 0) {
			// XXX - the java caseop will still be reported in the assembly,
			// this is an artifact to make ensure the disassembly is properly
			// represented during the analysis
			RListIter *iter;
			RAnalCaseOp *caseop;
			int cnt = r_list_length (ds->analop.switch_op->cases);
			r_cons_printf (", \"switch\":[");
			r_list_foreach (ds->analop.switch_op->cases, iter, caseop ) {
				cnt--;
				r_cons_printf ("{");
				r_cons_printf ("\"addr\":%"PFMT64d, caseop->addr);
				r_cons_printf (", \"value\":%"PFMT64d, (st64) caseop->value);
				r_cons_printf (", \"jump\":%"PFMT64d, caseop->jump);
				r_cons_printf ("}");
				if (cnt > 0) {
					r_cons_printf (",");
				}
			}
			r_cons_printf ("]");
		}
		if (ds->analop.jump != UT64_MAX ) {
			r_cons_printf (",\"jump\":%"PFMT64d, ds->analop.jump);
			if (ds->analop.fail != UT64_MAX) {
				r_cons_printf (",\"fail\":%"PFMT64d, ds->analop.fail);
			}
		}
		/* add flags */
		{
			const RList *flags = r_flag_get_list (core->flags, at);
			RFlagItem *flag;
			RListIter *iter;
			if (flags && !r_list_empty (flags)) {
				r_cons_printf (",\"flags\":[");
				r_list_foreach (flags, iter, flag) {
					r_cons_printf ("%s\"%s\"", iter->p?",":"",flag->name);
				}
				r_cons_printf ("]");
			}
		}
		/* add comments */
		{
			// TODO: slow because we are decoding and encoding b64
			char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, at);
			if (comment) {
				char *b64comment = sdb_encode ((const ut8*)comment, -1);
				r_cons_printf (",\"comment\":\"%s\"", b64comment);
				free (comment);
				free (b64comment);
			}
		}
		/* add xrefs */
		{
			RAnalRef *ref;
			RListIter *iter;
			RList *xrefs = r_anal_xref_get (core->anal, at);
			if (xrefs && !r_list_empty (xrefs)) {
				r_cons_printf (",\"xrefs\":[");
				r_list_foreach (xrefs, iter, ref) {
					r_cons_printf ("%s{\"addr\":%"PFMT64d",\"type\":\"%s\"}",
							iter->p?",":"", ref->addr,
						r_anal_xrefs_type_tostring (ref->type));
				}
				r_cons_printf ("]");
			}
			r_list_free (xrefs);
		}

		r_cons_printf ("}");
		i += oplen + asmop.payload + (ds->asmop.payload % ds->core->assembler->dataalign); // bytes
		k += oplen + asmop.payload + (ds->asmop.payload % ds->core->assembler->dataalign); // delta from addr
		j++; // instructions
		line++;

		free (opstr);
		end_nbopcodes = dis_opcodes == 1 && nb_opcodes > 0 && line>=nb_opcodes;
		end_nbbytes = dis_opcodes == 0 && nb_bytes > 0 && i>=nb_bytes;
		if (end_nbopcodes || end_nbbytes) {
			break;
		}
	}
	// r_cons_printf ("]");
	core->offset = old_offset;
	r_anal_op_fini (&ds->analop);
	ds_free (ds);
	return true;
}

R_API int r_core_print_disasm_all(RCore *core, ut64 addr, int l, int len, int mode) {
	const bool scr_color = r_config_get_i (core->config, "scr.color");
	int i, ret, err = 0, count = 0;
	ut8 *buf = core->block;
	char str[128];
	RAsmOp asmop;
	if (l < 1) {
		l = len;
	}
	RDisasmState *ds = ds_init (core);
	if (l > core->blocksize || addr != core->offset) {
		buf = malloc (l + 1);
		r_core_read_at (core, addr, buf, l);
	}
	if (mode == 'j') {
		r_cons_printf ("[");
	}
	r_cons_break_push (NULL, NULL);
	for (i = 0; i < l; i++) {
		ds->at = addr + i;
		ds->vat = p2v (ds, ds->at);
		r_asm_set_pc (core->assembler, ds->vat);
		if (r_cons_is_breaked ()) {
			break;
		}
		ret = r_asm_disassemble (core->assembler, &asmop, buf + i, l - i);
		if (ret < 1) {
			ret = err = 1;
			switch (mode) {
			case 'j':
			case '=':
				break;
			case 'i':
				r_cons_printf ("???\n");
				break;
			default:
				r_cons_printf ("0x%08"PFMT64x" ???\n", ds->vat);
				break;
			}
		} else {
			count ++;
			switch (mode) {
			case 'i':
				r_parse_filter (core->parser, core->flags, asmop.buf_asm,
						str, sizeof (str), core->print->big_endian);
				if (scr_color) {
					char *buf_asm;
					RAnalOp aop;
					r_anal_op (core->anal, &aop, addr, buf+i, l-i);
					buf_asm = r_print_colorize_opcode (core->print, str,
							core->cons->pal.reg, core->cons->pal.num, false);
					r_cons_printf ("%s%s\n",
							r_print_color_op_type (core->print, aop.type),
							buf_asm);
					free (buf_asm);
				} else {
					r_cons_println (asmop.buf_asm);
				}
				break;
			case '=':
				if (i < 28) {
					char *str = r_str_newf ("0x%08"PFMT64x" %60s  %s\n",
							ds->vat, "", asmop.buf_asm);
					char *sp = strchr (str, ' ');
					if (sp) {
						char *end = sp + 60 + 1;
						const char *src = asmop.buf_hex;
						char *dst = sp + 1 + (i * 2);
						int len = strlen (src);
						if (dst < end) {
							if (dst + len >= end) {
								len = end - dst;
								dst[len] = '.';
							}
							memcpy (dst, src, len);
						}
					}
					r_cons_strcat (str);
					free (str);
				}
				break;
			case 'j':
				r_cons_printf ("{\"addr\":%08"PFMT64d",\"bytes\":\"%s\",\"inst\":\"%s\"}%s",
					addr + i, asmop.buf_hex, asmop.buf_asm, ",");
				break;
			default:
				r_cons_printf ("0x%08"PFMT64x" %20s  %s\n",
						addr + i, asmop.buf_hex, asmop.buf_asm);
			}
		}
	}
	r_cons_break_pop ();
	if (buf != core->block) {
		free (buf);
	}
	if (mode == 'j') {
		r_cons_printf ("{}]\n");
	}
	ds_free (ds);
	return count;
}

R_API int r_core_print_fcn_disasm(RPrint *p, RCore *core, ut64 addr, int l, int invbreak, int cbytes) {
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
	ut32 cur_buf_sz = 0;
	ut8 *buf = NULL;
	ut32 len = 0;
	int ret, idx = 0, i;
	RListIter *bb_iter;
	RAnalBlock *bb = NULL;
	RDisasmState *ds;
	RList *bb_list = NULL;

	if (!fcn) {
		return -1;
	}

	cur_buf_sz = r_anal_fcn_size (fcn) + 1;
	buf = malloc (cur_buf_sz);
	if (!buf) {
		return -1;
	}
	len = r_anal_fcn_size (fcn);
	bb_list = r_list_new();
	if (!bb_list) {
		free (buf);
		return -1;
	}
	//r_cons_printf ("len =%d l=%d ib=%d limit=%d\n", len, l, invbreak, p->limit);
	// TODO: import values from debugger is possible
	// TODO: allow to get those register snapshots from traces
	// TODO: per-function register state trace
	idx = 0;
	memset (buf, 0, cur_buf_sz);

	// XXX - is there a better way to reset a the analysis counter so that
	// when code is disassembled, it can actually find the correct offsets
	if (core->anal->cur && core->anal->cur->reset_counter) {
		core->anal->cur->reset_counter (core->anal, addr);
	}

	// TODO: All those ds must be print flags
	ds = ds_init (core);
	ds->cbytes = cbytes;
	ds->print = p;
	ds->l = l;
	ds->buf = buf;
	ds->len = r_anal_fcn_size (fcn);
	ds->addr = fcn->addr;
	ds->fcn = fcn;
	ds->stackptr = core->anal->stackptr;

	r_list_foreach (fcn->bbs, bb_iter, bb) {
		r_list_add_sorted (bb_list, bb, cmpaddr);
	}
	// Premptively read the bb data locs for ref lines
	r_list_foreach (bb_list, bb_iter, bb) {
		if (idx >= cur_buf_sz) {
			break;
		}
		r_core_read_at (core, bb->addr, buf+idx, bb->size);
		//ret = r_asm_disassemble (core->assembler, &ds->asmop, buf+idx, bb->size);
		//if (ret > 0) eprintf ("%s\n",ds->asmop.buf_asm);
		idx += bb->size;
	}
	ds_reflines_fcn_init (ds, fcn, buf);
	core->inc = 0;
	core->cons->vline = r_config_get_i (core->config, "scr.utf8") ? (r_config_get_i (core->config, "scr.utf8.curvy") ? r_vline_uc : r_vline_u) : r_vline_a;
	i = idx = 0;
	r_cons_break_push (NULL, NULL);
	ds_print_esil_anal_init (ds);

	if (core->io && core->io->debug) {
		r_debug_map_sync (core->dbg);
	}
	r_list_foreach (bb_list, bb_iter, bb) {
		ut32 bb_size_consumed = 0;
		// internal loop to consume bb that contain case-like operations
		ds->at = bb->addr;
		ds->vat = p2v (ds, ds->at);
		ds->addr = bb->addr;
		len = bb->size;

		if (len > cur_buf_sz) {
			free (buf);
			buf = malloc (cur_buf_sz);
			ds->buf = buf;
			if (buf) {
				cur_buf_sz = len;
			} else {
				cur_buf_sz = 0;
			}
		}
		do {
			ds->printed_str_addr = UT64_MAX;
			ds->printed_flag_addr = UT64_MAX;
			// XXX - why is it necessary to set this everytime?
			r_asm_set_pc (core->assembler, ds->at);
			if (ds->lines >= ds->l) {
				break;
			}
			if (r_cons_is_breaked ()) {
				break;
			}

			ds_update_ref_lines (ds);
			/* show type links */
			r_core_cmdf (core, "tf 0x%08"PFMT64x, ds->at);

			ds_show_comments_right (ds);
			ret = ds_disassemble (ds, buf+idx, len - bb_size_consumed);
			ds_atabs_option (ds);
			// TODO: store previous oplen in core->dec
			if (!core->inc) {
				core->inc = ds->oplen;
			}
			r_anal_op_fini (&ds->analop);
			if (!ds->lastfail) {
				r_anal_op (core->anal, &ds->analop,
					ds->at+bb_size_consumed, buf+idx,
					len-bb_size_consumed);
			}
			if (ret < 1) {
				r_strbuf_init (&ds->analop.esil);
				ds->analop.type = R_ANAL_OP_TYPE_ILL;
			}
			ds_instruction_mov_lea (ds, idx);
			ds_control_flow_comments (ds);
			ds_adistrick_comments (ds);
			/* XXX: This is really cpu consuming.. need to be fixed */
			ds_show_functions (ds);
			if (ds_print_labels (ds, fcn)) {
				ds_show_functions (ds);
			}
			ds_show_xrefs (ds);
			ds_show_flags (ds);
			ds_setup_print_pre (ds, false, false);
			ds_print_lines_left (ds);
			ds_print_offset (ds);
			ds_print_op_size (ds);
			ds_print_trace (ds);
			ds_print_cycles (ds);
			ds_print_family (ds);
			ds_print_stackptr (ds);
			ret = ds_print_meta_infos (ds, buf, len, idx);
			if (ds->mi_found) {
				ds->mi_found = false;
				continue;
			}
			/* show cursor */
			ds_print_show_cursor (ds);
			ds_print_show_bytes (ds);
			ds_print_lines_right (ds);
			ds_build_op_str (ds, true);
			ds_print_opstr (ds);
			ds_print_sysregs (ds);
			ds_print_fcn_name (ds);
			ds_print_import_name (ds);
			ds_print_color_reset (ds);
			ds_print_dwarf (ds);
			ret = ds_print_middle (ds, ret);
			ds_print_asmop_payload (ds, buf + idx);
			if (core->assembler->syntax != R_ASM_SYNTAX_INTEL) {
				RAsmOp ao; /* disassemble for the vm .. */
				int os = core->assembler->syntax;
				r_asm_set_syntax (core->assembler,
					R_ASM_SYNTAX_INTEL);
				r_asm_disassemble (core->assembler, &ao,
					buf+idx, len-bb_size_consumed);
				r_asm_set_syntax (core->assembler, os);
			}
			if (ds->shortcut_pos > 0) {
				ds_print_core_vmode (ds, ds->shortcut_pos);
			}
			//ds_print_cc_update (ds);
			/*if (ds->analop.refptr) {
				handle_print_refptr (core, ds);
			} else {
				handle_print_ptr (core, ds, len, idx);
			}*/
			ds_print_ptr (ds, len, idx);
			ds_cdiv_optimization (ds);
			ds_print_comments_right (ds);
			ds_show_refs (ds);
			ds_print_esil_anal (ds);
			if (!(ds->show_comments && ds->show_comment_right && ds->comment)) {
				ds_newline (ds);
			}
			if (ds->line) {
				R_FREE (ds->line);
				R_FREE (ds->refline);
				R_FREE (ds->refline2);
			}
			ds_print_bbline (ds, false);

			bb_size_consumed += ds->oplen;
			ds->index += ds->oplen;
			idx += ds->oplen;
			ds->at += ds->oplen;
			ds->addr += ds->oplen;
			ds->lines++;

			R_FREE (ds->opstr);
		} while (bb_size_consumed < len);
		i++;
	}
	free (buf);
	r_cons_break_pop ();
	ds_print_esil_anal_fini (ds);

	ds_free (ds);
	r_list_free (bb_list);
	return idx;
}

static inline bool pdi_check_end(int nb_opcodes, int nb_bytes, int i, int j) {
	if (nb_opcodes > 0) {
		if (nb_bytes > 0) {
			return j < nb_opcodes && i < nb_bytes;
		}
		return j < nb_opcodes;
	}
	return i < nb_bytes;
}

R_API int r_core_disasm_pdi(RCore *core, int nb_opcodes, int nb_bytes, int fmt) {
	int show_offset = r_config_get_i (core->config, "asm.offset");
	int show_bytes = r_config_get_i (core->config, "asm.bytes");
	int decode = r_config_get_i (core->config, "asm.decode");
	int filter = r_config_get_i (core->config, "asm.filter");
	int show_color = r_config_get_i (core->config, "scr.color");
	bool asm_ucase = r_config_get_i (core->config, "asm.ucase");
	int esil = r_config_get_i (core->config, "asm.esil");
	int flags = r_config_get_i (core->config, "asm.flags");
	bool asm_immtrim = r_config_get_i (core->config, "asm.immtrim");
	int i = 0, j, ret, err = 0;
	ut64 old_offset = core->offset;
	RAsmOp asmop;
	const char *color_reg = R_CONS_COLOR_DEF (reg, Color_YELLOW);
	const char *color_num = R_CONS_COLOR_DEF (num, Color_CYAN);
	const int addrbytes = core->io->addrbytes;

	if (fmt == 'e') {
		show_bytes = 0;
		decode = 1;
	}
	if (!nb_opcodes && !nb_bytes) {
		return 0;
	}
	if (!nb_opcodes) {
		nb_opcodes = -1;
		if (nb_bytes < 0) {
			// Backward disasm `nb_bytes` bytes
			nb_bytes = -nb_bytes;
			core->offset -= nb_bytes;
			r_core_read_at (core, core->offset, core->block, nb_bytes);
		}
	} else if (!nb_bytes) {
		if (nb_opcodes < 0) {
			ut64 start;
			/* Backward disassembly of `ilen` opcodes
			* - We compute the new starting offset
			* - Read at the new offset */
			nb_opcodes = -nb_opcodes;
			if (r_core_prevop_addr (core, core->offset, nb_opcodes, &start)) {
				// We have some anal_info.
				nb_bytes = core->offset - start;
			} else {
				// anal ignorance.
				r_core_asm_bwdis_len (core, &nb_bytes, &core->offset,
					nb_opcodes);
			}
			nb_bytes *= core->io->addrbytes;
			if (nb_bytes > core->blocksize) {
				r_core_block_size (core, nb_bytes);
			}
			r_core_read_at (core, core->offset, core->block, nb_bytes);
		} else {
			// workaround for the `for` loop below
			nb_bytes = core->blocksize;
		}
	}

	// XXX - is there a better way to reset a the analysis counter so that
	// when code is disassembled, it can actually find the correct offsets
	if (core->anal && core->anal->cur && core->anal->cur->reset_counter) {
		core->anal->cur->reset_counter (core->anal, core->offset);
	}

	int len = (nb_opcodes + nb_bytes) * 5;
	if (core->fixedblock) {
		len = core->blocksize;
	} else {
		if (len > core->blocksize) {
			r_core_block_size (core, len);
			r_core_block_read (core);
		}
	}
	r_cons_break_push (NULL, NULL);

	int midflags = r_config_get_i (core->config, "asm.midflags");
	i = 0;
	j = 0;
toro:
	for (; pdi_check_end (nb_opcodes, nb_bytes, addrbytes * i, j); j++) {
		RFlagItem *item;
		if (r_cons_is_breaked ()) {
			err = 1;
			break;
		}
		RAnalMetaItem *meta = r_meta_find (core->anal, core->offset + i,
			R_META_TYPE_ANY, R_META_WHERE_HERE);
		if (meta && meta->size > 0) {
			switch (meta->type) {
			case R_META_TYPE_DATA:
				r_cons_printf (".data: %s\n", meta->str);
				i += meta->size;
				continue;
			case R_META_TYPE_STRING:
				r_cons_printf (".string: %s\n", meta->str);
				i += meta->size;
				continue;
			case R_META_TYPE_FORMAT:
				r_cons_printf (".format : %s\n", meta->str);
				i += meta->size;
				continue;
			case R_META_TYPE_MAGIC:
				r_cons_printf (".magic : %s\n", meta->str);
				i += meta->size;
				continue;
			case R_META_TYPE_RUN:
				/* TODO */
				break;
			}
		}
		r_asm_set_pc (core->assembler, core->offset + i);
		ret = r_asm_disassemble (core->assembler, &asmop, core->block + addrbytes * i,
			core->blocksize - addrbytes * i);
		if (midflags) {
			RDisasmState ds = {
				.oplen = ret,
				.at = core->offset + i,
				.midflags = midflags
			};
			int skip_bytes = handleMidFlags (core, &ds, true);
			if (skip_bytes && midflags > R_MIDFLAGS_SHOW) {
				ret = skip_bytes;
				asmop.size = ret;
			}
		}
		if (fmt == 'C') {
			char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, core->offset + i);
			if (comment) {
				r_cons_printf ("0x%08"PFMT64x " %s\n", core->offset + i, comment);
				free (comment);
			}
			i += ret;
			continue;
		}
		if (flags) {
			if (fmt != 'e') { // pie
				item = r_flag_get_i (core->flags, core->offset + i);
				if (item) {
					if (show_offset) {
						r_cons_printf ("0x%08"PFMT64x "  ", core->offset + i);
					}
					r_cons_printf ("  %s:\n", item->name);
				}
			} // do not show flags in pie
		}
		ut64 at = core->offset + i;
		if (show_offset) {
			const int show_offseg = (core->print->flags & R_PRINT_FLAGS_SEGOFF) != 0;
			const int show_offdec = (core->print->flags & R_PRINT_FLAGS_ADDRDEC) != 0;
			r_print_offset (core->print, at, 0, show_offseg, show_offdec, 0, NULL);
		}
		// r_cons_printf ("0x%08"PFMT64x"  ", core->offset+i);
		if (ret < 1) {
			err = 1;
			ret = asmop.size;
			if (ret < 1) {
				ret = 1;
			}
			if (show_bytes) {
				r_cons_printf ("%18s%02x  ", "", core->block[i]);
			}
			r_cons_println ("invalid"); // ???");
		} else {
			if (show_bytes) {
				r_cons_printf ("%20s  ", asmop.buf_hex);
			}
			ret = asmop.size;
			if (!asm_immtrim && (decode || esil)) {
				RAnalOp analop = {
					0
				};
				char *tmpopstr, *opstr = NULL;
				r_anal_op (core->anal, &analop, core->offset + i,
					core->block + addrbytes * i, core->blocksize - addrbytes * i);
				tmpopstr = r_anal_op_to_string (core->anal, &analop);
				if (fmt == 'e') { // pie
					char *esil = (R_STRBUF_SAFEGET (&analop.esil));
					r_cons_println (esil);
				} else {
					if (decode) {
						opstr = (tmpopstr)? tmpopstr: (asmop.buf_asm);
					} else if (esil) {
						opstr = (R_STRBUF_SAFEGET (&analop.esil));
					}
					if (asm_immtrim ) {
						r_parse_immtrim (opstr);
					}
					r_cons_println (opstr);
				}
			} else {
				char opstr[128] = {
					0
				};
				char *asm_str = (char *)&asmop.buf_asm;
				if (asm_ucase) {
					r_str_case (asm_str, 1);
				}
				if (asm_immtrim) {
					r_parse_immtrim (asm_str);
				}
				if (filter) {
					core->parser->hint = r_anal_hint_get (core->anal, at);
					r_parse_filter (core->parser, core->flags,
						asm_str, opstr, sizeof (opstr) - 1, core->print->big_endian);
					asm_str = (char *)&opstr;
				}
				if (show_color) {
					RAnalOp aop = {
						0
					};
					r_anal_op (core->anal, &aop, core->offset + i,
						core->block + addrbytes * i, core->blocksize - addrbytes * i);
					asm_str = r_print_colorize_opcode (core->print, asm_str, color_reg, color_num, false);
					r_cons_printf ("%s%s"Color_RESET "\n",
						r_print_color_op_type (core->print, aop.type),
						asm_str);
					free (asm_str);
					r_anal_op_fini (&aop);
				} else {
					r_cons_println (asm_str);
				}
			}
		}
		i += ret;
	}
	if (nb_opcodes > 0 && j < nb_opcodes) {
		r_core_seek (core, core->offset + i, 1);
		i = 0;
		goto toro;
	}
	r_cons_break_pop ();
	r_core_seek (core, old_offset, 1);
	return err;
}
