/* radare - LGPL - Copyright 2009-2016 - nibble, pancake, dso */

#include "r_core.h"
#include "r_cons.h"

#define HASRETRY 1
#define HAVE_LOCALS 1
#define DEFAULT_NARGS 4

#define R_MIDFLAGS_SHOW 1
#define R_MIDFLAGS_REALIGN 2

#define COLOR(ds, field) (ds->show_color ? ds->field : "")
#define COLOR_CONST(ds, color) (ds->show_color ? Color_ ## color : "")
#define COLOR_RESET(ds) COLOR_CONST(ds, RESET)


static const char* r_vline_a[] = {
	"|", // LINE_VERT
	"|-", // LINE_CROSS
	"/", // RUP_CORNER
	"\\", // RDWN_CORNER
	"->", // ARROW_RIGHT
	"=<", // ARROW_LEFT
	"-", // LINE_HORIZ
	",", // LUP_CORNER
	"`", // LDWN_CORNER
	"!", // LINE_UP
};

static const char* r_vline_u[] = {
	"│", // LINE_VERT
	"├", // LINE_CROSS
	"╒", // RUP_CORNER
	"╘", // RDWN_CORNER
	">", // ARROW_RIGHT
	"<", // ARROW_LEFT
	"─", // LINE_HORIZ
	"┌", // LUP_CORNER
	"└", // LDWN_CORNER
	"↑", // LINE_UP
};

// TODO: what about using bit shifting and enum for keys? see libr/util/bitmap.c
// the problem of this is that the fields will be more opaque to bindings, but we will earn some bits
typedef struct r_disam_options_t {
	RCore *core;
	char str[1024], strsub[1024];
	int use_esil;
	int show_color;
	int colorop;
	int acase;
	int show_flgoff;
	int atabs;
	int atabsonce;
	int atabsoff;
	int decode;
	int pseudo;
	int filter;
	int interactive;
	int varsub;
	int show_lines;
	int show_lines_ret;
	int show_lines_call;
	int linesright;
	int tracespace;
	int cyclespace;
	int cmtfold;
	int show_indent;
	bool show_dwarf;
	int show_size;
	int show_trace;
	int show_family;
	int asm_describe;
	int linesout;
	int adistrick;
	int asm_demangle;
	int show_offset;
	int show_bbline;
	int show_emu;
	int show_emu_str;
	int show_emu_write;
	int show_section;
	int show_section_col;
	int show_symbols;
	int show_symbols_col;
	int show_offseg;
	int show_flags;
	int show_bytes;
	int show_reloff;
	int show_comments;
	int show_jmphints;
	int show_slow;
	int cmtcol;
	int show_fcnlines;
	int show_calls;
	int show_cmtflgrefs;
	int show_cycles;
	int show_stackptr;
	int show_spacy;
	int show_xrefs;
	int show_functions;
	int show_fcncalls;
	int show_marks;
	int cursor;
	int show_comment_right_default;
	int flagspace_ports;
	int show_flag_in_bytes;
	int lbytes;
	int show_comment_right;
	char *pre;
	char *ocomment;
	int linesopts;
	int lastfail;
	int oldbits;
	int ocols;
	int lcols;
	int nb, nbytes;
	int show_utf8;
	int lines;
	int oplen;
	int varxs;
	int vars;
	int midflags;
	const char *pal_comment;
	const char *color_comment;
	const char *color_fname;
	const char *color_floc;
	const char *color_fline;
	const char *color_flow;
	const char *color_flag;
	const char *color_label;
	const char *color_other;
	const char *color_nop;
	const char *color_bin;
	const char *color_math;
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
	ut64 at, addr, dest;
	int tries, cbytes, idx;
	ut8 mi_found, retry, toro;
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

	// caches
	char *_tabsbuf;
	int _tabsoff;
} RDisasmState;

static void ds_setup_print_pre(RDisasmState *ds, bool tail, bool middle);
static void ds_setup_pre(RDisasmState *ds, bool tail, bool middle);
static void ds_print_pre(RDisasmState *ds);
static void ds_beginline(RDisasmState *ds, RAnalFunction *f, bool nopre);
static void ds_print_esil_anal(RDisasmState *ds);
static void ds_reflines_init(RDisasmState *ds);
static void ds_align_comment(RDisasmState *ds);
static RDisasmState * ds_init(RCore * core);
static void ds_set_pre(RDisasmState *ds, const char * str);
static void ds_build_op_str(RDisasmState *ds);
static void ds_pre_xrefs(RDisasmState *ds);
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
static void ds_print_fcn_name(RDisasmState *ds);
static void ds_print_as_string(RDisasmState *ds);
static void ds_print_core_vmode(RDisasmState *ds);
static void ds_print_cc_update(RDisasmState *ds);
static void ds_print_dwarf(RDisasmState *ds);
static void ds_print_asmop_payload(RDisasmState *ds);
static void ds_print_op_push_info(RDisasmState *ds);
//static int handle_read_refptr (RCore *core, RDisasmState *ds, ut64 *word8, ut32 *word4);
static void ds_print_comments_right(RDisasmState *ds);
//static void handle_print_refptr_meta_infos (RCore *core, RDisasmState *ds, ut64 word8 );
//static void handle_print_refptr (RCore *core, RDisasmState *ds);
static void ds_print_ptr(RDisasmState *ds, int len, int idx);

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
	if (oaddr == addr)
		return section;
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
					strncpy (section, mn+1, sizeof (section)-1);
				} else {
					strncpy (section, map->name, sizeof (section)-1);
				}
				break;
			}
		}
	}
	oaddr = addr;
	return section;
}

static void ds_print_spacy(RDisasmState *ds, int pre) {
	RCore *core = ds->core;
	RAnalFunction *f = NULL;
	if (pre) r_cons_newline ();
	if (ds->show_functions) {
		f = r_anal_get_fcn_in (core->anal, ds->at, R_ANAL_FCN_TYPE_NULL);
		if (!f) {
			r_cons_printf ("  ");
			ds_print_lines_left (ds);
		}
	}
	if (f) ds_beginline (ds, f, true);
	ds_print_offset (ds);
	if (!pre) r_cons_newline ();
}

static RDisasmState * ds_init(RCore *core) {
	RDisasmState *ds = R_NEW0 (RDisasmState);
	if (!ds) return NULL;
	ds->core = core;
	ds->pal_comment = core->cons->pal.comment;
	#define P(x) (core->cons && core->cons->pal.x)? core->cons->pal.x
	ds->color_comment = P(comment): Color_CYAN;
	ds->color_fname = P(fname): Color_RED;
	ds->color_floc = P(floc): Color_MAGENTA;
	ds->color_fline = P(fline): Color_CYAN;
	ds->color_flow = P(flow): Color_CYAN;
	ds->color_flag = P(flag): Color_CYAN;
	ds->color_label = P(label): Color_CYAN;
	ds->color_other = P(other): Color_WHITE;
	ds->color_nop = P(nop): Color_BLUE;
	ds->color_bin = P(bin): Color_YELLOW;
	ds->color_math = P(math): Color_YELLOW;
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

	ds->use_esil = r_config_get_i (core->config, "asm.esil");
	ds->show_flgoff = r_config_get_i (core->config, "asm.flgoff");
	ds->show_nodup = r_config_get_i (core->config, "asm.nodup");
	ds->show_spacy = r_config_get_i (core->config, "asm.spacy");
	ds->show_color = r_config_get_i (core->config, "scr.color");
	ds->colorop = r_config_get_i (core->config, "scr.colorops");
	ds->show_utf8 = r_config_get_i (core->config, "scr.utf8");
	ds->acase = r_config_get_i (core->config, "asm.ucase");
	ds->atabs = r_config_get_i (core->config, "asm.tabs");
	ds->atabsonce = r_config_get_i (core->config, "asm.tabsonce");
	ds->atabsoff = r_config_get_i (core->config, "asm.tabsoff");
	ds->midflags = r_config_get_i (core->config, "asm.midflags");
	ds->decode = r_config_get_i (core->config, "asm.decode");
	ds->pseudo = r_config_get_i (core->config, "asm.pseudo");
	ds->filter = r_config_get_i (core->config, "asm.filter");
	ds->interactive = r_config_get_i (core->config, "scr.interactive");
	ds->varsub = r_config_get_i (core->config, "asm.varsub");
	core->parser->relsub = r_config_get_i (core->config, "asm.relsub");
	ds->vars = r_config_get_i (core->config, "asm.vars");
	ds->varxs = r_config_get_i (core->config, "asm.varxs");
	ds->maxrefs = r_config_get_i (core->config, "asm.maxrefs");
	ds->show_lines = r_config_get_i (core->config, "asm.lines");
	ds->linesright = r_config_get_i (core->config, "asm.linesright");
	ds->show_indent = r_config_get_i (core->config, "asm.indent");
	ds->indent_space = r_config_get_i (core->config, "asm.indentspace");
	ds->tracespace = r_config_get_i (core->config, "asm.tracespace");
	ds->cyclespace = r_config_get_i (core->config, "asm.cyclespace");
	ds->show_dwarf = r_config_get_i (core->config, "asm.dwarf");
	ds->show_lines_call = r_config_get_i (core->config, "asm.lines.call");
	ds->show_lines_ret = r_config_get_i (core->config, "asm.lines.ret");
	ds->show_size = r_config_get_i (core->config, "asm.size");
	ds->show_trace = r_config_get_i (core->config, "asm.trace");
	ds->linesout = r_config_get_i (core->config, "asm.linesout");
	ds->adistrick = r_config_get_i (core->config, "asm.middle"); // TODO: find better name
	ds->asm_demangle = r_config_get_i (core->config, "asm.demangle");
	ds->asm_describe = r_config_get_i (core->config, "asm.describe");
	ds->show_offset = r_config_get_i (core->config, "asm.offset");
	ds->show_bbline = r_config_get_i (core->config, "asm.bbline");
	ds->show_section = r_config_get_i (core->config, "asm.section");
	ds->show_section_col = r_config_get_i (core->config, "asm.section.col");
	ds->show_symbols = r_config_get_i (core->config, "asm.symbol");
	ds->show_symbols_col = r_config_get_i (core->config, "asm.symbol.col");
	ds->show_emu = r_config_get_i (core->config, "asm.emu");
	ds->show_emu_str = r_config_get_i (core->config, "asm.emustr");
	ds->show_emu_write = r_config_get_i (core->config, "asm.emuwrite");
	ds->show_offseg = r_config_get_i (core->config, "asm.segoff");
	ds->show_flags = r_config_get_i (core->config, "asm.flags");
	ds->show_bytes = r_config_get_i (core->config, "asm.bytes");
	ds->show_reloff = r_config_get_i (core->config, "asm.reloff");
	ds->show_fcnlines = r_config_get_i (core->config, "asm.fcnlines");
	ds->show_comments = r_config_get_i (core->config, "asm.comments");
	ds->show_jmphints = r_config_get_i (core->config, "asm.jmphints");
	ds->show_slow = r_config_get_i (core->config, "asm.slow");
	ds->show_calls = r_config_get_i (core->config, "asm.calls");
	ds->show_family = r_config_get_i (core->config, "asm.family");
	ds->cmtcol = r_config_get_i (core->config, "asm.cmtcol");
	ds->show_cmtflgrefs = r_config_get_i (core->config, "asm.cmtflgrefs");
	ds->show_cycles = r_config_get_i (core->config, "asm.cycles");
	ds->show_stackptr = r_config_get_i (core->config, "asm.stackptr");
	ds->show_xrefs = r_config_get_i (core->config, "asm.xrefs");
	ds->cmtfold = r_config_get_i (core->config, "asm.cmtfold");
	ds->show_functions = r_config_get_i (core->config, "asm.functions");
	ds->show_fcncalls = r_config_get_i (core->config, "asm.fcncalls");
	ds->nbytes = r_config_get_i (core->config, "asm.nbytes");
	core->print->bytespace = r_config_get_i (core->config, "asm.bytespace");
	ds->cursor = 0;
	ds->nb = 0;
	ds->flagspace_ports = r_flag_space_get (core->flags, "ports");
	ds->lbytes = r_config_get_i (core->config, "asm.lbytes");
	ds->show_comment_right_default = r_config_get_i (core->config, "asm.cmtright");
	ds->show_comment_right = r_config_get_i (core->config, "asm.cmtright"); // XX conflict with show_comment_right_default
	ds->show_flag_in_bytes = r_config_get_i (core->config, "asm.flagsinbytes");
	ds->show_marks = r_config_get_i (core->config, "asm.marks");
	ds->pre = strdup ("  ");
	ds->ocomment = NULL;
	ds->linesopts = 0;
	ds->lastfail = 0;
	ds->oldbits = 0;
	ds->ocols = 0;
	ds->lcols = 0;

	ds->esil_old_pc = UT64_MAX;
	ds->esil_regstate = NULL;
	ds->esil_likely = false;

	if (ds->show_flag_in_bytes) {
		ds->show_flags = 0;
	}
	if (r_config_get_i (core->config, "asm.lineswide")) {
		ds->linesopts |= R_ANAL_REFLINE_TYPE_WIDE;
	}
	if (core->cons->vline) {
		if (ds->show_utf8)
			ds->linesopts |= R_ANAL_REFLINE_TYPE_UTF8;
	}

	if (ds->show_lines) ds->ocols += 10; // XXX
	if (ds->show_offset) ds->ocols += 14;
	ds->lcols = ds->ocols+2;
	if (ds->show_bytes) ds->ocols += 20;
	if (ds->show_trace) ds->ocols += 8;
	if (ds->show_stackptr) ds->ocols += 4;
	/* disasm */ ds->ocols += 20;
	ds->nb = ds->nbytes? (1+ds->nbytes*2): 0;
	ds->tries = 3;

	if (core->print->cur_enabled) {
		if (core->print->cur < 0) {
			core->print->cur = 0;
		}
		ds->cursor = core->print->cur;
	} else ds->cursor = -1;

	if (r_config_get_i (core->config, "asm.lineswide")) {
		ds->linesopts |= R_ANAL_REFLINE_TYPE_WIDE;
	}
	if (core->cons->vline) {
		if (core->utf8)
			ds->linesopts |= R_ANAL_REFLINE_TYPE_UTF8;
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
		anal->reflines = r_anal_reflines_fcn_get (anal,
			fcn, -1, ds->linesout, ds->show_lines_call);
		free (anal->reflines2); // TODO: leak
		anal->reflines2 = r_anal_reflines_fcn_get (anal,
			fcn, -1, ds->linesout, 1);
	} else {
		r_list_free (anal->reflines);
		r_list_free (anal->reflines2);
		anal->reflines = anal->reflines2 = NULL;
	}
}

static void ds_free(RDisasmState *ds) {
	if (!ds) return;
	RCore *core = ds->core;
	if (core && ds->oldbits) {
		r_config_set_i (core->config, "asm.bits", ds->oldbits);
		ds->oldbits = 0;
	}
	r_anal_op_fini (&ds->analop);
	r_anal_hint_free (ds->hint);
	free (ds->comment);
	free (ds->pre);
	free (ds->line);
	free (ds->refline);
	free (ds->refline2);
	free (ds->opstr);
	free (ds->osl);
	free (ds->sl);
	free (ds->_tabsbuf);
	free (ds);
}

static void ds_set_pre(RDisasmState *ds, const char * str) {
	if (!ds->show_fcnlines) {
		if (ds->pre && !*ds->pre) {
			return;
		}
		str = "";
	}
	free (ds->pre);
	ds->pre = strdup (str);
}

static char *colorize_asm_string(RCore *core, RDisasmState *ds) {
	char *spacer = NULL;
	char *source = ds->opstr? ds->opstr: ds->asmop.buf_asm;

	if (!ds->show_color || !ds->colorop) {
		return strdup (source);
	}

	r_cons_strcat (r_print_color_op_type (core->print, ds->analop.type));

	// workaround dummy colorizer in case of paired commands (tms320 & friends)

	spacer = strstr (source, "||");
	if (spacer) {
		char *scol1, *s1 = r_str_ndup (source, spacer - source);
		char *scol2, *s2 = strdup (spacer + 2);

		scol1 = r_print_colorize_opcode (s1, ds->color_reg, ds->color_num);
		free (s1);
		scol2 = r_print_colorize_opcode (s2, ds->color_reg, ds->color_num);
		free (s2);
		if (!scol1) scol1 = strdup ("");
		if (!scol2) scol2 = strdup ("");

		source = malloc (strlen(scol1) + strlen(scol2) + 2 + 1); // reuse source variable
		sprintf (source, "%s||%s", scol1, scol2);
		free (scol1);
		free (scol2);
		return source;
	}
	return r_print_colorize_opcode (source, ds->color_reg, ds->color_num);
}

static void ds_build_op_str(RDisasmState *ds) {
	RCore *core = ds->core;
	char *asm_str;
	if (!ds->opstr) {
		ds->opstr = strdup (ds->asmop.buf_asm);
	}
	/* initialize */
	core->parser->hint = ds->hint;
	if (ds->varsub && ds->opstr) {
		RAnalFunction *f = r_anal_get_fcn_in (core->anal,
			ds->at, R_ANAL_FCN_TYPE_NULL);
		//if (f) {
			core->parser->varlist = r_anal_var_list;
			r_parse_varsub (core->parser, f, ds->at, ds->analop.size,
				ds->opstr, ds->strsub, sizeof (ds->strsub));
			if (*ds->strsub) {
				free (ds->opstr);
				ds->opstr = strdup (ds->strsub);
			}
		//}
	}
	asm_str = colorize_asm_string (core, ds);
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
			r_parse_filter (core->parser, core->flags,
				asm_str, ds->str, sizeof (ds->str), core->print->big_endian);
			core->parser->flagspace = ofs;
			free (ds->opstr);
			ds->opstr = strdup (ds->str);
			core->parser->flagspace = ofs; // ???
		} else {
			if (!ds->opstr) {
				ds->opstr = strdup (asm_str? asm_str: "");
			}
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

R_API RAnalHint *r_core_hint_begin(RCore *core, RAnalHint* hint, ut64 at) {
	static char *hint_arch = NULL;
	static char *hint_syntax = NULL;
	static int hint_bits = 0;
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
	if (hint_bits) {
		r_config_set_i (core->config, "asm.bits", hint_bits);
		hint_bits = 0;
	}
	if (hint) {
		/* arch */
		if (hint->arch) {
			if (!hint_arch) hint_arch = strdup (
				r_config_get (core->config, "asm.arch"));
			r_config_set (core->config, "asm.arch", hint->arch);
		}
		/* arch */
		if (hint->syntax) {
			if (!hint_syntax) hint_syntax = strdup (
				r_config_get (core->config, "asm.syntax"));
			r_config_set (core->config, "asm.syntax", hint->syntax);
		}
		/* bits */
		if (hint->bits) {
			if (!hint_bits) hint_bits =
				r_config_get_i (core->config, "asm.bits");
			r_config_set_i (core->config, "asm.bits", hint->bits);
		}
	}
	return hint;
}

static void ds_beginline(RDisasmState *ds, RAnalFunction *f, bool nopre) {
	const char *pre;
	ds_setup_pre(ds, false, false);
	pre = ds->pre;
	if (nopre) {
		if (*pre == '/' || *pre == '\\')
			pre = "  ";
	}
	if (ds->show_functions && ds->show_fcnlines) {
		if (*pre == '\\') {
			ds_set_pre (ds, ds->core->cons->vline[LINE_VERT]);
		}
		ds_print_pre (ds);
	}
	char *tmp = ds->line;
	ds->line = ds->refline2;
	ds_print_lines_left (ds);
	ds->line = tmp;
}

static void ds_pre_xrefs(RDisasmState *ds) {
	RCore *core = ds->core;

	if (ds->show_fcnlines) {
		ds_setup_pre (ds, false, false);
		if (*ds->pre != ' '){
			ds_set_pre(ds, core->cons->vline[LINE_VERT]);
			ds->pre = r_str_concat (ds->pre, " ");
		}
	}
	ds_print_pre (ds);
	char *tmp = ds->line;
	ds->line = ds->refline2;
	ds_print_lines_left (ds);
	ds->line = tmp;
}

static void ds_show_xrefs(RDisasmState *ds) {
	RList *xrefs;
	RAnalRef *refi;
	RListIter *iter;
	RCore *core = ds->core;
	bool demangle = r_config_get_i (core->config, "bin.demangle");
	const char *lang = demangle ? r_config_get (core->config, "bin.lang") : NULL;
	char *name, *tmp;
	int count = 0;
	if (!ds->show_xrefs)
		return;
	if (!ds->show_comments)
		return;
	/* show xrefs */
	xrefs = r_anal_xref_get (core->anal, ds->at);
	if (!xrefs) return;
	if (r_list_length (xrefs) > ds->maxrefs) {
		int cols = r_cons_get_size (NULL);
		cols -= 15;
		cols /= 23;
		ds_pre_xrefs (ds);
		r_cons_printf ("%s; XREFS: ", ds->show_color?
				ds->pal_comment: "");
		r_list_foreach (xrefs, iter, refi) {
			r_cons_printf ("%s 0x%08"PFMT64x"  ",
				r_anal_xrefs_type_tostring (refi->type), refi->addr);
			if (count == cols) {
				if (iter->n) {
					ds_print_color_reset (ds);
					r_cons_newline ();
					ds_pre_xrefs (ds);
					r_cons_printf ("%s; XREFS: ",
						ds->show_color? ds->pal_comment: "");
				}
				count = 0;
			} else count++;
		}
		ds_print_color_reset (ds);
		r_cons_newline ();
		r_list_free (xrefs);
		return;
	}

	r_list_foreach (xrefs, iter, refi) {
		if (refi->at == ds->at) {
			RAnalFunction *fun = r_anal_get_fcn_in (
				core->anal, refi->addr, -1);
			name = strdup (fun ? fun->name : "unk");
			if (demangle) {
				tmp = r_bin_demangle (core->bin->cur, lang, name);
				if (tmp) {
					free (name);
					name = tmp;
				}
			}
			ds_pre_xrefs (ds);
			r_cons_printf ("%s; %s XREF from 0x%08"PFMT64x" (%s)%s\n",
				COLOR (ds, pal_comment),
				r_anal_xrefs_type_tostring (refi->type),
				refi->addr,
				name,
				COLOR_RESET (ds));
			R_FREE (name);
		}
	}
	r_list_free (xrefs);
}

static void ds_atabs_option(RDisasmState *ds) {
	int n, i = 0, comma = 0, word = 0;
	int size, brackets = 0;
	char *t, *b;
	if (!ds || !ds->atabs)
		return;
	size = strlen (ds->asmop.buf_asm)* (ds->atabs+1)*4;
	if (size < 1)
		return;
	free (ds->opstr);
	ds->opstr = b = malloc (size);
	strcpy (b, ds->asmop.buf_asm);
	for (; *b; b++, i++) {
		if (*b=='(' || *b=='[') brackets++;
		if (*b==')' || *b==']') brackets--;
		if (*b==',') comma = 1;
		if (*b!=' ') continue;
		if (word>0 && !comma) continue; //&& b[1]=='[') continue;
		if (brackets>0) continue;
		comma = 0;
		brackets = 0;
		n = (ds->atabs-i);
		t = strdup (b+1); //XXX slow!
		if (n<1) n = 1;
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
	RFlagItem *fi;
	int i;
	for (i = 1; i < ds->oplen; i++) {
		fi = r_flag_get_i (core->flags, ds->at + i);
		if (fi) {
			if (!strncmp (fi->name, "reloc.", 6)) {
				if (print) {
					r_cons_printf ("(%s)\n", fi->name);
				}
				continue;
			}
			return i;
		}
	}
	return 0;
}

static void ds_print_show_cursor(RDisasmState *ds) {
	RCore *core = ds->core;
	char res[] = "     ";
	void *p;
	int q, t;
	if (!ds->show_marks)
		return;
	q = core->print->cur_enabled &&
		ds->cursor >= ds->index &&
		ds->cursor < (ds->index + ds->asmop.size);
	p = r_bp_get_at (core->dbg->bp, ds->at);
	t = ds->midflags && handleMidFlags (core, ds, false) > 0;
	if (p) res[0] = 'b';
	if (t) res[1] = '~';
	if (q) {
		if (ds->cursor == ds->index) {
			res[2] = '*';
		} else {
			int i = 2, diff = ds->cursor - ds->index;
			if (diff > 9) res[i++] = '0' + (diff / 10);
			res[i] = '0' + (diff % 10);
		}
	}
	r_cons_strcat (res);
}

static int var_comparator(const RAnalVar *a, const RAnalVar *b){
	if (a && b) return a->delta > b->delta;
	return false;
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
		fcn_name = r_bin_demangle (core->bin->cur, lang, f->name);
		if (!fcn_name)
			fcn_name = strdup (f->name);
	} else {
		fcn_name = f->name;
	}
	sign = r_anal_fcn_to_string (core->anal, f);
	if (f->type == R_ANAL_FCN_TYPE_LOC) {
		r_cons_printf ("%s%s ", COLOR (ds, color_fline),
			core->cons->vline[LINE_CROSS]); // |-
		r_cons_printf ("%s%s%s %d\n", COLOR (ds, color_floc),
			fcn_name, COLOR_RESET (ds), r_anal_fcn_size (f));
	} else {
		const char *space = ds->show_fcnlines ? " " : "";
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
		ds_set_pre (ds, core->cons->vline[RUP_CORNER]);
		if (ds->show_flgoff) {
			r_cons_printf ("%s%s", COLOR (ds, color_fline), ds->pre);
			if (ds->show_fcnlines) {
				r_cons_printf (" ");
			}
			ds_print_lines_left (ds);
			ds_print_offset (ds);
			r_cons_printf ("%s%s%s(%s) %s%s%s %d\n",
					space, COLOR_RESET (ds), COLOR (ds, color_fname),
					fcntype, fcn_name, cmt, COLOR_RESET (ds), r_anal_fcn_size (f));
		} else {
			r_cons_printf ("%s%s%s%s%s(%s) %s%s%s %d\n",
					COLOR (ds, color_fline), ds->pre,
					space, COLOR_RESET (ds), COLOR (ds, color_fname),
					fcntype, fcn_name, cmt, COLOR_RESET (ds), r_anal_fcn_size (f));
		}
	}
	if (sign)
		r_cons_printf ("// %s\n", sign);
	R_FREE (sign);
	ds_set_pre (ds, core->cons->vline[LINE_VERT]);
	if (ds->show_fcnlines) {
		ds->pre = r_str_concat (ds->pre, " ");
	}
	ds->stackptr = 0;
	if (ds->vars) {
		char spaces[32];
		RAnalVar *var;
		RListIter *iter;
		RList *args = r_anal_var_list (core->anal, f, 'a');
		RList *regs = r_anal_var_list (core->anal, f, 'v');
		RList *sp_vars = r_anal_var_list (core->anal, f, 'e');
		r_list_sort (args, (RListComparator)var_comparator);
		r_list_sort (regs, (RListComparator)var_comparator);
		r_list_sort (sp_vars, (RListComparator)var_comparator);
		if (call) {
			//XXX probably broken
			r_cons_printf ("%s%s%s %s %s%s (",
				COLOR (ds, color_fline), ds->pre,
				COLOR_RESET (ds), COLOR (ds, color_fname),
				fcn_name, COLOR_RESET (ds));
			r_list_foreach (args, iter, var) {
				r_cons_printf ("%s %s%s", var->type, var->name, iter->n ? ", " : "");
			}
			r_cons_printf (");\n");
		}
		r_list_join (args, sp_vars);
		r_list_join (args, regs);
		r_list_foreach (args, iter, var) {
			char *tmp;
			int idx;
			RAnal *anal = ds->core->anal;
			memset (spaces, ' ', sizeof(spaces));
			idx = 12 - strlen (var->name);
			if (idx < 0) idx = 0;
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
			case 'a':
				if (var->delta > 0) {
					r_cons_printf ("arg %s %s @ %s+0x%x",
						var->type, var->name,
						anal->reg->name[R_REG_NAME_BP],
						var->delta);
				} else {
					r_cons_printf ("var %s %s @ %s-0x%x",
						var->type, var->name,
						anal->reg->name[R_REG_NAME_BP],
						-var->delta);
				}
				break;
			case 'v': {
				RRegItem *i = r_reg_index_get (anal->reg, var->delta);
				if (!i) {
					eprintf("Register not found");
					break;
				}
				r_cons_printf ("reg %s %s @ %s",
					var->type, var->name, i->name);
				}
				break;
			case 'e':
				if ( var->delta < f->stack) {
					r_cons_printf ("var %s %s @ %s+0x%x",
						var->type, var->name,
						anal->reg->name[R_REG_NAME_SP],
						var->delta);
				} else {
					r_cons_printf ("arg %s %s @ %s+0x%x",
						var->type, var->name,
						anal->reg->name[R_REG_NAME_SP],
						var->delta);
				}
				break;
			}
			char *comment = r_meta_get_string (anal, var->kind, var->delta);
			if (comment) {
				r_cons_printf ("\t%s;%s", COLOR(ds,color_comment),comment);
			}
			r_cons_printf ("%s\n", COLOR_RESET (ds));
		}
		r_list_free (regs);
		// it's already empty, but rlist instance is still there
		r_list_free (args);
		r_list_free (sp_vars);
	}
	if (demangle)
		free (fcn_name);
}

static void ds_setup_print_pre(RDisasmState *ds, bool tail, bool middle) {
	ds_setup_pre (ds, tail, middle);
	ds_print_pre (ds);
}

static void ds_setup_pre(RDisasmState *ds, bool tail, bool middle) {
	RCore *core = ds->core;
	RAnalFunction *f;

	if (!ds->show_functions) return;
	f = r_anal_get_fcn_in (core->anal, ds->at, R_ANAL_FCN_TYPE_NULL);
	if (f) {
		if (f->addr == ds->at) {
			if (ds->analop.size == r_anal_fcn_size (f) && !middle) {
				ds_set_pre (ds, core->cons->vline[RDWN_CORNER]);
			} else {
				ds_set_pre (ds, core->cons->vline[LINE_VERT]);
			}
		} else if (f->addr + r_anal_fcn_size (f) - ds->analop.size == ds->at) {
			ds_set_pre (ds, core->cons->vline[RDWN_CORNER]);
		} else if (r_anal_fcn_is_in_offset (f, ds->at)) {
			ds_set_pre (ds, core->cons->vline[LINE_VERT]);
		}

		if (ds->show_fcnlines) {
			ds->pre = r_str_concat (ds->pre, " ");
		}
		if (tail) {
			r_str_replace_char (ds->pre, '\\', ' ');
			r_str_replace_char (ds->pre, '|', '\\');
		}
	}
}

static void ds_print_pre(RDisasmState *ds) {
	RCore *core = ds->core;
	RAnalFunction *f;

	if (!ds->show_functions) {
		return;
	}
	f = r_anal_get_fcn_in (core->anal, ds->at, R_ANAL_FCN_TYPE_NULL);
	if (f) {
		r_cons_printf ("%s%s%s", COLOR (ds, color_fline),
			ds->pre, COLOR_RESET (ds));
	} else {
		if (ds->show_lines) {
			r_cons_printf ("  ");
		} else if (ds->show_fcnlines) {
			r_cons_printf (" ");
		}
	}
}

static void ds_show_comments_right(RDisasmState *ds) {
	int linelen, maxclen ;
	RCore *core = ds->core;
	RAnalFunction *f;
	RFlagItem *item;
	/* show comment at right? */
	int scr = ds->show_comment_right;
	if (!ds->show_comments) {
		return;
	}
	f = r_anal_get_fcn_in (core->anal, ds->at, R_ANAL_FCN_TYPE_NULL);
	item = r_flag_get_i (core->flags, ds->at);
	ds->comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, ds->at);
	if (!ds->comment && item && item->comment && *item->comment) {
		ds->ocomment = item->comment;
		ds->comment = strdup (item->comment);
	}
	if (!ds->comment) {
		return;
	}
	maxclen = strlen (ds->comment)+5;
	linelen = maxclen;
	if (ds->show_comment_right_default) {
		if (ds->ocols+maxclen < core->cons->columns) {
			if (ds->comment && *ds->comment && strlen (ds->comment)<maxclen) {
				if (!strchr (ds->comment, '\n')) // more than one line?
					ds->show_comment_right = 1;
			}
		}
	}
	if (!ds->show_comment_right) {
		int infun, mycols = ds->lcols;
		if (mycols + linelen + 10 > core->cons->columns)
			mycols = 0;
		mycols /= 2;
		if (ds->show_color) r_cons_strcat (ds->pal_comment);
#if OLD_COMMENTS
		r_cons_strcat ("; ");
		// XXX: always prefix with ; the comments
		if (*ds->comment != ';') r_cons_strcat ("  ;  ");
		r_cons_strcat_justify (ds->comment, mycols, ';');
#else
		infun = f && (f->addr != ds->at);
		if (infun) {
			char *str = strdup (ds->show_color ? ds->color_fline : "");
			str = r_str_concat (str, core->cons->vline[LINE_VERT]);
			if (ds->show_color) {
				str = r_str_concat (str, ds->color_flow);
			}
			// color refline
			str = r_str_concat (str, " ");
			str = r_str_concat (str, ds->refline2);
			// color comment
			if (ds->show_color) {
				str = r_str_concat (str, ds->color_comment);
			}
			str = r_str_concat (str, ";  ");
			ds->comment = r_str_prefix_all (ds->comment, str);
			free (str);
		} else {
			ds->comment = r_str_prefix_all (ds->comment, "   ;      ");
		}
		/* print multiline comment */
		if (ds->cmtfold) {
			char * p = strdup (ds->comment);
			char *q = strchr (p, '\n');
			if (q) {
				*q = 0;
				r_cons_strcat (p);
				r_cons_strcat (" ; [z] unfold");
			}
			free (p);
		} else {
			r_cons_strcat (ds->comment);
		}
#endif
		if (ds->show_color) ds_print_color_reset (ds);
		r_cons_newline ();
		R_FREE (ds->comment);

		/* flag one */
		if (item && item->comment && ds->ocomment != item->comment) {
			if (ds->show_color) r_cons_strcat (ds->pal_comment);
			r_cons_newline ();
			r_cons_strcat ("  ;  ");
			r_cons_strcat_justify (item->comment, mycols, ';');
			r_cons_newline ();
			if (ds->show_color) ds_print_color_reset (ds);
		}
	}
	ds->show_comment_right = scr;
}

static void ds_show_flags(RDisasmState *ds) {
	//const char *beginch;
	RFlagItem *flag;
	RListIter *iter;
	RAnalFunction *f;
	const RList /*RFlagList*/ *flaglist;
	//bool printed = false;

	if (!ds->show_flags) {
		return;
	}

	RCore *core = ds->core;
	f = r_anal_get_fcn_in (core->anal, ds->at, R_ANAL_FCN_TYPE_NULL);
	flaglist = r_flag_get_list (core->flags, ds->at);

	r_list_foreach (flaglist, iter, flag) {
		if (f && f->addr == flag->offset && !strcmp (flag->name, f->name)) {
			// do not show flags that have the same name as the function
			continue;
		}
		if (ds->show_flgoff) {
			if (f) {
				ds_beginline (ds, f, false);
			} else {
				ds_print_lines_left (ds);
				r_cons_printf ("  ");
			}
			ds_print_offset (ds);
			r_cons_printf (" ");
		} else {
			r_cons_printf ((f && ds->at > f->addr)?"| ": "  ");
			ds_print_lines_left (ds);
			r_cons_printf (";-- ");
		}
		if (ds->show_color)
			r_cons_strcat (ds->color_flag);
		//beginch = (iter->p && printed) ? ", " : "";
		if (ds->asm_demangle) {
			const char *lang = r_config_get (core->config, "bin.lang");
			char *name = r_bin_demangle (core->bin->cur, lang, flag->realname);
			r_cons_printf ("%s:\n", name? name: flag->realname);
			R_FREE (name);
		} else {
			r_cons_printf ("%s:\n", flag->name);
		}
		//printed = true;
	}
	if (ds->show_spacy) {
		if (!r_list_empty (flaglist)) {
			ds_print_spacy(ds, false);
		}
	}
}

static void ds_update_ref_lines(RDisasmState *ds) {
	if (ds->show_lines) {
		ds->line = r_anal_reflines_str (ds->core, ds->at, ds->linesopts);
		free (ds->refline);
		ds->refline = ds->line? strdup (ds->line): NULL;
		free (ds->refline2);
		ds->refline2 = r_anal_reflines_str (ds->core, ds->at,
			ds->linesopts | R_ANAL_REFLINE_TYPE_MIDDLE);
		if (ds->line) {
			if (strchr (ds->line, '<'))
				ds->indent_level++;
			if (strchr (ds->line, '>'))
				ds->indent_level--;
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

	if (ds->hint && ds->hint->size) {
		ds->oplen = ds->hint->size;
	}
	if (ds->hint && ds->hint->opcode) {
		free (ds->opstr);
		ds->opstr = strdup (ds->hint->opcode);
		return true;
	}
	ret = r_asm_disassemble (core->assembler, &ds->asmop, buf, len);
	if (ds->asmop.size < 1) ds->asmop.size = 1;

	if (ds->show_nodup) {
		const char *opname = (ret < 1)? "invalid": ds->asmop.buf_asm;
		if (ds->prev_ins && !strcmp (ds->prev_ins, opname)) {
			if (!ds->prev_ins_eq) {
				ds->prev_ins_eq = true;
				r_cons_printf ("...");
			}
			ds->prev_ins_count ++;
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
			ds->retry = 1;
			return ret;
		}
#endif
		ds->lastfail = 1;
		ds->asmop.size = (ds->hint && ds->hint->size) ?
			ds->hint->size : 1;
		ds->oplen = ds->asmop.size;
	} else {
		ds->lastfail = 0;
		ds->asmop.size = (ds->hint && ds->hint->size) ?
			ds->hint->size : r_asm_op_get_size (&ds->asmop);
		ds->oplen = ds->asmop.size;
	}
	if (ds->pseudo) {
		r_parse_parse (core->parser, ds->opstr ?
			ds->opstr : ds->asmop.buf_asm, ds->str);
		free (ds->opstr);
		ds->opstr = strdup (ds->str);
	}

	if (ds->acase) r_str_case (ds->asmop.buf_asm, 1);

	return ret;
}

static void ds_control_flow_comments(RDisasmState *ds) {
	if (ds->show_comments && ds->show_cmtflgrefs) {
		RFlagItem *item;
		switch (ds->analop.type) {
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_CALL:
			item = r_flag_get_i (ds->core->flags, ds->analop.jump);
			if (item && item->comment) {
				if (ds->show_color) r_cons_strcat (ds->pal_comment);
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
	if (!out) return;
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
		static RFlagItem sfi = {0};
		const char *name = "";
		int delta = 0;
		if (ds->fcn) {
			sfi.offset = ds->fcn->addr;
			sfi.name = ds->fcn->name;
			ds->lastflag = &sfi;
		} else {
			RFlagItem *fi = r_flag_get_at (core->flags, ds->at);
			if (fi) { // && (!ds->lastflag || fi->offset != ds->at)) {
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
	if (!ds->linesright && ds->show_lines && ds->line) {
		r_cons_printf ("%s%s%s", COLOR (ds, color_flow), ds->line, COLOR_RESET (ds));
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
		if (!ds->analop.failcycles)
			r_cons_printf ("%3d     ", ds->analop.cycles);
		else	r_cons_printf ("%3d %3d ", ds->analop.cycles, ds->analop.failcycles);
	}
	if (ds->cyclespace) {
		char spaces [32];
		int times = R_MIN (ds->analop.cycles/4, 30); // limit to 30
		memset (spaces, ' ', sizeof (spaces));
		spaces[times] = 0;
		r_cons_strcat (spaces);
	}
}

static void ds_print_stackptr(RDisasmState *ds) {
	if (ds->show_stackptr) {
		r_cons_printf ("%5d%s", ds->stackptr,
			ds->analop.type == R_ANAL_OP_TYPE_CALL?">":
			ds->analop.stackop == R_ANAL_STACK_ALIGN? "=":
			ds->stackptr > ds->ostackptr? "+":
			ds->stackptr < ds->ostackptr? "-": " ");
		ds->ostackptr = ds->stackptr;
		if (ds->analop.stackop == R_ANAL_STACK_RESET) {
			ds->stackptr = 0;
		} else {
			ds->stackptr += ds->analop.stackptr;
		}
		/* XXX if we reset the stackptr 'ret 0x4' has not effect.
		 * Use RAnalFunction->RAnalOp->stackptr? */
		if (ds->analop.type == R_ANAL_OP_TYPE_RET)
			ds->stackptr = 0;
	}
}

static void ds_print_offset(RDisasmState *ds) {
	RCore *core = ds->core;

	r_print_set_screenbounds (core->print, ds->at);
	if (ds->show_offset) {
		static RFlagItem sfi = {0};
		RFlagItem *fi;
		int delta = 0;
		if (ds->show_reloff) {
			RAnalFunction *f = r_anal_get_fcn_at (core->anal,
					ds->at, R_ANAL_FCN_TYPE_NULL);
			if (f) {
				delta = ds->at - f->addr;
				sfi.name = f->name;
				sfi.offset = f->addr;
				ds->lastflag = &sfi;
			} else {
				fi = r_flag_get_i (core->flags, ds->at);
				if (fi) ds->lastflag = fi;
				if (ds->lastflag) {
					if (ds->lastflag->offset == ds->at) {
						delta = 0;
					} else {
						delta = ds->at - ds->lastflag->offset;
					}
				} else {
					delta = ds->at - core->offset;
				}
			}
		}
		r_print_offset (core->print, ds->at, (ds->at==ds->dest),
				ds->show_offseg, delta);
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
		if (!tp)
			tp = r_debug_trace_get (ds->core->dbg, ds->at);
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


static bool ds_print_data_type(RCore *core, const ut8 *buf, int ib, int size) {
	const char *type = NULL;
	char msg[64];
	const int isSigned = (ib == 1 || ib == 8 || ib == 10)? 1: 0;
	switch (size) {
	case 1: type = isSigned? ".char": ".byte"; break;
	case 2: type = isSigned? ".int16": ".word"; break;
	case 4: type = isSigned? ".int32": ".dword"; break;
	case 8: type = isSigned? ".int64": ".qword"; break;
	default: return false;
	}
	ut64 n = r_read_ble (buf, core->print->big_endian, size * 8);

	switch (ib) {
	case 1:
		r_str_bits (msg, buf, size * 8, NULL);
		r_cons_printf ("%s %sb", type, msg);
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
			r_cons_printf ("%s 0x%016x", type, n);
			break;
		default:
			return false;
		}
	}

	if (size == 4 || size == 8) {
		RFlagItem *fi = r_flag_get_i (core->flags, n);
		if (fi) r_cons_printf (" ; %s", fi->name);
	}
	return true;
}

static int ds_print_meta_infos(RDisasmState *ds, ut8* buf, int len, int idx) {
	int ret = 0;
	const char *infos, *metas;
	char key[100];
	RAnalMetaItem MI, *mi = &MI;
	RCore * core = ds->core;
	Sdb *s = core->anal->sdb_meta;

	snprintf (key, sizeof (key)-1, "meta.0x%"PFMT64x, ds->at);
	infos = sdb_const_get (s, key, 0);
	if (infos)
	for (;*infos; infos++) {
		/* XXX wtf, must use anal.meta.deserialize() */
		char *p, *q;
		if (*infos==',')
			continue;
		snprintf (key, sizeof (key)-1, "meta.%c.0x%"PFMT64x, *infos, ds->at);
		metas = sdb_const_get (s, key, 0);
		MI.size = sdb_array_get_num (s, key, 0, 0);
		MI.type = *infos;
		MI.from = ds->at;
		MI.to = ds->at + MI.size;
		if (metas) {
			p = strchr (metas, ',');
			if (!p) {
				continue;
			}
			MI.space = atoi (p + 1);
			q = strchr (p + 1, ',');
			if (!q) {
				continue;
			}
			MI.str = (char*)sdb_decode (q + 1, 0);
		} else MI.str = NULL;
		// sdb-get blah
		// TODO: implement ranged meta find (if not at the begging of function..
#if 0
		RAnalMetaItem *mi = r_meta_find (core->anal, ds->at,
			R_META_TYPE_ANY, R_META_WHERE_HERE);
#endif
		char *out = NULL;
		int hexlen;
		int delta;
		ds->mi_found = 0;
		if (mi) {
			switch (mi->type) {
			case R_META_TYPE_STRING:
			{
				out = r_str_escape (mi->str);
				r_cons_printf ("    .string %s\"%s\"%s ; len=%"PFMT64d,
					COLOR_CONST (ds, YELLOW), out, COLOR_RESET (ds),
					mi->size);
				free (out);
				delta = ds->at-mi->from;
				ds->oplen = mi->size-delta;
				ds->asmop.size = (int)mi->size;
				//i += mi->size-1; // wtf?
				R_FREE (ds->line);
				R_FREE (ds->refline);
				R_FREE (ds->refline2);
				ds->mi_found = 1;
				break;
			}
			case R_META_TYPE_HIDE:
				r_cons_printf ("(%d bytes hidden)", mi->size);
				ds->asmop.size = mi->size;
				ds->oplen = mi->size;
				ds->mi_found = 1;
				break;
			case R_META_TYPE_DATA:
				hexlen = len - idx;
				delta = ds->at-mi->from;
				if (mi->size < hexlen) {
					hexlen = mi->size;
				}
				ds->oplen = mi->size;
				core->print->flags &= ~R_PRINT_FLAGS_HEADER;

				if (!ds_print_data_type (core, buf + idx,
					ds->hint? ds->hint->immbase: 0, mi->size)) {
					r_cons_printf ("hex length=%lld delta=%d\n", mi->size , delta);
					r_print_hexdump (core->print, ds->at, buf+idx, hexlen-delta, 16, 1);
				}

				core->inc = 16;
				core->print->flags |= R_PRINT_FLAGS_HEADER;
				ds->asmop.size = ret = (int)mi->size; //-delta;
				R_FREE (ds->line);
				R_FREE (ds->refline);
				R_FREE (ds->refline2);
				ds->mi_found = 1;
				break;
			case R_META_TYPE_FORMAT:
				r_cons_printf ("format %s {\n", mi->str);
				r_print_format (core->print, ds->at, buf+idx, len-idx, mi->str, R_PRINT_MUSTSEE, NULL, NULL);
				r_cons_printf ("} %d", mi->size);
				ds->oplen = ds->asmop.size = ret = (int)mi->size;
				R_FREE (ds->line);
				R_FREE (ds->refline);
				R_FREE (ds->refline2);
				ds->mi_found = 1;
				break;
			}
		}
		if (MI.str) {
			free (MI.str);
			MI.str = NULL;
		}
	}
	return ret;
}

static void ds_instruction_mov_lea(RDisasmState *ds, int idx) {
	RCore *core = ds->core;
	RAnalValue *src;

	switch (ds->analop.type) {
	case R_ANAL_OP_TYPE_LENGTH:
	case R_ANAL_OP_TYPE_CAST:
	case R_ANAL_OP_TYPE_CMOV:
	case R_ANAL_OP_TYPE_MOV:
		src = ds->analop.src[0];
		if (src && src->memref>0 && src->reg) {
			if (core->anal->reg) {
				const char *pc = core->anal->reg->name[R_REG_NAME_PC];
				RAnalValue *dst = ds->analop.dst;
				if (dst && dst->reg && dst->reg->name)
				if (!strcmp (src->reg->name, pc)) {
					RFlagItem *item;
					ut8 b[8];
					ut64 ptr = idx+ds->addr+src->delta+ds->analop.size;
					ut64 off = 0LL;
					r_core_read_at (core, ptr, b, src->memref);
					off = r_mem_get_num (b, src->memref);
					item = r_flag_get_i (core->flags, off);
					r_cons_printf ("; MOV %s = [0x%"PFMT64x"] = 0x%"PFMT64x" %s\n",
							dst->reg->name, ptr, off, item?item->name: "");
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
			if (dst && dst->reg && !strcmp (src->reg->name, pc)) {
				int index = 0;
				int memref = core->assembler->bits/8;
				RFlagItem *item;
				ut8 b[64];
				ut64 ptr = index+ds->addr+src->delta+ds->analop.size;
				ut64 off = 0LL;
				r_core_read_at (core, ptr, b, sizeof (b)); //memref);
				off = r_mem_get_num (b, memref);
				item = r_flag_get_i (core->flags, off);
				{
				char s[64];
				r_str_ncpy (s, (const char *)b, sizeof (s));
				r_cons_printf ("; LEA %s = [0x%"PFMT64x"] = 0x%"PFMT64x" \"%s\"\n",
						dst->reg->name, ptr, off, item?item->name: s);
				}
			}
		}
	}
}

static void ds_print_show_bytes(RDisasmState *ds) {
	RCore* core = ds->core;
	char *nstr, *str = NULL, pad[64];
	char *flagstr = NULL;
	char extra[64];
	int j,k;
	if (!ds->show_bytes)
		return;
	if (ds->nb<1)
		return;
	strcpy (extra, " ");
	if (ds->show_flag_in_bytes) {
		flagstr = r_flag_get_liststr (core->flags, ds->at);
	}
	if (flagstr) {
		str = flagstr;
		if (ds->nb > 0) {
			k = ds->nb-strlen (flagstr)-1;
			if (k < 0 || k > sizeof(pad)) k = 0;
			for (j = 0; j < k; j++)
				pad[j] = ' ';
			pad[j] = '\0';
		} else { 
		    	pad[0] = 0;
		}
	} else {
		if (ds->show_flag_in_bytes) {
			k = ds->nb - 1;
			if (k < 0 || k > sizeof(pad)) k = 0;
			for (j=0; j<k; j++)
				pad[j] = ' ';
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
				k = ds->nb - r_str_ansi_len (nstr)+1;
			}
			if (k > 0) {
			    	//setting to sizeof screw up the disasm
			    	if (k > sizeof(pad)) k = 18;
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
	if (ds->show_color) {
		r_cons_printf ("%s%s %s"Color_RESET, pad, str, extra);
	} else {
		r_cons_printf ("%s%s %s", pad, str, extra);
	}
	free (str);
}

static void ds_print_indent(RDisasmState *ds) {
	if (ds->show_indent) {
		char indent[128];
		int num = ds->indent_level * ds->indent_space;
		if (num < 0) num = 0;
		if (num >= sizeof (indent))
			num = sizeof(indent)-1;
		memset (indent, ' ', num);
		indent[num] = 0;
		r_cons_strcat (indent);
	}
}

static void ds_print_opstr(RDisasmState *ds) {
	ds_print_indent (ds);
	r_cons_strcat (ds->opstr);
	ds_print_color_reset (ds);
}

static void ds_print_color_reset(RDisasmState *ds) {
	if (ds->show_color) r_cons_strcat (Color_RESET);
}

static int ds_print_middle(RDisasmState *ds, int ret) {
	if (ds->middle != 0) {
		ret -= ds->middle;
		ds_align_comment (ds);
		if (ds->show_color) r_cons_strcat (ds->pal_comment);
		r_cons_printf (" ; *middle* %d", ret);
		if (ds->show_color) r_cons_strcat (Color_RESET);
	}
	return ret;
}

static bool ds_print_labels(RDisasmState *ds, RAnalFunction *f) {
	RCore *core = ds->core;
	const char *label;

	if (!f) f = r_anal_get_fcn_in (core->anal, ds->at, 0);
	label = r_anal_fcn_label_at (core->anal, f, ds->at);
	if (!label)
		return false;
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

static void ds_print_fcn_name(RDisasmState *ds) {
	int delta;
	const char *label;
	RAnalFunction *f;
	RCore *core = ds->core;
	if (!ds->show_comments)
		return;
	switch (ds->analop.type) {
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_CJMP:
	case R_ANAL_OP_TYPE_CALL:
		f = r_anal_get_fcn_in (core->anal,
			ds->analop.jump, R_ANAL_FCN_TYPE_NULL);
		if (f && !strstr (ds->opstr, f->name)) {
			if (ds->show_color) {
				r_cons_strcat (ds->color_fname);
			}
			//beginline (core, ds, f);
			// print label
			delta = ds->analop.jump - f->addr;
			label = r_anal_fcn_label_at (core->anal, f, ds->analop.jump);
			if (label) {
				ds_align_comment (ds);
				r_cons_printf (" ; %s.%s", f->name, label);
			} else {
				RAnalFunction *f2 = r_anal_get_fcn_in (core->anal, ds->at, 0);
				if (f != f2) {
					ds_align_comment (ds);
					if (delta>0) {
						r_cons_printf (" ; %s+0x%x", f->name, delta);
					} else if (delta<0) {
						r_cons_printf (" ; %s-0x%x", f->name, -delta);
					} else {
						r_cons_printf (" ; %s", f->name);
					}
				}
			}
			ds_print_color_reset (ds);
		}
		break;
	}
}

static void ds_print_core_vmode(RDisasmState *ds) {
	char *shortcut = NULL;
	RCore *core = ds->core;

	if (!ds->show_jmphints) return;
	if (core->vmode) {
		switch (ds->analop.type) {
		case R_ANAL_OP_TYPE_LEA:
			ds_align_comment(ds);
			if (ds->show_color) r_cons_strcat (ds->pal_comment);
			shortcut = r_core_add_asmqjmp (core, ds->analop.ptr);
			if (shortcut) {
				r_cons_printf (" ;[%s]", shortcut);
				free (shortcut);
			} else {
				r_cons_strcat (" ;[?]");
			}
			if (ds->show_color) r_cons_strcat (Color_RESET);
			break;
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_CALL:
		case R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_CALL:
			ds_align_comment (ds);
			if (ds->show_color) r_cons_strcat (ds->pal_comment);
			shortcut = r_core_add_asmqjmp (core, ds->analop.jump);
			if (shortcut) {
				r_cons_printf (" ;[%s]", shortcut);
				free (shortcut);
			} else {
				r_cons_strcat (" ;[?]");
			}
			if (ds->show_color) r_cons_strcat (Color_RESET);
			break;
		}
	}
}

// modifies anal register state
static void ds_print_cc_update(RDisasmState *ds) {
	// declare static since this variable is reused locally, and needs to maintain
	// state
	static RAnalCC cc = {0};
	RCore *core = ds->core;

	if (!ds->show_comments || !ds->show_fcncalls)
		return;
	if (!r_anal_cc_update (core->anal, &cc, &ds->analop)) {
		if (ds->show_functions) {
			RAnalFunction *f = r_anal_get_fcn_in (core->anal, ds->at, R_ANAL_FCN_TYPE_NULL);
			char tmp[128];
			char *ccstr = r_anal_cc_to_string (core->anal, &cc);
			tmp[0] = 0;
			r_anal_cc_update (core->anal, &cc, &ds->analop);
			if (ccstr) {
				RFlagItem *flag = r_flag_get_at (core->flags, cc.jump);
				if (flag && ccstr) {
					int delta = 0;
					if (f) { delta = cc.jump-flag->offset; }
					if (!strncmp (flag->name, ccstr, strlen (flag->name))) {
						if (ccstr[strlen (flag->name)] == '(') {
							tmp[0] = 0;
						} else {
							if (delta)
								snprintf (tmp, sizeof (tmp)-1, " ; %s+%d", flag->name, delta);
							else snprintf (tmp, sizeof (tmp)-1, " ; %s", flag->name);
						}
					} else {
						if (delta)
							snprintf (tmp, sizeof (tmp)-1, " ; %s+%d", flag->name, delta);
						else snprintf (tmp, sizeof (tmp)-1, " ; %s", flag->name);
					}
				}

				if (ds->show_calls) {
					const char *sn = ds->show_section? get_section_name (core, ds->at): "";
					int cmtright = ds->show_comment_right;
					if (core->cons->columns < 120) {
						cmtright = 0;
					}
					// if doesnt fits in screen newline
					if (cmtright) {
						ds_align_comment (ds);
						r_cons_printf (" %s%s; %s%s%s", COLOR_RESET (ds),
							COLOR (ds, pal_comment), ccstr, tmp, COLOR_RESET (ds));
					} else {
						r_cons_printf ("\n%s%s%s%s%s  %s^-%s %s%s%s",
							COLOR (ds, color_fline), ds->pre, COLOR (ds, color_flow),
							sn, ds->refline, COLOR_RESET (ds), COLOR (ds, pal_comment),
							ccstr, tmp, COLOR_RESET (ds));
					}
				}
				free (ccstr);
				if (f) {
					ds_set_pre (ds, core->cons->vline[LINE_VERT]);
					ds->pre = r_str_concat (ds->pre, " ");
				} else {
					ds_set_pre (ds, "  ");
				}
			}
		}
		r_anal_cc_reset (&cc);
	}
}

// align for comment
static void ds_align_comment(RDisasmState *ds) {
	const int cmtcol = ds->cmtcol;
	if (ds->show_comment_right_default) {
		char *ll = r_cons_lastline ();
		if (ll) {
			int cstrlen = strlen (ll);
			int cols, ansilen = r_str_ansi_len (ll);
			int utf8len = r_utf8_strlen ((const ut8*)ll);

			int cells = utf8len - (cstrlen-ansilen);

			cols = ds->interactive ? ds->core->cons->columns : 1024;
			//cols = r_cons_get_size (NULL);
			if (cmtcol+16>=cols) {
#if 0
				r_cons_newline ();
				r_cons_memset (' ', 10);
#endif
				int len = cmtcol - cells;
				r_cons_memset (' ', len);
			} else if (cells < cmtcol) {
				int len = cmtcol - cells;
				if (len < cols)
					r_cons_memset (' ', len);
			}
		}
	}
}

static void ds_print_dwarf(RDisasmState *ds) {
	if (ds->show_dwarf) {
		int len = strlen (ds->opstr);
		if (len < 30) {
			len = 30 - len;
		}
		ds->sl = r_bin_addr2text (ds->core->bin, ds->at, true);
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
				chopstr = r_str_chop (line);
				if (!*chopstr) {
					free (line);
					return;
				}
				// handle_set_pre (ds, "  ");
				ds_align_comment (ds);
				if (ds->show_color) {
					r_cons_printf ("%s ; %s"Color_RESET, ds->pal_comment, chopstr);
				} else {
					r_cons_printf (" ; %s", chopstr);
				}
				free (ds->osl);
				ds->osl = ds->sl;
				ds->sl = NULL;
				free (line);
			}
		}
	}
}

static void ds_print_asmop_payload(RDisasmState *ds) {
	if (ds->varxs) {
		// XXX asume analop is filled
		//r_anal_op (core->anal, &ds->analop, ds->at, core->block+i, core->blocksize-i);
		int v = ds->analop.ptr;
		switch (ds->analop.stackop) {
		case R_ANAL_STACK_GET:
			if (v<0) {
				r_cons_printf (" ; local.get %d", -v);
			} else {
				r_cons_printf (" ; arg.get %d", v);
			}
			break;
		case R_ANAL_STACK_SET:
			if (v<0) {
				r_cons_printf (" ; local.set %d", -v);
			} else {
				r_cons_printf (" ; arg.set %d", v);
			}
			break;
		}
	}
	if (ds->asmop.payload != 0)
		r_cons_printf ("\n; .. payload of %d bytes", ds->asmop.payload);
}

static void ds_print_op_push_info(RDisasmState *ds){
	switch (ds->analop.type) {
	case R_ANAL_OP_TYPE_PUSH:
		if (ds->analop.val) {
			RFlagItem *flag = r_flag_get_i (ds->core->flags, ds->analop.val);
			if (flag) r_cons_printf (" ; %s", flag->name);
		}
		break;
	}
}

static void ds_comment_newline(RDisasmState *ds) {
	const char *sn;

	if (ds->show_comment_right) return;
	sn = ds->show_section ? get_section_name (ds->core, ds->at) : "";
	ds_align_comment (ds);
	r_cons_printf ("\n%s%s%s%s%s  ^- %s", COLOR (ds, color_fline),
		ds->pre, sn, ds->refline, COLOR_RESET (ds),
		COLOR (ds, pal_comment));
}

/* convert numeric value in opcode to ascii char or number */
static void ds_print_ptr(RDisasmState *ds, int len, int idx) {
	RCore *core = ds->core;
	ut64 p = ds->analop.ptr;
	int aligned = 0;
#define DOALIGN() \
	if (!aligned) { \
		ds_align_comment (ds); \
		if (ds->show_color) r_cons_printf (ds->pal_comment); \
		aligned = 1; \
	}

	if (!ds->show_comments)
		return;
	if (!ds->show_slow) {
		return;
	}
	if (p == UT64_MAX) {
		/* do nothing */
	} else if (((st64)p) > 0) {
		const char *kind;
		char *msg = calloc (sizeof (char), len);
		RFlagItem *f, *f2;

		r_io_read_at (core->io, p, (ut8*)msg, len - 1);

		if (ds->analop.refptr) {
			ut64 num;
#if 0
			if (core->print->big_endian) {
				num = r_read_le64 (msg);
			} else {
				num = r_read_be64 (msg);
			}
#endif
			num = r_read_le64 (msg);
			// TODO: make this more complete
			switch (ds->analop.refptr) {
			case 1: num &= UT8_MAX; break;
			case 2: num &= UT16_MAX; break;
			case 4: num &= UT32_MAX; break;
			case 8: num &= UT64_MAX; break;
			}
			st64 n = (st64)num;
			st32 n32 = (st32)(n & UT32_MAX);

			DOALIGN();

			if (ds->analop.type == R_ANAL_OP_TYPE_LEA) {
				ds_comment_newline (ds);
				const char *flag = "";
				f = r_flag_get_i (core->flags, p);
				if (f) flag = f->name;
				r_cons_printf (" ; 0x%"PFMT64x"%s%s", p, *flag?" ; ":"", flag);
			} else {
				f = NULL;
				if (n == UT32_MAX || n == UT64_MAX) {
					r_cons_printf (" ; [0x%"PFMT64x":%d]=-1", p, ds->analop.refptr);
				} else if (n == n32 && (n32>-512 && n32 <512)) {
					r_cons_printf (" ; [0x%"PFMT64x":%d]=%"PFMT64d, p, ds->analop.refptr, n);
				} else {
					const char *kind, *flag = "";
					char *msg2 = NULL;
					f = r_flag_get_i (core->flags, n);
					if (f) {
						flag = f->name;
					} else {
						msg2 = calloc (sizeof (char), len);
						r_io_read_at (core->io, n, (ut8*)msg2, len - 1);
						msg2[len-1] = 0;
						kind = r_anal_data_kind (core->anal, p, (const ut8*)msg2, len - 1);
						if (kind && !strcmp (kind, "text")) {
							r_str_filter (msg2, 0);
							if (*msg2) {
								char *lala = r_str_newf ("\"%s\"", msg2);
								free (msg2);
								flag = msg2 = lala;
							}
						}
					}
					// try to guess what's in there
					r_cons_printf (" ; [0x%"PFMT64x":%d]=0x%"PFMT64x"%s%s",
							p, ds->analop.refptr, n, (flag&&*flag)?" ":"", flag);
					free (msg2);
				}
				// not just for LEA
				f2 = r_flag_get_i (core->flags, p);
				if (f2 && f != f2) {
					r_cons_printf (" LEA %s", f2->name);
				}
			}
		}
#if 1
		if (!IS_PRINTABLE (*msg))
			*msg = 0;
		else msg[len-1] = 0;
#endif
		f = r_flag_get_i (core->flags, p);
		if (f) {
			r_str_filter (msg, 0);

			ds_comment_newline (ds);

			DOALIGN();
			if (*msg) {
				//r_cons_printf (" ; \"%s\"", msg); // @ 0x%"PFMT64x, msg, p);
				r_cons_printf (" ; \"%s\" @ 0x%"PFMT64x, msg, p);
			} else {
				r_cons_printf (" ; %s", f->name);
			}
		} else {
			if (p == UT64_MAX || p == UT32_MAX) {
				DOALIGN();
				r_cons_printf (" ; -1", p);
			} else if (((char)p>0) && p>='!' && p<='~') {
				char ch = p;
				DOALIGN();
				r_cons_printf (" ; '%c'", ch);
			} else if (p > 10) {
				if ((st64)p<0) {
					// resolve local var if possible
					RAnalVar *v = r_anal_var_get (core->anal, ds->at, 'v', 1, (int)p);
					DOALIGN();
					if (v) {
						r_cons_printf (" ; var %s", v->name);
						r_anal_var_free (v);
					} else {
						r_cons_printf (" ; var %d", (int)-p);
					}
				} else {
					if (r_core_anal_address (core, p) & R_ANAL_ADDR_TYPE_ASCII) {
						r_str_filter (msg, 0);
						if (*msg) {
							DOALIGN();
							r_cons_printf (" ; \"%s\" 0x%08"PFMT64x" ",
									msg, p);
						}
					}
				}
			}
			kind = r_anal_data_kind (core->anal, p, (const ut8*)msg, len - 1);
			if (kind) {
				if (!strcmp (kind, "text")) {
					r_str_filter (msg, 0);
					if (*msg) {
						DOALIGN();
						//r_cons_printf (" ; \"%s\" @ 0x%"PFMT64x, msg, p);
						r_cons_printf (" ; \"%s\"", msg); // @ 0x%"PFMT64x, msg, p);
					}
				} else if (!strcmp (kind, "invalid")){
					int *n = (int*)&p;
					if (*n>-0xfff && *n < 0xfff) {
						DOALIGN();
						r_cons_printf (" ; %d", *n);
					}
				} else {
					//r_cons_printf (" ; %s", kind);
				}
				// TODO: check for more data kinds
			}
		}
		free (msg);
	} else ds_print_as_string (ds);
	if (aligned && ds->show_color) r_cons_printf (Color_RESET);
}

// TODO: Use sdb in rbin to accelerate this
// we shuold use aligned reloc addresses instead of iterating all of them
static RBinReloc *getreloc(RCore *core, ut64 addr, int size) {
	RList *list;
	RBinReloc *r;
	RListIter *iter;
	if (size<1 || addr == UT64_MAX) return NULL;
	list = r_bin_get_relocs (core->bin);
#if 0
addr       addr+size
|__._______|
   |
   reloc
#endif
	r_list_foreach (list, iter, r) {
		if ((r->vaddr >= addr) && (r->vaddr<(addr+size)))
			return r;
	}
	return NULL;
}

static void ds_print_relocs(RDisasmState *ds) {
	RCore *core = ds->core;
	RBinReloc *rel = getreloc (core, ds->at, ds->analop.size);

	if (rel) {
		if (rel->import)
			r_cons_printf ("  ; RELOC %d %s", rel->type, rel->import->name);
		else if (rel->symbol)
			r_cons_printf ("  ; RELOC %d %s", rel->type, rel->symbol->name);
		else r_cons_printf ("  ; RELOC %d ", rel->type);
	}
}

static int mymemwrite0(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	return 0;
}

static int mymemwrite1(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	return 1;
}

static int myregwrite(RAnalEsil *esil, const char *name, ut64 val) {
	char str[64], *msg = NULL;
	ut32 *n32 = (ut32*)str;
	RDisasmState *ds = esil->user;

	if (ds) {
		ds->esil_likely = true;
		if (!ds->show_slow) {
			return 0;
		}
	}

	memset (str, 0, sizeof (str));
	if (val != 0LL) {
#if 0
		RFlagItem *fi = r_flag_get_i (esil->anal->flb.f, val);
		if (fi) {
			strncpy (str, fi->name, sizeof (str)-1);
		}
		if (!str[0]) {
			(void)r_io_read_at (esil->anal->iob.io, val, (ut8*)str, sizeof (str)-1);
			str[sizeof (str)-1] = 0;
			if (*str && r_str_is_printable (str)) {
				// do nothing
				msg = r_str_newf ("\"%s\"", str);
			} else {
				str[0] = 0;
				if (*n32 == 0) {
					// msg = strdup ("NULL");
				} else if (*n32 == UT32_MAX) {
					/* nothing */
				} else {
					if (ds && !ds->show_emu_str) {
						msg = r_str_newf ("-> 0x%x", *n32);
					}
				}
			}
		} else {
			msg = r_str_newf ("%s", str);
		}

#endif
		(void)r_io_read_at (esil->anal->iob.io, val, (ut8*)str, sizeof (str)-1);
		str[sizeof (str)-1] = 0;
		if (*str && r_str_is_printable (str)) {
			// do nothing
			msg = r_str_newf ("\"%s\"", str);
		} else {
			str[0] = 0;
			if (*n32 == 0) {
				// msg = strdup ("NULL");
			} else if (*n32 == UT32_MAX) {
				/* nothing */
			} else {
				if (ds && !ds->show_emu_str) {
					msg = r_str_newf ("-> 0x%x", *n32);
				}
			}
		}
		RFlagItem *fi = r_flag_get_i (esil->anal->flb.f, val);
		if (fi) {
			msg = r_str_concatf (msg, " %s", fi->name);
		}
	}
	if (ds && ds->show_emu_str) {
		if (msg && *msg) r_cons_printf ("; %s", msg);
	} else {
		r_cons_printf ("; %s=0x%"PFMT64x" %s", name, val, msg? msg: "");
	}
	free (msg);
	return 0;
}

static void ds_print_esil_anal_init(RDisasmState *ds) {
	RCore *core = ds->core;
	const char *pc = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
	ds->esil_old_pc = r_reg_getv (core->anal->reg, pc);
	if (!ds->esil_old_pc || ds->esil_old_pc == UT64_MAX) ds->esil_old_pc = core->offset;
	if (!ds->show_emu) {
		return;
	}
	if (!core->anal->esil) {
		int iotrap = r_config_get_i (core->config, "esil.iotrap");
		int stacksize = r_config_get_i (core->config, "esil.stacksize");
		if (!(core->anal->esil = r_anal_esil_new (stacksize, iotrap))) {
			R_FREE (ds->esil_regstate);
			return;
		}
		r_anal_esil_setup (core->anal->esil, core->anal, 0, 0);
	}
	core->anal->esil->user = ds;
	free (ds->esil_regstate);
	if (core->anal->gp) {
		r_reg_setv (core->anal->reg, "gp", core->anal->gp);
	}
	ds->esil_regstate = r_reg_arena_peek (core->anal->reg);
}

static void ds_print_esil_anal_fini(RDisasmState *ds) {
	if (ds->show_emu && ds->esil_regstate) {
		RCore* core = ds->core;
		const char *pc = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
		r_reg_arena_poke (core->anal->reg, ds->esil_regstate);
		r_reg_setv (core->anal->reg, pc, ds->esil_old_pc);
		R_FREE (ds->esil_regstate);
	}
}

static void ds_print_bbline(RDisasmState *ds) {
	RAnalBlock *bb;

	if (!ds->show_bbline || !ds->fcn) return;

	bb = r_anal_fcn_bbget (ds->fcn, ds->at);
	if (bb) {
		ds_setup_print_pre (ds, false, false);
		ds_update_ref_lines (ds);
		if (!ds->linesright && ds->show_lines && ds->line) {
			r_cons_printf ("%s%s%s", COLOR (ds, color_flow),
				ds->refline2, COLOR_RESET (ds));
		}
		r_cons_printf("|\n");
	}
}

// modifies anal register state
static void ds_print_esil_anal(RDisasmState *ds) {
	RCore *core = ds->core;
	RAnalEsil *esil = core->anal->esil;
	const char *pc;
	int i, ioc, nargs;
	if (!esil || !ds->show_comments || !ds->show_emu) {
		goto beach;
	}
	{
		const RAnalMetaItem *mi = r_meta_find (core->anal, ds->at, R_META_TYPE_ANY, 0);
		if (mi) { goto beach; }
	}
	ioc = r_config_get_i (core->config, "io.cache");
	r_config_set (core->config, "io.cache", "true");
	ds_align_comment (ds);
	esil = core->anal->esil;
	pc = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
	r_reg_setv (core->anal->reg, pc, ds->at + ds->analop.size);
	//r_reg_setv (core->anal->reg, pc, ds->at);
	esil->cb.hook_reg_write = myregwrite;
	if (ds->show_emu_write) {
		esil->cb.hook_mem_write = mymemwrite0;
	} else {
		esil->cb.hook_mem_write = mymemwrite1;
	}
	ds->esil_likely = 0;
	r_anal_esil_parse (esil, R_STRBUF_SAFEGET (&ds->analop.esil));
	r_anal_esil_stack_free (esil);

	switch (ds->analop.type) {
	case R_ANAL_OP_TYPE_SWI: {
		char *s = cmd_syscall_dostr (core, -1);
		if (s) {
			r_cons_printf ("; %s", s);
			free (s);
		}
		} break;
	case R_ANAL_OP_TYPE_CJMP:
		if (ds->esil_likely) {
			r_cons_printf ("; likely");
		} else {
			r_cons_printf ("; unlikely");
		}
		break;
	case R_ANAL_OP_TYPE_UCALL:
	case R_ANAL_OP_TYPE_CALL:
		{
			RAnalFunction *fcn;
			const char *usefmt = NULL;
			ut64 pcv = ds->analop.jump;
			if (pcv == UT64_MAX) {
				pcv = ds->analop.ptr; // call [reloc-addr] // windows style
				if (pcv == UT64_MAX) {
					pcv = r_reg_getv (core->anal->reg, pc);
				}
			}
			fcn = r_anal_get_fcn_at (core->anal, pcv, 0);
			if (fcn) {
				nargs = fcn->nargs;
				usefmt = r_anal_get_fcnsign (core->anal, fcn->name);
			} else {
				RFlagItem *item = r_flag_get_i (core->flags, pcv);
				if (item) usefmt = r_anal_get_fcnsign (core->anal, item->name);
				if (!usefmt) nargs = DEFAULT_NARGS;
			}
			if (usefmt) {
				const char *sp = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
				ut64 spv = r_reg_getv (core->anal->reg, sp);
				spv += (core->anal->bits == 64)? 8: 4;
				r_cons_newline ();
				r_core_cmdf (core, "pf %s @ 0x%08"PFMT64x, usefmt, spv);
				r_cons_chop ();
			} else {
				//handle_print_pre (core, ds, false);
				//handle_print_lines_left (core, ds);
				r_cons_printf ("; CALL: ");
				for (i = 0; i < nargs; i++) {
					ut64 v = r_debug_arg_get (core->dbg, R_ANAL_CC_TYPE_STDCALL, i);
					r_cons_printf ("%s0x%"PFMT64x, i?", ":"", v);
				}
			}
		}
		break;
	}
	r_config_set_i (core->config, "io.cache", ioc);
beach:
	if (ds->show_spacy) {
		switch (ds->analop.type) {
		case R_ANAL_OP_TYPE_CALL:
		case R_ANAL_OP_TYPE_MJMP:
		case R_ANAL_OP_TYPE_UJMP:
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_RET:
			ds_print_spacy (ds, 1);
			break;
		}
	}
}

static void ds_print_comments_right(RDisasmState *ds) {
	char *desc = NULL;
	RCore *core = ds->core;
	ds_print_relocs (ds);
	if (ds->asm_describe) {
		char *locase = strdup (ds->asmop.buf_asm);
		if (!locase) return;
		char *op = strchr (locase, ' ');
		if (op) *op = 0;
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
			r_cons_strcat (" ; ");
			r_cons_strcat (desc);
		}
		if (ds->show_comment_right && ds->comment) {
			char *comment = r_str_chop (ds->comment);
			if (*comment) {
				if (!desc) {
					ds_align_comment (ds);
				}
				if (ds->show_color) {
					r_cons_strcat (ds->color_comment);
				}
				r_cons_printf (" ; %s", comment);
			}
			// r_cons_strcat_justify (comment, strlen (ds->refline) + 5, ';');
			if (ds->show_color) {
				ds_print_color_reset (ds);
			}
			R_FREE (ds->comment);
		}
	}
	free (desc);
}

#if 0
static void handle_print_refptr_meta_infos(RCore *core, RDisasmState *ds, ut64 word8 ) {
	RAnalMetaItem *mi2 = r_meta_find (core->anal, word8,
		R_META_TYPE_ANY, R_META_WHERE_HERE);
	if (mi2) {
		switch (mi2->type) {
		case R_META_TYPE_STRING:
			{ char *str = r_str_escape (mi2->str);
			r_cons_printf (" (at=0x%08"PFMT64x") (len=%"PFMT64d
				") \"%s\" ", word8, mi2->size, str);
			free (str);
			}
			break;
		case 'd':
			r_cons_printf (" (data)");
			break;
		default:
			r_cons_printf (" (%c) %s", mi2->type, mi2->str);
			break;
		}
	} else {
		mi2 = r_meta_find (core->anal, (ut64)ds->analop.ptr,
			R_META_TYPE_ANY, R_META_WHERE_HERE);
		if (mi2) {
			char *str = r_str_escape (mi2->str);
			r_cons_printf (" \"%s\" @ 0x%08"PFMT64x":%"PFMT64d,
					str, ds->analop.ptr, mi2->size);
			free (str);
		} else r_cons_printf (" ; 0x%08x [0x%"PFMT64x"]",
				word8, ds->analop.ptr);
	}
}
#endif

static void ds_print_as_string(RDisasmState *ds) {
	char *str = r_num_as_string (NULL, ds->analop.ptr);
	if (str) {
		ds_align_comment (ds);
		r_cons_printf (" %s; \"%s\"%s", COLOR (ds, pal_comment),
			str, COLOR_RESET (ds));
	}
	free (str);
}

#if 0
static void handle_print_refptr(RCore *core, RDisasmState *ds) {
	ut64 word8 = 0;
	ut32 word4 = 0;
	int ret;
	ret = handle_read_refptr (core, ds, &word8, &word4);
	if (ret) {
		handle_print_refptr_meta_infos (core, ds, word8);
	} else {
		st64 sref = ds->analop.ptr; // todo. use .refptr?
		if (sref>0) {
			RFlagItem *f = r_flag_get_i (core->flags, ds->analop.ptr);
			if (f) {
				r_cons_printf (" ; %s", f->name);
			} else {
				r_cons_printf (" ; 0x%08"PFMT64x, ds->analop.ptr);
			}
		}
	}
}
#endif

// int l is for lines
R_API int r_core_print_disasm(RPrint *p, RCore *core, ut64 addr, ut8 *buf, int len, int l, int invbreak, int cbytes) {
	int continueoninvbreak = (len == l) && invbreak;
	RAnalFunction *of = NULL;
	RAnalFunction *f = NULL;
	int ret, i, inc, skip_bytes = 0, idx = 0;
	int dorepeat = 1;
	ut8 *nbuf = NULL;
	RDisasmState *ds;

	// TODO: All those ds must be print flags
	ds = ds_init (core);
	ds->cbytes = cbytes;
	ds->print = p;
	ds->l = l;
	ds->buf = buf;
	ds->len = len;
	ds->addr = addr;
	ds->hint = NULL;
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
toro:
	// uhm... is this necesary? imho can be removed
	r_asm_set_pc (core->assembler, ds->addr+idx);
	core->cons->vline = r_config_get_i (core->config, "scr.utf8") ?
		r_vline_u : r_vline_a;

	if (core->print->cur_enabled) {
		// TODO: support in-the-middle-of-instruction too
		r_anal_op_fini (&ds->analop);
		if (r_anal_op (core->anal, &ds->analop, core->offset + core->print->cur,
			buf+core->print->cur, (int)(len - core->print->cur))) {
			// TODO: check for ds->analop.type and ret
			ds->dest = ds->analop.jump;
		}
	} else {
		/* highlight eip */
		const char *pc = core->anal->reg->name[R_REG_NAME_PC];
		RFlagItem *item = r_flag_get (core->flags, pc);
		if (item) ds->dest = item->offset;
	}

	ds_print_esil_anal_init (ds);
	r_cons_break (NULL, NULL);
	inc = 0;
	if (ds->l == 0) {
		len = ds->l = core->blocksize;
	}
	for (i = idx = ret = 0; idx < len && ds->lines < ds->l;
			idx += inc, i++, ds->index += inc, ds->lines++) {
		ds->at = ds->addr + idx;
		if (r_cons_singleton ()->breaked) {
			dorepeat = 0;
			break;
		}
		r_core_seek_archbits (core, ds->at); // slow but safe
		ds->hint = r_core_hint_begin (core, ds->hint, ds->at);
		r_asm_set_pc (core->assembler, ds->at);
		ds_update_ref_lines (ds);
		/* show type links */
		r_core_cmdf (core, "tf 0x%08"PFMT64x, ds->at);

		f = r_anal_get_fcn_in (core->anal, ds->at, R_ANAL_FCN_TYPE_NULL);
		ds->fcn = f;
		if (f && f->folded && r_anal_fcn_is_in_offset (f, ds->at)) {
			int delta = (ds->at <= f->addr)? (ds->at - f->addr + r_anal_fcn_size (f)): 0;
			if (of != f) {
				char cmt[32];
				get_bits_comment(core, f, cmt, sizeof (cmt));
				ds_show_comments_right (ds);
				r_cons_printf ("%s%s%s (fcn) %s%s%s\n",
					COLOR (ds, color_fline), core->cons->vline[RUP_CORNER],
					COLOR (ds, color_fname), f->name, cmt, COLOR_RESET (ds));
				ds_setup_print_pre (ds, true, false);
				ds_print_lines_left (ds);
				ds_print_offset (ds);
				r_cons_printf ("(%d byte folded function)\n", r_anal_fcn_size (f));
				//r_cons_printf ("%s%s%s\n", COLOR (ds, color_fline), core->cons->vline[RDWN_CORNER], COLOR_RESET (ds));
				if (delta<0) delta = -delta;
				ds->addr += delta + idx;
				r_io_read_at (core->io, ds->addr, buf, len);
				inc = 0; //delta;
				idx = 0;
				of = f;
				if (len == l)
					break;
				continue;
			} else {
				ds->lines--;
				ds->addr += 1;
				r_io_read_at (core->io, ds->addr, buf, len);
				inc = 0; //delta;
				idx = 0;
			//	 r_cons_printf ("delta %d fsize %d\n", delta, f->size);
			//	inc = 1;
				continue;
			}
		}
		if (!ds->hint || !ds->hint->bits) {
			if (f) {
				if (f->bits) {
					if (!ds->oldbits) {
						ds->oldbits = r_config_get_i (core->config, "asm.bits");
					}
					if (ds->oldbits != f->bits) {
						r_config_set_i (core->config, "asm.bits", f->bits);
					}
				} else {
					if (ds->oldbits) {
						r_config_set_i (core->config, "asm.bits", ds->oldbits);
						ds->oldbits = 0;
					}
				}
			} else {
				if (ds->oldbits) {
					r_config_set_i (core->config, "asm.bits", ds->oldbits);
					ds->oldbits = 0;
				}
			}
		}
		ds_show_comments_right (ds);
		ret = ds_disassemble (ds, buf+idx, len-idx);
		if (ret == -31337) {
			inc = ds->oplen;
			continue;
		}
		if (ds->retry) {
			ds->retry = 0;
			goto retry;
		}
		ds_atabs_option (ds);
		// TODO: store previous oplen in core->dec
		if (core->inc == 0) {
			core->inc = ds->oplen;
		}
		if (ds->analop.mnemonic || !ds->lastfail) {
			r_anal_op_fini (&ds->analop);
		}
		if (!ds->lastfail) {
			r_anal_op (core->anal, &ds->analop, ds->at, buf+idx, (int)(len-idx));
		}
		if (ret < 1) {
			r_strbuf_init (&ds->analop.esil);
			ds->analop.type = R_ANAL_OP_TYPE_ILL;
		}
		if (ds->hint) {
			if (ds->hint->size) ds->analop.size = ds->hint->size;
			if (ds->hint->ptr) ds->analop.ptr = ds->hint->ptr;
		}
		ds_print_bbline (ds);
		if (ds->at >= addr) {
			r_print_set_rowoff (core->print, ds->lines, ds->at - addr);
		}
		if (ds->midflags) {
			skip_bytes = handleMidFlags (core, ds, true);
			if (skip_bytes && ds->midflags == R_MIDFLAGS_SHOW)
				ds->at += skip_bytes;
		}
		ds_show_flags (ds);
		if (skip_bytes && ds->midflags == R_MIDFLAGS_SHOW)
			ds->at -= skip_bytes;
		ds_instruction_mov_lea (ds, idx);
		ds_control_flow_comments (ds);
		ds_adistrick_comments (ds);
		/* XXX: This is really cpu consuming.. need to be fixed */
		ds_show_functions (ds);
		ds_show_xrefs (ds);
		ds_setup_print_pre (ds, false, false);
		ds_print_lines_left (ds);

		if (ds->show_comments && !ds->show_comment_right) {
			if (ds->show_emu) {
				ds_print_esil_anal (ds);
				r_cons_newline ();
				ds_setup_print_pre (ds, false, false);
				ds_print_lines_left (ds);
			}
		}

		f = r_anal_get_fcn_in (core->anal, ds->addr, 0);
		if (ds_print_labels (ds, f)) {
			ds_show_functions (ds);
			ds_show_xrefs (ds);
			ds_setup_print_pre (ds, false, false);
			ds_print_lines_left (ds);
		}
		ds_print_offset (ds);
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
			ds_build_op_str (ds);
			ds_print_opstr (ds);

			ds_print_fcn_name (ds);
			ds_print_color_reset (ds);
			ds_print_dwarf (ds);
			ret = ds_print_middle (ds, ret);

			ds_print_asmop_payload (ds);
			if (core->assembler->syntax != R_ASM_SYNTAX_INTEL) {
				RAsmOp ao; /* disassemble for the vm .. */
				int os = core->assembler->syntax;
				r_asm_set_syntax (core->assembler, R_ASM_SYNTAX_INTEL);
				r_asm_disassemble (core->assembler, &ao, buf+idx, len-idx+5);
				r_asm_set_syntax (core->assembler, os);
			}
			ds_print_core_vmode (ds);
			ds_print_cc_update (ds);
		} else {
			ds->mi_found = 0;
		}
		ds_print_op_push_info (ds);
		ds_print_ptr (ds, len + 256, idx);
		ds_print_comments_right (ds);
		if (!(ds->show_comments && ds->show_comment_right && ds->comment)) {
			ds_print_esil_anal (ds);
			r_cons_newline ();
		}
		if (ds->line) {
			if (ds->show_lines_ret && ds->analop.type == R_ANAL_OP_TYPE_RET) {
				if (strchr (ds->line, '>')) {
					memset (ds->line, ' ', r_str_len_utf8 (ds->line));
				}
				r_cons_printf ("%s%s%s%s; --------------------------------------\n",
					ds->pre, COLOR (ds, color_flow), ds->line, COLOR_RESET (ds));
			}
			R_FREE (ds->line);
			R_FREE (ds->refline);
			R_FREE (ds->refline2);
		}
		R_FREE (ds->opstr);
		inc = ds->oplen;
		if (ds->midflags == R_MIDFLAGS_REALIGN && skip_bytes)
			inc = skip_bytes;
		if (inc < 1)
			inc = 1;
	}
	if (nbuf == buf) {
		free (buf);
		buf = NULL;
	}
	r_cons_break_end ();

#if HASRETRY
	if (!ds->cbytes && ds->lines<ds->l && dorepeat) {
	retry:
		if (len<4) len = 4;
		buf = nbuf = malloc (len);
		if (ds->tries>0) {
			if (r_core_read_at (core, ds->addr, buf, len) ) {
				goto toro;
			}
		}
		if (ds->lines<ds->l) {
			//ds->addr += idx;
			if (r_core_read_at (core, ds->addr, buf, len) != len) {
				//ds->tries = -1;
			}
			goto toro;
		}
		if (continueoninvbreak) {
			goto toro;
		}
	}
#endif
	if (ds->oldbits) {
		r_config_set_i (core->config, "asm.bits", ds->oldbits);
		ds->oldbits = 0;
	}
	r_print_set_rowoff (core->print, ds->lines, ds->at - addr);
	r_print_set_rowoff (core->print, ds->lines + 1, UT32_MAX);
	// TODO: this too (must review)
	ds_print_esil_anal_fini (ds);
	ds_reflines_fini (ds);
	ds_free (ds);
	{ /* used by asm.emu */
		r_reg_arena_pop (core->anal->reg);
	}
	return idx; //-ds->lastfail;
}

/* Disassemble either `nb_opcodes` instructions, or
 * `nb_bytes` bytes; both can be negative.
 * Set to 0 the parameter you don't use */
R_API int r_core_print_disasm_instructions (RCore *core, int nb_bytes, int nb_opcodes) {
	RDisasmState *ds = NULL;
	int i, j, ret, len = 0;
	RAnalFunction *f;
	char *tmpopstr;
	const ut64 old_offset = core->offset;
	bool hasanal = false;

	r_reg_arena_push (core->anal->reg);
	if (!nb_bytes) {
		nb_bytes = core->blocksize;
		if (nb_opcodes < 0) {
			/* Backward disassembly or nb_opcodes opcodes
			 * - We compute the new starting offset
			 * - Read at the new offset */
			nb_opcodes = -nb_opcodes;
			r_core_asm_bwdis_len (core, &nb_bytes, &core->offset, nb_opcodes);
			r_core_read_at (core, core->offset, core->block, nb_bytes);
		}
	} else {
		if (nb_bytes < 0) { // Disassemble backward `nb_bytes` bytes
			nb_bytes = -nb_bytes;
			core->offset -= nb_bytes;
			r_core_read_at (core, core->offset, core->block, nb_bytes);
		}
	}

	// XXX - is there a better way to reset a the analysis counter so that
	// when code is disassembled, it can actually find the correct offsets
	if (core->anal->cur && core->anal->cur->reset_counter)
		core->anal->cur->reset_counter (core->anal, core->offset);

	ds = ds_init (core);
	ds->l = nb_opcodes;
	ds->len = nb_opcodes * 8;

	if (ds->len > core->blocksize) {
		if (core->fixedblock) {
			nb_bytes = ds->len = core->blocksize;
		} else {
			r_core_block_size (core, ds->len);
			r_core_block_read (core, 0);
		}
	}

	if (ds->l == 0)
		ds->l = ds->len;

	r_cons_break (NULL, NULL);
#define isTheEnd (nb_opcodes? j<nb_opcodes: i<nb_bytes)
	for (i = j = 0; isTheEnd; i += ret, j++) {
		ds->at = core->offset +i;
		hasanal = false;
		r_core_seek_archbits (core, ds->at);
		if (r_cons_singleton ()->breaked)
			break;
		if (ds->hint) {
			r_anal_hint_free (ds->hint);
			ds->hint = NULL;
		}
		ds->hint = r_core_hint_begin (core, ds->hint, ds->at);
		r_asm_set_pc (core->assembler, ds->at);
		// XXX copypasta from main disassembler function
		f = r_anal_get_fcn_in (core->anal, ds->at, R_ANAL_FCN_TYPE_NULL);
		if (!ds->hint || !ds->hint->bits) {
			if (f) {
				if (f->bits) {
					if (!ds->oldbits)
						ds->oldbits = r_config_get_i (core->config, "asm.bits");
					if (ds->oldbits != f->bits) {
						r_config_set_i (core->config, "asm.bits", f->bits);
					}
				} else {
					if (ds->oldbits != 0) {
						r_config_set_i (core->config, "asm.bits", ds->oldbits);
						ds->oldbits = 0;
					}
				}
			} else {
				if (ds->oldbits) {
					r_config_set_i (core->config, "asm.bits", ds->oldbits);
					ds->oldbits = 0;
				}
			}
		}
		ret = r_asm_disassemble (core->assembler,
			&ds->asmop, core->block+i, core->blocksize-i);
		r_anal_op_fini (&ds->analop);
		if (ds->show_color && !hasanal) {
			r_anal_op (core->anal, &ds->analop, ds->at,
				core->block + i, core->blocksize - i);
			hasanal = true;
		}
		//r_cons_printf ("0x%08"PFMT64x"  ", core->offset+i);
		if (ds->hint && ds->hint->size) {
			ret = ds->hint->size;
			ds->oplen = ret;
			ds->analop.size = ret;
			ds->asmop.size = ret;
		}
		len += R_MAX (0, ret);
		if (ds->hint && ds->hint->opcode) {
			free (ds->opstr);
			ds->opstr = strdup (ds->hint->opcode);
		} else {
			if (ds->use_esil) {
				if (!hasanal) {
					r_anal_op (core->anal, &ds->analop,
						ds->at, core->block+i,
						core->blocksize-i);
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
				r_parse_filter (core->parser, core->flags,
						ds->asmop.buf_asm, ds->str, sizeof (ds->str), core->print->big_endian);
				ds->opstr = strdup (ds->str);
				asm_str = colorize_asm_string (core, ds);
				core->parser->flagspace = ofs;
				free (ds->opstr);
				ds->opstr = asm_str;
				core->parser->flagspace = ofs; // ???
			} else {
				ds->opstr = strdup (ds->asmop.buf_asm);
			}
			if (ds->decode) {
				free (ds->opstr);
				if (!hasanal) {
					r_anal_op (core->anal, &ds->analop, ds->at, core->block+i, core->blocksize-i);
					hasanal = true;
				}
				tmpopstr = r_anal_op_to_string (core->anal, &ds->analop);
				ds->opstr = (tmpopstr)? tmpopstr: strdup (ds->asmop.buf_asm);
			}
		}
		{
			const char *opcolor = NULL;
			if (ds->show_color) {
				opcolor = r_print_color_op_type (core->print, ds->analop.type);
				r_cons_printf ("%s%s" Color_RESET "\n", opcolor, ds->opstr);
			} else {
				r_cons_printf ("%s\n", ds->opstr);
			}
			R_FREE (ds->opstr);
		}
		if (ds->hint) {
			r_anal_hint_free (ds->hint);
			ds->hint = NULL;
		}
	}
	r_cons_break_end ();
	if (ds->oldbits) {
		r_config_set_i (core->config, "asm.bits", ds->oldbits);
		ds->oldbits = 0;
	}
	ds_free (ds);
	core->offset = old_offset;
	r_reg_arena_pop (core->anal->reg);

	return len;
}

R_API int r_core_print_disasm_json(RCore *core, ut64 addr, ut8 *buf, int nb_bytes, int nb_opcodes) {
	RAsmOp asmop;
	RAnalOp analop;
	RDisasmState *ds;
	RAnalFunction *f;
	int i, j, k, oplen, ret, line;
	ut64 old_offset = core->offset;
	ut64 at;
	int dis_opcodes = 0;
	r_cons_printf ("[");
	int limit_by = 'b';

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
			if (!r_core_asm_bwdis_len (core, &nbytes, &addr, nb_opcodes)) {
				/* workaround to avoid empty arrays */
#define BWRETRY 0
#if BWRETRY
				nb_opcodes+=1;
				if (!r_core_asm_bwdis_len (core, &nbytes, &addr, nb_opcodes)) {
#endif
					r_cons_printf ("]");
					return false;
#if BWRETRY
				}
#endif
				nb_opcodes-=1;
			}
			count = R_MIN (nb_bytes, nbytes);
			if (count>0) {
				r_core_read_at (core, addr, buf, count);
				r_core_read_at (core, addr+count, buf+count, nb_bytes-count);
			} else {
				if (nb_bytes>0)
					memset (buf, 0xff, nb_bytes);
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
	for (;;) {
		bool end_nbopcodes, end_nbbytes;

		at = addr + k;
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
		r_anal_op (core->anal, &analop, at, buf + i, nb_bytes - i);
		ds = ds_init (core);
		if (ds->pseudo) r_parse_parse (core->parser, asmop.buf_asm, asmop.buf_asm);
		f = r_anal_get_fcn_in (core->anal, at, R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
		if (ds->varsub && f) {
			core->parser->varlist = r_anal_var_list;
			r_parse_varsub (core->parser, f, at, ds->analop.size,
				asmop.buf_asm, asmop.buf_asm, sizeof (asmop.buf_asm));
		}
		oplen = r_asm_op_get_size (&asmop);
		r_cons_printf (j>0? ",{": "{");
		r_cons_printf ("\"offset\":%"PFMT64d, at);
		if (f) {
			r_cons_printf (",\"fcn_addr\":%"PFMT64d, f->addr);
			r_cons_printf (",\"fcn_last\":%"PFMT64d, f->addr + r_anal_fcn_size (f) - oplen);
		} else {
			r_cons_printf (",\"fcn_addr\":0");
			r_cons_printf (",\"fcn_last\":0");
		}
		r_cons_printf (",\"size\":%d", oplen);
		{
			char *escaped_str = r_str_escape (asmop.buf_asm);
			r_cons_printf (",\"opcode\":\"%s\"", escaped_str);
			free (escaped_str);
		}
		if (ds->use_esil) {
			const char * esil = R_STRBUF_SAFEGET (&analop.esil);
			r_cons_printf (",\"esil\":\"%s\"", esil);
		}
		r_cons_printf (",\"bytes\":\"%s\"", asmop.buf_hex);
		r_cons_printf (",\"family\":\"%s\"",
				r_anal_op_family_to_string (analop.family));
		r_cons_printf (",\"type\":\"%s\"", r_anal_optype_to_string (analop.type));
		// wanted the numerical values of the type information
		r_cons_printf (",\"type_num\":%"PFMT64d, analop.type);
		r_cons_printf (",\"type2_num\":%"PFMT64d, analop.type2);
		// handle switch statements
		if (analop.switch_op && r_list_length (analop.switch_op->cases) > 0) {
			// XXX - the java caseop will still be reported in the assembly,
			// this is an artifact to make ensure the disassembly is properly
			// represented during the analysis
			RListIter *iter;
			RAnalCaseOp *caseop;
			int cnt = r_list_length (analop.switch_op->cases);
			r_cons_printf (", \"switch\":[");
			r_list_foreach (analop.switch_op->cases, iter, caseop ) {
				cnt--;
				r_cons_printf ("{");
				r_cons_printf ("\"addr\":%"PFMT64d, caseop->addr);
				r_cons_printf (", \"value\":%"PFMT64d, (st64) caseop->value);
				r_cons_printf (", \"jump\":%"PFMT64d, caseop->jump);
				r_cons_printf ("}");
				if (cnt > 0) r_cons_printf (",");
			}
			r_cons_printf ("]");
		}
		if (analop.jump != UT64_MAX ) {
			r_cons_printf (",\"jump\":%"PFMT64d, analop.jump);
			if (analop.fail != UT64_MAX) {
				r_cons_printf (",\"fail\":%"PFMT64d, analop.fail);
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
		i += oplen; // bytes
		k += oplen; // delta from addr
		j++; // instructions
		line++;

		end_nbopcodes = dis_opcodes == 1 && nb_opcodes > 0 && line>=nb_opcodes;
		end_nbbytes = dis_opcodes == 0 && nb_bytes > 0 && i>=nb_bytes;
		if (end_nbopcodes || end_nbbytes) break;
	}
	r_cons_printf ("]");
	core->offset = old_offset;
	return true;
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

	if (!fcn)
		return -1;

	cur_buf_sz = r_anal_fcn_size (fcn) + 1;
	buf = malloc (cur_buf_sz);
	if (!buf) return -1;
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

	r_list_foreach (fcn->bbs, bb_iter, bb) {
		r_list_add_sorted (bb_list, bb, cmpaddr);
	}
	// Premptively read the bb data locs for ref lines
	r_list_foreach (bb_list, bb_iter, bb) {
		if (idx >= cur_buf_sz) break;
		r_core_read_at (core, bb->addr, buf+idx, bb->size);
		//ret = r_asm_disassemble (core->assembler, &ds->asmop, buf+idx, bb->size);
		//if (ret > 0) eprintf ("%s\n",ds->asmop.buf_asm);
		idx += bb->size;
	}

	ds_reflines_fcn_init (ds, fcn, buf);
	core->inc = 0;

	core->cons->vline = r_config_get_i (core->config, "scr.utf8")?
			r_vline_u: r_vline_a;
	i = 0;
	idx = 0;
	r_cons_break (NULL, NULL);
	ds_print_esil_anal_init (ds);

	if (core->io && core->io->debug)
		r_debug_map_sync (core->dbg);
	r_list_foreach (bb_list, bb_iter, bb) {
		ut32 bb_size_consumed = 0;
		// internal loop to consume bb that contain case-like operations
		ds->at = bb->addr;
		ds->addr = bb->addr;
		len = bb->size;

		if (len > cur_buf_sz) {
			free (buf);
			cur_buf_sz = len;
			buf = malloc (cur_buf_sz);
			ds->buf = buf;
		}
		do {
			// XXX - why is it necessary to set this everytime?
			r_asm_set_pc (core->assembler, ds->at);
			if (ds->lines >= ds->l) break;
			if (r_cons_singleton ()->breaked) break;

			ds_update_ref_lines (ds);
			/* show type links */
			r_core_cmdf (core, "tf 0x%08"PFMT64x, ds->at);

			ds_show_comments_right (ds);
			ret = ds_disassemble (ds, buf+idx, len - bb_size_consumed);
			ds_atabs_option (ds);
			// TODO: store previous oplen in core->dec
			if (core->inc == 0) {
				core->inc = ds->oplen;
			}

			r_anal_op_fini (&ds->analop);

			if (!ds->lastfail)
				r_anal_op (core->anal, &ds->analop,
					ds->at+bb_size_consumed, buf+idx,
					len-bb_size_consumed);

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
				ds->mi_found = 0;
				continue;
			}
			/* show cursor */
			ds_print_show_cursor (ds);
			ds_print_show_bytes (ds);
			ds_print_lines_right (ds);
			ds_build_op_str (ds);
			ds_print_opstr (ds);
			ds_print_fcn_name (ds);
			ds_print_import_name (ds);
			ds_print_color_reset (ds);
			ds_print_dwarf (ds);
			ret = ds_print_middle (ds, ret);
			ds_print_asmop_payload (ds);
			if (core->assembler->syntax != R_ASM_SYNTAX_INTEL) {
				RAsmOp ao; /* disassemble for the vm .. */
				int os = core->assembler->syntax;
				r_asm_set_syntax (core->assembler,
					R_ASM_SYNTAX_INTEL);
				r_asm_disassemble (core->assembler, &ao,
					buf+idx, len-bb_size_consumed);
				r_asm_set_syntax (core->assembler, os);
			}
			ds_print_core_vmode (ds);
			ds_print_cc_update (ds);
			ds_print_op_push_info (ds);
			/*if (ds->analop.refptr) {
				handle_print_refptr (core, ds);
			} else {
				handle_print_ptr (core, ds, len, idx);
			}*/
			ds_print_ptr (ds, len, idx);
			ds_print_comments_right (ds);
			ds_print_esil_anal (ds);
			if ( !(ds->show_comments && ds->show_comment_right && ds->comment)) {
				r_cons_newline ();
			}
			if (ds->line) {
				R_FREE (ds->line);
				R_FREE (ds->refline);
				R_FREE (ds->refline2);
			}
			ds_print_bbline (ds);

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
	r_cons_break_end ();
	ds_print_esil_anal_fini (ds);

	if (ds->oldbits) {
		r_config_set_i (core->config, "asm.bits", ds->oldbits);
		ds->oldbits = 0;
	}
	ds_free (ds);
	r_list_free (bb_list);
	return idx;
}
