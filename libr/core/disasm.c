/* radare - LGPL - Copyright 2009-2025 - nibble, pancake, dso, lazula */

#define R_LOG_ORIGIN "disasm"

#include <r_core.h>
#include <r_vec.h>

R_VEC_TYPE(RVecAnalRef, RAnalRef);

#define HASRETRY 1
#define HAVE_LOCALS 1
#define DEFAULT_NARGS 4
#define FLAG_PREFIX ";-- "

#define COLOR(ds, field)       ((ds)->show_color? (ds)->field: "")
#define COLOR_ARG(ds, field)   ((ds)->show_color && (ds)->show_color_args? (ds)->field: "")
#define COLOR_CONST(ds, color) ((ds)->show_color? Color_##color: "")
#define COLOR_RESET(ds)        COLOR_CONST (ds, RESET)

#define ds_offset(ds) ((ds)->index * (ds)->addrbytes)
#define ds_bufat(ds)  ((ds)->buf + ds_offset (ds))
#define ds_left(ds)   ((ds)->len - ds_offset (ds))

// global cache
static R_TH_LOCAL ut64 Goaddr = UT64_MAX;
static R_TH_LOCAL char *Gsection = NULL; // maybe as a fixed array size is less racy, but still incorrect as its not guarded and its global

static bool isarm(RCore *core) {
	return r_str_startswith (r_config_get (core->config, "asm.arch"), "arm");
}

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
	"╎", // LINE_UP
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
	// "↑", // LINE_UP
	"╎", // LINE_UP
	// "≀", // LINE_UP
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
// imho this should be moved to RAsm
typedef struct r_disasm_state_t {
	RCore *core;
	// char str[1024];
	bool immtrim;
	bool immstr;
	bool use_esil;
	bool show_color;
	bool show_color_bytes;
	bool show_color_args;
	bool colorop;
	int acase;
	bool capitalize;
	bool show_flgoff;
	bool hasMidflag;
	bool hasMidbb;
	int atabs;
	bool atabsonce;
	int atabsoff;
	int decode;
	bool pseudo;
	bool sparse;
	bool subnames;
	bool interactive;
	bool subjmp;
	bool subvar;
	bool show_lines;
	bool show_lines_jmp;
	bool show_lines_split;
	bool show_lines_ret;
	bool show_lines_call;
	bool show_lines_fcn;
	bool linesright;
	int tracespace;
	int cyclespace;
	int cmtfold;
	int show_indent;
	bool show_dwarf;
	bool show_size;
	bool show_trace;
	bool show_trace_stats;
	bool show_trace_color;
	bool show_family;
	bool asm_describe;
	int linesout;
	int adistrick;
	bool asm_meta;
	bool flags_prefix;
	bool asm_xrefs_code;
	int asm_demangle;
	bool asm_instr;
	bool show_offset;
	bool show_offset_focus;
	bool show_offdec; // dupe for r_print->flags
	bool show_bbline;
	bool show_emu;
	bool pre_emu;
	bool show_emu_bb;
	bool show_anos;
	bool show_emu_str;
	bool show_emu_stroff;
	bool show_emu_strinv;
	bool show_emu_strflag;
	bool show_emu_strlea;
	bool show_emu_stack;
	bool show_emu_write;
	bool show_optype;
	bool show_emu_ssa;
	bool show_section;
	int show_section_col;
	bool show_section_perm;
	bool show_section_name;
	bool show_symbols;
	int show_symbols_col;
	int default_immbase;
	bool show_offseg;
	bool show_flags;
	bool flags_inline;
	RSpace *flagspace_ports;
	bool asm_flags_right;
	int midflags;
	bool bblined;
	bool show_bytes;
	bool show_bytes_align;
	bool show_bytes_ascii;
	bool show_bytes_asbits;
	bool show_bytes_ascmt;
	bool show_bytes_right;
	bool show_bytes_opcolor;
	bool show_reloff;
	ut32 show_reloff_to;
	bool show_comments;
	bool show_cmt_user;
	bool asm_hints;
	bool asm_hint_jmp;
	bool asm_hint_cdiv;
	bool asm_hint_call;
	bool asm_hint_call_indirect;
	bool asm_hint_lea;
	bool asm_hint_imm;
	bool asm_hint_emu;
	int  asm_hint_pos;
	ut64 emuptr;
	bool show_slow;
	Sdb *ssa;
	int cmtcol;
	bool show_calls;
	bool show_cmt_flgrefs;
	bool show_cmt_esil;
	bool show_cmt_pseudo;
	bool show_cycles;
	bool show_refptr;
	bool show_stackptr;
	int stackFd;
	bool show_xrefs;
	bool show_cmtrefs;
	const char *show_cmtoff;
	bool show_functions;
	bool show_marks;
	bool show_asciidot;
	RStrEnc strenc;
	int cursor;
	int show_cmt_right_default;
	bool show_flag_in_bytes;
	bool show_flag_in_offset;
	int lbytes;
	int show_cmt_right;
	int pre;
	const char *ocomment; // weak pointer
	bool cmt_wrap;
	int linesopts;
	int lastfail;
	int ocols;
	int lcols;
	int nb, nbytes;
	int show_utf8;
	int lines;
	int oplen;
	int vliw_count;
	bool show_varaccess;
	bool show_vars;
	bool show_fcnsig;
	bool hinted_line;
	int show_varsum;
	bool midbb;
	bool midcursor;
	bool show_noisy_comments;
	ut64 asm_highlight;
	const char *pal_hint;
	const char *pal_comment; // dupe with color_comment??
	const char *color_comment;
	const char *color_usrcmt;
	const char *color_fname;
	const char *color_floc;
	const char *color_fline;
	const char *color_flow;
	const char *color_flow2;
	const char *color_flag;
	const char *color_label;
	const char *color_offset;
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
	const char *color_gui_background2;
	const char *color_gui_border;
	const char *color_linehl;
	const char *color_var;
	const char *color_var_name;
	const char *color_var_type;
	const char *color_var_addr;
	const char *cmtoken; // ";"

	RFlagItem *lastflag;
	RAnalHint *hint;
	RPrint *print;

	ut64 esil_old_pc;
	ut8* esil_regstate;
	int esil_regstate_size;
	bool esil_likely;
	bool offset_focus;

	int count;
	int middle;
	int indent_level;
	int indent_space;
	char *lineup;
	char *lineup_col;
	char *line;
	char *line_col, *prev_line_col;
	char *refline;
	char *refline2;
	char *comment;
	char *opstr;
	char *osl, *sl;
	int stackptr, ostackptr;
	int index, addrbytes;
	ut64 at, vat, addr, dest;
	int tries;
	bool count_bytes;
	char chref;
	RAnalOp asmop;
	RAnalOp analop;
	RAnalFunction *fcn;
	RAnalFunction *pdf;
	const ut8 *buf;
	int len;
	int maxrefs;
	int foldxrefs;
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
	bool asm_anal;
	ut64 printed_str_addr;
	ut64 printed_flag_addr;
	ut64 min_ref_addr;

	PJ *pj; // not null if printing json
	int buf_line_begin;
	const char *strip;
	int maxflags;
	int asm_types;
	RFlagItem sfi;
	char *hint_syntax;
	// ugly ones but at least not globals
	ut64 emustack_min;
	ut64 emustack_max;
	int skiplines; // for smooth scrolling in visual disasm
} RDisasmState;

static void ds_setup_print_pre(RDisasmState *ds, bool tail, bool middle);
static void ds_setup_pre(RDisasmState *ds, bool tail, bool middle);
static void ds_print_pre(RDisasmState *ds, bool fcnline);
static void ds_pre_line(RDisasmState *ds);
static void ds_begin_line(RDisasmState *ds);
static void ds_newline(RDisasmState *ds);
static void ds_begin_cont(RDisasmState *ds);
static void ds_print_esil_anal(RDisasmState *ds);
static void ds_reflines_init(RDisasmState *ds);
static void ds_align_comment(RDisasmState *ds);
static RDisasmState * ds_init(RCore *core);
static void ds_build_op_str(RDisasmState *ds, bool print_color);
static void ds_print_bytes(RDisasmState *ds);
static char *ds_getstring(RDisasmState *ds, const char *str, int len, const char **prefix);
static void ds_pre_xrefs(RDisasmState *ds, bool no_fcnlines);
static void ds_show_xrefs(RDisasmState *ds);
static void ds_show_anos(RDisasmState *ds);
static void ds_atabs_option(RDisasmState *ds);
static void ds_show_functions(RDisasmState *ds);
static void ds_control_flow_comments(RDisasmState *ds);
static void ds_adistrick_comments(RDisasmState *ds);

// TODO: if those two functions do the same should be unified
static void ds_print_comments_right(RDisasmState *ds);
static void ds_show_comments_right(RDisasmState *ds);

static bool ds_show_flags(RDisasmState *ds, bool overlapped);
static void ds_update_ref_lines(RDisasmState *ds);
static int ds_disassemble(RDisasmState *ds, ut8 *buf, int len);
static void ds_print_lines_right(RDisasmState *ds);
static void ds_print_lines_split (RDisasmState *ds);
static void ds_print_lines_left(RDisasmState *ds);
static void ds_print_cycles(RDisasmState *ds);
static void ds_print_family(RDisasmState *ds);
static void ds_print_stackptr(RDisasmState *ds);
static void ds_print_offset(RDisasmState *ds);
static void ds_print_op_size(RDisasmState *ds);
static void ds_print_trace(RDisasmState *ds);
static void ds_print_opstr(RDisasmState *ds);
static void ds_print_color_reset(RDisasmState *ds);
static int ds_print_middle(RDisasmState *ds, int ret);
static bool ds_print_labels(RDisasmState *ds, RAnalFunction *f);
static void ds_print_sysregs(RDisasmState *ds);
static void ds_print_fcn_name(RDisasmState *ds);
static void ds_print_as_string(RDisasmState *ds);
static bool ds_print_core_vmode(RDisasmState *ds, int pos);
static void ds_print_dwarf(RDisasmState *ds);
static void ds_print_asmop_payload(RDisasmState *ds, const ut8 *buf);
static char *ds_esc_str(RDisasmState *ds, const char *str, int len, const char **prefix_out, bool is_comment);
static void ds_print_ptr(RDisasmState *ds, int len, int idx);
static void ds_print_demangled(RDisasmState *ds);
static void ds_print_str(RDisasmState *ds, const char *str, int len, ut64 refaddr);
static char *ds_sub_jumps(RDisasmState *ds, const char *str);
static void ds_start_line_highlight(RDisasmState *ds);
static void ds_end_line_highlight(RDisasmState *ds);
static bool line_highlighted(RDisasmState *ds);
static int ds_print_shortcut(RDisasmState *ds, ut64 addr, int pos);

R_API ut64 r_core_pava(RCore *core, ut64 addr) {
	if (core->print->pava) {
		RIOMap *map = r_io_map_get_paddr (core->io, addr);
		if (map) {
			const ut64 base = r_io_map_begin (map);
			return base + (addr - map->delta);
		}
	}
	return addr;
}

static RAnalFunction *fcnIn(RDisasmState *ds, ut64 at, int type) {
	if (ds->fcn && r_anal_function_contains (ds->fcn, at)) {
		return ds->fcn;
	}
	return r_anal_get_fcn_in (ds->core->anal, at, type);
}

typedef const char *(*fn_utf8char)(const char line, RDisasmState *ds);

static const char *get_utf8_char(const char line, RDisasmState *ds) {
	switch (line) {
	case '<': return ds->core->cons->vline[ARROW_LEFT];
	case '>': return ds->core->cons->vline[ARROW_RIGHT];
	case ':': return ds->core->cons->vline[LINE_UP];
	case '|': return ds->core->cons->vline[LINE_VERT];
	case '!': return "!";
	case '=':
	case '-': return ds->core->cons->vline[LINE_HORIZ];
	case ',': return ds->core->cons->vline[CORNER_TL];
	case '.': return ds->core->cons->vline[CORNER_TR];
	case '`': return ds->core->cons->vline[CORNER_BL];
	default: return " ";
	}
}

static const char *get_utf8_char_split(const char line, RDisasmState *ds) {
	switch (line) {
	case '<': return ds->core->cons->vline[ARROW_RIGHT]; //LEFT];
	case '>': return ds->core->cons->vline[ARROW_LEFT];
	case ':': return ds->core->cons->vline[LINE_UP];
	case '|': return ds->core->cons->vline[LINE_VERT];
	case '!': return "!";
	case '=':
	case '-': return ds->core->cons->vline[LINE_HORIZ];
	case ',': return ds->core->cons->vline[CORNER_TL];
	case '.': return RUNE_CORNER_TR; // ds->core->cons->vline[CORNER_TR]; // XXX
	case '`': return ds->core->cons->vline[CORNER_BR];
	default: return " ";
	}
}

static void ds_print_ref_lines(RDisasmState *ds, char *line, char *line_col, bool split) {
	RCons *cons = ds->core->cons;
	fn_utf8char utf8char = split? get_utf8_char_split: get_utf8_char;
	int i;
	int len = strlen (line);
	if (cons->use_utf8 || ds->linesopts & R_ANAL_REFLINE_TYPE_UTF8) {
		if (ds->show_color) {
			for (i = 0; i < len; i++) {
				if (line[i] == ' ') {
					r_cons_printf (cons, " ");
					continue;
				}
				const char *flow_tint = (line_col[i] == 'd')? COLOR (ds, color_flow): COLOR (ds, color_flow2);
				r_cons_printf (cons, "%s%s%s", flow_tint, utf8char (line[i], ds), COLOR_RESET (ds));
			}
		} else {
			len = strlen (line);
			for (i = 0; i < len; i++) {
				r_cons_printf (cons, "%s", utf8char (line[i], ds));
			}
		}
	} else {
		if (ds->show_color) {
			for (i = 0; i < len; i++) {
				if (line[i] == ' ') {
					r_cons_printf (cons, " ");
					continue;
				}
				const char *flow_tint = (line_col[i] == 'd')? COLOR (ds, color_flow): COLOR (ds, color_flow2);
				r_cons_printf (cons, "%s%c%s", flow_tint, line[i], COLOR_RESET (ds));
			}
		} else {
			r_cons_printf (cons, "%s", line);
		}
	}
}

static void get_bits_comment(RCore *core, RAnalFunction *f, char *cmt, int cmt_size) {
	if (core && f && cmt && cmt_size > 0 && f->bits && f->bits != core->rasm->config->bits) {
		if (isarm (core)) {
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
			*cmt = 0;
		}
	}
}

R_API const char *r_core_get_section_name(RCore *core, ut64 addr) {
	if (addr == UT64_MAX) {
		return NULL;
	}
	if (Gsection && Goaddr == addr) {
		return Gsection;
	}
	if (r_config_get_b (core->config, "cfg.debug")) {
		char *rv = r_core_cmd_str_at (core, addr, "dmi.");
		if (rv) {
			r_str_replace_char (rv, '\n', ' ');
			free (Gsection);
			Gsection = r_str_trim_dup (rv);
			return Gsection;
		}
		return NULL;
	}
	RBinObject *bo = r_bin_cur_object (core->bin);
	RBinSection *s = bo? r_bin_get_section_at (bo, addr, core->io->va): NULL;
	if (s && R_STR_ISNOTEMPTY (s->name)) {
		free (Gsection);
		Gsection = r_str_newf ("%10s ", s->name);
	} else {
		RListIter *iter;
		RDebugMap *map;
		R_FREE (Gsection);
		r_list_foreach (core->dbg->maps, iter, map) {
			if (addr >= map->addr && addr < map->addr_end) {
				const char *mn = r_str_lchr (map->name, '/');
				Gsection = strdup (mn? mn + 1: map->name);
				break;
			}
		}
	}
	Goaddr = addr;
	return Gsection? Gsection: NULL;
}

static const char *get_section_name(RDisasmState *ds) {
	return r_core_get_section_name (ds->core, ds->at);
}

static void ds_comment_align(RDisasmState *ds) {
	RCons *cons = ds->core->cons;
	if (ds->show_cmt_right) {
		if (ds->show_color) {
			r_cons_print (cons, ds->pal_comment);
		}
	} else {
		const char *ss =get_section_name (ds);
		const char *sn = (ds->show_section && ss)? ss: "";
		ds_align_comment (ds);
		r_cons_print (cons, COLOR_RESET (ds));
		ds_print_pre (ds, true);
		r_cons_print (cons, sn);
		ds_print_ref_lines (ds, ds->refline, ds->line_col, false);
		r_cons_printf (cons, "   %s", COLOR (ds, color_comment));
	}
}

static void ds_comment_lineup(RDisasmState *ds) {
	ds_comment_align (ds);
}

static void ds_comment_(RDisasmState *ds, bool align, bool donl, const char *format, va_list ap) {
	RCons *cons = ds->core->cons;
	char *s = r_str_newvf (format, ap);
	char *p = s;
	bool multiline = strchr (p, '\n');
	bool first = true;
	while (true) {
		char *nl = strchr (p, '\n');
		if (nl) {
			*nl = 0;
		}
		if (ds->show_comments) {
			if (ds->show_cmt_right && align) {
				ds_align_comment (ds);
			}
		}
		r_cons_printf (cons, "%s", COLOR (ds, color_comment));
		if (multiline) {
			if (!first) {
				ds_begin_line (ds);
				// ds_print_labels (ds, f);
				ds_setup_print_pre (ds, false, false);
				ds_print_lines_left (ds);
				// core->print->resetbg = (ds->asm_highlight == UT64_MAX);
				r_cons_printf (cons, "%s ", ds->cmtoken);
			}
		}
		r_cons_print (cons, p);
		if (!nl) {
			break;
		}
		if (!ds->show_cmt_right) {
			r_cons_newline (cons);
		}
		first = false;
		p = nl + 1;
	}
	free (s);
	if (!ds->show_cmt_right && donl) {
		ds_newline (ds);
	}
}

static void ds_comment(RDisasmState *ds, bool align, const char *format, ...) {
	va_list ap;
	va_start (ap, format);
	ds->cmtcount++;
	ds_comment_ (ds, align, align, format, ap);
	va_end (ap);
}

#define DS_COMMENT_FUNC(name, align, nl) \
	static void ds_comment_##name(RDisasmState *ds, const char *format, ...) { \
		va_list ap; \
		va_start (ap, format); \
		ds_comment_ (ds, align, nl, format, ap); \
		va_end (ap); \
	}

DS_COMMENT_FUNC (start, true, false)
DS_COMMENT_FUNC (middle, false, false)
DS_COMMENT_FUNC (end, false, true)

static void ds_comment_esil(RDisasmState *ds, bool up, bool end, const char *format, ...) {
	va_list ap;
	va_start (ap, format);

	RCons *cons = ds->core->cons;
	if (ds->show_comments && up) {
		ds->show_cmt_right ? ds_align_comment (ds) : ds_comment_lineup (ds);
	}
	r_cons_printf_list (cons, format, ap);
	va_end (ap);

	if (end && ds->show_comments && !ds->show_cmt_right) {
		ds_newline (ds);
	}
}

static void ds_print_esil_anal_fini(RDisasmState *ds) {
	RCore *core = ds->core;
	if (ds->show_emu && ds->esil_regstate) {
		RCore* core = ds->core;
		core->anal->last_disasm_reg = r_reg_arena_peek (core->anal->reg, &core->anal->last_disasm_reg_size);
		RRegSet *regset = r_reg_regset_get (ds->core->anal->reg, R_REG_TYPE_GPR);
		if (ds->esil_regstate_size == regset->arena->size) {
			r_reg_arena_poke (core->anal->reg, ds->esil_regstate, ds->esil_regstate_size);
		}
		r_reg_setv (core->anal->reg, "PC", ds->esil_old_pc);
		R_FREE (ds->esil_regstate);
	}
	if (core && core->anal && core->anal->esil) {
		// make sure to remove reference to ds to avoid UAF
		core->anal->esil->user = NULL;
		ds->core->anal->esil->cb.user = NULL;
	}
}

static RDisasmState *ds_init(RCore *core) {
	RDisasmState *ds = R_NEW0 (RDisasmState);
	ds->ssa = sdb_new0 ();
	ds->core = core;
	ds->addrbytes = core->io->addrbytes;
	ds->strip = r_config_get (core->config, "asm.strip");
	ds->cmtoken = r_config_get (core->config, "asm.cmt.token");
	ds->pal_hint = core->cons->context->pal.jmp;
	ds->pal_comment = core->cons->context->pal.comment;
	#define P(x) (core->cons && core->cons->context->pal.x)? core->cons->context->pal.x
	ds->color_comment = P(comment): Color_CYAN;
	ds->color_usrcmt = P(usercomment): Color_CYAN;
	ds->color_fname = P(fname): Color_RED;
	ds->color_floc = P(floc): Color_MAGENTA;
	ds->color_fline = P(fline): Color_CYAN;
	ds->color_flow = P(flow): Color_CYAN;
	ds->color_flow2 = P(flow2): Color_BLUE;
	ds->color_flag = P(flag): Color_CYAN;
	ds->color_label = P(label): Color_CYAN;
	ds->color_offset = P(addr): Color_GREEN;
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
	ds->color_gui_background2 = P(gui_background2): Color_GRAY;
	ds->color_gui_border = P(gui_border): Color_BGGRAY;
	ds->color_linehl = P(linehl): Color_BGBLUE;
	ds->color_var = P(var): Color_WHITE;
	ds->color_var_type = P(var_type): Color_BLUE;
	ds->color_var_addr = P(var_addr): Color_CYAN;
	ds->color_var_name = P(var_name): Color_RED;

	ds->immstr = r_config_get_i (core->config, "asm.imm.str");
	ds->immtrim = r_config_get_i (core->config, "asm.imm.trim");
	ds->use_esil = r_config_get_i (core->config, "asm.esil");
	ds->pre_emu = r_config_get_i (core->config, "emu.pre");
	ds->show_flgoff = r_config_get_i (core->config, "asm.flags.offset");
	ds->show_nodup = r_config_get_i (core->config, "asm.nodup");
	const char *ah = r_config_get (core->config, "asm.highlight");
	ds->asm_highlight = R_STR_ISNOTEMPTY (ah)? r_num_math (core->num, ah): UT64_MAX;
	ds->asm_anal = r_config_get_i (core->config, "asm.anal");
	ds->show_color = r_config_get_i (core->config, "scr.color");
	ds->show_color_bytes = r_config_get_i (core->config, "scr.color.bytes");
	ds->show_color_args = r_config_get_i (core->config, "scr.color.args");
	ds->colorop = r_config_get_b (core->config, "scr.color.ops");
	ds->show_utf8 = r_config_get_i (core->config, "scr.utf8");
	ds->acase = r_config_get_b (core->config, "asm.ucase");
	ds->capitalize = r_config_get_b (core->config, "asm.capitalize");
	ds->atabs = r_config_get_i (core->config, "asm.tabs");
	ds->atabsonce = r_config_get_b (core->config, "asm.tabs.once");
	ds->atabsoff = r_config_get_i (core->config, "asm.tabs.off");
	ds->midflags = r_config_get_i (core->config, "asm.flags.middle");
	ds->asm_flags_right = r_config_get_i (core->config, "asm.flags.right");
	ds->midbb = r_config_get_i (core->config, "asm.bbmiddle");
	ds->midcursor = r_config_get_i (core->config, "asm.midcursor");
	ds->decode = r_config_get_i (core->config, "asm.decode");
	core->rasm->parse->pseudo = ds->pseudo = r_config_get_b (core->config, "asm.pseudo");
	if (ds->pseudo) {
		ds->atabs = 0;
	}
	ds->subnames = r_config_get_b (core->config, "asm.sub.names");
	ds->interactive = r_cons_is_interactive (ds->core->cons);
	ds->subjmp = r_config_get_b (core->config, "asm.sub.jmp");
	ds->subvar = r_config_get_b (core->config, "asm.sub.var");
	core->rasm->parse->subrel = r_config_get_b (core->config, "asm.sub.rel");
	core->rasm->parse->subreg = r_config_get_b (core->config, "asm.sub.reg");
	core->rasm->parse->localvar_only = r_config_get_b (core->config, "asm.sub.varonly");
	core->rasm->parse->retleave_asm = NULL;
	ds->show_fcnsig = r_config_get_b (core->config, "asm.fcnsig");
	ds->show_vars = r_config_get_b (core->config, "asm.var");
	ds->cmt_wrap = r_config_get_b (core->config, "asm.cmt.wrap");
	ds->show_varsum = r_config_get_i (core->config, "asm.var.summary");
	ds->show_varaccess = r_config_get_i (core->config, "asm.var.access");
	ds->maxrefs = r_config_get_i (core->config, "asm.xrefs.max");
	ds->maxflags = r_config_get_i (core->config, "asm.flags.limit");
	ds->flags_inline = r_config_get_i (core->config, "asm.flags.inline");
	ds->asm_types = r_config_get_i (core->config, "asm.types");
	ds->foldxrefs = r_config_get_i (core->config, "asm.xrefs.fold");
	ds->show_lines = r_config_get_b (core->config, "asm.lines");
	ds->show_lines_jmp = ds->show_lines ? r_config_get_b (core->config, "asm.lines.jmp") : false;
	ds->show_lines_split = r_config_get_b (core->config, "asm.lines.split");
	ds->linesright = r_config_get_i (core->config, "asm.lines.right");
	ds->show_indent = r_config_get_i (core->config, "asm.indent");
	ds->indent_space = r_config_get_i (core->config, "asm.indentspace");
	ds->tracespace = r_config_get_i (core->config, "asm.trace.space");
	ds->cyclespace = r_config_get_i (core->config, "asm.cyclespace");
	ds->show_dwarf = r_config_get_i (core->config, "asm.dwarf");
	ds->dwarfFile = r_config_get_i (ds->core->config, "asm.dwarf.file");
	ds->dwarfAbspath = r_config_get_i (ds->core->config, "asm.dwarf.abspath");
	ds->show_lines_call = ds->show_lines ? r_config_get_i (core->config, "asm.lines.call") : false;
	ds->show_lines_ret = ds->show_lines ? r_config_get_i (core->config, "asm.lines.ret") : false;
	ds->show_size = r_config_get_i (core->config, "asm.size");
	ds->show_trace = r_config_get_b (core->config, "asm.trace");
	ds->show_trace_stats = r_config_get_b (core->config, "asm.trace.stats");
	ds->show_trace_color = r_config_get_b (core->config, "asm.trace.color");
	ds->linesout = r_config_get_i (core->config, "asm.lines.out");
	ds->adistrick = r_config_get_i (core->config, "asm.middle"); // TODO: find better name
	ds->asm_demangle = r_config_get_b (core->config, "asm.demangle");
	ds->asm_describe = r_config_get_b (core->config, "asm.describe");
	ds->show_offset = r_config_get_b (core->config, "asm.addr");
	ds->show_offset_focus = r_config_get_b (core->config, "asm.addr.focus");
	ds->show_offdec = r_config_get_i (core->config, "asm.addr.base10");
	ds->show_bbline = r_config_get_i (core->config, "asm.lines.bb");
	ds->show_section = r_config_get_i (core->config, "asm.section");
	ds->show_section_col = r_config_get_i (core->config, "asm.section.col");
	ds->show_section_perm = r_config_get_i (core->config, "asm.section.perm");
	ds->show_section_name = r_config_get_i (core->config, "asm.section.name");
	ds->show_symbols = r_config_get_i (core->config, "asm.symbol");
	ds->show_symbols_col = r_config_get_i (core->config, "asm.symbol.col");
	ds->asm_instr = r_config_get_i (core->config, "asm.instr");
	ds->show_emu = r_config_get_b (core->config, "asm.emu");
	ds->show_emu_bb = r_config_get_b (core->config, "emu.bb");
	ds->show_emu_str = r_config_get_b (core->config, "emu.str");
	ds->show_emu_stroff = r_config_get_b (core->config, "emu.str.off");
	ds->show_emu_strinv = r_config_get_b (core->config, "emu.str.inv");
	ds->show_emu_strflag = r_config_get_b (core->config, "emu.str.flag");
	ds->show_emu_strlea = r_config_get_b (core->config, "emu.str.lea");
	ds->show_emu_write = r_config_get_b (core->config, "emu.write");
	ds->show_emu_ssa = r_config_get_b (core->config, "emu.ssa");
	ds->show_emu_stack = r_config_get_b (core->config, "emu.stack");
	ds->stackFd = -1;
	if (ds->show_emu_stack) {
		// TODO: initialize fake stack in here
		const char *uri = "malloc://32K";
		ut64 size = r_num_get (core->num, "32K");
		ut64 addr = r_reg_getv (core->anal->reg, "SP") - (size / 2);
		ds->emustack_min = addr;
		ds->emustack_max = addr + size;
		ds->stackFd = r_io_fd_open (core->io, uri, R_PERM_RW, 0);
		RIOMap *map = r_io_map_add (core->io, ds->stackFd, R_PERM_RW, 0LL, addr, size);
		if (!map) {
			r_io_fd_close (core->io, ds->stackFd);
			R_LOG_ERROR ("Cannot create map for tha stack, fd %d got closed again", ds->stackFd);
			ds->stackFd = -1;
		} else {
			r_io_map_set_name (map, "fake.stack");
		}
	}
	ds->stackptr = core->anal->stackptr;
	ds->show_offseg = r_config_get_b (core->config, "asm.addr.segment");
	ds->default_immbase = r_config_get_i (core->config, "asm.imm.base");
	ds->show_flags = r_config_get_b (core->config, "asm.flags");
	ds->show_bytes = r_config_get_b (core->config, "asm.bytes");
	ds->show_bytes_ascii = r_config_get_b (core->config, "asm.bytes.ascii");
	ds->show_bytes_asbits = r_config_get_i (core->config, "asm.bytes.asbits");
	ds->show_bytes_align = r_config_get_i (core->config, "asm.bytes.align");
	ds->show_bytes_right = r_config_get_i (core->config, "asm.bytes.right");
	ds->show_bytes_ascmt = r_config_get_i (core->config, "asm.bytes.ascmt");
	ds->show_bytes_opcolor = r_config_get_i (core->config, "asm.bytes.opcolor");
	ds->show_optype = r_config_get_i (core->config, "asm.optype");
	ds->asm_meta = r_config_get_i (core->config, "asm.meta");
	ds->asm_xrefs_code = r_config_get_i (core->config, "asm.xrefs.code");
	{
		const char *relto = r_config_get (core->config, "asm.addr.relto");
		ds->show_reloff_to = 0;
		ds->show_reloff_to |= strstr (relto, "fu")? RELOFF_TO_FUNC: 0;
		ds->show_reloff_to |= strstr (relto, "fl")? RELOFF_TO_FLAG: 0;
		ds->show_reloff_to |= strstr (relto, "ma")? RELOFF_TO_MAPS: 0;
		ds->show_reloff_to |= strstr (relto, "dm")? RELOFF_TO_DMAP: 0;
		ds->show_reloff_to |= strstr (relto, "se")? RELOFF_TO_SECT: 0;
		ds->show_reloff_to |= strstr (relto, "sy")? RELOFF_TO_SYMB: 0;
		ds->show_reloff_to |= strstr (relto, "fi")? RELOFF_TO_FILE: 0;
		ds->show_reloff_to |= strstr (relto, "fm")? RELOFF_TO_FMAP: 0;
		ds->show_reloff_to |= strstr (relto, "li")? RELOFF_TO_LIBS: 0;
	}
	ds->show_reloff = ds->show_reloff_to != 0; // r_config_get_i (core->config, "asm.addr.rel");
	ds->show_lines_fcn = ds->show_lines ? r_config_get_i (core->config, "asm.lines.fcn") : false;
	ds->show_comments = r_config_get_b (core->config, "asm.comments");
	ds->show_cmt_user = r_config_get_b (core->config, "asm.cmt.user");
	ds->asm_hint_jmp = r_config_get_i (core->config, "asm.hint.jmp");
	ds->asm_hint_call = r_config_get_i (core->config, "asm.hint.call");
	ds->asm_hint_call_indirect = r_config_get_i (core->config, "asm.hint.call.indirect");
	ds->asm_hint_lea = r_config_get_i (core->config, "asm.hint.lea");
	ds->asm_hint_imm = r_config_get_i (core->config, "asm.hint.imm");
	ds->asm_hint_emu = r_config_get_i (core->config, "asm.hint.emu");
	ds->asm_hint_cdiv = r_config_get_i (core->config, "asm.hint.cdiv");
	ds->asm_hint_pos = r_config_get_i (core->config, "asm.hint.pos");
	ds->asm_hints = r_config_get_i (core->config, "asm.hints"); // only for cdiv wtf
	ds->show_slow = r_config_get_i (core->config, "asm.slow");
	ds->show_refptr = r_config_get_i (core->config, "asm.refptr");
	ds->show_calls = r_config_get_i (core->config, "asm.cmt.calls");
	ds->show_family = r_config_get_i (core->config, "asm.family");
	ds->cmtcol = r_config_get_i (core->config, "asm.cmt.col");
	ds->show_cmt_esil = r_config_get_b (core->config, "asm.cmt.esil");
	ds->show_cmt_pseudo = r_config_get_b (core->config, "asm.cmt.pseudo");
	ds->show_cmt_flgrefs = r_config_get_b (core->config, "asm.cmt.flgrefs");
	ds->show_cycles = r_config_get_i (core->config, "asm.cycles");
	ds->show_stackptr = r_config_get_i (core->config, "asm.stackptr");
	ds->show_xrefs = r_config_get_b (core->config, "asm.xrefs");
	ds->show_anos = r_config_get_b (core->config, "asm.anos");
	ds->show_cmtrefs = r_config_get_i (core->config, "asm.cmt.refs");
	ds->cmtfold = r_config_get_i (core->config, "asm.cmt.fold");
	ds->show_cmtoff = r_config_get (core->config, "asm.cmt.off");
	if (!ds->show_cmtoff) {
		ds->show_cmtoff = "nodup";
	}
	ds->show_functions = r_config_get_b (core->config, "asm.functions");
	ds->nbytes = r_config_get_i (core->config, "asm.nbytes");
	ds->show_asciidot = !strcmp (core->print->strconv_mode, "asciidot");
	const char *strenc_str = r_config_get (core->config, "bin.str.enc");
	if (!strenc_str) {
		ds->strenc = R_STRING_ENC_GUESS;
	} else if (!strcmp (strenc_str, "latin1")) {
		ds->strenc = R_STRING_ENC_LATIN1;
	} else if (!strcmp (strenc_str, "utf8")) {
		ds->strenc = R_STRING_ENC_UTF8;
	} else if (!strcmp (strenc_str, "utf16le")) {
		ds->strenc = R_STRING_ENC_UTF16LE;
	} else if (!strcmp (strenc_str, "utf32le")) {
		ds->strenc = R_STRING_ENC_UTF32LE;
	} else if (!strcmp (strenc_str, "utf16be")) {
		ds->strenc = R_STRING_ENC_UTF16BE;
	} else if (!strcmp (strenc_str, "utf32be")) {
		ds->strenc = R_STRING_ENC_UTF32BE;
	} else {
		ds->strenc = R_STRING_ENC_GUESS;
	}
	core->print->bytespace = r_config_get_i (core->config, "asm.bytes.space");
	ds->cursor = 0;
	ds->nb = 0;
	ds->flagspace_ports = r_flag_space_get (core->flags, "ports");
	ds->lbytes = r_config_get_i (core->config, "asm.lbytes");
	ds->show_cmt_right_default = r_config_get_b (core->config, "asm.cmt.right");
	ds->show_cmt_right = ds->show_cmt_right_default;
	ds->show_flag_in_bytes = r_config_get_i (core->config, "asm.flags.inbytes");
	ds->show_flag_in_offset = r_config_get_i (core->config, "asm.flags.inoffset");
	ds->show_marks = r_config_get_i (core->config, "asm.marks");
	ds->show_noisy_comments = r_config_get_i (core->config, "asm.noisy");
	ds->pre = DS_PRE_NONE;
	ds->flags_prefix = r_config_get_b (ds->core->config, "asm.flags.prefix");
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
	ds->min_ref_addr = r_config_get_i (core->config, "asm.sub.varmin");

	if (ds->show_flag_in_bytes) {
		ds->show_flags = false;
	}
	if (r_config_get_i (core->config, "asm.lines.wide")) {
		ds->linesopts |= R_ANAL_REFLINE_TYPE_WIDE;
	}
	if (core->cons->vline) {
		if (ds->show_utf8) {
			ds->linesopts |= R_ANAL_REFLINE_TYPE_UTF8;
		}
	}
	if (ds->show_lines_jmp) {
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
	if (r_config_get_b (core->config, "asm.lines.wide")) {
		ds->linesopts |= R_ANAL_REFLINE_TYPE_WIDE;
	}
	if (core->cons->vline) {
		if (ds->show_utf8) {
			ds->linesopts |= R_ANAL_REFLINE_TYPE_UTF8;
		}
	}
	return ds;
}

static void ds_reflines_fini(RDisasmState *ds) {
	RAnal *anal = ds->core->anal;
	r_list_free (anal->reflines);
	anal->reflines = NULL;
	r_list_free (anal->reflines2);
	anal->reflines2 = NULL;
	R_FREE (ds->refline);
	R_FREE (ds->refline2);
	R_FREE (ds->prev_line_col);
}

static void ds_reflines_init(RDisasmState *ds) {
	RAnal *anal = ds->core->anal;
	st64 limit = r_config_get_i (ds->core->config, "asm.lines.limit");
	bool split = r_config_get_b (ds->core->config, "asm.lines.split");
	const bool inlimit = (limit > 0 && ds->len < limit);

	if (inlimit && (ds->show_lines_jmp || ds->pj)) {
		ds_reflines_fini (ds);
		if (split) {
			anal->reflines = r_anal_reflines_get (anal,
				ds->addr, ds->buf, ds->len, ds->count,
				ds->linesout, ds->show_lines_call, 1);
			anal->reflines2 = r_anal_reflines_get (anal,
				ds->addr, ds->buf, ds->len, ds->count,
				ds->linesout, ds->show_lines_call, -1);
		} else {
			anal->reflines = r_anal_reflines_get (anal,
				ds->addr, ds->buf, ds->len, ds->count,
				ds->linesout, ds->show_lines_call, 0);
			anal->reflines2 = NULL;
		}
	} else {
		r_list_free (anal->reflines);
		anal->reflines = NULL;
		r_list_free (anal->reflines2);
		anal->reflines2 = NULL;
	}
}

static void ds_free(RDisasmState *ds) {
	if (!ds) {
		return;
	}
	if (ds->show_emu_stack) {
		R_LOG_TODO ("destroy fake stack");
		if (ds->stackFd != -1) {
			r_io_fd_close (ds->core->io, ds->stackFd);
		}
	}
	r_anal_op_fini (&ds->asmop);
	r_anal_op_fini (&ds->analop);
	r_anal_hint_free (ds->hint);
	ds_reflines_fini (ds);
	ds_print_esil_anal_fini (ds);
	sdb_free (ds->ssa);
	free (ds->comment);
	free (ds->line);
	free (ds->line_col);
	free (ds->refline);
	free (ds->refline2);
	free (ds->prev_line_col);
	free (ds->opstr);
	free (ds->osl);
	free (ds->sl);
	free (ds->_tabsbuf);
	R_FREE (ds);
}

/* XXX move to r_asm_parse */
static char *colorize_asm_string(RCore *core, RDisasmState *ds, bool print_color) {
	char *source = ds->opstr? ds->opstr: ds->asmop.mnemonic;
	const char *hlstr = r_meta_get_string (ds->core->anal, R_META_TYPE_HIGHLIGHT, ds->at);
	bool partial_reset = line_highlighted (ds) ? true : ((hlstr && *hlstr) ? true : false);
	RAnalFunction *f = ds->show_color_args ? fcnIn (ds, ds->vat, R_ANAL_FCN_TYPE_NULL) : NULL;
	if (!ds->asm_meta && *source == '.') {
		return strdup (source);
	}
	if (!ds->show_color || !ds->colorop) {
		return strdup (source);
	}

	if (print_color) {
		r_cons_print (core->cons, r_print_color_op_type (core->print, ds->analop.type));
	}
	// workaround dummy colorizer in case of paired commands (tms320 & friends)
	char *spacer = strstr (source, "||");
	if (spacer) {
		char *scol1, *s1 = r_str_ndup (source, spacer - source);
		char *scol2, *s2 = strdup (spacer + 2);

		scol1 = r_print_colorize_opcode (ds->core->print, s1, ds->color_reg, ds->color_num, partial_reset, f ? f->addr : 0);
		free (s1);
		scol2 = r_print_colorize_opcode (ds->core->print, s2, ds->color_reg, ds->color_num, partial_reset, f ? f->addr : 0);
		free (s2);
		if (!scol1) {
			scol1 = strdup ("");
		}
		if (!scol2) {
			scol2 = strdup ("");
		}
		source = r_str_newf ("%s||%s", scol1, scol2);
		free (scol1);
		free (scol2);
		return source;
	}
	return r_print_colorize_opcode (ds->core->print, source, ds->color_reg, ds->color_num, partial_reset, f ? f->addr : 0);
}

static bool ds_must_strip(RDisasmState *ds) {
	if (ds && ds->strip && *ds->strip) {
		const char * optype = r_anal_optype_tostring (ds->analop.type);
		if (optype && *optype) {
			return strstr (ds->strip, optype);
		}
	}
	return false;
}

static void ds_highlight_word(RDisasmState *ds, char *word, char *color) {
	char *source = ds->opstr? ds->opstr: ds->asmop.mnemonic;
	const char *color_reset = line_highlighted (ds) ? ds->color_linehl : Color_RESET_BG;
	char *asm_str = r_str_highlight (source, word, color, color_reset);
	ds->opstr = asm_str? asm_str: source;
}

static void __replaceImports(RDisasmState *ds) {
	if (ds->core->anal->imports) {
		char *imp;
		RListIter *iter;
		r_list_foreach (ds->core->anal->imports, iter, imp) {
			ds->opstr = r_str_replace (ds->opstr, imp,  ".", 1);
		}
	}
	if (ds->fcn && ds->fcn->imports) {
		char *imp;
		RListIter *iter;
		r_list_foreach (ds->fcn->imports, iter, imp) {
			ds->opstr = r_str_replace (ds->opstr, imp,  ".", 1);
		}
	}
}

static char *get_op_ireg(void *user, ut64 addr) {
	RCore *core = (RCore *)user;
	char *res = NULL;
	RAnalOp *op = r_core_anal_op (core, addr, 0);
	if (op && op->ireg) {
		res = strdup (op->ireg);
	}
	r_anal_op_free (op);
	return res;
}

static st64 get_ptr_at(RAnalFunction *fcn, st64 delta, ut64 addr) {
	return r_anal_function_get_var_stackptr_at (fcn, delta, addr);
}

static const char *get_reg_at(RAnalFunction *fcn, st64 delta, ut64 addr) {
	return r_anal_function_get_var_reg_at (fcn, delta, addr);
}

static void ds_build_op_str(RDisasmState *ds, bool print_color) {
	RCore *core = ds->core;
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (ds->core->rasm->config);
	// if (ds->show_trace_color && ds->show_trace) {
	if (ds->show_trace_color) {
		bool extraspace = true;
		if (ds->fcn) {
			RAnalBlock *bb = r_anal_function_bbget_in (ds->core->anal, ds->fcn, ds->at);
			if (bb && (bb->color.r || bb->color.g || bb->color.b)) {
				RColor bg = { .r2 = bb->color.r, .g2 = bb->color.g, .b2 = bb->color.b, };
				bg.a = ALPHA_FGBG;
				bg.r2 = bb->color.r;
				bg.g2 = bb->color.g;
				bg.b2 = bb->color.b;
				// RColor bg = { .r2 = bb->color.r, .g2 = bb->color.g, .b2 = bb->color.b, };
				char *color = r_cons_rgb_str (core->cons, NULL, -1, &bg); // &bb->color);
				r_cons_printf (core->cons, "%s_%s ", color, Color_RESET);
				free (color);
				extraspace = false;
			}
		}
		if (!ds->show_trace) {
			extraspace = false;
		}
		if (extraspace) {
			r_cons_printf (core->cons, "  ");
		}
	}
	if (ds->use_esil) {
		free (ds->opstr);
		if (*R_STRBUF_SAFEGET (&ds->analop.esil)) {
			ds->opstr = strdup (R_STRBUF_SAFEGET (&ds->analop.esil));
		} else {
			ds->opstr = strdup (",");
		}
		return;
	}
	if (ds->decode) {
		free (ds->opstr);
		ds->opstr = r_anal_op_tostring (core->anal, &ds->analop);
		return;
	}
	if (!ds->opstr) {
		// asmop works, analop fails hard
		ds->opstr = strdup (r_str_get (ds->asmop.mnemonic));
	}
	/* initialize */
	core->rasm->parse->subrel = r_config_get_b (core->config, "asm.sub.rel");
	core->rasm->parse->subreg = r_config_get_b (core->config, "asm.sub.reg");
	core->rasm->parse->subrel_addr = 0;
	if (core->rasm->parse->subrel
			&& (ds->analop.type == R_ANAL_OP_TYPE_LEA
				|| ds->analop.type == R_ANAL_OP_TYPE_MOV
				|| ds->analop.type == R_ANAL_OP_TYPE_CMP)
			&& ds->analop.ptr != UT64_MAX) {
		core->rasm->parse->subrel_addr = ds->analop.ptr;
	}
	if (ds->subvar && ds->opstr) {
		ut64 at = ds->vat;
		RAnalFunction *f = fcnIn (ds, at, R_ANAL_FCN_TYPE_NULL);
		core->rasm->parse->get_op_ireg = get_op_ireg;
		core->rasm->parse->get_ptr_at = get_ptr_at;
		core->rasm->parse->get_reg_at = get_reg_at;
		char *res = r_asm_parse_subvar (core->rasm, f, at, ds->analop.size, ds->opstr);
		if (res) {
			free (ds->opstr);
			ds->opstr = res;
		}
		if (core->rasm->parse->subrel) {
			RVecAnalRef *refs = r_anal_refs_get (core->anal, at);
			if (refs) {
				RAnalRef *ref;
				R_VEC_FOREACH (refs, ref) {
					int rt = R_ANAL_REF_TYPE_MASK (ref->type);
					if ((rt == R_ANAL_REF_TYPE_DATA || rt == R_ANAL_REF_TYPE_STRN) && ds->analop.type == R_ANAL_OP_TYPE_LEA) {
						core->rasm->parse->subrel_addr = ref->addr;
						break;
					}
				}
			}
			RVecAnalRef_free (refs);
		}
	}
	char *res = ds_sub_jumps (ds, ds->opstr);
	if (res) {
		free (ds->opstr);
		ds->opstr = res;
	}
	if (ds->immtrim) {
		char *res = r_asm_parse_immtrim (core->rasm, ds->opstr);
		if (res) {
			free (ds->opstr);
			ds->opstr = res;
		}
		return;
	}
	if (ds->hint && ds->hint->opcode) {
		free (ds->opstr);
		ds->opstr = strdup (ds->hint->opcode);
	}
	if (ds->subnames) {
		RSpace *ofs = core->rasm->parse->flagspace;
		RSpace *fs = ds->flagspace_ports;
		if (ds->analop.type == R_ANAL_OP_TYPE_IO) {
			core->rasm->parse->notin_flagspace = NULL;
			core->rasm->parse->flagspace = fs;
		} else {
			if (fs) {
				core->rasm->parse->notin_flagspace = fs;
				core->rasm->parse->flagspace = fs;
			} else {
				core->rasm->parse->notin_flagspace = NULL;
				core->rasm->parse->flagspace = NULL;
			}
		}
		if (core->rasm->parse->subrel && ds->analop.refptr) {
			if (core->rasm->parse->subrel_addr == 0) {
				ut64 killme = UT64_MAX;
				r_io_read_i (core->io, ds->analop.ptr, &killme, ds->analop.refptr, be);
				core->rasm->parse->subrel_addr = killme;
			}
		}
		if (ds->pseudo) {
			char *res = r_asm_parse_pseudo (core->rasm, ds->opstr);
			if (res) {
				free (ds->opstr);
				ds->opstr = res;
			}
		}
		bool isjmp = false;
		if (ds->subjmp) {
			char *str = r_asm_parse_filter (core->rasm, ds->vat, core->flags, ds->hint, ds->opstr);
			if (str) {
				// isjmp = true;
				free (ds->opstr);
				ds->opstr = str;
			}
		}
		switch (ds->analop.type & R_ANAL_OP_TYPE_MASK) {
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_JMP:
			isjmp = true;
			break;
		}
		if (ds->subvar && !isjmp) {
			// R2_600 - HACK to do subvar outside rparse becacuse the whole rparse api must be rewritten
			char *ox = strstr (ds->opstr, "0x");
			if (ox && ox > ds->opstr) {
				// if opcode contains "switch.0x" we wont replace it again "switch.switch.0x"
				char *pox = ox - 1;
				if (*pox == '.') {
					ox = NULL;
				}
			}
			if (ox) {
				char *e = strchr (ox, ']');
				if (!e) {
					e = strchr (ox, ',');
					if (!e) {
						e = strchr (ox, ')');
						if (!e) {
							e = "";
						}
					}
				}
				e = strdup (e);
				ut64 addr = r_num_get (NULL, ox);
				if (addr > ds->min_ref_addr) {
					const RList *ls = r_flag_get_list (ds->core->flags, addr);
					RFlagItem *fi;
					RListIter *iter;
					r_list_foreach (ls, iter, fi) {
						const char *fsname = R_UNWRAP3 (fi, space, name);
						if (fsname && (!strcmp (fsname, "format") || !strcmp (fsname, "segments") || !strcmp (fsname, "sections"))) {
							// ignore
						} else {
							const char *n = (core->flags->realnames) ? fi->realname? fi->realname: fi->name: fi->name;
							if (strlen (n) > 3) {
								char *opstrx = r_str_ndup (ds->opstr, ox - ds->opstr);
								char *newox = r_str_newf ("%s%s%s", opstrx, n, e);
								free (ds->opstr);
								ds->opstr = newox;
								free (opstrx);
								break;
							}
						}
					}
				}
				free (e);
			}
		}
		core->rasm->parse->flagspace = ofs;
	} else {
		r_str_trim (ds->opstr); // trim before coloring git
	}
	__replaceImports (ds);
	char *asm_str = colorize_asm_string (core, ds, print_color);
	if (asm_str) {
		free (ds->opstr);
		ds->opstr = asm_str;
	}
	r_str_trim (ds->opstr);
	if (ds->show_color) {
		int i = 0;
		char *word = NULL;
		char *bgcolor = NULL;
		const char *wcdata = r_meta_get_string (ds->core->anal, R_META_TYPE_HIGHLIGHT, ds->at);
		int argc = 0;
		char **wc_array = r_str_argv (wcdata, &argc);
		for (i = 0; i < argc; i++) {
			bgcolor = strchr (wc_array[i], '\x1b');
			word = R_STR_NDUP (wc_array[i], bgcolor - wc_array[i]);
			ds_highlight_word (ds, word, bgcolor);
		}
	}
}

static void ds_hint_begin(RDisasmState *ds, ut64 at) {
	RCore *core = ds->core;
	r_anal_hint_free (ds->hint);
	ds->hint = r_anal_hint_get (core->anal, at);
	if (ds->hint_syntax) {
		r_config_set (core->config, "asm.syntax", ds->hint_syntax);
		ds->hint_syntax = NULL;
	}
	if (ds->hint) {
		/* syntax */
		if (ds->hint->syntax) {
			if (!ds->hint_syntax) {
				ds->hint_syntax = strdup (r_config_get (core->config, "asm.syntax"));
			}
			r_config_set (core->config, "asm.syntax", ds->hint->syntax);
		}
		if (ds->hint->high) {
			/* TODO: do something here */
		}
	}
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, at, 0);
	if (fcn && (fcn->bits == 16 || fcn->bits == 32)) {
		if (!ds->hint) {
			ds->hint = R_NEW0 (RAnalHint);
		}
		ds->hint->bits = fcn->bits;
		ds->hint->new_bits = fcn->bits;
	}
	if (ds->default_immbase) {
		if (!ds->hint) {
			ds->hint = R_NEW0 (RAnalHint);
			ds->hint->type = R_ANAL_ADDR_HINT_TYPE_IMMBASE;
		}
		ds->hint->immbase = ds->default_immbase;
	}
}

static void ds_pre_line(RDisasmState *ds) {
	ds_setup_pre (ds, false, false);
	ds_print_pre (ds, true);
	char *tmp = ds->line;
	char *tmp_col = ds->line_col;
	ds->line = ds->refline2;
	ds->line_col = ds->prev_line_col;
	ds_print_lines_left (ds);
	ds->line = tmp;
	ds->line_col = tmp_col;
}

static void ds_begin_line(RDisasmState *ds) {
	if (ds->pj) {
		pj_o (ds->pj);
		pj_kn (ds->pj, "addr", ds->vat);
		if (ds->core->anal->reflines) {
			RAnalRefline *ref;
			RListIter *iter;
			// XXX Probably expensive
			r_list_foreach (ds->core->anal->reflines, iter, ref) {
				if (ref->from == ds->vat) {
					pj_kn (ds->pj, "arrow", ref->to);
					break;
				}
			}
		}
	}
	size_t buflen;
	r_cons_get_buffer (ds->core->cons, &buflen);
	ds->buf_line_begin = buflen;
	if (!ds->pj && ds->asm_hint_pos == -1) {
		if (!ds_print_core_vmode (ds, ds->asm_hint_pos)) {
			r_cons_printf (ds->core->cons, "    ");
		}
	}
}

static void ds_newline(RDisasmState *ds) {
	RCons *cons = ds->core->cons;
	if (ds->pj) {
		const bool is_html = r_config_get_b (ds->core->config, "scr.html");
		if (is_html) {
			char *s = r_str_html_strip (r_cons_get_buffer (cons, NULL), NULL);
			pj_ks (ds->pj, "text", s);
			free (s);
		} else {
			pj_ks (ds->pj, "text", r_cons_get_buffer (cons, NULL));
		}
		r_cons_reset (cons);
		pj_end (ds->pj);
	} else {
		r_cons_newline (cons);
	}
}

static void ds_begin_cont(RDisasmState *ds) {
	ds_begin_line (ds);
	ds_setup_print_pre (ds, false, false);
	if (!ds->linesright && ds->show_lines_jmp && ds->line) {
		RAnalRefStr *refstr = r_anal_reflines_str (ds->core, ds->at,
				ds->linesopts | R_ANAL_REFLINE_TYPE_MIDDLE_AFTER);
		ds_print_ref_lines (ds, refstr->str, refstr->cols, false);
		r_anal_reflines_str_free (refstr);
	}
}

static void ds_begin_comment(RDisasmState *ds) {
	if (ds->show_cmt_right) {
		ds_comment_align (ds);
	} else {
		ds_begin_line (ds);
		ds_pre_xrefs (ds, false);
	}
}

static void ds_print_pins(RDisasmState *ds) {
	RCore *core = ds->core;
	const char *lepin = r_anal_pin_at (core->anal, ds->at);
	if (R_STR_ISNOTEMPTY (lepin)) {
	 	ds_begin_comment (ds);
		ds_comment (ds, true, "%s [aep: %s]", ds->cmtoken, lepin);
		if (r_str_startswith (lepin, "soft.")) {
			const char *cmd = r_anal_pin_get (core->anal, lepin);
			if (cmd) {
				r_cons_newline (ds->core->cons);
				r_core_cmd0 (core, cmd);
			}
		}
	}
}

static void ds_show_refs(RDisasmState *ds) {
	if (!ds->show_cmtrefs) {
		return;
	}

	RVecAnalRef *refs = r_anal_xrefs_get_from (ds->core->anal, ds->at);
	if (!refs) {
		return;
	}

	RAnalRef *ref;
	R_VEC_FOREACH (refs, ref) {
		const char *cmt = r_meta_get_string (ds->core->anal, R_META_TYPE_COMMENT, ref->addr);
		const RList *fls = r_flag_get_list (ds->core->flags, ref->addr);
		RListIter *iter2;
		RFlagItem *fis;
		r_list_foreach (fls, iter2, fis) {
			ds_begin_comment (ds);
			ds_comment (ds, true, "%s (%s)", ds->cmtoken, fis->name);
		}

		// ds_align_comment (ds);
		if (ds->show_color) {
			r_cons_print (ds->core->cons, ds->color_comment);
		}
		if (cmt) {
			ds_begin_comment (ds);
			ds_comment (ds, true, "%s (%s)", ds->cmtoken, cmt);
		}
		if (ref->type & R_ANAL_REF_TYPE_CALL) {
			RAnalOp aop;
			ut8 buf[12];
			r_io_read_at (ds->core->io, ref->at, buf, sizeof (buf));
			int opsz = r_anal_op (ds->core->anal, &aop, ref->at, buf, sizeof (buf), R_ARCH_OP_MASK_BASIC);
			if (opsz > 0 && (aop.type & R_ANAL_OP_TYPE_MASK) == R_ANAL_OP_TYPE_UCALL) {
				RAnalFunction *fcn = r_anal_get_function_at (ds->core->anal, ref->addr);
				ds_begin_comment (ds);
				if (fcn) {
					ds_comment (ds, true, "%s %s", ds->cmtoken, fcn->name);
				} else {
					ds_comment (ds, true, "%s 0x%" PFMT64x, ds->cmtoken, ref->addr);
				}
			}
			r_anal_op_fini (&aop);
		}
		ds_print_color_reset (ds);
	}
	RVecAnalRef_free (refs);
}

static void ds_show_anos(RDisasmState *ds) {
	if (ds->show_anos) {
		r_core_cmd_call_at (ds->core, ds->at, "anol");
	}
}

static void ds_show_xrefs(RDisasmState *ds) {
	char xrefs_char[32] = {0}; // no more than 32 xrefs meh
	int xci = 0;
	RCore *core = ds->core;
	char *name, *realname;
	int count = 0;
	if (!ds->show_xrefs || !ds->show_comments) {
		return;
	}
	char keyhint[64] = " ";
	if (core->vmode && core->addr == ds->at && r_config_get_b (core->config, "scr.interactive")) {
		const char *hintcolor = ds->pal_hint;
		const char *commentcolor = ds->color_comment;
		snprintf (keyhint, sizeof (keyhint), "%s[x] %s", hintcolor, commentcolor);
	} else {
		strcpy (keyhint, " ");
	}
	/* show xrefs */
	RVecAnalRef *xrefs = r_anal_xrefs_get (core->anal, ds->at);
	if (!xrefs) {
		return;
	}
	// only show fcnline in xrefs when addr is not the beginning of a function
	bool fcnlines = (ds->fcn && ds->fcn->addr == ds->at);
	if (RVecAnalRef_length (xrefs) > ds->maxrefs) {
		ds_begin_line (ds);
		ds_pre_xrefs (ds, fcnlines);
		ds_comment (ds, false, "%s;%sXREFS(%lu)",
			ds->show_color? ds->pal_comment: "",
			keyhint, RVecAnalRef_length (xrefs));
		if (ds->show_color) {
			ds_print_color_reset (ds);
		}
		ds_newline (ds);
		RVecAnalRef_free (xrefs);
		return;
	}
	if (RVecAnalRef_length (xrefs) > ds->foldxrefs) {
		int cols = r_cons_get_size (ds->core->cons, NULL);
		cols -= 15;
		cols /= 23;
		cols = cols > 5 ? 5 : cols;
		ds_begin_line (ds);
		ds_pre_xrefs (ds, fcnlines);
		ds_comment (ds, false, "%s;%sXREFS: ", ds->show_color? ds->pal_comment: "", keyhint);
		const ut64 length = RVecAnalRef_length (xrefs);
		ut64 i = 0;
		RAnalRef *refi;
		R_VEC_FOREACH (xrefs, refi) {
			const bool is_at_second_last = (i + 1 == length);
			const char *t = r_anal_ref_type_tostring (refi->type);
			if (t && strcmp (t, "NULL")) {
				ds_comment (ds, false, "%s 0x%08"PFMT64x"  ", t, refi->addr);
			} else {
				ds_comment (ds, false, "0x%08"PFMT64x"  ", refi->addr);
			}
			if (count == cols) {
				if (!is_at_second_last) {
					ds_print_color_reset (ds);
					ds_newline (ds);
					ds_begin_line (ds);
					ds_pre_xrefs (ds, fcnlines);
					ds_comment (ds, false, "%s; XREFS: ", ds->show_color? ds->pal_comment: "");
				}
				count = 0;
			} else {
				count++;
			}
			i++;
		}
		ds_print_color_reset (ds);
		ds_newline (ds);
		RVecAnalRef_free (xrefs);
		return;
	}

	RList *addrs = r_list_newf (free);
	RAnalFunction *fun, *next_fun;
	ut64 i = 0;
	const ut64 length = RVecAnalRef_length (xrefs);
	RFlagItem *f, *next_f;
	RAnalRef *refi;
	R_VEC_FOREACH (xrefs, refi) {
		int rt = R_ANAL_REF_TYPE_MASK (refi->type);
		if (!ds->asm_xrefs_code && rt == R_ANAL_REF_TYPE_CODE) {
			i++;
			continue;
		}
		if (refi->at == ds->at) {
			realname = NULL;
			fun = fcnIn (ds, refi->addr, -1);
			const bool is_at_second_last = (i + 1 == length);
			if (fun) {
				if (!is_at_second_last) {
					const RAnalRef *next = RVecAnalRef_at (xrefs, i + 1);
					ut64 next_addr = next->addr;
					next_fun = r_anal_get_fcn_in (core->anal, next_addr, -1);
					if (next_fun && next_fun->addr == fun->addr) {
						if (xci < 32) {
							xrefs_char[xci++] = r_anal_ref_perm_tochar (refi);
						}
						r_list_append (addrs, r_num_dup (refi->addr));
						i++;
						continue;
					}
				}
				if (ds->asm_demangle) {
					f = r_flag_get_by_spaces (core->flags, false, fun->addr, R_FLAGS_FS_SYMBOLS, NULL);
					if (f && f->demangled && f->realname) {
						realname = strdup (f->realname);
					}
				}
				name = strdup (fun->name);
				if (xci < 32) {
					xrefs_char[xci++] = r_anal_ref_perm_tochar (refi);
				}
				r_list_append (addrs, r_num_dup (refi->addr));
			} else {
				f = r_flag_get_at (core->flags, refi->addr, true);
				if (f) {
					if (!is_at_second_last) {
						const RAnalRef *next = RVecAnalRef_at (xrefs, i + 1);
						ut64 next_addr = next->addr;
						next_f = r_flag_get_at (core->flags, next_addr, true);
						if (next_f && f->addr == next_f->addr) {
							if (xci < 32) {
								xrefs_char[xci++] = r_anal_ref_perm_tochar (refi);
							}
							r_list_append (addrs, r_num_dup (refi->addr - f->addr));
							i++;
							continue;
						}
					}
					if (ds->asm_demangle) {
						RFlagItem *f_sym = f;
						if (!r_str_startswith (f_sym->name, "sym.")) {
							f_sym = r_flag_get_by_spaces (core->flags, false, f->addr,
									R_FLAGS_FS_SYMBOLS, NULL);
						}
						if (f_sym && f_sym->demangled && f_sym->realname) {
							f = f_sym;
							realname = strdup (f->realname);
						}
					}
					name = strdup (f->name);
					if (xci < 32) {
						xrefs_char[xci++] = r_anal_ref_perm_tochar (refi);
					}
					r_list_append (addrs, r_num_dup (refi->addr - f->addr));
				} else {
					name = strdup ("unk");
				}
			}
			ds_begin_line (ds);
			ds_pre_xrefs (ds, fcnlines);
			const char* plural = r_list_length (addrs) > 1 ? "S" : "";
			const char* plus = fun ? "" : "+";
			ds_comment (ds, false, "%s%s%s%s XREF%s from %s @ ",
				COLOR (ds, pal_comment), ds->cmtoken, keyhint, r_anal_ref_type_tostring (refi->type), plural,
				realname ? realname : name);
			ut64 *addrptr;

			int i = 0;
			RListIter *it;
			r_list_foreach (addrs, it, addrptr) {
				if (R_STR_ISNOTEMPTY (addrptr)) {
					char ch = xrefs_char [i++];
					ds_comment (ds, false, "%s%s0x%"PFMT64x"(%c)",
						it == addrs->head ? "" : ", ", plus, *addrptr, ch);
				}
			}
			if (realname && (!fun || r_anal_get_function_at (core->anal, ds->at))) {
				const char *pad = ds->show_cmt_right ? "" : " ";
				if (!ds->show_cmt_right) {
					ds_newline (ds);
					ds_begin_line (ds);
					ds_pre_xrefs (ds, fcnlines);
				}
				ds_comment (ds, false, " %s%s %s", pad, ds->cmtoken, name);
			}
			ds_comment (ds, false, "%s", COLOR_RESET (ds));
			ds_newline (ds);
			r_list_purge (addrs);
			R_FREE (name);
			free (realname);
		} else {
			R_LOG_ERROR ("Corrupted database?");
		}
		i++;
	}
	r_list_free (addrs);
	RVecAnalRef_free (xrefs);
}

static void ds_atabs_option(RDisasmState *ds) {
	R_RETURN_IF_FAIL (ds);
	int n, i = 0, word = 0;
	bool comma = false;
	int brackets = 0;

	if (!ds->atabs) {
		return;
	}
	size_t bufasm_len = strlen (ds->asmop.mnemonic);
	size_t size = (bufasm_len * (ds->atabs + 1)) + 8;
	if (size < 1 || size < bufasm_len) {
		return;
	}
	RStrBuf *sb = r_strbuf_new ("");
	char *b, *ob = (ds->opstr)? strdup (ds->opstr): strdup (ds->asmop.mnemonic);
	for (b = ob; b && *b; b++, i++) {
		r_strbuf_append_n (sb, b, 1);
		if (*b == '(' || *b == '[') {
			brackets++;
		}
		if (*b == ')' || *b == ']') {
			brackets--;
		}
		if (*b == ',') {
			comma = true;
		}
		if (*b != ' ') {
			continue;
		}
		if (word > 0 && !comma) {
			continue;
		}
		if (brackets > 0) {
			continue;
		}
		comma = false;
		brackets = 0;
		n = (ds->atabs - i);
		if (n < 1) {
			n = 1;
		}
		const char *tab = r_str_pad (' ', n);
		r_strbuf_append_n (sb, tab, n);
		i = 0;
		word++;
		if (ds->atabsonce) {
			r_strbuf_append (sb, b + 1);
			break;
		}
	}
	free (ob);
	free (ds->opstr);
	ds->opstr = r_strbuf_drain (sb);
}

static int handleMidFlags(RCore *core, RDisasmState *ds, bool print) {
	int i;

	ds->midflags = r_config_get_i (core->config, "asm.flags.middle");
	ds->hasMidflag = false;
	if (ds->midcursor && core->print->cur != -1) {
		ut64 cur = core->addr + core->print->cur;
		ut64 from = ds->at;
		ut64 to = ds->at + ds->oplen;
		if (cur > from && cur < to) {
			return cur - from;
		}
	}
	if (ds->midflags == R_MIDFLAGS_HIDE) {
		return 0;
	}

	for (i = 1; i < ds->oplen; i++) {
		RFlagItem *fi = r_flag_get_in (core->flags, ds->at + i);
		if (fi && fi->name) {
			const char *finame = fi->name;
			if (r_anal_get_block_at (core->anal, ds->at)) {
				ds->midflags = ds->midflags? R_MIDFLAGS_SHOW: R_MIDFLAGS_HIDE;
			}
			if (ds->midflags == R_MIDFLAGS_REALIGN && ((finame[0] == '$') || (fi->realname && fi->realname[0] == '$'))) {
				i = 0;
			} else if (r_str_startswith (finame, "hit.")) { // use search.prefix ?
				i = 0;
			} else if (r_str_startswith (finame, "str.")) {
				ds->midflags = R_MIDFLAGS_REALIGN;
			} else if (r_str_startswith (finame, "reloc.")) {
				continue;
			}
			if (ds->midflags == R_MIDFLAGS_SYMALIGN) {
				if (!r_str_startswith (finame, "sym.")) {
					continue;
				}
			}
			ds->hasMidflag = true;
			return i;
		}
	}
	return 0;
}

static int handleMidBB(RCore *core, RDisasmState *ds) {
	int i;
	ds->hasMidbb = false;
	R_RETURN_VAL_IF_FAIL (core->anal, 0);
	// Unfortunately, can't just check the addr of the last insn byte since
	// a bb (and fcn) can be as small as 1 byte, and advancing i based on
	// bb->size is unsound if basic blocks can nest or overlap
	for (i = 1; i < ds->oplen; i++) {
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, ds->at + i, 0);
		if (fcn) {
			RAnalBlock *bb = r_anal_function_bbget_in (core->anal, fcn, ds->at + i);
			if (bb && bb->addr > ds->at) {
				ds->hasMidbb = true;
				return bb->addr - ds->at;
			}
		}
	}
	return 0;
}

R_API int r_core_flag_in_middle(RCore *core, ut64 at, int oplen, int *midflags) {
	R_RETURN_VAL_IF_FAIL (midflags, 0);
	RDisasmState ds = {
		.at = at,
		.oplen = oplen,
		.midflags = *midflags
	};
	int ret = handleMidFlags (core, &ds, true);
	*midflags = ds.midflags;
	return ret;
}

R_API int r_core_bb_starts_in_middle(RCore *core, ut64 at, int oplen) {
	RDisasmState ds = {
		.at = at,
		.oplen = oplen
	};
	return handleMidBB (core, &ds);
}

static void ds_print_show_cursor(RDisasmState *ds) {
	RCore *core = ds->core;
	char res[] = "     ";
	if (!ds->show_marks) {
		return;
	}
	ut64 cursor_addr = core->addr + ds->cursor;
	int q = core->print->cur_enabled &&
		cursor_addr >= ds->at &&
		cursor_addr < (ds->at + ds->asmop.size);

	RBreakpointItem *p = r_bp_get_at (core->dbg->bp, ds->at);
	(void)handleMidFlags (core, ds, false);
	if (ds->midbb) {
		(void)handleMidBB (core, ds);
	}
	if (p) {
		res[0] = 'b';
	}
	if (ds->hasMidflag || ds->hasMidbb) {
		res[1] = '~';
	}
	if (q) {
		r_cons_mark (ds->core->cons, UT64_MAX, "cursor");
		if (cursor_addr == ds->at) {
			res[2] = '*';
		} else {
			int i = 2, diff = cursor_addr - ds->at;
			if (diff > 9) {
				res[i++] = '0' + (diff / 10);
			}
			res[i] = '0' + (diff % 10);
		}
	}
	r_cons_print (ds->core->cons, res);
}

static void ds_pre_xrefs(RDisasmState *ds, bool no_fcnlines) {
	ds_setup_pre (ds, false, false);
	if (ds->pre != DS_PRE_NONE && ds->pre != DS_PRE_EMPTY) {
		ds->pre = no_fcnlines ? DS_PRE_EMPTY : DS_PRE_FCN_MIDDLE;
	}
	ds_print_pre (ds, !no_fcnlines);
	char *tmp = ds->line;
	char *tmp_col = ds->line_col;
	ds->line = ds->refline2;
	ds->line_col = ds->prev_line_col;
	ds_print_lines_left (ds);
	if (!ds->show_offset && ds->show_marks) {
		ds_print_show_cursor (ds);
	}
	ds->line = tmp;
	ds->line_col = tmp_col;
}

//TODO: this function is a temporary fix. All analysis should be based on realsize. However, now for same architectures realisze is not used
static ut32 tmp_get_realsize(RAnalFunction *f) {
	ut32 size = r_anal_function_realsize (f);
	return (size > 0) ? size : r_anal_function_linear_size (f);
}

static void ds_show_functions_argvar(RDisasmState *ds, RAnalFunction *fcn, RAnalVar *var, const char *base, bool is_var, char sign) {
	int delta = var->kind == 'b' ? R_ABS (var->delta + fcn->bp_off) : R_ABS (var->delta);
	const char *pfx = is_var ? VARPREFIX: ARGPREFIX;
	char *constr = r_anal_var_get_constraints_readable (var);
	r_cons_printf (ds->core->cons, "%s%s %s%s%s%s%s %s%s%s%s@ %s%c0x%x",
			COLOR_ARG (ds, color_var), pfx,
			COLOR_ARG (ds, color_var_type), var->type, r_str_endswith (var->type, "*") ? "" : " ",
			COLOR_ARG (ds, color_var_name), var->name,
			COLOR_ARG (ds, color_var_addr), constr? " { ":"", r_str_get (constr), constr? " } ":"",
			base, sign, delta);
	if (ds->show_varsum == -1) {
		char *val = r_core_cmd_strf (ds->core, ".afvd %s", var->name);
		if (val) {
			r_str_replace_char (val, '\n', '\0');
			r_cons_printf (ds->core->cons, " = %s", val);
			free (val);
		}
	}
	free (constr);
}

static void print_var_summary(RDisasmState *ds, RList *list) {
	const char *numColor = ds->core->cons->context->pal.num;
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
		if (var->isarg) {
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
	RCons *cons = ds->core->cons;
	if (bp_vars) { bp_vars_color = numColor; }
	if (sp_vars) { sp_vars_color = numColor; }
	if (rg_vars) { rg_vars_color = numColor; }
	if (bp_args) { bp_args_color = numColor; }
	if (sp_args) { sp_args_color = numColor; }
	if (rg_args) { rg_args_color = numColor; }
	if (ds->show_varsum == 4) {
		int total_args = bp_args + sp_args + rg_args;
		int total_vars = bp_vars + sp_vars + rg_vars;
		if (total_args > 0 || total_vars > 0) {
			ds_begin_line (ds);
			ds_print_pre (ds, true);
		}
		if (total_args > 0) {
			r_cons_printf (cons, "`- args(");
			const char *comma = "";
			int minsprange = ST32_MAX;
			int maxsprange = 0;
			r_list_foreach (list, iter, var) {
				if (var->isarg) {
					if (var->kind == 'r') {
						r_cons_printf (cons, "%s%s", comma, var->regname);
						comma = ", ";
					} else {
						ut64 v = R_ABS (var->delta);
						if (v > maxsprange) {
							maxsprange = v;
						}
						if (v < minsprange) {
							minsprange = v;
						}
					}
				}
			}
			if (maxsprange > 0) {
				r_cons_printf (cons, "%ssp[0x%x..0x%x]", comma, minsprange, maxsprange);
			}
			if (total_vars > 0) {
				r_cons_printf (cons, ") ");
			} else {
				r_cons_printf (cons, ")");
			}
		}
		if (total_vars > 0) {
			if (total_args < 1) {
				r_cons_printf (cons, "afv: ");
			}
			const char *comma = "";
			r_cons_printf (cons, "vars(");
			int minsprange = ST32_MAX;
			int maxsprange = 0;
			r_list_foreach (list, iter, var) {
				if (!var->isarg) {
					if (var->kind == 'r') {
						r_cons_printf (cons, "%s%s", comma, var->regname);
						comma = ", ";
					} else {
						ut64 v = R_ABS (var->delta);
						if (v > maxsprange) {
							maxsprange = v;
						}
						if (v < minsprange) {
							minsprange = v;
						}
					}
				}
			}
			if (maxsprange > 0) {
				r_cons_printf (cons, "%s%d:sp[0x%x..0x%x]", comma, total_vars, minsprange, maxsprange);
			}
			r_cons_printf (cons, ")");
		}
		if (total_args > 0 || total_vars > 0) {
			ds_newline (ds);
		}
		return;
	}
	if (ds->show_varsum == 3) {
		ds_begin_line (ds);
		ds_print_pre (ds, true);
		int total_args = bp_args + sp_args + rg_args;
		if (total_args > 0) {
			r_cons_printf (cons, "afv: args(");
			const char *comma = "";
			if (rg_args) {
				r_cons_printf (cons, "reg:%d", rg_args);
				comma = ",";
			}
			if (sp_args) {
				r_cons_printf (cons, "%ssp:%d", comma, sp_args);
			}
			if (bp_args) {
				r_cons_printf (cons, "%sbp:%d", comma, rg_args);
			}
			r_cons_printf (cons, ") ");
		}
		int total_vars = bp_vars + sp_vars + rg_vars;
		if (total_vars > 0) {
			if (total_args < 1) {
				r_cons_printf (cons, "afv: ");
			}
			const char *comma = "";
			r_cons_printf (cons, "vars(");
			if (rg_vars) {
				r_cons_printf (cons, "reg:%d", rg_vars);
			}
			if (sp_vars) {
				r_cons_printf (cons, "%ssp:%d", comma, sp_vars);
			}
			if (bp_vars) {
				r_cons_printf (cons, "%sbp:%d", comma, rg_vars);
			}
			r_cons_printf (cons, ")");
		}
		ds_newline (ds);
		return;
	}
	if (ds->show_varsum == 2) {
		ds_begin_line (ds);
		ds_print_pre (ds, true);
		r_cons_printf (cons, "args: %s%d%s %s%d%s %s%d%s",
				bp_args_color, bp_args, COLOR_RESET (ds),
				sp_args_color, sp_args, COLOR_RESET (ds),
				rg_args_color, rg_args, COLOR_RESET (ds));
		ds_newline (ds);
		ds_begin_line (ds);
		ds_print_pre (ds, true);
		r_cons_printf (cons, "vars: %s%d%s %s%d%s %s%d%s",
				bp_vars_color, bp_vars, COLOR_RESET (ds),
				sp_vars_color, sp_vars, COLOR_RESET (ds),
				rg_vars_color, rg_vars, COLOR_RESET (ds));
		ds_newline (ds);
		return;
	}
	ds_begin_line (ds);
	ds_print_pre (ds, true);
	r_cons_printf (cons, "rg: %s%d%s (vars %s%d%s, args %s%d%s)",
			rg_args || rg_vars ? numColor : COLOR_RESET (ds), rg_args+rg_vars, COLOR_RESET (ds),
			rg_vars_color, rg_vars, COLOR_RESET (ds),
			rg_args_color, rg_args, COLOR_RESET (ds));
	ds_newline (ds);
	ds_begin_line (ds);
	ds_print_pre (ds, true);
	r_cons_printf (cons, "bp: %s%d%s (vars %s%d%s, args %s%d%s)",
			bp_args || bp_vars ? numColor : COLOR_RESET (ds), bp_args + bp_vars, COLOR_RESET (ds),
			bp_vars_color, bp_vars, COLOR_RESET (ds),
			bp_args_color, bp_args, COLOR_RESET (ds));
	ds_newline (ds);
	ds_begin_line (ds);
	ds_print_pre (ds, true);
	r_cons_printf (cons, "sp: %s%d%s (vars %s%d%s, args %s%d%s)",
			sp_args || sp_vars ? numColor : COLOR_RESET (ds), sp_args+sp_vars, COLOR_RESET (ds),
			sp_vars_color, sp_vars, COLOR_RESET (ds),
			sp_args_color, sp_args, COLOR_RESET (ds));
	ds_newline (ds);

}

static bool empty_signature(const char *s) {
	return (s && !strncmp (s, "void ", 5) && strstr (s, "()"));
}

static void ds_show_functions(RDisasmState *ds) {
	RCore *core = ds->core;
	if (!ds->show_functions) {
		return;
	}
	bool demangle = r_config_get_i (core->config, "bin.demangle");
	bool keep_lib = r_config_get_i (core->config, "bin.demangle.pfxlib");
	bool showSig = ds->show_fcnsig && ds->show_calls;
	bool call = r_config_get_i (core->config, "asm.cmt.calls");
	const char *lang = demangle ? r_config_get (core->config, "bin.lang") : NULL;
	RAnalFunction *f = r_anal_get_function_at (core->anal, ds->at);
	if (!f) {
		return;
	}
	char *fcn_name;
	bool fcn_name_alloc = false; // whether fcn_name needs to be freed by this function
	if (demangle) {
		fcn_name = r_bin_demangle (core->bin->cur, lang, f->name, f->addr, keep_lib);
		if (fcn_name) {
			fcn_name_alloc = true;
		} else {
			fcn_name = f->name;
		}
	} else {
		fcn_name = f->name;
	}
	RCons *cons = ds->core->cons;
	ds_begin_line (ds);
	char *sign = r_anal_function_get_signature (f);
	if (empty_signature (sign)) {
		R_FREE (sign);
	}
	if (f->type == R_ANAL_FCN_TYPE_LOC) {
		r_cons_printf (cons, "%s%s ", COLOR (ds, color_fline), core->cons->vline[LINE_CROSS]); // |-
		if (!showSig) {
			r_cons_printf (cons, "%s%s%s %"PFMT64u, COLOR (ds, color_floc),
					fcn_name, COLOR_RESET (ds), r_anal_function_linear_size (f));
			ds_newline (ds);
		}
	} else {
		const char *fcntype;
		char cmt[32];
		get_bits_comment (core, f, cmt, sizeof (cmt));

		switch (f->type) {
		case R_ANAL_FCN_TYPE_FCN:
		case R_ANAL_FCN_TYPE_SYM:
			fcntype = "fcn";
			break;
		case R_ANAL_FCN_TYPE_IMP:
			fcntype = "imp";
			break;
		default:
			fcntype = "loc";
			break;
		}
		// ds_set_pre (ds, core->cons->vline[CORNER_TL]);
		if (ds->show_lines_fcn) {
			ds->pre = DS_PRE_FCN_HEAD;
		}
		ds_print_pre (ds, true);
		if (ds->show_flgoff) {
			ds_print_lines_left (ds);
			ds_print_offset (ds);
		}
		if (!showSig) {
			r_cons_printf (cons, "%s(%s) %s%s%s %d", COLOR (ds, color_fname),
					fcntype, fcn_name, cmt, COLOR_RESET (ds), tmp_get_realsize (f));
			ds_newline (ds);
		}
	}
	if (!showSig) {
		if (sign) {
			ds_begin_line (ds);
			r_cons_printf (cons, "// %s", sign);
			ds_newline (ds);
		}
	}
	R_FREE (sign);
	if (ds->show_lines_fcn) {
		ds->pre = DS_PRE_FCN_MIDDLE;
	}
	ds->stackptr = core->anal->stackptr;
	RAnalFcnVarsCache vars_cache;
	r_anal_function_vars_cache_init (core->anal, &vars_cache, f);

	int o_varsum = ds->show_varsum;
	if (ds->interactive && !o_varsum) {
		int padding = 10;
		int numvars = vars_cache.bvars->length + vars_cache.rvars->length + vars_cache.svars->length + padding;
		if (numvars > ds->count) {
			ds->show_varsum = 1;
		} else {
			ds->show_varsum = 0;
		}
	}

	if (call) {
		if (!showSig) {
			ds_begin_line (ds);
			r_cons_print (cons, COLOR (ds, color_fline));
			ds_print_pre (ds, true);
			r_cons_printf (cons, "%s  ", COLOR_RESET (ds));
		}
		r_cons_printf (cons, "%" PFMT64d ": ", r_anal_function_realsize (f));

		// show function's realname in the signature if realnames are enabled
		if (core->flags->realnames) {
			RFlagItem *flag = r_flag_get (core->flags, fcn_name);
			if (flag && flag->realname) {
				fcn_name = flag->realname;
			}
		}

		char *sig = r_anal_function_format_sig (core->anal, f, fcn_name, &vars_cache, COLOR (ds, color_fname), COLOR_RESET (ds));
		if (sig) {
			r_cons_print (cons, sig);
			if (f->is_noreturn) {
				r_cons_printf (cons, " // noreturn");
			}
			free (sig);
		}
		ds_newline (ds);
	}

	if (ds->show_vars) {
		if (ds->show_varsum && ds->show_varsum != -1) {
			RList *all_vars = vars_cache.bvars;
			r_list_join (all_vars, vars_cache.svars);
			r_list_join (all_vars, vars_cache.rvars);
			print_var_summary (ds, all_vars);
		} else {
			char spaces[32];
			RAnalVar *var;
			RListIter *iter;

			int skipped = 0;
			if (f->addr == core->addr) {
				skipped = core->skiplines;
			}
			RList *all_vars = vars_cache.rvars;
			r_list_join (all_vars, vars_cache.bvars);
			r_list_join (all_vars, vars_cache.svars);
			r_list_foreach (all_vars, iter, var) {
				if (skipped > 0) {
					skipped--;
					continue;
				}
				ds_begin_line (ds);
				int idx;
				RAnal *anal = ds->core->anal;
				memset (spaces, ' ', sizeof (spaces));
				idx = 12 - strlen (var->name);
				if (idx < 0) {
					idx = 0;
				}
				spaces[idx] = 0;
				ds_pre_xrefs (ds, false);

				if (ds->show_flgoff) {
					ds_print_offset (ds);
				}
				r_cons_printf (cons, "%s; ", COLOR_ARG (ds, color_var));
				switch (var->kind) {
				case R_ANAL_VAR_KIND_BPV:
					{
						const char *bpreg = r_reg_alias_getname (anal->reg, R_REG_ALIAS_BP);
						char sign = var->isarg || (-var->delta <= f->bp_off) ? '+' : '-';
						bool is_var = !var->isarg;
						ds_show_functions_argvar (ds, f, var, bpreg? bpreg: "BP", is_var, sign);
					}
					break;
				case R_ANAL_VAR_KIND_REG: {
					RRegItem *i = r_reg_index_get (anal->reg, var->delta);
					if (!i) {
						R_LOG_ERROR ("Register not found");
						break;
					}
					r_cons_printf (cons, "%sarg %s%s%s%s%s %s@ %s", COLOR_ARG (ds, color_var),
						COLOR_ARG (ds, color_var_type),
						var->type, r_str_endswith (var->type, "*") ? "" : " ",
						COLOR_ARG (ds, color_var_name), var->name,
						COLOR_ARG (ds, color_var_addr), i->name);
					if (ds->show_varsum == -1) {
						char *val = r_core_cmd_strf (ds->core, ".afvd %s", var->name);
						if (val) {
							r_str_replace_char (val, '\n', '\0');
							r_cons_printf (cons, "%s", val);
							free (val);
						}
					}
					}
					break;
				case R_ANAL_VAR_KIND_SPV:
					{
						bool is_var = !var->isarg;
						int saved_delta = var->delta;
						const char *spreg = r_reg_alias_getname (anal->reg, R_REG_ALIAS_SP);
						var->delta = f->maxstack + var->delta;
						char sign = var->isarg || (-var->delta <= f->maxstack) ? '+' : '-';
						ds_show_functions_argvar (ds, f, var, spreg? spreg: "SP", is_var, sign);
						var->delta = saved_delta;
					}
					break;
				}
				if (var->comment) {
					r_cons_printf (cons, "    %s%s %s", COLOR (ds, color_comment), ds->cmtoken, var->comment);
				}
				r_cons_print (cons, COLOR_RESET (ds));
				ds_newline (ds);
			}
		}
	}
	ds->show_varsum = o_varsum;
	r_anal_function_vars_cache_fini (&vars_cache);
	if (fcn_name_alloc) {
		free (fcn_name);
	}
	{
		RListIter *iter;
		char *imp;
		if (ds->fcn && ds->fcn->imports) {
			r_list_foreach (ds->fcn->imports, iter, imp) {
				ds_print_pre (ds, true);
				ds_print_lines_left(ds);
				r_cons_printf (cons, ".import %s", imp);
				ds_newline (ds);
			}
		}
		r_list_foreach (ds->core->anal->imports, iter, imp) {
			ds_print_pre (ds, true);
			ds_print_lines_left(ds);
			r_cons_printf (cons, ".globalimport %s", imp);
			ds_newline (ds);
		}
	}
}

static void ds_setup_print_pre(RDisasmState *ds, bool tail, bool middle) {
	ds_setup_pre (ds, tail, middle);
	ds_print_pre (ds, true);
}

static void ds_setup_pre(RDisasmState *ds, bool tail, bool middle) {
	ds->cmtcount = 0;
	if (!ds->show_functions || !ds->show_lines_fcn) {
		ds->pre = DS_PRE_NONE;
		return;
	}
	ds->pre = DS_PRE_EMPTY;
	RAnalFunction *f = fcnIn (ds, ds->at, R_ANAL_FCN_TYPE_NULL);
	if (f) {
		if (f->addr == ds->at) {
			if (ds->analop.size == r_anal_function_linear_size (f) && !middle) {
				ds->pre = DS_PRE_FCN_TAIL;
			} else {
				ds->pre = DS_PRE_FCN_MIDDLE;
			}
		} else if (r_anal_function_max_addr (f) - ds->analop.size == ds->at && f->addr == r_anal_function_min_addr (f)) {
			ds->pre = DS_PRE_FCN_TAIL;
		} else if (r_anal_function_contains (f, ds->at)) {
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

static void ds_print_pre(RDisasmState *ds, bool fcnline) {
	RCore *core = ds->core;
	RCons *cons = ds->core->cons;
	int pre = ds->pre;
	const char *c = NULL;
	if (!fcnline) {
		pre = DS_PRE_EMPTY;
	}
	switch (pre) {
	case DS_PRE_FCN_HEAD:
		c = cons->vline[CORNER_TL];
		break;
	case DS_PRE_FCN_MIDDLE:
		c = cons->vline[LINE_VERT];
		break;
	case DS_PRE_FCN_TAIL:
		c = cons->vline[CORNER_BL];
		break;
	case DS_PRE_EMPTY:
		r_cons_print (cons, "  ");
		return;
	case DS_PRE_NONE:
	default:
		return;
	}
	char *kolor = strdup (ds->color_fline);
	RAnalBlock *bb;
	RList *list = r_anal_get_blocks_in (core->anal, ds->at);
	RListIter *iter;
	r_list_foreach (list, iter, bb) {
		if (bb->color.r || bb->color.g || bb->color.b) {
			free (kolor);
			kolor = r_cons_rgb_str (cons, NULL, -1, &bb->color);
			break;
		}
	}
	r_cons_printf (cons, "%s%s%s ", kolor, c, COLOR_RESET (ds));
	r_list_free (list);
	free (kolor);
}

static void ds_show_comments_describe(RDisasmState *ds) {
	/* respect asm.describe */
	char *desc = NULL;
	if (ds->asm_describe && !ds->has_description) {
		char *op, *locase = strdup (ds->asmop.mnemonic);
		if (!locase) {
			return;
		}
		op = strchr (locase, ' ');
		if (op) {
			*op = 0;
		}
		r_str_case (locase, 0);
		desc = r_asm_describe (ds->core->rasm, locase);
		free (locase);
	}
	if (desc && *desc) {
		ds_begin_comment (ds);
		ds_align_comment (ds);
		if (ds->show_color) {
			r_cons_print (ds->core->cons, ds->color_comment);
		}
		r_cons_printf (ds->core->cons, "%s %s", ds->cmtoken, desc);
		ds_print_color_reset (ds);
		ds_newline (ds);
		free (desc);
	}
}

//XXX review this with asm.cmt.right
static void ds_show_comments_right(RDisasmState *ds) {
	int linelen;
	RCore *core = ds->core;
	RCons *cons = core->cons;
	/* show comment at right? */
	int scr = ds->show_cmt_right;
	if (!ds->show_comments && !ds->show_cmt_user) {
		return;
	}
	RFlagItem *item = r_flag_get_in (core->flags, ds->at);
	if (!item && ds->analop.ptr && ds->analop.ptr != UT64_MAX) {
		item = r_flag_get_in (core->flags, ds->analop.ptr);
	}
	const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, ds->at);
	// vartype also contains varname, so we use varname color to display it
	const char *vartype = r_meta_get_string (core->anal, R_META_TYPE_VARTYPE, ds->at);
	if (!comment) {
		if (vartype) {
			R_FREE (ds->comment);
			ds->comment = r_str_newf ("%s%s %s", COLOR_ARG (ds, color_usrcmt), ds->cmtoken, vartype);
		} else if (item) {
			const char *cmt = r_flag_item_set_comment (core->flags, item, NULL);
			if (cmt) {
				R_FREE (ds->comment);
				ds->ocomment = cmt;
				ds->comment = strdup (cmt);
			}
		}
	} else if (vartype) {
		ds->comment = r_str_newf ("%s%s %s %s%s%s %s",
				COLOR_ARG (ds, color_usrcmt), ds->cmtoken, vartype, Color_RESET,
				COLOR (ds, color_usrcmt), ds->cmtoken, comment);
	} else {
		ds->comment = r_str_newf ("%s%s %s", COLOR_ARG (ds, color_usrcmt), ds->cmtoken, comment);
	}
	if (R_STR_ISEMPTY (ds->comment)) {
		R_FREE (ds->comment);
		return;
	}
	linelen = strlen (ds->comment) + 5;
	if (ds->show_cmt_right_default) {
		if (ds->ocols + linelen < core->cons->columns) {
			if (!strchr (ds->comment, '\n')) { // more than one line?
				ds->show_cmt_right = true;
			}
		}
	}
	if (!ds->show_cmt_right) {
		ds_begin_line (ds);
		int mycols = ds->lcols;
		if ((mycols + linelen + 10) > core->cons->columns) {
			mycols = 0;
		}
		mycols /= 2;
		if (ds->show_color) {
			r_cons_print (cons, ds->pal_comment);
		}
		/* print multiline comment */
		if (ds->cmtfold) {
			char *p = strdup (ds->comment);
			char *q = strchr (p, '\n');
			if (q) {
				*q = 0;
				r_cons_printf (cons, "%s ; [z] unfold", p);
			}
			free (p);
		} else {
			ds_pre_xrefs (ds, false);
			if (ds->show_color) {
				r_cons_print (cons, ds->color_usrcmt);
			}
			ds_comment (ds, false, "%s", ds->comment);
		}
		if (ds->show_color) {
			ds_print_color_reset (ds);
		}
		R_FREE (ds->comment);
		ds_newline (ds);
		/* flag comments */
		if (item) {
			const char *item_comment = r_flag_item_set_comment (core->flags, item, NULL);
			if (item_comment && ds->ocomment != item_comment) {
				ds_begin_line (ds);
				ds_newline (ds);
				ds_begin_line (ds);
				if (ds->show_color) {
					r_cons_print (cons, ds->pal_comment);
				}
				r_cons_print (cons, "  ;  ");
				r_cons_print_justify (cons, item_comment, mycols, ';');
				ds_newline (ds);
				if (ds->show_color) {
					ds_print_color_reset (ds);
				}
			}
		}
	}
	ds->show_cmt_right = scr;
}

static ut64 flagVal(const void *a) {
	const RFlagItem *fa = a;
	return r_str_hash64 (fa->realname? fa->realname: fa->name);
}

#if 0
static int flagCmp(const void *a, const void *b) {
	const RFlagItem *fa = a;
	const RFlagItem *fb = b;
	if (fa->realname && fb->realname) {
		return strcmp (fa->realname, fb->realname);
	}
	return strcmp (fa->name, fb->name);
}
#endif

static void __preline_flag(RDisasmState *ds, RFlagItem *fi) {
	R_RETURN_IF_FAIL (ds && fi);
	ds_newline (ds);
	ds_begin_line (ds);
	ds_pre_line (ds);
	RCons *cons = ds->core->cons;
	if (ds->show_color) {
		bool hasColor = false;
		RFlagItemMeta *fim = r_flag_get_meta (ds->core->flags, fi->id);
		if (fim && fim->color) {
			char *color = r_cons_pal_parse (cons, fim->color, NULL);
			if (color) {
				r_cons_print (cons, color);
				free (color);
				ds->lastflag = fi;
				hasColor = true;
			}
		}
		if (!hasColor) {
			r_cons_print (cons, ds->color_flag);
		}
	}
	if (!ds->show_offset) {
		r_cons_printf (ds->core->cons, "     ");
	}
}

static bool is_first(const char *fs) {
	if (fs) {
		if (strstr (fs, "segment")) {
			return true;
		}
		if (strstr (fs, "section")) {
			return true;
		}
		if (strstr (fs, "format")) {
			return true;
		}
		if (strstr (fs, "class")) {
			return true;
		}
	}
	return false;
}

static RList *custom_sorted_flags(const RList *flaglist) {
	if (!flaglist) {
		return NULL;
	}
	RListIter *iter;
	RFlagItem *fi;
	RList *list = r_list_uniq (flaglist, flagVal);
	RList *res = r_list_newf (NULL);
	RList *rest = r_list_newf (NULL);
	RList *tail = r_list_newf (NULL);
	r_list_foreach (list, iter, fi) {
		const char *fs = fi->space? fi->space->name: NULL;
		if (is_first (fs)) {
			r_list_append (res, fi);
		} else {
			r_list_append (rest, fi);
		}
	}
	r_list_foreach (rest, iter, fi) {
		const char *fs = R_UNWRAP3 (fi, space, name);
		if (fs && !strcmp (fs, "registers")) {
			r_list_append (tail, fi);
		} else {
			r_list_append (res, fi);
		}
	}
	r_list_foreach (tail, iter, fi) {
		r_list_append (res, fi);
	}
	r_list_free (tail);
	r_list_free (rest);
	list->free = NULL;
	r_list_free (list);
	return res;
}

#define printPre (outline || !*comma)
static bool ds_show_flags(RDisasmState *ds, bool overlapped) {
	RCons *cons = ds->core->cons;
	RFlagItem *flag;
	RListIter *iter;

	if (ds->asm_flags_right || !ds->show_flags) {
		return false;
	}
	RCore *core = ds->core;
	char addr[64] = {0};
	ut64 switch_addr = UT64_MAX;
	int case_start = -1, case_prev = 0, case_current = 0;
	RAnalFunction *f = r_anal_get_function_at (ds->core->anal, ds->at);
	const RList *flaglist = r_flag_get_list (core->flags, ds->at);
	RList *uniqlist = custom_sorted_flags (flaglist);
	int count = 0;
	bool outline = !ds->flags_inline;
	const char *comma = "";
	bool keep_lib = r_config_get_b (core->config, "bin.demangle.pfxlib");
	bool docolon = true;
	int nth = 0;
	bool any = false;
	r_list_foreach (uniqlist, iter, flag) {
		if (!overlapped && f && f->addr == flag->addr && !strcmp (flag->name, f->name)) {
			// do not show non-overlapped flags that have the same name as the function
			// do not show flags that have the same name as the function
			continue;
		}
		bool no_fcn_lines = (!overlapped && f && f->addr == flag->addr);
		if (ds->maxflags && count >= ds->maxflags) {
			if (printPre) {
				ds_pre_xrefs (ds, no_fcn_lines);
			}
			r_cons_print (cons, "...");
			break;
		}
		count++;
		if (r_str_startswith (flag->name, "case.")) {
			char *chop = strdup (flag->name + strlen ("case."));
			char *dot = strchr (chop, '.');
			if (dot) {
				int mul = 1;
				*dot++ = 0;
				if (*dot == '_') {
					mul = -1;
					dot++;
				}
				ut64 saddr = r_num_get (core->num, chop);
				case_current = mul * atoi (dot);
				snprintf (addr, sizeof (addr), "0x%08"PFMT64x, saddr);
				R_FREE (chop);
				if (case_start == -1) {
					switch_addr = saddr;
					case_prev = case_current;
					case_start = case_current;
					if (iter != uniqlist->tail) {
						continue;
					}
				}
				if (case_current == case_prev + 1 && switch_addr == saddr) {
					case_prev = case_current;
					if (iter != uniqlist->tail) {
						continue;
					}
				}
			}
			R_FREE (chop);
		}
		if (printPre) {
			ds_begin_line (ds);
		}

		bool fake_flag_marks = (!ds->show_offset && ds->show_marks);
		if (printPre) {
			if (ds->show_flgoff) {
				ds_pre_line (ds);
				ds_print_offset (ds);
				if (!fake_flag_marks) {
					r_cons_printf (cons, " ");
				}
			} else {
				ds_pre_xrefs (ds, no_fcn_lines);
			}
		}

		bool hasColor = false;
		char *color = NULL;
		if (ds->show_color) {
			const char *fcolor = r_flag_item_set_color (core->flags, flag, NULL);
			if (fcolor) {
				color = r_cons_pal_parse (core->cons, fcolor, NULL);
				if (color) {
					r_cons_print (cons, color);
					ds->lastflag = flag;
					hasColor = true;
				}
			}
			if (!hasColor) {
				r_cons_print (cons, ds->color_flag);
			}
		}
			any = true;

		if (ds->asm_demangle && flag->realname) {
			if (!strncmp (flag->name, "switch.", 7)) {
				if (ds->flags_prefix) {
					r_cons_printf (cons, FLAG_PREFIX);
				}
				r_cons_printf (cons, "switch:");
			} else if (r_str_startswith (flag->name, "case.")) {
				if (nth > 0) {
					__preline_flag (ds, flag);
				}
				if (ds->flags_prefix) {
					r_cons_printf (cons, FLAG_PREFIX);
				}
				if (!strncmp (flag->name + 5, "default", 7)) {
					r_cons_printf (cons, "default:"); // %s:", flag->name);
					r_str_ncpy (addr, flag->name + 5 + strlen ("default."), sizeof (addr));
					nth = 0;
				} else if (case_prev != case_start) {
					r_cons_printf (cons, "case %d...%d:", case_start, case_prev);
					if (iter != uniqlist->head && iter != uniqlist->tail) {
						iter = iter->p;
					}
					case_start = case_current;
				} else {
					r_cons_printf (cons, "case %d:", case_prev);
					case_start = -1;
				}
				case_prev = case_current;
				ds_align_comment (ds);
				r_cons_printf (cons, "%s%s from %s", ds->show_color ? ds->pal_comment : "", ds->cmtoken, addr);
				outline = false;
				docolon = false;
			} else {
				const char *lang = r_config_get (core->config, "bin.lang");
				char *name = r_bin_demangle (core->bin->cur, lang, flag->realname, flag->addr, keep_lib);
				if (!name) {
					const char *n = flag->realname? flag->realname: flag->name;
					if (n) {
						name = strdup (n);
					}
				}
				if (name) {
					r_str_ansi_filter (name, NULL, NULL, -1);
					if (!ds->flags_inline || nth == 0) {
						if (ds->flags_prefix) {
							r_cons_printf (cons, FLAG_PREFIX);
						}
						if (overlapped) {
							r_cons_printf (cons, "%s(0x%08"PFMT64x")%s ",
									ds->show_color ? ds->color_offset : "", ds->at,
									ds->show_color ? (hasColor ? color : ds->color_flag): "");
						}
					}
					if (outline) {
						r_cons_printf (cons, "%s:", name);
					} else {
						r_cons_printf (cons, "%s%s", comma, flag->name);
					}
					R_FREE (name);
				}
			}
		} else {
			if (outline) {
				r_cons_printf (cons, "%s", flag->name);
			} else {
				r_cons_printf (cons, "%s%s", comma, flag->name);
			}
		}
		if (ds->show_color) {
			r_cons_print (cons, Color_RESET);
		}
		if (outline) {
			ds_newline (ds);
		} else {
			comma = ", ";
		}
		nth++;
		free (color);
	}
	if (!outline && *comma) {
		if (nth > 0 && docolon) {
			r_cons_printf (cons, ":");
		}
		ds_newline (ds);
	}
	r_list_free (uniqlist);
	return any;
}

static void ds_update_ref_lines(RDisasmState *ds) {
	if (ds->show_lines_jmp) {
		free (ds->line);
		free (ds->line_col);
		if (ds->show_lines_split) {
			RAnalRefStr *line2 = r_anal_reflines_str (ds->core, ds->at, ds->linesopts | R_ANAL_REFLINE_TYPE_SPLIT);
			if (line2) {
				free (ds->lineup);
				ds->lineup = strdup (line2->str);
				r_str_reverse (ds->lineup);
				r_str_replace_char (ds->lineup, ':', '|');
				r_str_replace_char (ds->lineup, '=', '-');
				ds->lineup_col = strdup (line2->cols);
			} else {
				ds->lineup = NULL;
			}
			r_anal_reflines_str_free (line2);
		}
		RAnalRefStr *line = r_anal_reflines_str (ds->core, ds->at, ds->linesopts);
		if (!line) {
			return;
		}
		ds->line = line->str;
		ds->line_col = line->cols;
		free (ds->refline);
		ds->refline = ds->line? strdup (ds->line): NULL;
		free (ds->refline2);
		free (ds->prev_line_col);
		free (line);
		line = r_anal_reflines_str (ds->core, ds->at,
			ds->linesopts | R_ANAL_REFLINE_TYPE_MIDDLE_BEFORE);
		ds->refline2 = line->str;
		ds->prev_line_col = line->cols;
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
		free (line);
	} else {
		R_FREE (ds->line);
		R_FREE (ds->line_col);
		R_FREE (ds->prev_line_col);
		free (ds->refline);
		free (ds->refline2);
		free (ds->prev_line_col);
		ds->refline = strdup ("");
		ds->refline2 = strdup ("");
		ds->line = NULL;
		ds->line_col = NULL;
		ds->prev_line_col = NULL;
	}
}

static int ds_disassemble(RDisasmState *ds, ut8 *buf, int len) {
	RCore *core = ds->core;
	RCons *cons = core->cons;
	int ret;

	// find the meta item at this offset if any
	RPVector *metas = r_meta_get_all_at (ds->core->anal, ds->at); // TODO: do in range
	RAnalMetaItem *meta = NULL;
	ut64 meta_size = UT64_MAX;
	if (metas) {
		void **it;
		r_pvector_foreach (metas, it) {
			RIntervalNode *node = *it;
			RAnalMetaItem *mi = node->data;
			switch (mi->type) {
			case R_META_TYPE_DATA:
			case R_META_TYPE_STRING:
			case R_META_TYPE_FORMAT:
			case R_META_TYPE_MAGIC:
			case R_META_TYPE_HIDE:
			case R_META_TYPE_RUN:
				meta = mi;
				meta_size = r_meta_item_size (node->start, node->end);
				break;
			default:
				break;
			}
		}
		r_pvector_free (metas);
	}
	if (ds->hint) {
		if (ds->hint->bits) {
			if (!ds->core->anal->opt.ignbithints) {
				r_config_set_i (core->config, "asm.bits", ds->hint->bits);
			}
		}
		if (ds->hint->size) {
			ds->oplen = ds->hint->size;
		}
		if (ds->hint->opcode) {
			free (ds->opstr);
			ds->opstr = strdup (ds->hint->opcode);
		}
	}
	r_anal_op_fini (&ds->asmop);
	ret = r_asm_disassemble (core->rasm, &ds->asmop, buf, len);
	if (len > ds->asmop.size) {
		len = ds->asmop.size;
	}
	if (!ds->asmop.bytes) {
		// this happens only when the instruction is truncated
		r_anal_op_set_bytes (&ds->asmop, ds->at, buf, len);
	}
	// handle meta here //
	if (!ds->asm_meta) {
		size_t i = 0;
		if (meta && meta_size > 0 && meta->type != R_META_TYPE_HIDE) {
			// XXX this is just noise. should be rewritten
			switch (meta->type) {
			case R_META_TYPE_DATA:
#if 0
				if (!R_STR_ISEMPTY (meta->str)) {
					r_cons_printf (".data: %s\n", meta->str);
				}
#endif
				i += meta_size;
				break;
			case R_META_TYPE_STRING:
				i += meta_size;
				break;
			case R_META_TYPE_FORMAT:
				r_cons_printf (cons, ".format : %s\n", meta->str);
				i += meta_size;
				break;
			case R_META_TYPE_MAGIC:
				r_cons_printf (cons, ".magic : %s\n", meta->str);
				i += meta_size;
				break;
			case R_META_TYPE_RUN:
				{
					char *s = r_core_cmd_strf (core, "%s@%"PFMT64d, meta->str, ds->at);
					r_str_trim (s);
					r_cons_printf (cons, "%s (Cr %d %s)\n%s", ds->cmtoken, (int)meta_size, meta->str, s);
					free (s);
					i += meta_size;
				}
				break;
			default:
				break;
			}
			int sz = R_MIN (16, meta_size);
			ds->asmop.size = sz;
			r_anal_op_set_bytes (&ds->asmop, 0, buf, sz);
			const char *tail = (meta_size > 16)? "...": "";
			r_strf_buffer (256);
			switch (meta->type) {
			case R_META_TYPE_STRING:
				r_anal_op_set_mnemonic (&ds->asmop, 0, r_strf (".string \"%s%s\"", meta->str, tail));
				break;
			default: {
				char *op_hex = r_hex_bin2strdup (ds->asmop.bytes, ds->asmop.size);
				if (!op_hex) {
					R_LOG_ERROR ("Cannot get hex");
					break;
				}
				r_anal_op_set_mnemonic (&ds->asmop, 0, r_strf (".hex %s%s", op_hex, tail));
				const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (core->rasm->config);
				const int immbase = (ds->hint && ds->hint->immbase)? ds->hint->immbase: 0;
				switch (meta_size) {
				case 2:
					ds->analop.val = r_read_ble16 (buf, be);
					r_anal_op_set_mnemonic (&ds->asmop, 0, r_strf (".word 0x%04hx%s", (ut16)ds->analop.val, tail));
					break;
				case 4:
					ds->analop.val = r_read_ble32 (buf, be);
					switch (immbase) {
					case 10:
						r_anal_op_set_mnemonic (&ds->asmop, 0, r_strf (".int32 %d%s", (st32)ds->analop.val, tail));
						break;
					case 32:
						{
							ut32 oval = ds->analop.val;
							ut32 eval  = r_read_le32 (&oval);
							r_anal_op_set_mnemonic (&ds->asmop, 0, r_strf (".ipaddr 0x%08x%s", (ut32)eval, tail));
						}
						break;
					default:
						r_anal_op_set_mnemonic (&ds->asmop, 0, r_strf (".dword 0x%08x%s", (ut32)ds->analop.val, tail));
						break;
					}
					break;
				case 8:
					ds->analop.val = r_read_ble64 (buf, be);
					r_anal_op_set_mnemonic (&ds->asmop, 0, r_strf (".qword 0x%016"PFMT64x"%s", ds->analop.val, tail));
					break;
				}
				free (op_hex);
				break;
			}
			}
			ds->oplen = meta_size;
			return i;
		}
	}

	if (ds->show_nodup) {
		const char *opname = (ret < 1)? "invalid": ds->asmop.mnemonic;
		if (ds->prev_ins && !strcmp (ds->prev_ins, opname)) {
			if (!ds->prev_ins_eq) {
				ds->prev_ins_eq = true;
				r_cons_printf (cons, "...");
			}
			ds->prev_ins_count++;
			return -31337;
		}
		if (ds->prev_ins_eq) {
			r_cons_printf (cons, "dup (%d)\n", ds->prev_ins_count);
		}
		ds->prev_ins_count = 0;
		ds->prev_ins_eq = false;
		if (ds->prev_ins) {
			R_FREE (ds->prev_ins);
		}
		ds->prev_ins = strdup (ds->asmop.mnemonic);
	}
	ds->oplen = ds->asmop.size;

	if (ret < 1) {
		ret = -1;
#if HASRETRY
		if (!ds->count_bytes && ds->tries > 0) {
			ds->at = core->rasm->pc;
			ds->index = ds->at - ds->addr;
			ds->tries--;
			return ret;
		}
#endif
		ds->lastfail = 1;
		ds->asmop.size = (ds->hint && ds->hint->size) ? ds->hint->size : 1;
	} else {
		ds->lastfail = 0;
		if (ds->hint && ds->hint->size) {
			ds->asmop.size = ds->hint->size;
		}
	}
	ds->oplen = ds->asmop.size;
	if (ds->pseudo) {
		const char *str = ds->opstr ? ds->opstr : ds->asmop.mnemonic;
		char *res = r_asm_parse_pseudo (core->rasm, str);
		if (res) {
			free (ds->opstr);
			ds->opstr = strdup (res);
		}
	}
	if (ds->acase) {
		r_str_case (ds->asmop.mnemonic, 1);
	} else if (ds->capitalize) {
		char *ba = ds->asmop.mnemonic;
		*ba = toupper ((ut8)*ba);
	}
	if (meta && meta_size != UT64_MAX) {
		ds->oplen = meta_size;
	}
	return ret;
}

static void ds_control_flow_comments(RDisasmState *ds) {
	if (ds->show_comments && ds->show_cmt_flgrefs) {
		RFlagItem *item;
		if (ds->asm_anal) {
			switch (ds->analop.type) {
			case R_ANAL_OP_TYPE_CALL:
				r_core_cmdf (ds->core, "af @ 0x%"PFMT64x, ds->analop.jump);
				break;
			}
		}
		switch (ds->analop.type) {
		case R_ANAL_OP_TYPE_SWI:
			if (ds->analop.jump == UT64_MAX) {
				break;
			}
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_CALL:
			item = r_flag_get_in (ds->core->flags, ds->analop.jump);
			if (item) {
				const char *cmt = r_flag_item_set_comment (ds->core->flags, item, NULL);
				if (cmt) {
					RCons *cons = ds->core->cons;
					if (ds->show_color) {
						r_cons_print (cons, ds->pal_comment);
					}
					ds_align_comment (ds);
					const char *cmt = r_flag_item_set_comment (ds->core->flags, item, NULL);
					r_cons_printf (cons, "  ; ref to %s: %s\n", item->name, cmt);
					ds_print_color_reset (ds);
				}
			}
			break;
		}
	}
}

static void ds_print_lines_split(RDisasmState *ds) {
	if (ds->show_lines_split) {
		ds_print_ref_lines (ds, ds->lineup, ds->lineup_col, true);
	}
}

static void ds_print_lines_right(RDisasmState *ds) {
#if 0
	if (ds->show_lines_split) {
		ds_print_ref_lines (ds, ds->lineup, ds->lineup_col);
		r_cons_printf (ds->core->cons, "--");
	}
#endif
	if (ds->linesright && ds->show_lines_jmp && ds->line) {
		ds_print_ref_lines (ds, ds->line, ds->line_col, false);
	}
}

static void printCol(RDisasmState *ds, char *sect, int cols, const char *color) {
	int pre;
	if (cols < 8) {
		cols = 8;
	}
	int outsz = cols + 32;
	char *out = malloc (outsz);
	if (!out) {
		return;
	}
	memset (out, ' ', outsz);
	out[outsz - 1] = 0;
	int sect_len = strlen (sect);

	if (sect_len > cols) {
		sect[cols - 2] = '.';
		sect[cols - 1] = '.';
		sect[cols] = 0;
	}
	if (ds->show_color) {
		pre = strlen (color) + 1;
		snprintf (out, outsz - pre, "%s %s"Color_RESET, color, sect);
		out[outsz - 1] = 0;
	} else {
		r_str_ncpy (out + 1, sect, outsz - 2);
	}
	strcat (out, " ");
	r_cons_print (ds->core->cons, out);
	free (out);
}

static void ds_print_lines_left(RDisasmState *ds) {
	if (ds->linesright) {
		return;
	}
	RCore *core = ds->core;
	if (ds->show_section) {
		char *str = NULL;
		if (ds->show_section_perm) {
			// iosections must die, this should be rbin_section_get
			RIOMap *map = r_io_map_get_at (core->io, ds->at);
			str = strdup (map? r_str_rwx_i (map->perm): "---");
		}
		if (ds->show_section_name) {
			const char *ss = get_section_name (ds);
			str = r_str_appendf (str, " %s", ss? ss: "");
		}
		char *sect = str? str: strdup ("");
		printCol (ds, sect, ds->show_section_col, ds->color_reg);
		free (sect);
	}
	if (ds->show_symbols) {
		const char *name = "";
		int delta = 0;
		if (ds->fcn) {
			ds->sfi.addr = ds->fcn->addr;
			ds->sfi.name = ds->fcn->name;
			ds->lastflag = &ds->sfi;
		} else {
			RFlagItem *fi = r_flag_get_at (core->flags, ds->at, !ds->lastflag);
			if (fi) {
				ds->sfi.addr = fi->addr;
				ds->sfi.name = fi->name;
				ds->lastflag = &ds->sfi;
			}
		}
		if (ds->lastflag && ds->lastflag->name) {
			name = ds->lastflag->name;
			delta = ds->at - ds->lastflag->addr;
		}
		{
			char *str = r_str_newf ("%s + %-4d", name, delta);
			printCol (ds, str, ds->show_symbols_col, ds->color_num);
			free (str);
		}
	}
	if (ds->line) {
		ds_print_ref_lines (ds, ds->line, ds->line_col, false);
	}
}

static void ds_print_family(RDisasmState *ds) {
	if (ds->show_family) {
		const char *familystr = r_anal_op_family_tostring (ds->analop.family);
		r_cons_printf (ds->core->cons, "%5s ", r_str_get (familystr));
	}
}

static void ds_print_cycles(RDisasmState *ds) {
	RCons *cons = ds->core->cons;
	if (ds->show_cycles) {
		if (!ds->analop.failcycles) {
			r_cons_printf (cons, "%3d     ", ds->analop.cycles);
		} else {
			r_cons_printf (cons, "%3d %3d ", ds->analop.cycles, ds->analop.failcycles);
		}
	}
	if (ds->cyclespace) {
		char spaces [32];
		int times = R_MIN (ds->analop.cycles/4, 30); // limit to 30
		memset (spaces, ' ', sizeof (spaces));
		spaces[times] = 0;
		r_cons_print (cons, spaces);
	}
}

#define R_INCLUDE_BEGIN 1
#include "disasm_stackptr.inc.c"
#undef R_INCLUDE_BEGIN

R_API char *r_core_get_reloff(RCore *core, int type, ut64 at, st64 *delta) {
	char *label = NULL;
	if (!label && type & RELOFF_TO_FUNC) {
		RAnalFunction *f = r_anal_get_function_at (core->anal, at);
		if (f) {
			*delta = at - f->addr;
			label = strdup (f->name);
		}
	}
	if (!label && type & RELOFF_TO_FLAG) {
		RFlagItem *fi = r_flag_get_at (core->flags, at, true);
		if (fi) {
			*delta = at - fi->addr;
			label = strdup (fi->name);
		}
	}
	if (!label && type & RELOFF_TO_MAPS) {
		RIOMap *map = r_io_map_get_at (core->io, at);
		if (map) {
			*delta = at - r_io_map_begin (map);
			if (map->name) {
				label = strdup (map->name);
			} else {
				label = r_str_newf ("map(%d)", map->id);
			}
		}
	}
	if (!label && type & RELOFF_TO_FILE) {
		RIOMap *map = r_io_map_get_at (core->io, at);
		if (map) {
			*delta = at - r_io_map_begin (map) + map->delta;
			label = r_str_newf ("fd(%d)", map->fd);
		}
	}
	if (!label && type & RELOFF_TO_FMAP) {
		RFlag *f = core->flags;
		r_flag_space_push (f, "maps");
		RFlagItem *fi = r_flag_get_at (f, at, true);
		if (fi) {
			*delta = at - fi->addr;
			label = r_str_trim_dup (fi->name);
		}
		r_flag_space_pop (f);
	}
	if (!label && type & RELOFF_TO_LIBS) {
		RFlag *f = core->flags;
		r_flag_space_push (f, "libs");
		RFlagItem *fi = r_flag_get_at (f, at, true);
		if (fi) {
			*delta = at - fi->addr;
			label = strdup (fi->name);
			r_str_trim (label);
		}
		r_flag_space_pop (f);
	}
	if (!label && type & RELOFF_TO_SYMB) {
#if 0
		// TODO
#endif
	}
	if (!label && type & RELOFF_TO_SECT) {
		RBinObject *bo = r_bin_cur_object (core->bin);
		RBinSection *s = bo? r_bin_get_section_at (bo, at, core->io->va): NULL;
		if (s) {
			*delta = at - s->vaddr;
			label = strdup (s->name);
		}
	}
	if (!label && type & RELOFF_TO_DMAP) {
		RDebugMap *dmap = r_debug_map_get (core->dbg, at);
		if (dmap) {
			*delta = at - dmap->addr;
			label = strdup (dmap->name);
		}
	}
	return label;
}

static char *get_reloff(RDisasmState *ds, ut64 at, st64 *delta) {
	char *label = NULL;
	RCore *core = ds->core;
	int type = ds->show_reloff_to;
	// this is dupped from the public api because we do some caching here
	if (!label && type & RELOFF_TO_FUNC) {
		RAnalFunction *f = r_anal_get_function_at (core->anal, at);
		if (!f) {
			f = fcnIn (ds, at, R_ANAL_FCN_TYPE_NULL); // r_anal_get_fcn_in (core->anal, at, R_ANAL_FCN_TYPE_NULL);
		}
		if (f) {
			*delta = at - f->addr;
			ds->sfi.name = f->name;
			ds->sfi.addr = f->addr;
			ds->lastflag = &ds->sfi;
			label = strdup (f->name);
		}
		if (!ds->lastflag) {
			*delta = 0;
		}
	}
	if (!label && type & RELOFF_TO_FLAG) {
		RFlagItem *fi = r_flag_get_in (core->flags, at);
		if (fi) {
			ds->lastflag = fi;
		}
		if (ds->lastflag) {
			if (ds->lastflag->addr == at) {
				*delta = 0;
			} else {
				*delta = at - ds->lastflag->addr;
			}
		} else {
			*delta = at - core->addr;
		}
		if (ds->lastflag) {
			label = strdup (ds->lastflag->name);
		}
	}
	if (label) {
		return label;
	}
	return r_core_get_reloff (ds->core, ds->show_reloff_to, at, delta);
}

static void ds_print_offset(RDisasmState *ds) {
	RCore *core = ds->core;
	RCons *cons = core->cons;
	ut64 at = ds->vat;

	bool hasCustomColor = false;
	// probably tooslow
	RFlagItem *f = r_flag_get_at (core->flags, at, 1);
	const char *fcolor = NULL;
	if (f && ds->show_flag_in_offset && f->addr == at) {
		ds_newline (ds);
		if (ds_show_flags (ds, false)) {
			ds_begin_cont (ds);
		}
		fcolor = r_flag_item_set_color (core->flags, f, NULL);
	}
	if (ds->show_color && f && fcolor) {
		if (ds->at >= f->addr && ds->at < f->addr + f->size) {
			char *k = r_cons_pal_parse (cons, fcolor, NULL);
			if (R_STR_ISNOTEMPTY (k)) {
				r_cons_printf (cons, "%s", k);
				hasCustomColor = true;
				free (k);
			}
		}
	}
	// r_print_set_screenbounds (core->print, at);
	if (ds->show_offset) {
		char *label = NULL;
		st64 delta = -1;
		bool show_trace = false;

		if (ds->show_reloff) {
			label = get_reloff (ds, at, &delta);
			// label = r_core_get_reloff (ds->core, ds->show_reloff_to, at, &delta);
		}
		if (ds->show_trace) {
			RDebugTracepointItem *tp = r_debug_trace_get (ds->core->dbg, ds->at);
			show_trace = (tp? !!tp->count: false);
		}
		if (ds->hint && ds->hint->high) {
			show_trace = true;
		}
		if (hasCustomColor) {
			int of = core->print->flags;
			core->print->flags = 0;
			r_print_offset (core->print, at, (at == ds->dest) || show_trace, delta, label);
			core->print->flags = of;
			r_cons_print (core->cons, Color_RESET);
		} else {
			if (ds->show_offset_focus) {
				ut64 bb = r_anal_get_bbaddr (core->anal, at);
				bool incur = core->print->cur_enabled && (at == core->addr + ds->cursor);
				if (incur || bb == at || bb == UT64_MAX || ds->analop.jump != UT64_MAX) {
					r_print_offset (core->print, at, (at == ds->dest) || show_trace, delta, label);
				} else {
					char atstr[64];
					snprintf (atstr, sizeof (atstr), " 0x%08"PFMT64x, at);
					memset (atstr, ' ', strlen (atstr));
					r_cons_print (core->cons, atstr);
				}
			} else {
				r_print_offset (core->print, at, (at == ds->dest) || show_trace, delta, label);
			}
		}
		free (label);
	}
	if (ds->atabsoff > 0 && ds->show_offset) {
		if (ds->_tabsoff != ds->atabsoff) {
			// TODO optimize to avoid down resizing
			char *b = malloc (ds->atabsoff + 1);
			if (b) {
				memset (b, ' ', ds->atabsoff);
				b[ds->atabsoff] = 0;
				free (ds->_tabsbuf);
				ds->_tabsbuf = b;
				ds->_tabsoff = ds->atabsoff;
			}
		}
		r_cons_print (ds->core->cons, ds->_tabsbuf);
	}
}

static void ds_print_op_size(RDisasmState *ds) {
	if (ds->show_size) {
		int size = ds->oplen;
		r_cons_printf (ds->core->cons, "%d ", size);
	}
}

static void ds_print_trace(RDisasmState *ds) {
	RCons *cons = ds->core->cons;
	RDebugTracepointItem *tp = NULL;
	if (ds->show_trace && ds->show_trace_stats) {
		tp = r_debug_trace_get (ds->core->dbg, ds->at);
		r_cons_printf (cons, "%02x:%04x ", tp? tp->times: 0, tp? tp->count: 0);
	}
	if (ds->tracespace) {
		if (!tp) {
			tp = r_debug_trace_get (ds->core->dbg, ds->at);
		}
		if (tp) {
			char spaces[32];
			int times = R_MIN (tp->times, 30); // limit to 30
			memset (spaces, ' ', sizeof (spaces));
			spaces[times] = 0;
			r_cons_print (cons, spaces);
		}
	}
}

static void ds_adistrick_comments(RDisasmState *ds) {
	if (ds->adistrick) {
		ds->middle = r_anal_reflines_middle (ds->core->anal,
			ds->core->anal->reflines, ds->at, ds->analop.size);
	}
}

// TODO move into RAnal.meta
static bool ds_print_data_type(RDisasmState *ds, const ut8 *obuf, int ib, int size) {
	RCore *core = ds->core;
	const char *type = NULL;
	char msg[64];
	const bool isSigned = (ib == 1 || ib == 8 || ib == 10);
	switch (size) {
	case 1: type = isSigned? ".char": ".byte"; break;
	case 2: type = isSigned? ".int16": ".word"; break;
	case 3: type = "htons"; break;
	case 4: type = isSigned? ".int32": ".dword"; break;
	case 8: type = isSigned? ".int64": ".qword"; break;
	case 31: type = ".smi"; break;
	default: return false;
	}
	ut8 buf[sizeof (ut64)] = {0};
	memcpy (buf, obuf, R_MIN (sizeof (ut64), size));
	// adjust alignment
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (core->rasm->config);
	ut64 n = r_read_ble (buf, be, size * 8);
	if (ds->asm_hint_imm) { // thats not really an imm.. but well dont add more hints for now
		(void) ds_print_shortcut (ds, n, ds->asm_hint_pos);
	}
	RCons *cons = core->cons;
	if (r_config_get_b (core->config, "asm.marks")) {
		r_cons_printf (cons, "  ");
		int q = core->print->cur_enabled &&
			ds->cursor >= ds->index &&
			ds->cursor < (ds->index + size);
		if (q) {
			if (ds->cursor > ds->index) {
				int diff = ds->cursor - ds->index;
				r_cons_printf (cons, "%d  ", diff);
			} else if (ds->cursor == ds->index) {
				r_cons_mark (cons, ds->at, "cursor");
				r_cons_printf (cons, "*  ");
			} else {
				r_cons_printf (cons, "   ");
			}
		} else {
			r_cons_printf (cons, "   ");
		}
	}
	if (R_STR_ISNOTEMPTY (ds->color_mov)) {
		r_cons_print (cons, ds->color_mov);
	}
	switch (ib) {
	case 1:
		r_str_bits (msg, buf, size * 8, NULL);
		r_cons_printf (cons, "%s %sb", type, msg);
		break;
	case 3:
		r_cons_printf (cons, "%s %d", type, ntohs (n & 0xFFFF));
		break;
	case 8:
		r_cons_printf (cons, "%s %" PFMT64o "o", type, n);
		break;
	case 10:
		r_cons_printf (cons, "%s %" PFMT64d, type, n);
		break;
	case 31:
		r_cons_printf (cons, "%s 0x%02x", type, (ut32)(n & UT32_MAX) >> 1);
		break;
	default:
		switch (size) {
		case 1:
			r_cons_printf (cons, "%s 0x%02" PFMT64x, type, n);
			break;
		case 2:
			r_cons_printf (cons, "%s 0x%04" PFMT64x, type, n);
			break;
		case 4:
			r_cons_printf (cons, "%s 0x%08" PFMT64x, type, n);
			break;
		case 8:
			r_cons_printf (cons, "%s 0x%016" PFMT64x, type, n);
			break;
		default:
			return false;
		}
	}

	if (size == 4 || size == 8) {
		if (isarm (core)) {
			ut64 bits = r_config_get_i (core->config, "asm.bits");
			// adjust address for arm/thumb address
			if ((bits < 64) && (n & 1)) {
				n--;
			}
		}
		if (n >= ds->min_ref_addr) {
			const RList *flags = r_flag_get_list (core->flags, n);
			RListIter *iter;
			RFlagItem *fi;
			r_list_foreach (flags, iter, fi) {
				r_cons_printf (cons, " %s %s", ds->cmtoken, fi->name);
			}
		}
	}
	return true;
}

static bool ds_print_meta_infos(RDisasmState *ds, ut8* buf, int len, int idx, int *mi_type) {
	bool ret = false;
	RAnalMetaItem *fmi;
	RCore *core = ds->core;
	RCons *cons = core->cons;
	if (!ds->asm_meta) {
		return false;
	}
	RPVector *metas = r_meta_get_all_in (core->anal, ds->at, R_META_TYPE_ANY);
	if (!metas) {
		return false;
	}
	bool once = true;
	fmi = NULL;
	void **it;
	r_pvector_foreach (metas, it) {
		RIntervalNode *node = *it;
		RAnalMetaItem *mi = node->data;
		switch (mi->type) {
		case R_META_TYPE_BIND:
			if (ds->at == node->start) {
				ut64 n = r_num_get (NULL, mi->str);
				if (n != 0 && n != UT64_MAX) {
					ds_print_shortcut (ds, n, 0);
				}
			}
			break;
		case R_META_TYPE_DATA:
			if (once) {
				// TODO: check in range if (ds->at == node->start) {
				if (ds->asm_hint_pos == 0) {
					if (ds->asm_hint_lea) {
						ds_print_shortcut (ds, node->start, 0);
					} else {
						r_cons_print (cons, "   ");
					}
				}
				once = false;
			}
			break;
		case R_META_TYPE_STRING:
			fmi = mi;
			break;
		default:
			break;
		}
	}
	r_pvector_foreach (metas, it) {
		RIntervalNode *node = *it;
		RAnalMetaItem *mi = node->data;
		ut64 mi_size = r_meta_node_size (node);
		char *out = NULL;
		int hexlen;
		int delta;
		if (fmi && mi != fmi) {
			continue;
		}
		if (mi_type) {
			*mi_type = mi->type;
		}
		switch (mi->type) {
		case R_META_TYPE_STRING:
		if (mi->str) {
			bool esc_bslash = core->print->esc_bslash;
			switch (mi->subtype) {
			case R_STRING_ENC_UTF8:
				out = r_str_escape_utf8 (mi->str, false, esc_bslash);
				break;
			case 0:  /* temporary legacy workaround */
				esc_bslash = false;
				/* fallthrough */
			default:
				out = r_str_escape_latin1 (mi->str, false, esc_bslash, false);
			}
			if (!out) {
				break;
			}
			r_cons_printf (cons, "    .string %s\"%s\"%s ; len=%"PFMT64d,
					COLOR (ds, color_btext), out, COLOR_RESET (ds),
					mi_size);
			free (out);
			delta = ds->at - node->start;
			ds->oplen = mi_size - delta;
			ds->asmop.size = (int)mi_size;
			//i += mi->size-1; // wtf?
			R_FREE (ds->line);
			R_FREE (ds->line_col);
			R_FREE (ds->refline);
			R_FREE (ds->refline2);
			R_FREE (ds->prev_line_col);
			ret = true;
			break;
		}
		case R_META_TYPE_HIDE:
			r_cons_printf (cons, "(%"PFMT64d" bytes hidden)", mi_size);
			ds->asmop.size = mi_size;
			ds->oplen = mi_size;
			ret = true;
			break;
		case R_META_TYPE_RUN:
			{
				int obs = core->blocksize;
				ut8 *oblock = core->block;
				core->block = r_mem_dup (core->block, core->blocksize);
				// XXX temporal seek causes UAF char *s = r_core_cmd_strf (core, "%s@%"PFMT64d, mi->str, ds->at);
				char *s = r_core_cmd_strf (core, "s %"PFMT64d";%s;s-", ds->at, mi->str);
				r_str_trim (s);
				r_cons_printf (cons, "%s (Cr %d %s)\n%s", ds->cmtoken, (int)mi_size, mi->str, s);
				free (s);
				ds->asmop.size = mi_size;
				ds->oplen = mi_size;
				ret = true;
				free (core->block);
				core->block = oblock;
				core->blocksize = obs;
			}
			break;
		case R_META_TYPE_DATA:
			hexlen = len - idx;
			delta = ds->at - node->start;
			if (mi_size < hexlen) {
				hexlen = mi_size;
			}
			ds->oplen = mi_size - delta;
			core->print->flags &= ~R_PRINT_FLAGS_HEADER;
			int size = mi_size;
			ut8 *b = malloc (mi_size);
			if (b) {
				int limit = r_config_get_i (core->config, "hex.cols");
				int delta = ds->at - node->start;
#if 0
				if (delta > 0) {
					ds->at -= delta;
				}
#endif
				ds->oplen = R_MIN (mi_size, limit);
				r_io_read_at (core->io, ds->at, b, mi_size);
				if (size > 0 && !ds_print_data_type (ds, b, ds->hint? ds->hint->immbase: 0, mi_size)) {
					int remaining = (size - delta); //  - idx;
					if (size > delta) {
						remaining = R_MAX (remaining, 0);
						// r_cons_printf (cons, "LEFT %d (%d - %d) - %d\n", remaining, size, delta, idx);
						// remaining = R_MIN (mi_size, remaining - idx);
						remaining = R_MIN (limit, remaining);
						if (remaining == 0) {
							remaining = limit;
						}
						RPrint p = *core->print;
						p.flags &= ~R_PRINT_FLAGS_OFFSET;
						p.flags |= R_PRINT_FLAGS_TRIMLAST;
						if (remaining > (len - delta)) {
							size_t calloc_size = R_MAX (len, size - delta);
							if (idx < calloc_size) {
								ut8 *b = calloc (1, calloc_size);
								if (b) {
									memcpy (b, buf, len);
									r_print_hexdump (&p, ds->at,
											b + idx, remaining, 16, 1, 1);
									free (b);
								}
							}
						} else {
							r_print_hexdump (&p, ds->at,
									buf + idx, remaining, 16, 1, 1);
						}
					} else {
						r_cons_printf (cons, "hex size=%d hexlen=%d delta=%d",
								size, hexlen, delta);
					}
					size = remaining;
						// r_cons_printf (cons, "hex size=%d delta=%d\n", size , delta);
					if (delta > 0) {
						ds->at -= delta;
						r_cons_printf (cons, " ; +%d  (%d)", delta, remaining);
					} else {
						r_cons_printf (cons, " ; +0 ");
					}
				}
				free (b);
			}
			core->print->flags |= R_PRINT_FLAGS_HEADER;
			ds->asmop.size = size; // (int)size - (node->start - ds->at);
			ds->oplen = size;
			// ds->asmop.size = 16;
			// ds->oplen = 16;
			R_FREE (ds->line);
			R_FREE (ds->line_col);
			R_FREE (ds->refline);
			R_FREE (ds->refline2);
			R_FREE (ds->prev_line_col);
			ret = true;
			break;
		case R_META_TYPE_FORMAT:
			{
				r_cons_printf (cons, "pf %s # size=%" PFMT64d "\n", mi->str, mi_size);
				size_t len_before, len_after;
				r_cons_get_buffer (core->cons, &len_before);
				r_print_format (core->print, ds->at, buf + idx,
						len - idx, mi->str, R_PRINT_MUSTSEE, NULL, NULL);
				const char *cons_buf = r_cons_get_buffer (core->cons, &len_after);
				if (len_after > len_before && buf && cons_buf[len_after - 1] == '\n') {
					r_cons_drop (cons, 1);
				}
				ds->oplen = ds->asmop.size = (int)mi_size;
				R_FREE (ds->line);
				R_FREE (ds->refline);
				R_FREE (ds->refline2);
				R_FREE (ds->prev_line_col);
				ret = true;
			}
			break;
		default:
			break;
		}
	}
	r_pvector_free (metas);
	return ret;
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
			if (((N * magic) >> (32 + s)) == (N / candidate) ) {
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
	if (!ds->asm_hints || !ds->asm_hint_cdiv) {
		return;
	}
	switch (ds->analop.type) {
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_MUL:
		esil = R_STRBUF_SAFEGET (&ds->analop.esil);
		while (esil) {
			comma = strchr (esil, ',');
			if (!comma) {
				break;
			}
			imm = strtol (esil, &end, 10);
			if (comma == end) {
				divisor = revert_cdiv_magic (imm);
				if (divisor) {
					r_cons_printf (ds->core->cons, " ; CDIV: %"PFMT64d" * 2^n", divisor);
					break;
				}
			}
			esil = comma + 1;
		}
	}
	// TODO: check following SHR instructions
}

static void ds_print_bytes(RDisasmState *ds) {
	if (!ds->show_bytes || ds->nb < 1) {
		return;
	}
	RCore* core = ds->core;
	char pad[128];
	size_t maxpad = sizeof (pad);
	char *nstr, *str = NULL;
	char *flagstr = NULL;
	int oldFlags = core->print->flags;
	char extra[128];
	int j, k;
	int n = ds->at - core->addr;

	if (!ds->show_color_bytes) {
		core->print->flags &= ~R_PRINT_FLAGS_COLOR;
	} else if (ds->show_bytes_ascmt) {
		core->print->flags &= ~R_PRINT_FLAGS_COLOR;
	}
	strcpy (extra, " ");
	if (ds->show_flag_in_bytes) {
		flagstr = r_flag_get_liststr (core->flags, ds->at);
	}
	bool off = false;
	int nb = R_MIN (100, ds->nb);
	if (flagstr) {
		if (nb > 3 && strlen (flagstr) >= nb) {
			flagstr[nb - 3] = '.';
			flagstr[nb - 2] = 0;
		}
		str = r_str_newf ("%s:", flagstr);
		if (nb > 0) {
			k = nb - r_str_ansi_len (str) - 1;
			if (k < 0) {
				k = 0;
			} else if (k >= maxpad) {
				k = maxpad - 1;
			}
			for (j = 0; j < k; j++) {
				pad[j] = ' ';
			}
			pad[j] = '\0';
		} else {
			pad[0] = 0;
		}
		R_FREE (flagstr);
	} else {
		if (ds->show_flag_in_bytes) {
			k = nb - 1;
			if (k < 0 || k > maxpad) {
				k = maxpad;
			}
			for (j = 0; j < k; j++) {
				pad[j] = ' ';
			}
			pad[j] = '\0';
			str = strdup ("");
		} else if (ds->show_bytes_ascii) {
			int i;
			const int bb = nb / 2;
			const int chrlen = R_MIN (ds->oplen, bb);
			const int padlen = bb - chrlen;
			for (i = 0; i < padlen; i++) {
				pad[i] = ' ';
			}
			pad[padlen] = 0;
			str = malloc (chrlen + 1);
			const ut8 *bytes = ds->analop.bytes;
			for (i = 0; i < chrlen; i++) {
				if (IS_PRINTABLE (bytes[i])) {
					str[i] = bytes[i];
				} else {
					str[i] = '.';
				}
			}
			str[chrlen] = 0;
		} else if (ds->show_bytes_asbits) {
			// TODO: use C api instead of calling commands
			char *_opsize = r_core_cmd_strf (core, "aos@0x%08"PFMT64x, ds->at);
			int opsize = atoi (_opsize);
			const int len = 8 * R_MIN (opsize, nb);
			*pad = 0;
			str = r_core_cmd_strf (core, "pb1 %d @ 0x%08"PFMT64x, len, ds->at);
			r_str_trim (str);
			free (_opsize);
		} else {
#if 0
			str = r_hex_bin2strdup (&ds->asmop->bytes, &ds->asmop->size);
#else
			if (ds->oplen < 1) {
				int minopsz = r_anal_archinfo (core->anal, R_ARCH_INFO_MINOP_SIZE);
				ds->oplen = minopsz;
			}
			if (ds->analop.bytes && ds->analop.size > ds->oplen) {
				str = r_hex_bin2strdup (ds->analop.bytes, ds->oplen);
			} else {
				ut8 *bytes = calloc (ds->oplen, 1);
				if (bytes) {
					r_io_read_at (core->io, ds->at, bytes, ds->oplen);
					str = r_hex_bin2strdup (bytes, ds->oplen);
					free (bytes);
				} else {
					str = strdup ("??");
				}
			}
#endif
			ds->print->cur_enabled = (ds->cursor != -1);
			if (ds->show_bytes_opcolor) {
				ds->print->nbcolor = (ds->analop.nopcode > 1)? ds->analop.nopcode: 1;
			} else {
				ds->print->nbcolor = 0;
			}
			// R2R db/cmd/cmd_disassembly
			nstr = r_print_hexpair (ds->print, str, n);
			if (r_str_ansi_len (nstr) > nb) {
				if (!core->print->bytespace) { //  && !ds->show_bytes_align) {
					if (nb % 2) {
						nb--;
						if (ds->show_bytes_align) {
							r_cons_printf (core->cons, " ");
						}
					}
				}
				char *p = (char *)r_str_ansi_chrn (nstr, nb);
				if (p) {
					off = true;
					if (!core->print->bytespace) {
						p--;
					}
				//	eprintf ("PP(%s)=(%s) %d\n", nstr, p, r_str_ansi_len (p));
					p[0] = '.';
					p[1] = '.';
					if (ds->show_bytes_align) {
						p[2] = '\0';
					} else {
						if (core->print->bytespace) {
							int pos = ds->nbytes + 2;
							memset (p + 2, ' ', pos - 2);
							p[pos] = 0;
						} else {
							p[2] = ' ';
							p[3] = '\0';
						}
					}
				}
			}
			ds->print->nbcolor = 0;
			if (ds->print->bytespace) {
				k = (nb + (nb / 2)) - r_str_ansi_len (nstr) + 2;
			} else {
				k = nb - r_str_ansi_len (nstr) + 1;
			}
  			if (k > 0) {
				// setting to sizeof screw up the disasm
				if (k >= maxpad) {
					k = maxpad - 1;
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
	if (ds->show_bytes_align) {
		if (core->print->bytespace) {
			const int d = off? 2: 1;
			const char *air = off? " ":"";
			r_cons_printf (core->cons, "%s%s%s %s", (extra[0] && extra[1])? extra + d: extra, str, pad, air);
		} else {
			r_cons_printf (core->cons, "%s%s%s  ", (extra[0])? extra + 1: extra, str, pad);
		}
	} else {
		r_cons_printf (core->cons, "%s%s %s", pad, str, extra);
	}
	free (str);
	core->print->flags = oldFlags;
}

R_VEC_TYPE(RVecUT64, ut64);

static int bb_cmp(const void *a, const void *b) {
	const RAnalBlock *ba = a;
	const RAnalBlock *bb = b;
	return ba->addr - bb->addr;
}

static int cmp_ut64(const ut64 *a, const void *_b) {
	ut64 *b = (ut64*)_b;
	return *a-*b;
}

static int inbounds(RList *bbs, ut64 addr) {
	int count = 0;
	RAnalBlock *bb;
	RListIter *iter;
	RVecUT64 vec;
	RVecUT64_init (&vec);
	r_list_foreach (bbs, iter, bb) {
		if (bb->jump == UT64_MAX) {
			continue;
		}
		ut64 *found = RVecUT64_find (&vec, &bb->jump, cmp_ut64);
		if (found) {
			// ignore duplicated destinations
			continue;
		}
		RVecUT64_push_back (&vec, &bb->jump);
		if (bb->jump < bb->addr) {
			if (addr >= bb->jump && addr < bb->addr) {
				count++;
			}
		} else {
			if (addr >= (bb->addr + bb->size) && addr < bb->jump) {
				count++;
			}
		}
	}
	RVecUT64_fini (&vec);
	return count;
}

static int instruction_depth(RCore *core, RAnalFunction *f, RAnalBlock *obb) {
	if (!obb->depth && f) {
		RAnalBlock *bb;
		RListIter *iter;
		r_list_sort (f->bbs, bb_cmp);
		r_list_foreach (f->bbs, iter, bb) {
			if (bb->depth) {
				// dont compute twice
				break;
			}
			bb->depth = inbounds (f->bbs, bb->addr);
		}
	}
	return obb->depth;
}

static void ds_print_indent(RDisasmState *ds) {
	if (ds->show_indent) {
		int num = 0;
		RAnalBlock *bb = ds->fcn? r_anal_function_bbget_in (ds->core->anal, ds->fcn, ds->at): NULL;
		if (bb) {
			if (bb->depth) {
				num = bb->depth;
			} else {
				num = instruction_depth (ds->core, ds->fcn, bb);
			}
#if 0
			// find how many bbs since start need to be traversed to reach here
			char *res = r_core_cmd_strf (ds->core, "abp 0x%08"PFMT64x" @ $F~?", bb->addr);
			if (res) {
				num = atoi (res);
				free (res);
			}
#endif
		} else {
			num = 0; // ds->indent_level;
		}
		char indent[128];
		if (num < 0) {
			num = 0;
		}
		num *= ds->indent_space;
		if (num >= sizeof (indent)) {
			num = sizeof (indent) - 1;
		}
		memset (indent, ' ', num);
		indent[num] = 0;
		r_cons_print (ds->core->cons, indent);
	}
}

static void ds_print_vliw(RDisasmState *ds, bool after) {
	const int c = ds->vliw_count;
	const int v = ds->analop.vliw;
	if (after) {
		if (c > 0) {
			ds->vliw_count--;
			if (c == 1) {
				r_cons_printf (ds->core->cons, "}");
			}
		}
	} else {
		if (v > 0) {
			r_cons_printf (ds->core->cons, (c > 0)? "}{": "{");
			ds->vliw_count = v;
		}
	}
}

static void ds_print_optype(RDisasmState *ds) {
	if (ds->show_optype) {
		const char *optype = r_anal_optype_tostring (ds->analop.type);
		ds_print_color_reset (ds);
		const char *pad = r_str_pad (' ', 8 - strlen (optype));
		r_cons_printf (ds->core->cons, "[%s]%s", optype, pad);
	}
}

static void ds_print_opstr(RDisasmState *ds) {
	ds_print_indent (ds);
	if (ds->asm_instr) {
		r_cons_print (ds->core->cons, ds->opstr);
		ds_print_color_reset (ds);
	}
}

static void ds_print_color_reset(RDisasmState *ds) {
	if (ds->show_color) {
		r_cons_print (ds->core->cons, Color_RESET);
	}
}

static int ds_print_middle(RDisasmState *ds, int ret) {
	if (ds->middle != 0) {
		ret -= ds->middle;
		ds_align_comment (ds);
		RCons *cons = ds->core->cons;
		if (ds->show_color) {
			r_cons_print (cons, ds->pal_comment);
		}
		r_cons_printf (cons, " ; *middle* %d", ret);
		if (ds->show_color) {
			r_cons_print (cons, Color_RESET);
		}
	}
	return ret;
}

static bool ds_print_labels(RDisasmState *ds, RAnalFunction *f) {
	const char *label;
	if (!f) {
		// f = r_anal_get_fcn_in (core->anal, ds->at, 0);
		f = fcnIn (ds, ds->at, 0);
	}
	if (!f) {
		return false;
	}
	label = r_anal_function_get_label_at (f, ds->at);
	if (!label) {
		return false;
	}
	ds_pre_line (ds);
	RCons *cons = ds->core->cons;
	if (ds->show_color) {
		r_cons_print (cons, ds->color_label);
		r_cons_printf (cons, " .%s:\n", label);
		ds_print_color_reset (ds);
	} else {
		r_cons_printf (cons, " .%s:\n", label);
	}
	return true;
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
				ds_comment_align (ds);
				ds_comment (ds, true, "%s IO %s", ds->cmtoken, ioname);
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
				ds_comment_align (ds);
				ds_comment (ds, true, "%s REG %s - %s", ds->cmtoken, sr, "");
				// TODO: add register description description
				ds->has_description = true;
			}
		}
		break;
	}
}

static void ds_print_fcn_name(RDisasmState *ds) {
	if (!ds->show_comments) {
		return;
	}
	ut32 optype = ds->analop.type;
	if (optype != R_ANAL_OP_TYPE_JMP
		&& optype != R_ANAL_OP_TYPE_CJMP
		&& optype != R_ANAL_OP_TYPE_CALL) {
		return;
	}
	RAnalFunction *f = fcnIn (ds, ds->analop.jump, R_ANAL_FCN_TYPE_NULL);
	if (!f && ds->core->flags && (!ds->core->vmode || (!ds->subjmp && !ds->subnames))) {
		const char *arch;
		RFlagItem *flag = r_flag_get_by_spaces (ds->core->flags, false, ds->analop.jump,
				R_FLAGS_FS_CLASSES, R_FLAGS_FS_SYMBOLS, NULL);
		if (flag && flag->name
				&& ds->opstr && !strstr (ds->opstr, flag->name)
				&& (r_str_startswith (flag->name, "sym.")
					|| r_str_startswith (flag->name, "method."))
				&& (arch = r_config_get (ds->core->config, "asm.arch"))
				&& strcmp (arch, "dalvik")) {
			RFlagItem *flag_sym = flag;
			if (flag_sym->demangled && ds->core->vmode && ds->asm_demangle
					&& (r_str_startswith (flag->name, "sym.")
						|| (flag_sym = r_flag_get_by_spaces (ds->core->flags, false,
							ds->analop.jump, R_FLAGS_FS_SYMBOLS, NULL)))) {
				return;
			}
			ds_begin_comment (ds);
			ds_comment (ds, true, "%s %s", ds->cmtoken, flag->name);
			return;
		}
	}
	if (!f || !f->name) {
		return;
	}
	st64 delta = ds->analop.jump - f->addr;
	const char *label = r_anal_function_get_label_at (f, ds->analop.jump);
	if (label) {
		ds_begin_comment (ds);
		ds_comment (ds, true, "%s %s.%s", ds->cmtoken, f->name, label);
	} else {
		RAnalFunction *f2 = fcnIn (ds, ds->at, 0);
		if (f == f2) {
			return;
		}
		if (delta > 0) {
			ds_begin_comment (ds);
			ds_comment (ds, true, "%s %s+0x%x", ds->cmtoken, f->name, (unsigned int)delta);
		} else if (delta < 0) {
			ds_begin_comment (ds);
			unsigned int udelta = (unsigned int) -delta;
			ds_comment (ds, true, "%s %s-0x%x", ds->cmtoken, f->name, udelta);
		} else if ((!ds->core->vmode || (!ds->subjmp && !ds->subnames))
			   && (!ds->opstr || !strstr (ds->opstr, f->name))) {
			RFlagItem *flag_sym;
			if (ds->core->vmode
					&& ds->asm_demangle
					&& (flag_sym = r_flag_get_by_spaces (ds->core->flags, false,
						ds->analop.jump,
						R_FLAGS_FS_SYMBOLS, NULL))
					&& flag_sym->demangled) {
				return;
			}
			ds_begin_comment (ds);
			ds_comment (ds, true, "%s %s", ds->cmtoken, f->name);
		}
	}
}

static int ds_print_shortcut(RDisasmState *ds, ut64 addr, int pos) {
	RCons *cons = ds->core->cons;
	char *shortcut = r_core_add_asmqjmp (ds->core, addr);
	int slen = shortcut? strlen (shortcut): 0;
	if (ds->asm_hint_pos > 0) {
		if (pos) {
			ds_align_comment (ds);
		}
	}
	const char *ch = (pos)? ds->cmtoken: "";
	if (ds->asm_hint_pos == -1) {
		ch = " ";
	}
	if (ds->show_color) {
		r_cons_print (cons, ds->pal_hint);
	}
	if (*ch) {
		slen++;
	}
	if (shortcut) {
		if (ds->core->is_asmqjmps_letter) {
			r_cons_printf (cons, "%s[o%s]", ch, shortcut);
			slen++;
		} else {
			r_cons_printf (cons, "%s[%s]", ch, shortcut);
		}
		free (shortcut);
	} else {
		r_cons_printf (cons, "%s[?]", ch);
	}
	if (ds->show_color) {
		if (ds->core->print->resetbg) {
			r_cons_print (cons, Color_RESET);
		} else {
			r_cons_print (cons, Color_RESET_NOBG);
		}
	}
	slen++;
	return slen;
}

static bool ds_print_core_vmode_jump_hit(RDisasmState *ds, int pos) {
	RCore *core = ds->core;
	RAnal *a = core->anal;
	RAnalHint *hint = r_anal_hint_get (a, ds->at);
	bool res = false;
	if (hint) {
		if (hint->jump != UT64_MAX) {
			ds_print_shortcut (ds, hint->jump, pos);
			res = true;
		}
		r_anal_hint_free (hint);
	}
	return res;
}

static ut64 get_ptr(RDisasmState *ds, ut64 addr) {
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (ds->core->rasm->config);
	const int bits = r_config_get_i (ds->core->config, "asm.bits");

	if (bits == 64) {
		ut8 buf[sizeof (ut64)] = {0};
		r_io_read_at (ds->core->io, addr, buf, sizeof (buf));
		return r_read_ble64 (buf, be);
	}
	ut8 buf[sizeof (ut32)] = {0};
	r_io_read_at (ds->core->io, addr, buf, sizeof (buf));
	return (ut64) r_read_ble32 (buf, be);
}

static ut64 get_ptr_ble(RDisasmState *ds, ut64 addr) {
	ut8 buf[sizeof (ut64)] = {0};
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (ds->core->rasm->config);
	ut64 n64_32;
	r_io_read_at (ds->core->io, addr, buf, sizeof (buf));
	if (ds->core->rasm->config->bits == 64) {
		n64_32 = r_read_ble64 (buf, be);
	} else {
		n64_32 = r_read_ble32 (buf, be);
	}
	return n64_32;
}

static bool ds_print_core_vmode(RDisasmState *ds, int pos) {
	RCore *core = ds->core;
	RCons *cons = core->cons;
	bool gotShortcut = false;
	int i, slen = 0;

	if (!core->vmode) {
		return false;
	}
	if (!ds->asm_hints) {
		return false;
	}
	if (ds->asm_hint_emu) {
		if (ds->emuptr && r_io_is_valid_offset (core->io, ds->emuptr, 0)) {
			ds_print_shortcut (ds, ds->emuptr, pos);
			ds->emuptr = 0;
			ds->hinted_line = true;
			gotShortcut = true;
			goto beach;
		}
	}
	if (ds->asm_hint_lea) {
		ut64 size;
		RAnalMetaItem *mi = r_meta_get_at (ds->core->anal, ds->at, R_META_TYPE_ANY, &size);
		if (mi) {
			int obits = ds->core->rasm->config->bits;
			r_arch_config_set_bits (ds->core->rasm->config, size * 8);
			slen = ds_print_shortcut (ds, get_ptr (ds, ds->at), pos);
			r_arch_config_set_bits (ds->core->rasm->config, obits);
			gotShortcut = true;
		}
	}
	switch (ds->analop.type) {
	case R_ANAL_OP_TYPE_UJMP:
	case R_ANAL_OP_TYPE_UJMP | R_ANAL_OP_TYPE_IND:
	case R_ANAL_OP_TYPE_UJMP | R_ANAL_OP_TYPE_IND | R_ANAL_OP_TYPE_COND:
	case R_ANAL_OP_TYPE_UJMP | R_ANAL_OP_TYPE_IND | R_ANAL_OP_TYPE_REG:
		if (ds->asm_hint_lea) {
			if (ds->analop.ptr != UT64_MAX && ds->analop.ptr != UT32_MAX) {
				slen = ds_print_shortcut (ds, get_ptr (ds, ds->analop.ptr), pos);
				gotShortcut = true;
			}
		}
		break;
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_LEA:
	case R_ANAL_OP_TYPE_LOAD:
		if (ds->asm_hint_imm) {
			if (ds->analop.val != UT64_MAX && ds->analop.val != UT32_MAX && ds->analop.val > 256) {
				slen = ds_print_shortcut (ds, ds->analop.val, pos);
				gotShortcut = true;
			}
		} else if (ds->asm_hint_lea) {
			if (ds->analop.ptr != UT64_MAX && ds->analop.ptr != UT32_MAX && ds->analop.ptr > 256) {
				slen = ds_print_shortcut (ds, ds->analop.ptr, pos);
				gotShortcut = true;
			}
		}
		break;
	case R_ANAL_OP_TYPE_UCALL:
	case R_ANAL_OP_TYPE_UCALL | R_ANAL_OP_TYPE_REG | R_ANAL_OP_TYPE_IND:
	case R_ANAL_OP_TYPE_UCALL | R_ANAL_OP_TYPE_IND:
		if (ds->asm_hint_call) {
			if (ds->analop.jump != UT64_MAX) {
				slen = ds_print_shortcut (ds, ds->analop.jump, pos);
			} else {
				ut64 addr;
				if (ds->asm_hint_call_indirect) {
					addr = get_ptr_ble (ds, ds->analop.ptr);
				} else {
					addr = ds->analop.ptr;
				}
				slen = ds_print_shortcut (ds, addr, pos);
			}
			gotShortcut = true;
		}
		break;
	case R_ANAL_OP_TYPE_RJMP:
	case R_ANAL_OP_TYPE_RCALL:
		if (ds->analop.jump != UT64_MAX && ds->analop.jump != UT32_MAX) {
			slen = ds_print_shortcut (ds, ds->analop.jump, pos);
			gotShortcut = true;
		}
		break;
	case R_ANAL_OP_TYPE_SWI:
		if (ds->analop.jump == UT64_MAX) {
			break;
		}
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_CJMP:
		if (ds->asm_hint_jmp) {
			slen = ds_print_shortcut (ds, ds->analop.jump, pos);
			gotShortcut = true;
		}
		break;
	case R_ANAL_OP_TYPE_CALL:
	case R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_CALL:
		if (ds->asm_hint_call) {
			slen = ds_print_shortcut (ds, ds->analop.jump, pos);
			gotShortcut = true;
		}
		break;
	default:
		if (ds_print_core_vmode_jump_hit (ds, pos)) {
			gotShortcut = true;
		}
		break;
	}
beach:
	if (ds->asm_hint_pos > 0) {
		const int begin = gotShortcut ? 2: 3;
		for (i = begin - slen; i > 0; i--) {
			r_cons_print (cons, " ");
		}
	} else if (ds->asm_hint_pos == 0 && !gotShortcut) {
		r_cons_print (cons, "   ");
	}
	ds->hinted_line = gotShortcut;
	return gotShortcut;
}

static void ds_begin_nl_comment(RDisasmState *ds) {
	if (ds->cmtcount > 0 && ds->show_cmt_right) {
		ds_newline (ds);
		ds_begin_cont (ds);
	} else if (ds->cmtcount > 0 || !ds->show_cmt_right) {
		ds_begin_line (ds);
		ds_pre_xrefs (ds, false);
	}
	if (ds->show_color && (ds->cmtcount > 0 || ds->show_cmt_right)) {
		r_cons_print (ds->core->cons, ds->pal_comment);
	}
}

// align for comment
static void ds_align_comment(RDisasmState *ds) {
	if (!ds->show_cmt_right_default) {
		return;
	}
	RCons *cons = ds->core->cons;
	const int cmtcol = ds->cmtcol - 1;
	const char *ll = r_cons_get_buffer (cons, NULL);
	if (!ll) {
		return;
	}
	ll += ds->buf_line_begin;
	int cells = r_str_len_utf8_ansi (ll);
	int cols = ds->interactive ? cons->columns : 1024;
	if (cells < cmtcol) {
		int len = cmtcol - cells;
		if (len < cols && len > 0) {
			r_cons_memset (cons, ' ', len);
		}
	}
	r_cons_print (cons, " ");
}

static void ds_print_dwarf(RDisasmState *ds) {
	RCons *cons = ds->core->cons;
	if (!ds->show_dwarf) {
		return;
	}
	// TODO: cache value in ds
	int dwarfFile = (int)ds->dwarfFile + (int)ds->dwarfAbspath;
	free (ds->sl);
	ds->sl = r_bin_addrline_tostring (ds->core->bin, ds->at, dwarfFile);
	if (ds->sl && (!ds->osl || (ds->osl && strcmp (ds->sl, ds->osl)))) {
		char *line = strdup (ds->sl);
		if (!line) {
			return;
		}
		r_str_replace_char (line, '\t', ' ');
		r_str_replace_char (line, '\x1b', ' ');
		r_str_replace_char (line, '\r', ' ');
		r_str_replace_char (line, '\n', '\x00');
		r_str_trim (line);
		if (!*line) {
			free (line);
			return;
		}
		// handle_set_pre (ds, "  ");
		ds_align_comment (ds);
		if (ds->show_color) {
			r_cons_printf (cons, "%s%s %s"Color_RESET, ds->pal_comment, ds->cmtoken, line);
		} else {
			r_cons_printf (cons, "%s %s", ds->cmtoken, line);
		}
		free (ds->osl);
		ds->osl = ds->sl;
		ds->sl = NULL;
		free (line);
	}
}

static void ds_print_asmop_payload(RDisasmState *ds, const ut8 *buf) {
	if (ds->show_varaccess) {
		RCons *cons = ds->core->cons;
		// XXX assume analop is filled
		//r_anal_op (core->anal, &ds->analop, ds->at, core->block+i, core->blocksize-i);
		int v = ds->analop.ptr;
		switch (ds->analop.stackop) {
		case R_ANAL_STACK_GET:
			if (v < 0) {
				r_cons_printf (cons, " ; local.get %d", -v);
			} else {
				r_cons_printf (cons, " ; arg.get %d", v);
			}
			break;
		case R_ANAL_STACK_SET:
			if (v < 0) {
				r_cons_printf (cons, " ; local.set %d", -v);
			} else {
				r_cons_printf (cons, " ; arg.set %d", v);
			}
			break;
		default:
			break;
		}
	}
	if (ds->asmop.payload != 0) {
		RCons *cons = ds->core->cons;
		r_cons_printf (cons, "\n; .. payload of %d byte(s)", ds->asmop.payload);
		if (ds->showpayloads) {
			int mod = ds->asmop.payload % ds->core->rasm->dataalign;
			int x;
			for (x = 0; x < ds->asmop.payload; x++) {
				r_cons_printf (cons, "\n        0x%02x", buf[ds->oplen + x]);
			}
			for (x = 0; x < mod; x++) {
				r_cons_printf (cons, "\n        0x%02x ; alignment", buf[ds->oplen + ds->asmop.payload + x]);
			}
		}
	}
}

/* Do not use this function for escaping JSON! */
// XXX overseeded by ds_getstring()
static char *ds_esc_str(RDisasmState *ds, const char *str, int len, const char **prefix_out, bool is_comment) {
	int str_len;
	char *escstr = NULL;
	const char *prefix = "";
	const bool esc_bslash = ds->core->print->esc_bslash;
	RStrEnc strenc = ds->strenc;
	if (strenc == R_STRING_ENC_GUESS) {
		strenc = r_utf_bom_encoding ((ut8 *)str, len);
	}
	switch (strenc) {
	case R_STRING_ENC_LATIN1:
		escstr = r_str_escape_latin1 (str, ds->show_asciidot, esc_bslash, is_comment);
		break;
	case R_STRING_ENC_UTF8:
		escstr = r_str_escape_utf8 (str, ds->show_asciidot, esc_bslash);
		break;
	case R_STRING_ENC_UTF16LE:
		escstr = r_str_escape_utf16le (str, len, ds->show_asciidot, esc_bslash);
		prefix = "u";
		break;
	case R_STRING_ENC_UTF32LE:
		escstr = r_str_escape_utf32le (str, len, ds->show_asciidot, esc_bslash);
		prefix = "U";
		break;
	case R_STRING_ENC_UTF16BE:
		escstr = r_str_escape_utf16be (str, len, ds->show_asciidot, esc_bslash);
		prefix = "ub";
		break;
	case R_STRING_ENC_UTF32BE:
		escstr = r_str_escape_utf32be (str, len, ds->show_asciidot, esc_bslash);
		prefix = "Ub";
		break;
	default:
		str_len = strlen (str);
		if ((str_len == 1 && len > 3 && str[2] && !str[3])
		    || (str_len == 3 && len > 5 && !memcmp (str, "\xff\xfe", 2) && str[4] && !str[5])) {
			escstr = r_str_escape_utf16le (str, len, ds->show_asciidot, esc_bslash);
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
				escstr = r_str_escape_utf32le (str, len, ds->show_asciidot, esc_bslash);
				prefix = "U";
			} else {
				escstr = r_str_escape_latin1 (str, ds->show_asciidot, esc_bslash, is_comment);
			}
		} else {
			RStrEnc enc = R_STRING_ENC_LATIN1;
			const char *ptr = str;
			const char *end = str + str_len;
			for (; ptr < end; ptr++) {
				if (r_utf8_decode ((ut8 *)ptr, end - ptr, NULL) > 1) {
					enc = R_STRING_ENC_UTF8;
					break;
				}
			}
			escstr = (enc == R_STRING_ENC_UTF8 ?
				r_str_escape_utf8 (str, ds->show_asciidot, esc_bslash) :
				r_str_escape_latin1 (str, ds->show_asciidot, esc_bslash, is_comment));
		}
	}
	if (prefix_out) {
		*prefix_out = prefix;
	}
	char *ffff = strstr (escstr, "\\xff\\xff\\xff");
	if (ffff) {
		*ffff = 0;
	}
	return escstr;
}

static void ds_print_str(RDisasmState *ds, const char *str, int len, ut64 refaddr) {
	if (ds->core->flags->realnames || !r_bin_string_filter (ds->core->bin, str, refaddr)) {
		return;
	}
	// do not resolve strings on arm64 pointed with ADRP
	if (ds->analop.type == R_ANAL_OP_TYPE_LEA) {
		if (ds->core->rasm->config->bits == 64 && isarm (ds->core)) {
			return;
		}
	}
	const char *prefix = "";
	char *escstr = ds_getstring (ds, str, len, &prefix);
	if (escstr) {
		bool inv = ds->show_color && !ds->show_emu_strinv;
		ds_begin_comment (ds);
		ds_comment (ds, true, "%s %s%s\"%s\"%s", ds->cmtoken,
				inv? Color_INVERT: "", prefix, escstr,
				inv? Color_INVERT_RESET: "");
		ds->printed_str_addr = refaddr;
		free (escstr);
	}
}

static inline bool is_filtered_flag(RDisasmState *ds, const char *name) {
	if (ds->show_noisy_comments || strncmp (name, "str.", 4)) {
		return false;
	}
	ut64 refaddr = ds->analop.ptr;
	const char *anal_flag = r_meta_get_string (ds->core->anal, R_META_TYPE_STRING, refaddr);
	if (anal_flag) {
		char *dupped = strdup (anal_flag);
		if (dupped) {
			r_name_filter (dupped, -1);
			if (!strcmp (&name[4], dupped)) {
				return true;
			}
		}
	}
	return false;
}

/* convert numeric value in opcode to ascii char or number */
static void ds_print_ptr(RDisasmState *ds, int len, int idx) {
	R_RETURN_IF_FAIL (ds);
	RCore *core = ds->core;
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (core->rasm->config);
	ut64 p = ds->analop.ptr;
	ut64 v = ds->analop.val;
	ut64 refaddr = p;
	bool aligned = false;
	int refptr = ds->analop.refptr;
	RFlagItem *f = NULL, *f2 = NULL;
	bool f2_in_opstr = false; /* Also if true, f exists */
	if (!ds->show_comments || !ds->show_slow) {
		return;
	}
	const int opType = ds->analop.type & R_ANAL_OP_TYPE_MASK;
	bool canHaveChar = false;
	switch (opType) {
	case R_ANAL_OP_TYPE_PUSH:
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_CMP:
		canHaveChar = true;
		break;
	}

	ds->chref = 0;
	if ((char)v > 0 && v >= '!') {
		ds->chref = (char)v;
		if (ds->immstr) {
			char *str = r_str_from_ut64 (r_read_ble64 (&v, be));
			if (R_STR_ISNOTEMPTY (str)) {
				bool printable = true;
				const signed char *ptr = (const signed char *)str;
				for (; *ptr ; ptr++) {
					if (*ptr < 10) {
						printable = false;
					}
				}
				if (printable && r_flag_get_in (core->flags, v)) {
					printable = false;
				}
				if (canHaveChar && printable) {
					char *s = r_str_escape (str);
					s = r_str_replace (s, "'", "\\'", true);
					ds_begin_comment (ds);
					ds_comment (ds, true, "%s '%s'", ds->cmtoken, s);
					free (s);
				}
			}
			free (str);
		} else {
			if (canHaveChar && (char)v > 0 && v >= (int)'!' && v <= (int)'~') {
				ds_begin_comment (ds);
				aligned = true;
				if (v != ds->analop.ptr) {
					ds_comment (ds, true, "%s '%c'", ds->cmtoken, (char)v);
				}
			}
		}
	}

	RVecAnalRef *refs = r_anal_refs_get (core->anal, ds->at);
	if (refs) {
		RAnalRef *ref;
		R_VEC_FOREACH (refs, ref) {
			int rt = R_ANAL_REF_TYPE_MASK (ref->type);
			if (rt == R_ANAL_REF_TYPE_STRN || rt == R_ANAL_REF_TYPE_DATA) {
				if ((f = r_flag_get_in (core->flags, ref->addr))) {
					refaddr = ref->addr;
					break;
				}
			}
		}
	}
	RVecAnalRef_free (refs);

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
	if (refaddr == UT64_MAX) {
		/* do nothing */
	} else if (((st64)p) > 0 || ((st64)refaddr) > 0) {
		const char *kind;
		char *msg = calloc (sizeof (char), len);
		if (((st64)p) > 0) {
			f = r_flag_get_in (core->flags, p);
			if (f) {
				ut64 subrel_addr = core->rasm->parse->subrel_addr;
				if (subrel_addr && subrel_addr != p) {
					f2 = r_core_flag_get_by_spaces (core->flags, false, subrel_addr);
					f2_in_opstr = f2 && ds->opstr && (strstr (ds->opstr, f2->name) || strstr (ds->opstr, f2->realname)) ;
				}
				refaddr = p;
				if (!flag_printed && !is_filtered_flag (ds, f->name)
				    && (!ds->opstr || (!strstr (ds->opstr, f->name) && !strstr (ds->opstr, f->realname)))
				    && !f2_in_opstr) {
					ds_begin_comment (ds);
					ds_comment (ds, true, "%s %s", ds->cmtoken, f->name);
					ds->printed_flag_addr = p;
					flag_printed = true;
				}
			}
		}
		r_io_read_at (core->io, refaddr, (ut8*)msg, len - 1);
		if (refptr && ds->show_refptr) {
			ut64 num = r_read_ble (msg, be, refptr * 8);
			st64 n = (st64)num;
			st32 n32 = (st32)(n & UT32_MAX);
			if (ds->analop.type == R_ANAL_OP_TYPE_LEA) {
				char str[128] = {0};
				f = r_flag_get_in (core->flags, refaddr);
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
				if (n == UT32_MAX || n == UT64_MAX) {
					ds_begin_nl_comment (ds);
					ds_comment (ds, true, "%s [0x%" PFMT64x":%d]=-1",
							ds->cmtoken, refaddr, refptr);
				} else if (n == n32 && (n32 > -512 && n32 < 512)) {
					ds_begin_nl_comment (ds);
					ds_comment (ds, true, "%s [0x%" PFMT64x
							  ":%d]=%"PFMT64d, ds->cmtoken, refaddr, refptr, n);
				} else {
					const char *kind, *flag = "";
					char *msg2 = NULL;
					RFlagItem *f2_ = r_flag_get_in (core->flags, n);
					if (f2_) {
						flag = f2_->name;
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
					//ds_align_comment (ds);
					{
						const char *refptrstr = "";
						if (core->print->flags & R_PRINT_FLAGS_SECSUB) {
							RBinObject *bo = r_bin_cur_object (core->bin);
							RBinSection *s = bo? r_bin_get_section_at (bo, n, core->io->va): NULL;
							if (s) {
								refptrstr = s->name;
							}
						}
						ds_begin_nl_comment (ds);
						ds_comment_start (ds, "%s [", ds->cmtoken);
						if (f && f2_in_opstr) {
							ds_comment_middle (ds, "%s", f->name);
							flag_printed = true;
						} else {
							ds_comment_middle (ds, "0x%" PFMT64x, refaddr);
						}
						ds_comment_end (ds, ":%d]=%s%s0x%" PFMT64x "%s%s",
								refptr, refptrstr, *refptrstr ? "." : "",
								n, (flag && *flag) ? " " : "", flag);
					}
					free (msg2);
				}
				refaddr_printed = true;
			}
		}
		if (!strcmp (ds->show_cmtoff, "true")) {
			ds_begin_comment (ds);
			ds_comment (ds, true, "%s 0x%" PFMT64x, ds->cmtoken, refaddr);
			refaddr_printed = true;
		} else if (!refaddr_printed && strcmp (ds->show_cmtoff, "false")) {
			char addrstr[32] = {0};
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
							ds_begin_nl_comment (ds);
						}
						ds_comment (ds, true, "%s 0x%" PFMT64x, ds->cmtoken, refaddr);
						refaddr_printed = true;
					}
				}
			}
		}
		bool print_msg = true;
#if 1
		if (ds->strenc == R_STRING_ENC_GUESS
		    && r_utf_bom_encoding ((ut8 *)msg, len) == R_STRING_ENC_GUESS
		    && !(IS_PRINTABLE (*msg) || IS_WHITECHAR (*msg))) {
			print_msg = false;
		} else {
			msg[len - 1] = 0;
		}
#endif
		f = r_flag_get_in (core->flags, refaddr);
		if (f) {
			if (strlen (msg) != 1) {
				char *msg2 = strdup (msg);
				if (msg2) {
					r_str_filter (msg2, 0);
					if (!strncmp (msg2, "UH..", 4)) {
						print_msg = false;
					}
					free (msg2);
				}
			}
			if (print_msg) {
				if (!string_printed) {
					ds_print_str (ds, msg, len, refaddr);
					string_printed = true;
				}
			} else if (!flag_printed && (!ds->opstr ||
						(!strstr (ds->opstr, f->name) && !strstr (ds->opstr, f->realname)))) {
				ds_begin_nl_comment (ds);
				ds_comment (ds, true, "%s %s", ds->cmtoken, f->name);
				const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, refaddr);
				if (R_STR_ISNOTEMPTY (comment)) {
					ds_begin_nl_comment (ds);
					ds_begin_comment (ds);
					ds_comment (ds, true, "%s", comment);
				}

				ds->printed_flag_addr = refaddr;
				flag_printed = true;
			}
		} else {
			if (refaddr == UT64_MAX || refaddr == UT32_MAX) {
				ds_begin_comment (ds);
				ds_comment (ds, true, "%s -1", ds->cmtoken);
			} else if (((char)refaddr > 0) && refaddr >= (int)'!' && refaddr <= (int)'~') {
				int ch = refaddr;
				if (ch != ds->chref && canHaveChar) {
					ds_begin_comment (ds);
					if (ch != ds->analop.ptr) {
						ds_comment (ds, true, "%s '%c'", ds->cmtoken, (char)ch);
					}
				}
			} else if (refaddr > 10) {
				if ((st64)refaddr < 0) {
					// resolve local var if possible
					RAnalFunction *fcn = r_anal_get_function_at (core->anal, ds->at);
					RAnalVar *v = fcn ? r_anal_function_get_var (fcn, 'v', (int)refaddr) : NULL;
					ds_begin_comment (ds);
					if (v) {
						ds_comment (ds, true, "%s var %s", ds->cmtoken, v->name);
					} else {
						ds_comment (ds, true, "%s var %d", ds->cmtoken, -(int)refaddr);
					}
				} else {
					if (r_core_anal_address (core, refaddr) & R_ANAL_ADDR_TYPE_ASCII) {
						if (!string_printed && print_msg) {
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
					if (!string_printed && print_msg) {
						ds_print_str (ds, msg, len, refaddr);
						string_printed = true;
					}
				} else if (!strcmp (kind, "invalid")) {
					int n32 = (int)refaddr;
					int *n = &n32; // (int*)&refaddr;
					ut64 p = ds->analop.val;
					if (p == UT64_MAX || p == UT32_MAX) {
						p = ds->analop.ptr;
					}
					/* avoid double ; -1 */
					if (p && p != UT64_MAX && p != UT32_MAX) {
						if (*n > -0xfff && *n < 0xfff) {
							if (!aligned) {
								ds_begin_comment (ds);
							}
							ds_comment (ds, true, "%s %"PFMT64d, ds->cmtoken, p);
						}
					}
				} else {
					// r_cons_printf (ds->core->cons, " ; %s", kind);
				}
				// TODO: check for more data kinds
			}
		}
		free (msg);
	} else {
		ds_print_as_string (ds);
	}
	if (!ds->show_cmt_right && ds->cmtcount > 0) {
		size_t len;
		const char *p = r_cons_get_buffer (core->cons, &len);
		if (p && len > 0) {
			if (p[len - 1] != '\n') {
				ds_newline (ds);
			}
		}
	}
#if DEADCODE
	if (aligned && ds->show_color) {
		r_cons_print (ds->core->cons, Color_RESET);
	}
#endif
}

static void ds_print_demangled(RDisasmState *ds) {
	if (!ds->show_comments || !ds->asm_demangle) {
		return;
	}
	RCore *core = ds->core;
	RFlagItem *f;
	int optype = ds->analop.type & 0xFFFF;
	switch (optype) {
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_UJMP:
	case R_ANAL_OP_TYPE_CALL:
		f = r_flag_get_by_spaces (core->flags, false, ds->analop.jump, R_FLAGS_FS_SYMBOLS, NULL);
		if (f && f->demangled && f->realname && ds->opstr && !strstr (ds->opstr, f->realname)) {
			ds_begin_nl_comment (ds);
			ds_comment (ds, true, "%s %s", ds->cmtoken, f->realname);
		}
	}
}

static void ds_print_relocs(RDisasmState *ds) {
	char *demname = NULL;
	if (!ds->showrelocs || !ds->show_slow) {
		return;
	}
	RCore *core = ds->core;
	RCons *cons = core->cons;
	// const char *lang = r_config_get (core->config, "bin.lang");
	const bool demangle = r_config_get_i (core->config, "asm.demangle");
	// bool keep_lib = r_config_get_i (core->config, "bin.demangle.pfxlib");
	RBinReloc *rel = r_core_getreloc (core, ds->at, ds->analop.size);
#if 0
	if (!rel) {
		ut8 buf[8];
		r_io_read_at (core->io, ds->at, buf, 8);
		ut64 n = r_read_le64 (buf);
		rel = r_core_getreloc (core, n, ds->analop.size);
	}
#endif
	if (rel) {
		int cstrlen = 0;
		char *ll = r_cons_lastline (cons, &cstrlen);
		if (!ll) {
			return;
		}
		int ansilen = r_str_ansi_len (ll);
		int utf8len = r_utf8_strlen ((const ut8*)ll);
		int cells = utf8len - (cstrlen - ansilen);
		int len = ds->cmtcol - cells;
		r_cons_memset (cons, ' ', len);
		int pref = demangle? 'd': 0;
		// if (demangle) { demname = r_bin_demangle (core->bin->cur, lang, rel->import->name, rel->vaddr, keep_lib); }
		// demname = r_bin_demangle (core->bin->cur, lang, rel->symbol->name, rel->symbol->vaddr, keep_lib);
		// demname ? demname : rel->symbol->name,
		if (rel->import) {
			const char *rel_imp_name = r_bin_name_tostring2 (rel->import->name, pref);
			r_cons_printf (cons, "%s RELOC %d %s", ds->cmtoken, rel->type, rel_imp_name);
		} else if (rel->symbol) {
			const char *rel_sym_name = r_bin_name_tostring2 (rel->symbol->name, pref);
			r_cons_printf (cons, "%s RELOC %d %s @ 0x%08" PFMT64x,
					ds->cmtoken,
					rel->type, rel_sym_name,
					rel->symbol->vaddr);
			if (rel->addend) {
				if (rel->addend > 0) {
					r_cons_printf (cons, " + 0x%" PFMT64x, rel->addend);
				} else {
					r_cons_printf (cons, " - 0x%" PFMT64x, -rel->addend);
				}
			}
		} else {
			r_cons_printf (cons, "%s RELOC %d ", ds->cmtoken, rel->type);
		}
		free (demname);
	}
}

static bool mymemwrite1(REsil *esil, ut64 addr, const ut8 *buf, int len) {
	RDisasmState *ds = esil->cb.user;
	const bool be = false;
	ut64 v = 0;
	switch (len) {
	case 1:
		v = buf[0];
		break;
	case 2:
		v = r_read_ble16 (buf, be);
		break;
	case 4:
		v = r_read_ble32 (buf, be);
		break;
	case 8:
		v = r_read_ble64 (buf, be);
		break;
	}
	if (!ds->show_emu_str) {
		ds_comment_esil (ds, true, true, "; [0x%08"PFMT64x":%d] = 0x%"PFMT64x, addr, len, v);
	}
	return true;
}

static bool mymemwrite0(REsil *esil, ut64 addr, const ut8 *buf, int len) {
	(void)mymemwrite1 (esil, addr, buf, len);
	return false;
}

static bool mymemwrite2(REsil *esil, ut64 addr, const ut8 *buf, int len) {
	RDisasmState *ds = esil->cb.user;
	const ut64 min = ds->emustack_min;
	const ut64 max = ds->emustack_max;
	return (addr >= min && addr < max);
}

static char *ssa_get(REsil *esil, const char *reg) {
	//RCore *core = esil->user;
	RDisasmState *ds = esil->cb.user;
	if (isdigit ((ut8)*reg)) {
		return strdup (reg);
	}
	int n = sdb_num_get (ds->ssa, reg, NULL);
	return r_str_newf ("%s_%d", reg, n);
}

static void ssa_set(REsil *esil, const char *reg) {
	RDisasmState *ds = esil->cb.user;
	(void)sdb_num_inc (ds->ssa, reg, 1, 0);
}

static bool myregread(REsil *esil, const char *name, ut64 *res, int *size) {
	RDisasmState *ds = esil->cb.user;
	if (ds && ds->show_emu_ssa && name) {
		if (!isdigit ((ut8)*name)) {
			char *r = ssa_get (esil, name);
			ds_comment_esil (ds, true, false, "<%s", r);
			free (r);
		}
	}
	return false;
}

static char *ds_getstring(RDisasmState *ds, const char *str, int len, const char **prefix) {
	char *escstr = NULL;
	*prefix = "";
	const char *strconv = r_config_get (ds->core->config, "scr.strconv");
	if (R_STR_ISNOTEMPTY (strconv)) {
		if (strstr (strconv, "esc")) {
			escstr = ds_esc_str (ds, str, (int)len, prefix, false);
		} else if (strstr (strconv, "pascal")) {
			int slen = str[0]; // TODO: support pascal16, pascal32, ..
			escstr = r_str_ndup (str + 1, slen);
		} else if (strstr (strconv, "dot")) {
			escstr = ds_esc_str (ds, str, (int)len, prefix, false);
			int i;
			for (i = 0; i < len ; i++) {
				if (!escstr[i]) {
					break;
				}
				if (!IS_PRINTABLE (escstr[i])) {
					escstr[i] = '.';
				}
			}
		} else {
			// raw string (null terminated) - works for chinese/russian/..
			escstr = r_str_ndup (str, len);
			r_str_trim (escstr);
		}
	} else {
		escstr = strdup (str); // r_str_ndup (str, len);
	}
	return escstr;
}

static bool myregwrite(REsil *esil, const char *name, ut64 *val) {
	char str[64], *msg = NULL;
	ut32 *n32 = (ut32*)str;
	RDisasmState *ds = esil->user;
	if (!ds) {
		return false;
	}
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (ds->core->rasm->config);
	if (!ds->show_emu_strlea && ds->analop.type == R_ANAL_OP_TYPE_LEA) {
		// useful for ARM64
		// reduce false positives in emu.str=true when loading strings via adrp+add
		return false;
	}
	if (ds->pj) {
		// "pdJ" -> reg: value
		pj_kn (ds->pj, name, *val);
	}
	ds->esil_likely = true;
	if (ds->show_emu_ssa) {
		ssa_set (esil, name);
		char *r = ssa_get (esil, name);
		ds_comment_esil (ds, true, false, ">%s", r);
		free (r);
		return false;
	}
	if (!ds->show_slow) {
		return false;
	}
	memset (str, 0, sizeof (str));
	if (*val) {
		bool emu_str_printed = false;
		char *type = NULL;
		(void)r_io_read_at (esil->anal->iob.io, *val, (ut8*)str, sizeof (str)-1);
		str[sizeof (str) - 1] = 0;
		ds->emuptr = *val;
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
					(ut8*)str, sizeof (str) - 1);
			//	eprintf ("IS PSTRING 0x%llx %s\n", addr, str);
			}
		}

		if (*str && !r_bin_strpurge (ds->core->bin, str, *val) && r_str_is_printable_incl_newlines (str)
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
			// case R_ANAL_OP_TYPE_RCALL:
			// case R_ANAL_OP_TYPE_UCALL:
				jump_op = true;
				break;
			case R_ANAL_OP_TYPE_CALL:
			case R_ANAL_OP_TYPE_TRAP:
			case R_ANAL_OP_TYPE_RET:
				ignored = true;
				break;
			// case R_ANAL_OP_TYPE_STORE:
			// case R_ANAL_OP_TYPE_LOAD:
				ignored = true;
				break;
			case R_ANAL_OP_TYPE_LEA:
				if (ds->core->rasm->config->bits == 64 && isarm (ds->core)) {
					ignored = true;
				}
				break;
			}
			if (!jump_op && !ignored) {
				ut32 len = sizeof (str) -1;
				ds->emuptr = *val;
				if (ds->pj) {
					// "pdJ"
					pj_ks (ds->pj, "str", str);
				}
				const char *prefix = "";
				char *escstr = ds_getstring (ds, str, len, &prefix);
				if (escstr) {
					char *m;
					if (ds->show_color) {
						bool inv = ds->show_emu_strinv;
						m = r_str_newf ("%s%s%s\"%s\"%s",
								prefix, r_str_get (type), inv? Color_INVERT: "",
								escstr, inv? Color_INVERT_RESET: "");
					} else {
						m = r_str_newf ("%s%s\"%s\"", prefix, r_str_get (type), escstr);
					}
					msg = r_str_append_owned (msg, m);
					emu_str_printed = true;
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
					ut32 v = r_read_ble32 (n32, be);
					msg = r_str_appendf (msg, "-> 0x%x", v);
				}
			}
		}
		R_FREE (type);
		if ((ds->printed_flag_addr == UT64_MAX || *val != ds->printed_flag_addr)
		    && (ds->show_emu_strflag || !emu_str_printed)) {
			RFlagItem *fi = r_flag_get_in (esil->anal->flb.f, *val);
			if (fi && (!ds->opstr || !strstr (ds->opstr, fi->name))) {
				msg = r_str_appendf (msg, "%s%s", R_STR_ISNOTEMPTY (msg)? " " : "", fi->name);
				if (ds->pj) {
					pj_ks (ds->pj, "flag", fi->name);
				}
			}
		}
	}
	if (ds->show_emu_str) {
		if (R_STR_ISNOTEMPTY (msg)) {
			ds->emuptr = *val;
			if (ds->show_emu_stroff && *msg == '"') {
				ds_comment_esil (ds, true, false, "%s 0x%"PFMT64x" %s", ds->cmtoken, *val, msg);
			} else {
				ds_comment_esil (ds, true, false, "%s %s", ds->cmtoken, msg);
			}
			if (ds->show_comments && !ds->show_cmt_right) {
				ds_newline (ds);
			}
		}
	} else {
		if (R_STR_ISEMPTY (msg)) {
			ds_comment_esil (ds, true, false, "%s %s=0x%"PFMT64x, ds->cmtoken, name, *val);
		} else {
			ds_comment_esil (ds, true, false, "%s %s=0x%"PFMT64x" %s", ds->cmtoken, name, *val, msg);
		}
		if (ds->show_comments && !ds->show_cmt_right) {
			ds_newline (ds);
		}
	}
	free (msg);
	return false;
}

static void ds_pre_emulation(RDisasmState *ds) {
	bool do_esil = ds->show_emu;
	if (!ds->pre_emu) {
		return;
	}
	RFlagItem *f = r_flag_get_at (ds->core->flags, ds->core->addr, true);
	if (!f) {
		return;
	}
	ut64 base = f->addr;
	REsil *esil = ds->core->anal->esil;
	int i, end = ds->core->addr - base;
	int maxemu = 1024 * 1024;
	REsilHookRegWriteCB orig_cb = esil->cb.hook_reg_write;
	if (end < 0 || end > maxemu) {
		return;
	}
	ds->stackptr = ds->core->anal->stackptr;
	esil->cb.hook_reg_write = NULL;
	const ut64 pc = r_reg_getv (ds->core->anal->reg, "PC");
	for (i = 0; i < end; i++) {
		ut64 addr = base + i;
		RAnalOp* op = r_core_anal_op (ds->core, addr, R_ARCH_OP_MASK_ESIL | R_ARCH_OP_MASK_HINT);
		if (op) {
			if (do_esil) {
				// underlying assumption of esil expressions is pc register is set prior to emulation
				r_reg_setv (ds->core->anal->reg, "PC", addr + op->size);
				r_esil_set_pc (esil, addr);
				r_esil_parse (esil, R_STRBUF_SAFEGET (&op->esil));
				if (op->size > 0) {
					i += op->size - 1;
				}
			}
			ds_update_stackptr (ds, op);
			r_anal_op_free (op);
		}
	}
	r_reg_setv (ds->core->anal->reg, "PC", pc);
	esil->cb.hook_reg_write = orig_cb;
}

static void ds_print_esil_anal_init(RDisasmState *ds) {
	RCore *core = ds->core;
	r_esil_setup (core->anal->esil, core->anal, 0, 0, 1);
	ds->esil_old_pc = r_reg_getv (core->anal->reg, "PC");
	if (!ds->esil_old_pc || ds->esil_old_pc == UT64_MAX) {
		ds->esil_old_pc = core->addr;
	}
	if (!ds->show_emu) {
		// XXX. stackptr not computed without asm.emu, when its not required
		return;
	}
	core->anal->esil->user = ds;
	free (ds->esil_regstate);
	R_FREE (core->anal->last_disasm_reg);
	if (core->anal->gp) {
		r_reg_setv (core->anal->reg, "gp", core->anal->gp);
	}
	ds->esil_regstate = r_reg_arena_peek (core->anal->reg, &ds->esil_regstate_size);
	RRegSet *regset = r_reg_regset_get (core->anal->reg, R_REG_TYPE_GPR);
	if (ds->esil_regstate && regset) {
		ds->esil_regstate_size = regset->arena->size;
	}

	// TODO: emulate N instructions BEFORE the current offset to get proper full function emulation
	ds_pre_emulation (ds);
}

static void ds_print_bbline(RDisasmState *ds) {
	if (!ds->show_bbline || !ds->at) {
		return;
	}
	RAnalBlock *bb = NULL;
	RAnalFunction *f_before = NULL;
	if (ds->fcn) {
		bb = r_anal_function_bbget_at (ds->core->anal, ds->fcn, ds->at);
	} else {
		f_before = fcnIn (ds, ds->at - 1, R_ANAL_FCN_TYPE_NULL);
	}
	if ((ds->fcn && bb && ds->fcn->addr != ds->at) || (!ds->fcn && f_before)) {
		ds_begin_line (ds);
		// adapted from ds_setup_pre ()
		ds->cmtcount = 0;
		if (!ds->show_functions || !ds->show_lines_fcn) {
			ds->pre = DS_PRE_NONE;
		} else {
			ds->pre = DS_PRE_EMPTY;
			if (!f_before) {
				f_before = fcnIn (ds, ds->at - 1, R_ANAL_FCN_TYPE_NULL);
			}
			if (f_before == ds->fcn) {
				ds->pre = DS_PRE_FCN_MIDDLE;
			}
		}
		ds_print_pre (ds, true);
		if (ds->show_section && ds->line_col) {
			const char *sn = get_section_name (ds);
			size_t snl = sn? strlen (sn) + 4: 4;
			r_cons_printf (ds->core->cons, "%s", r_str_pad (' ', R_MAX (10, snl - 1)));
		}
		if (!ds->linesright && ds->show_lines_jmp && ds->line) {
			ds_update_ref_lines (ds);
			char *refline = ds->refline2;
			char *reflinecol = ds->prev_line_col;
			ds_print_ref_lines (ds, refline, reflinecol, false);
		}
		r_cons_printf (ds->core->cons, "|");
		ds_newline (ds);
	}
}

static const char *getarg(RCore *core, const char *cc, int nth) {
	if (isarm (core) && core->rasm->config->bits == 32) {
		// workaround for arm32
		static const char *ccargs[] = {"r0", "r1", "r2", "r3"};
		if (nth >= 0 && nth < 4) {
			return ccargs[nth];
		}
		return NULL;
	}
	return r_anal_cc_arg (core->anal, cc, nth, 0);
}

// print function arguments when emu.str=true
static void print_fcn_arg(RCore *core, int nth, const char *type, const char *name,
			   const char *fmt, ut64 addr, const int on_stack, int asm_types) {
	if (on_stack == 1 && asm_types > 1) {
		r_cons_printf (core->cons, "%s", type);
	}
	if (addr == UT32_MAX || addr == UT64_MAX || addr == 0) {
		// if argument address cannot be resolved, fallback to use the calling convention
		const char *cc = r_config_get (core->config, "anal.cc"); // XXX
		const char *reg = getarg (core, cc, nth);
		if (reg) {
			ut64 rv = r_reg_getv (core->anal->reg, reg);
			if (rv >> 63) {
				fmt = NULL;
			} else if (rv < 64) {
				fmt = NULL;
			} else {
				addr = rv;
			}
		} else {
			fmt = NULL;
		}
	}
	if (fmt) {
		char *res = NULL;
		if (!strcmp (fmt, "z")) {
			const char *strconv = r_config_get (core->config, "scr.strconv");
			if (strconv && strstr (strconv, "raw")) { // TODO. raw or none?
				// dupe from ds_getstring
				char *s = r_core_cmd_strf (core, "prz@0x%08"PFMT64x, addr);
				r_str_trim (s);
				res = r_str_newf ("\"%s\"", s);
				free (s);
			} else {
				res = r_core_cmd_strf (core, "pf%s %s%s %s @ 0x%08" PFMT64x,
						(asm_types==2)? "": "q", (on_stack == 1) ? "*" : "", fmt, name, addr);
			}
			if (strconv && strstr (strconv, "dot")) {
				int i;
				size_t len = strlen (res);
				for (i = 0; i < len ; i++) {
					if (!IS_PRINTABLE (res[i])) {
						res[i] = '.';
					}
				}
			}
		} else {
			res = r_core_cmd_strf (core, "pf%s %s%s %s @ 0x%08" PFMT64x,
					(asm_types==2)? "": "q", (on_stack == 1) ? "*" : "", fmt, name, addr);
		}
		r_str_trim (res);
		if (r_str_startswith (res, "\"\\xff\\xff")) {
			r_cons_printf (core->cons, "\"\"");
		} else {
			r_cons_printf (core->cons, "%s", res);
		}
		free (res);
	} else {
		const char *cc = r_config_get (core->config, "anal.cc"); // XXX
		const char *reg = r_anal_cc_arg (core->anal, cc, nth, 0);
		if (reg) {
			ut64 rv = r_reg_getv (core->anal->reg, reg);
			if (rv >> 63) {
				r_cons_printf (core->cons, "-1");
			} else if (rv < 64) {
				r_cons_printf (core->cons, "%"PFMT64d, rv);
			} else {
				r_cons_printf (core->cons, "0x%"PFMT64x, rv);
			}
		} else {
			r_cons_printf (core->cons, "-1");
		}
	}
	r_cons_trim (core->cons);
}

static void delete_last_comment(RDisasmState *ds) {
	if (!ds->show_cmt_right_default) {
		return;
	}
	const char *ll = r_cons_get_buffer (ds->core->cons, NULL);
	if (ll) {
		ll += ds->buf_line_begin;
		const char *begin = ll;
		if (begin) {
			ds_newline (ds);
			ds_begin_cont (ds);
		}
	}
}

static bool can_emulate_metadata(RCore *core, ut64 at) {
	// check if there is a meta at the addr that is unemulateable
	const char *emuskipmeta = r_config_get (core->config, "emu.skip");
	bool ret = true;
	RPVector *metas = r_meta_get_all_at (core->anal, at);
	void **it;
	r_pvector_foreach (metas, it) {
		RAnalMetaItem *item = ((RIntervalNode *)*it)->data;
		if (strchr (emuskipmeta, (char)item->type)) {
			ret = false;
			break;
		}
	}
	r_pvector_free (metas);
	return ret;
}

static void mipsTweak(RDisasmState *ds) {
	RCore *core = ds->core;
	const char *asm_arch = r_config_get (core->config, "asm.arch");
	if (r_str_startswith (asm_arch, "mips")) {
		if (r_config_get_b (core->config, "anal.fixed.gp")) {
			ut64 gp = r_config_get_i (core->config, "anal.gp");
			r_reg_setv (core->anal->reg, "gp", gp);
		}
	}
}

// dupe from `afsv` - avoid code duplication
static void ds_comment_call(RDisasmState *ds) {
	RCore *core = ds->core;
	REsil *esil = core->anal->esil;
	RAnalFuncArg *arg;
	RListIter *iter;
	RListIter *nextele;
	const char *fcn_name = NULL;
	char *key = NULL;
	ut64 pcv = ds->analop.jump;
	if (ds->analop.type == R_ANAL_OP_TYPE_RCALL) {
		pcv = UT64_MAX;
	}
	if (pcv == UT64_MAX) {
		pcv = ds->analop.ptr; // call [reloc-addr] // windows style
		if (pcv == UT64_MAX || !pcv) {
			r_esil_reg_read (esil, "$jt", &pcv, NULL);
			if (pcv == UT64_MAX || !pcv) {
				pcv = r_reg_getv (core->anal->reg, "PC");
			}
		}
	}
	RAnalFunction *fcn = r_anal_get_function_at (core->anal, pcv);
	if (fcn) {
		fcn_name = fcn->name;
	} else {
		RFlagItem *item = r_flag_get_in (core->flags, pcv);
		if (item) {
			fcn_name = item->name;
		}
	}
	if (fcn_name) {
		key = r_type_func_name (core->anal->sdb_types, fcn_name);
	}
	int nargs = DEFAULT_NARGS;
	if (key) {
		if (ds->asm_types < 1) {
			free (key);
			return;
		}
		const char *fcn_type = r_type_func_ret (core->anal->sdb_types, key);
		nargs = r_type_func_args_count (core->anal->sdb_types, key);
		// remove other comments
		delete_last_comment (ds);
		// ds_comment_start (ds, "");
		ds_comment_esil (ds, true, false, "%s", ds->show_color ? ds->pal_comment : "");
		if (fcn_type) {
			// XXX this makes some emu.str function signature + call arguments to be displayed one line below the call
			ds_comment_middle (ds, "%s %s%s%s(", ds->cmtoken, r_str_getf (fcn_type),
					(*fcn_type && fcn_type[strlen (fcn_type) - 1] == '*') ? "" : " ",
					r_str_getf (key));
			if (!nargs) {
				ds_comment_end (ds, "void)");
				free (key);
				return;
			}
		}
	}
	ut64 s_width = (core->anal->config->bits == 64)? 8: 4;
	ut64 spv = r_reg_getv (core->anal->reg, "SP");
	r_reg_setv (core->anal->reg, "SP", spv + s_width); // temporarily set stack ptr to sync with carg.c
	RList *list = r_core_get_func_args (core, fcn_name);
	// show function arguments
	if (!r_list_empty (list)) {
		int nth = 0;
		// bool warning = false;
		bool on_stack = false;
		r_list_foreach (list, iter, arg) {
			if (arg->cc_source && r_str_startswith (arg->cc_source, "stack")) {
				on_stack = true;
			}
			nextele = r_list_iter_get_next (iter);
#if 0
			if (!arg->size) {
				if (ds->asm_types == 2) {
					ds_comment_middle (ds, "%s: unk_size", arg->c_type);
				}
				warning = true;
			}
			if (arg->fmt) {
				if (ds->asm_types > 1) {
					if (warning) {
						ds_comment_middle (ds, "_format");
					} else {
						ds_comment_middle (ds, "%s : unk_format", arg->c_type);
					}
				} else {
					ds_comment_middle (ds, "?");
				}
				ds_comment_middle (ds, nextele?", ":")");
			} else {
				// TODO: may need ds_comment_esil
				print_fcn_arg (core, nth, arg->orig_c_type, arg->name, arg->fmt, arg->src, on_stack, ds->asm_types);
				ds_comment_middle (ds, nextele?", ":")");
			}
#else
			print_fcn_arg (core, nth, arg->orig_c_type, arg->name, arg->fmt, arg->src, on_stack, ds->asm_types);
			ds_comment_middle (ds, nextele?", ":")");
#endif
			nth++;
		}
		ds_comment_end (ds, "");
		r_list_free (list);
		free (key);
		return;
	}
	r_list_free (list);
	// function name not resolved
	R_WARN_IF_FAIL (!key);
	free (key);
	if (fcn) {
		// @TODO: fcn->nargs should be updated somewhere and used here instead
		nargs = r_anal_var_count_args (fcn);
	}
	if (nargs > 0) {
		ds_comment_esil (ds, true, false, "%s", ds->show_color? ds->pal_comment : "");
		if (fcn_name) {
			if (ds->pj) {
				// "pdJ"
				pj_ks (ds->pj, "call", fcn_name);
			}
			ds_comment_middle (ds, "%s %s(", ds->cmtoken, fcn_name);
		} else {
			ds_comment_middle (ds, "%s 0x%"PFMT64x"(", ds->cmtoken, pcv);
			if (ds->pj) {
				// "pdJ"
				pj_kn (ds->pj, "call", pcv);
			}
		}
		const char *cc = r_anal_syscc_default (core->anal);
		int i;
		for (i = 0; i < nargs; i++) {
			ut64 v = r_debug_arg_get (core->dbg, cc, i);
			if (v == UT64_MAX || v == UT32_MAX) {
				ds_comment_middle (ds, "%s-1", i?", ":"");
			} else {
				ds_comment_middle (ds, "%s0x%"PFMT64x, i?", ":"", v);
			}
		}
		ds_comment_end (ds, ")");
	}
	r_reg_setv (core->anal->reg, "SP", spv); // reset stack ptr
}

// modifies anal register state
static void ds_print_esil_anal(RDisasmState *ds) {
	RCore *core = ds->core;
	REsil *esil = core->anal->esil;
	bool (*hook_mem_write)(REsil *esil, ut64 addr, const ut8 *buf, int len) = NULL;
	ut64 at = r_core_pava (core, ds->at);
	if (!ds->show_comments) {
		return;
	}
	RConfigHold *hc = r_config_hold_new (core->config);
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
	if (ds->show_color && ds->show_comments) {
		r_cons_print (core->cons, ds->pal_comment);
	}
	esil = core->anal->esil;
	r_reg_setv (core->anal->reg, "PC", at + ds->analop.size);
	esil->cb.user = ds;
	esil->cb.hook_reg_write = myregwrite;
	esil->cb.hook_reg_read = myregread;
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
	const char *esilstr = R_STRBUF_SAFEGET (&ds->analop.esil);
	if (R_STR_ISNOTEMPTY (esilstr)) {
		mipsTweak (ds);
		r_esil_set_pc (esil, at);
		if (ds->pj) {
			pj_ko (ds->pj, "esil");
			pj_ks (ds->pj, "expr", esilstr);
		}
		r_esil_parse (esil, esilstr);
		if (ds->pj) {
			pj_end (ds->pj);
		}
	}
	r_esil_stack_free (esil);
	r_config_hold (hc, "io.cache", NULL);
	r_config_set_b (core->config, "io.cache", true);
	if (!ds->show_comments) {
		goto beach;
	}
	switch (ds->analop.type) {
	case R_ANAL_OP_TYPE_SWI: {
		char *s = cmd_syscall_dostr (core, ds->analop.val, at);
		if (s) {
			ds_comment_esil (ds, true, true, "%s %s", ds->cmtoken, s);
			free (s);
		}
		} break;
	case R_ANAL_OP_TYPE_CJMP:
		ds_comment_esil (ds, true, true, ds->esil_likely? "%s likely" : "%s unlikely", ds->cmtoken);
		break;
	case R_ANAL_OP_TYPE_JMP:
		{
			ut64 addr = ds->analop.jump;
			if (!r_anal_get_function_at (ds->core->anal, addr) && !r_flag_get_at (core->flags, addr, false)) {
				break;
			}
		}
		// fallthrough for failcalls
	case R_ANAL_OP_TYPE_UCALL:
	case R_ANAL_OP_TYPE_ICALL:
	case R_ANAL_OP_TYPE_RCALL:
	case R_ANAL_OP_TYPE_IRCALL:
	case R_ANAL_OP_TYPE_CALL:
		ds_comment_call (ds);
		break;
	}
	ds_print_color_reset (ds);
beach:
	if (esil) {
		esil->cb.hook_mem_write = hook_mem_write;
	}
	r_config_hold_restore (hc);
	r_config_hold_free (hc);
}

static void ds_print_calls_hints(RDisasmState *ds) {
	bool emu = r_config_get_b (ds->core->config, "asm.emu");
	bool emuwrite = r_config_get_b (ds->core->config, "emu.write");
	if (emu && emuwrite) {
		// this is done by ESIL
		return;
	}
	RAnal *anal = ds->core->anal;
	Sdb *TDB = anal->sdb_types;
	char *name;
	char *full_name = NULL;
	if (ds->analop.type == R_ANAL_OP_TYPE_CALL) {
		// RAnalFunction *fcn = r_anal_get_fcn_in (anal, ds->analop.jump, -1);
		RAnalFunction *fcn = fcnIn (ds, ds->analop.jump, -1);
		if (fcn) {
			full_name = fcn->name;
		}
	} else if (ds->analop.ptr != UT64_MAX) {
		RFlagItem *flag = r_flag_get_in (ds->core->flags, ds->analop.ptr);
		if (flag && flag->space && !strcmp (flag->space->name, R_FLAGS_FS_IMPORTS)) {
			full_name = flag->realname;
		}
	}
	if (!full_name) {
		return;
	}
	if (r_type_func_exist (TDB, full_name)) {
		name = strdup (full_name);
	} else if (!(name = r_type_func_guess (TDB, full_name))) {
		return;
	}
	ds_begin_comment (ds);
	const char *fcn_type = r_type_func_ret (TDB, name);
	if (!fcn_type || !*fcn_type) {
		free (name);
		return;
	}
	char *cmt = r_str_newf ("%s %s%s%s(", ds->cmtoken, fcn_type,
		fcn_type[strlen (fcn_type) - 1] == '*' ? "" : " ",
		name);
	int i, arg_max = r_type_func_args_count (TDB, name);
	if (!arg_max) {
		cmt = r_str_append (cmt, "void)");
	} else {
		for (i = 0; i < arg_max; i++) {
			char *type = r_type_func_args_type (TDB, name, i);
			const char *tname = r_type_func_args_name (TDB, name, i);
			if (type && *type) {
				cmt = r_str_appendf (cmt, "%s%s%s%s%s", i == 0 ? "": " ", type,
						type[strlen (type) - 1] == '*' ? "": " ",
						tname, i == arg_max - 1 ? ")": ",");
			} else if (tname && !strcmp (tname, "...")) {
				cmt = r_str_appendf (cmt, "%s%s%s", i == 0 ? "": " ",
						tname, i == arg_max - 1 ? ")": ",");
			}
			free (type);
		}
	}
	ds_comment (ds, true, "%s", cmt);
	ds_print_color_reset (ds);
	free (cmt);
	free (name);
}

static void ds_print_comments_right(RDisasmState *ds) {
	char *desc = NULL;
	RCore *core = ds->core;
	ds_print_relocs (ds);
	ds_print_pins (ds);
	bool is_code = (!ds->hint) || (ds->hint && ds->hint->type != 'd');
	RAnalMetaItem *mi = r_meta_get_at (ds->core->anal, ds->at, R_META_TYPE_ANY, NULL);
	if (mi) {
		switch (mi->type) {
		case 'd':
		case 'h':
		case 'm':
		case 's':
		case 'f':
			is_code = false;
			break;
		default:
			break;
		}
		mi = NULL;
	}
	if (ds->asm_flags_right) {
		const RList *flaglist = r_flag_get_list (core->flags, ds->at);
		RFlagItem *fi;
		RListIter *iter;
		if (!r_list_empty (flaglist)) {
			ds_align_comment (ds);
			if (ds->show_color) {
				r_cons_print (core->cons, ds->color_comment);
			}
			r_cons_print (core->cons, ";-- ");
			r_list_foreach (flaglist, iter, fi) {
				r_cons_printf (core->cons, "%s%s", fi->name, iter->n? ", ": " ");
			}
		}
		return;
	}
	if (is_code && ds->asm_describe && !ds->has_description) {
		const char *asmstr = ds->asmop.mnemonic;
		if (R_STR_ISNOTEMPTY (asmstr)) {
			char *locase = strdup (asmstr);
			r_str_after (locase, ' ');
			r_str_case (locase, 0);
			desc = r_asm_describe (core->rasm, locase);
			free (locase);
		}
	}
	if (ds->show_cmt_user || ds->show_comments) {
		if (R_STR_ISNOTEMPTY (desc)) {
			ds_align_comment (ds);
			if (ds->show_color) {
				r_cons_print (core->cons, ds->color_comment);
			}
			r_cons_printf (core->cons, "%s %s", ds->cmtoken, desc);
			ds_print_color_reset (ds);
		}
		if (ds->show_cmt_right && ds->comment) {
			char *comment = ds->comment;
			r_str_trim (comment);
			if (*comment) {
				if (!desc) {
					ds_align_comment (ds);
				}
				if (strchr (comment, '\n')) {
					comment = strdup (comment);
					if (comment) {
						ds_newline (ds);
						ds_begin_line (ds);
						size_t lines_count;
						size_t *line_indexes = r_str_split_lines (comment, &lines_count);
						if (line_indexes) {
							int i;
							for (i = 0; i < lines_count; i++) {
								char *c = comment + line_indexes[i];
								ds_print_pre (ds, true);
								ds_align_comment (ds);
								if (ds->show_color) {
									r_cons_print (core->cons, ds->color_usrcmt);
								}
								if (i == 0) {
									r_cons_print (core->cons, c);
								} else {
									r_cons_printf (core->cons, "%s %s", ds->cmtoken, c);
								}
								if (i < lines_count - 1) {
									ds_newline (ds);
									ds_begin_line (ds);
								}
							}
						}
						free (line_indexes);
					}
					free (comment);
				} else {
					if (comment) {
						r_cons_print (core->cons, comment);
					}
				}
			}
			// r_cons_print_justify (core->cons, comment, strlen (ds->refline) + 5, ';');
			ds_print_color_reset (ds);
			R_FREE (ds->comment);
		}
	}
	free (desc);
#if 1
	// TODO: if0 this block
	if ((ds->analop.type == R_ANAL_OP_TYPE_CALL || ds->analop.type & R_ANAL_OP_TYPE_UCALL) && ds->show_calls) {
		ds_print_calls_hints (ds);
	}
#else
	if (ds->show_calls) {
		switch (ds->analop.type) {
		case R_ANAL_OP_TYPE_CALL:
		case R_ANAL_OP_TYPE_ICALL:
		case R_ANAL_OP_TYPE_CCALL:
		case R_ANAL_OP_TYPE_UCCALL:
		case R_ANAL_OP_TYPE_UCALL:
		case R_ANAL_OP_TYPE_RCALL:
			ds_print_calls_hints (ds);
			break;
		}
	}
#endif
}

static void ds_print_as_string(RDisasmState *ds) {
	char *str = r_num_as_string (NULL, ds->analop.ptr, true);
	if (str) {
		ds_comment (ds, false, "%s; \"%s\"%s", COLOR (ds, pal_comment),
			str, COLOR_RESET (ds));
		free (str);
	}
}

static char *_find_next_number(char *op) {
	char *p = op;
	if (p) {
		while (*p) {
			// look for start of next separator or ANSI sequence
			while (*p && !IS_SEPARATOR (*p) && *p != 0x1b) {
				p++;
			}
			if (*p == 0x1b) {
				// skip to end of ANSI sequence (lower or uppercase char)
				while (*p && !(*p >= 'A' && *p <= 'Z') && !(*p >= 'a' && *p <= 'z')) {
					p++;
				}
				if (*p) {
					p++;
				}
			}
			if (IS_SEPARATOR (*p)) {
				// skip to end of separator
				while (*p && IS_SEPARATOR (*p)) {
					p++;
				}
			}
			if (isdigit (*p)) {
				// we found the start of the next number
				return p;
			}
		}
	}
	return NULL;
}

#if 0
static bool set_jump_realname(RDisasmState *ds, ut64 addr, const char **kw, const char **name) {
return true;
	RFlag *f = ds->core->flags;
	if (!f) {
		return false;
	}
	if (!ds->asm_demangle && !f->realnames) {
		// nothing to do, neither demangled nor regular realnames should be shown
		return false;
	}
	RFlagItem *flag_sym = r_flag_get_by_spaces (f, true, addr, R_FLAGS_FS_SYMBOLS, NULL);
	if (!flag_sym || !flag_sym->realname) {
		// nothing to replace
		return false;
	}
	if (!flag_sym->demangled && !f->realnames) {
		// realname is not demangled and we don't want to show non-demangled realnames
		return false;
	}
	*name = flag_sym->realname;
	RFlagItem *flag_mthd = r_flag_get_by_spaces (f, false, addr, R_FLAGS_FS_CLASSES, NULL);
	if (!f->realnames) {
#if 1
		// for asm.flags.real, we don't want these prefixes
		if (flag_mthd && flag_mthd->name && r_str_startswith (flag_mthd->name, "method.")) {
			*kw = "method,";
		} else {
			*kw = "sym,";
		}
#endif
	}
	return true;
}
#endif

// R2_600 - TODO: this should be moved into r_parse
static char *ds_sub_jumps(RDisasmState *ds, const char *str) {
	RAnal *anal = ds->core->anal;
	RFlag *f = ds->core->flags;
	const char* arch = r_config_get (ds->core->config, "asm.arch");
	const bool x86 = r_str_startswith (arch, "x86");
	const char *name = NULL;
	const char *kw = "";
	if (!ds->subjmp || !anal) {
		return NULL;
	}
	ut64 addr = ds->analop.jump;
#if 1
	int optype = ds->analop.type & R_ANAL_OP_TYPE_MASK;
	switch (optype) {
	case R_ANAL_OP_TYPE_LEA:
		if (x86) {
			// let the pseudo plugin trim the '[]'
			return NULL;
		}
		// for ARM adrp, section is better than adrp, segment
		break;
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_CJMP:
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_MJMP:
		break;
	case R_ANAL_OP_TYPE_PUSH:
		addr = ds->analop.val;
		if (addr < 10) {
			// ignore push 0
			return NULL;
		}
		break;
	case R_ANAL_OP_TYPE_CALL:
	case R_ANAL_OP_TYPE_UJMP:
	case R_ANAL_OP_TYPE_UCALL:
		break;
	//	return NULL;
	default:
		return NULL;
	}
#endif
	RBinReloc *rel = NULL;
	RBinObject *bo = r_bin_cur_object (ds->core->bin);
	if (bo && !bo->is_reloc_patched) {
		rel = r_core_getreloc (ds->core, ds->analop.addr, ds->analop.size);
	}
	if (!rel) {
		rel = r_core_getreloc (ds->core, addr, ds->analop.size);
		if (!rel) {
			// some jmp 0 are actually relocs, so we can just ignore it
			if (!addr || addr == UT64_MAX) {
				rel = r_core_getreloc (ds->core, ds->analop.ptr, ds->analop.size);
				if (rel) {
					addr = ds->analop.ptr;
				}
			}
		}
	}
	if (addr == UT64_MAX) {
		if (rel) {
			addr = 0;
		} else {
			addr = ds->analop.ptr;
		}
	}
	RAnalFunction *fcn = r_anal_get_function_at (anal, addr);
	if (fcn) {
	//	if (!set_jump_realname (ds, addr, &kw, &name)) {
			name = fcn->name;
	//	}
	} else {
		if (rel) {
			if (rel && rel->import && rel->import->name) {
				name = r_bin_name_tostring (rel->import->name);
			} else if (rel && rel->symbol && rel->symbol->name) {
				name = r_bin_name_tostring (rel->symbol->name);
			}
			if (addr) { //  && *name == '.') {
				RFlagItem *flag = r_core_flag_get_by_spaces (f, false, addr);
				if (flag) {
					if (!r_str_startswith (flag->name, "section")) {
						name = flag->name;
						if (f->realnames && flag->realname) {
							name = flag->realname;
						}
					}
				}
			}
		} else {

			// if (!set_jump_realname (ds, addr, &kw, &name)) {
				RFlagItem *flag = r_core_flag_get_by_spaces (f, false, addr);
				if (flag) {
					// R2R db/anal/jmptbl
					// adrp x0, segment.DATA //instead-of// adrp x0, section.20.__DATA.__objc_const
					if (!r_str_startswith (flag->name, "section")) {
						name = flag->name;
						if (f->realnames && flag->realname) {
							name = flag->realname;
						}
					}
				}
			// }
		}
	}
	if (name) {
		char *nptr;
		ut64 numval;
		char *hstr = strdup (str);
		char *ptr = hstr;
		const int bits = ds->core->rasm->config->bits;
		const int seggrn = ds->core->rasm->config->seggrn;
		while ((nptr = _find_next_number (ptr))) {
			ptr = nptr;
			char* colon = strchr (ptr, ':');
			if (x86 && bits == 16 && colon) {
				*colon = '\0';
				ut64 seg = r_num_get (NULL, ptr);
				ut64 off = r_num_get (NULL, colon + 1);
				*colon = ':';
				numval = (seg << seggrn) + off;
			} else {
				numval = r_num_get (NULL, ptr);
			}
			if (numval == addr) {
				while ((*nptr && !IS_SEPARATOR (*nptr) && *nptr != 0x1b) || (x86 && bits == 16 && colon && *nptr == ':')) {
					nptr++;
				}
				char *kwname = r_str_newf ("%s%s", kw, name);
				if (kwname) {
					char* numstr = r_str_ndup (ptr, nptr - ptr);
					if (numstr) {
						hstr = r_str_replace (hstr, numstr, kwname, 0);
						free (numstr);
					}
					free (kwname);
				}
				break;
			}
		}
		return hstr;
	}
	return NULL;
}

static bool line_highlighted(RDisasmState *ds) {
	return ds->asm_highlight != UT64_MAX && ds->vat == ds->asm_highlight;
}

static void ds_start_line_highlight(RDisasmState *ds) {
	if (ds->show_color && line_highlighted (ds)) {
		r_cons_print (ds->core->cons, ds->color_linehl);
	}
}

static void ds_end_line_highlight(RDisasmState *ds) {
	if (ds->show_color && line_highlighted (ds)) {
		r_cons_print (ds->core->cons, Color_RESET);
	}
}

/* Disassemble `count` instructions, or bytes if `count_bytes` is enabled
 *
 * pdu_condition_type is only used if pdu_condition is not NULL
 */
R_API int r_core_print_disasm(RCore *core, ut64 addr, ut8 *buf, int len, int count, enum r_pdu_condition_t pdu_condition_type, const void *pdu_condition, bool count_bytes, bool json, PJ *pj, RAnalFunction *pdf) {
	RPrint *p = core->print;
	RCons *cons = core->cons;
	RAnalFunction *of = NULL;
	RAnalFunction *f = NULL;
	bool calc_row_offsets = p->calc_row_offsets;
	int skip_bytes_flag = 0, skip_bytes_bb = 0;
	ut8 *nbuf = NULL;
	const int max_op_size = r_anal_archinfo (core->anal, R_ARCH_INFO_MAXOP_SIZE);

	/* pdu vars */
	bool pdu_condition_met = false;
	char *opstr_nocolor = NULL;
	int opcode_len = -1;
	const char *pdu_condition_instruction = NULL;
	const char *pdu_condition_opcode = NULL;

	// TODO: All those ds must be print flags
	RDisasmState *ds = ds_init (core);
	ds->count_bytes = count_bytes;
	ds->print = p;
	ds->count = count? count: core->blocksize;
	ds->buf = buf;
	ds->len = len;
	ds->addr = addr;
	ds->hint = NULL;
	ds->buf_line_begin = 0;
	ds->pdf = pdf;

	int minopsz = 4;
	if (pdu_condition) {
		ds->count_bytes = false;
		ds->count = INT_MAX;
		if (pdu_condition_type == pdu_instruction) {
			pdu_condition_instruction = (const char *)pdu_condition;
		} else if (pdu_condition_type == pdu_opcode) {
			pdu_condition_opcode = (const char *)pdu_condition;
			opcode_len = strlen (pdu_condition_opcode);
		}
	}

	if (json) {
		ds->pj = pj? pj: r_core_pj_new (core);
		if (!ds->pj) {
			ds_free (ds);
			return 0;
		}
		r_cons_push (cons);
	} else {
		ds->pj = NULL;
	}

	// disable row_offsets to prevent other commands to overwrite computed info
	p->calc_row_offsets = false;

	//r_cons_printf (ds->core->cons, "len=%d count=%d limit=%d\n", len, count, p->limit);
	// TODO: import values from debugger is possible
	// TODO: allow to get those register snapshots from traces
	// TODO: per-function register state trace
	// XXX - is there a better way to reset a the analysis counter so that
	// when code is disassembled, it can actually find the correct offsets
	{ /* used by asm.emu */
		r_reg_arena_push (core->anal->reg);
	}

	ds_reflines_init (ds);
	/* reset jmp table if not asked to keep it */
	if (!core->keep_asmqjmps) { // hack
		core->asmqjmps_count = 0;
		ut64 *p = realloc (core->asmqjmps, R_CORE_ASMQJMPS_NUM * sizeof (ut64));
		if (p) {
			core->asmqjmps_size = R_CORE_ASMQJMPS_NUM;
			core->asmqjmps = p;
			int i;
			for (i = 0; i < R_CORE_ASMQJMPS_NUM; i++) {
				core->asmqjmps[i] = UT64_MAX;
			}
		}
	}
	if (ds->pj && !pj) {
		pj_a (ds->pj);
	}
toro:
	// uhm... is this necessary? imho can be removed
	r_asm_set_pc (core->rasm, r_core_pava (core, ds->addr));
	core->cons->vline = r_config_get_b (core->config, "scr.utf8")
		? (r_config_get_b (core->config, "scr.utf8.curvy")
			? r_vline_uc
			: r_vline_u)
		: r_vline_a;

	if (core->print->cur_enabled) {
		// TODO: support in-the-middle-of-instruction too
		r_anal_op_fini (&ds->analop);
		if (r_anal_op (core->anal, &ds->analop, core->addr + core->print->cur,
			buf + core->print->cur, (int)(len - core->print->cur), R_ARCH_OP_MASK_ALL)) {
			// TODO: check for ds->analop.type and ret
			ds->dest = ds->analop.jump;
		}
		r_anal_op_fini (&ds->analop);
	} else {
		ds->dest = r_reg_getv (core->anal->reg, "PC");
#if 0
		/* highlight the program counter */
		const char *pc = core->anal->reg->name[R_REG_ALIAS_PC];
		if (pc) {
			RFlagItem *item = r_flag_get (core->flags, pc);
			if (item) {
				ds->dest = item->offset;
			}
		}
#endif
	}

	ds_print_esil_anal_init (ds);
	r_cons_break_push (cons, NULL, NULL);

	ds->fcn = fcnIn (ds, ds->at, R_ANAL_FCN_TYPE_NULL);

	if (ds->show_emu_bb) {
		// check if we are in the middle of a basic block, so we can emulate the previous instructions
		RList *list = r_anal_get_blocks_in (core->anal, ds->addr);
		if (!r_list_empty (list)) {
			RAnalBlock *bb = r_list_first (list);
			if (bb) {
				REsil *esil = core->anal->esil;
				esil->cb.hook_reg_write = NULL;
				if (bb->esil) {
					r_esil_parse (core->anal->esil, bb->esil);
				}
				// set regstate from here
				if (ds->addr != bb->addr) {
					int i;
					for (i = 0; i < bb->ninstr; i++) {
						if (i >= bb->op_pos_size) {
							R_LOG_ERROR ("Prevent op_pos overflow on large basic block at 0x%08"PFMT64x, bb->addr);
							break;
						}
						ut64 addr = bb->addr + (i > 0? bb->op_pos[i - 1]: 0);
						if (ds->addr == addr) {
							break;
						}
						RAnalOp *op = r_core_anal_op (core, addr, R_ARCH_OP_MASK_ESIL);
						if (op) {
							const char *esilstr = R_STRBUF_SAFEGET (&op->esil);
							if (R_STR_ISNOTEMPTY (esilstr)) {
								r_esil_parse (core->anal->esil, esilstr);
							}
						}
						r_anal_op_free (op);
					}
				}
				esil->cb.hook_reg_write = myregwrite;
			}
		}
		r_list_free (list);
	}
	int inc = 0;
	int ret = 0;
	for (ds->index = 0; ds_left (ds) > 0 && ds->lines < ds->count
				&& (pdu_condition? !pdu_condition_met: true);
			ds->index += inc, count_bytes? ds->lines += inc: ds->lines++) {
		ds->at = ds->addr + ds->index;
		ds->vat = r_core_pava (core, ds->at);

		if (r_cons_is_breaked (cons) || r_cons_was_breaked (cons)) {
			R_FREE (nbuf);
			if (ds->pj) {
				r_cons_pop (cons);
			}
			r_cons_break_pop (cons);
			ds_free (ds);
			return 0; //break;
		}
		if (ds->show_emu_bb) {
			RAnalBlock *bb = r_anal_get_block_at (core->anal, ds->at);
			if (bb && ds->at == bb->addr) {
				if (bb->esil) {
					REsil *esil = core->anal->esil;
					// disable emulation callbacks
					esil->cb.hook_reg_write = NULL;
					r_esil_parse (core->anal->esil, bb->esil);
					esil->cb.hook_reg_write = myregwrite;
				}
			}
		}
		if (core->print->flags & R_PRINT_FLAGS_UNALLOC) {
			if (!core->anal->iob.is_valid_offset (core->anal->iob.io, ds->at, 0)) {
				ds_begin_line (ds);
				ds_print_labels (ds, f);
				ds_setup_print_pre (ds, false, false);
				ds_print_lines_left (ds);
				core->print->resetbg = (ds->asm_highlight == UT64_MAX);
				ds_start_line_highlight (ds);
				ds_print_offset (ds);
				r_cons_printf (ds->core->cons, "  unmapped\n");
				inc = 1;
				continue;
			}
		}
		r_core_seek_arch_bits (core, ds->at); // slow but safe
		ds->has_description = false;
		ds_hint_begin (ds, ds->at);
		ds->printed_str_addr = UT64_MAX;
		ds->printed_flag_addr = UT64_MAX;
		// XXX. this must be done in ds_update_pc()
		// ds_update_pc (ds, ds->at);
		r_asm_set_pc (core->rasm, ds->at);
		ds_update_ref_lines (ds);
		ret = r_anal_op (core->anal, &ds->analop, ds->at, ds_bufat (ds), ds_left (ds), R_ARCH_OP_MASK_ALL);
		if (ret < 1) {
			ret = ds->analop.size;
			inc = minopsz;
		}
		ds->oplen = ds->analop.size;
		if (ds_must_strip (ds)) {
			inc = ds->analop.size;
			// inc = ds->asmop.payload + (ds->asmop.payload % ds->core->rasm->dataalign);
			continue;
		}
		if (!ds->show_cmt_right) {
			if (ds->show_cmt_pseudo) {
				char *res = r_asm_parse_pseudo (core->rasm, ds->analop.mnemonic);
				if (res) {
					ds_comment (ds, true, "%s", res);
					free (res);
				}
			}
			if (ds->show_cmt_esil) {
				const char *esil = R_STRBUF_SAFEGET (&ds->analop.esil);
				ds_pre_line (ds);
				ds_setup_print_pre (ds, false, false);
				r_cons_print (ds->core->cons, "      ");
				ds_print_lines_left (ds);
				ds_begin_comment (ds);
				if (ds->show_color) {
					ds_comment (ds, true, "%s %s%s%s", ds->cmtoken,
						ds->pal_comment, esil, Color_RESET);
				} else {
					ds_comment (ds, true, "%s %s", ds->cmtoken, esil);
				}
			}
		}
		f = ds->fcn = fcnIn (ds, ds->at, R_ANAL_FCN_TYPE_NULL);
		if (f && f->folded && r_anal_function_contains (f, ds->at)) {
			int delta = (ds->at <= f->addr)? (ds->at - r_anal_function_max_addr (f)): 0;
			if (of != f) {
				char cmt[32];
				get_bits_comment (core, f, cmt, sizeof (cmt));
				const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, ds->at);
				if (comment) {
					ds_pre_xrefs (ds, true);
					r_cons_printf (ds->core->cons, "%s %s\n", ds->cmtoken, comment);
				}
				r_cons_printf (ds->core->cons, "%s%s%s (fcn) %s%s%s\n",
					COLOR (ds, color_fline), core->cons->vline[CORNER_TL],
					COLOR (ds, color_fname), f->name, cmt, COLOR_RESET (ds));
				ds_setup_print_pre (ds, true, false);
				ds_print_lines_left (ds);
				ds_print_offset (ds);
				r_cons_printf (ds->core->cons, "(%" PFMT64d " byte folded function)\n", r_anal_function_linear_size (f));
				if (delta < 0) {
					delta = -delta;
				}
				ds->addr += delta + ds->index;
				r_io_read_at (core->io, ds->addr, buf, len);
				inc = 0; //delta;
				ds->index = 0;
				of = f;
				if (count_bytes) {
					break;
				}
			} else {
				ds->lines--;
				ds->addr++;
				r_io_read_at (core->io, ds->addr, buf, len);
				inc = 0; //delta;
				ds->index = 0;
			}
			continue;
		}
		ds_show_comments_right (ds);
		// TRY adding here
		r_strf_var (link_key, 32, "link.%08" PFMT64x, ds->addr + ds->index);
		const char *link_type = sdb_const_get (core->anal->sdb_types, link_key, 0);
		if (link_type) {
			char *fmt = r_type_format (core->anal->sdb_types, link_type);
			if (fmt) {
				r_cons_printf (core->cons, "(%s)\n", link_type);
				r_core_cmdf (core, "pf %s @ 0x%08" PFMT64x, fmt, ds->addr + ds->index);
				const ut32 type_bitsize = r_type_get_bitsize (core->anal->sdb_types, link_type);
				// always round up when calculating byte_size from bit_size of types
				// could be struct with a bitfield entry
				inc = (type_bitsize >> 3) + (!!(type_bitsize & 0x7));
				free (fmt);
				continue;
			}
		} else {
			int left = ds_left (ds);
			R_LOG_DEBUG ("BEFORE: ds->index=%#x len=%#x left=%#x ds->addr=%#" PFMT64x " ds->at=%#" PFMT64x " ds->count=%#x ds->lines=%#x",
				ds->index, len, left, ds->addr, ds->at, ds->count, ds->lines);
			if (left < max_op_size && !count_bytes) {
				R_LOG_DEBUG ("Not enough bytes to disassemble, going to retry");
				goto retry;
			}
			const int real_oplen = ds->oplen;
			int ret = ds_disassemble (ds, (ut8 *)ds_bufat (ds), left);
			// hack over hack, this tracks metadata size vs instruction size vs padding
			if (ret == ds->oplen) {
				ds->oplen = ret;
			} else {
				ds->oplen = real_oplen; // overwritten by ds_disassemble
			}
			R_LOG_DEBUG ("AFTER: ret=%d len=%#x left=%#x ds->addr=%#" PFMT64x " ds->at=%#" PFMT64x " ds->count=%#x ds->lines=%#x",
				ret, len, left, ds->addr, ds->at, ds->count, ds->lines);
			if (ret == -31337) {
				inc = ds->oplen; // minopsz maybe? or we should add invopsz
				continue;
			}
		}

		ds_atabs_option (ds);
		if (ds->analop.addr != ds->at) {
			// TODO : check for error
			r_anal_op (core->anal, &ds->analop, ds->at, ds_bufat (ds), ds_left (ds), R_ARCH_OP_MASK_ALL);
		}
		if (ret < 1) {
			r_strbuf_fini (&ds->analop.esil);
			r_strbuf_init (&ds->analop.esil);
			ds->asmop.type = R_ANAL_OP_TYPE_ILL;
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
		ds_print_bbline (ds);
		if (ds->at >= addr) {
			r_print_set_rowoff (core->print, ds->lines, ds->at - addr, calc_row_offsets);
		}
		skip_bytes_flag = handleMidFlags (core, ds, true);
		if (ds->midbb) {
			skip_bytes_bb = handleMidBB (core, ds);
		}
		ds_show_anos (ds);
		if (!ds->show_flag_in_offset) {
			ds_show_flags (ds, false);
		}
		ds_show_xrefs (ds);
		if (skip_bytes_flag && ds->midflags == R_MIDFLAGS_SHOW &&
				(!ds->midbb || !skip_bytes_bb || skip_bytes_bb > skip_bytes_flag)) {
			ds->at += skip_bytes_flag;
			if (!ds->show_flag_in_offset) {
				ds_show_flags (ds, true);
			}
			ds_show_xrefs (ds);
			ds->at -= skip_bytes_flag;
		}
		if (ds->pdf) {
			RAnalBlock *bb = r_anal_function_bbget_in (core->anal, ds->pdf, ds->at);
			if (!bb) {
				for (inc = 1; inc < ds->oplen; inc++) {
					RAnalBlock *bb = r_anal_function_bbget_in (core->anal, ds->pdf, ds->at + inc);
					if (bb) {
						break;
					}
				}
				if (!ds->sparse) {
					r_cons_printf (ds->core->cons, "..\n");
					ds->sparse = true;
				}
				continue;
			}
			ds->sparse = false;
		}
		ds_control_flow_comments (ds);
		ds_adistrick_comments (ds);
		/* XXX: This is really cpu consuming.. need to be fixed */
		ds_show_functions (ds);
		if (ds->cmt_wrap && ds->comment) {
			const int maxcols = 70; // XXX maybe configurable?
			size_t clen = strlen (ds->comment);
			if (clen > maxcols) {
				r_str_ansi_strip (ds->comment);
				r_str_trim (ds->comment);
				int off = 0;
				while (ds->comment) {
					char *c = r_str_ndup (ds->comment + off, maxcols);
					char *nl = strchr (c, '\n');
					if (nl) {
						*nl = 0;
					}
					size_t clen = strlen (c);
					r_str_trim (c);
					if (clen > 1) {
						if (ds->show_color) {
							r_cons_print (cons, ds->color_usrcmt);
						}
						r_cons_printf (cons, "%s%s\n", off? "; ": "", c);
						off += clen;
					} else {
						off++;
					}
					free (c);
					if (clen < maxcols && !nl) {
						R_FREE (ds->comment);
					}
				}
			}
		}
		if (ds->show_comments && !ds->show_cmt_right) {
			ds_show_refs (ds);
			ds_build_op_str (ds, false);
			ds_print_ptr (ds, len + 256, ds->index);
			ds_print_sysregs (ds);
			ds_print_fcn_name (ds);
			ds_print_demangled (ds);
			ds_print_pins (ds);
			ds_print_color_reset (ds);
			if (!ds->pseudo) {
				R_FREE (ds->opstr);
			}
			if (ds->show_emu) {
				ds_print_esil_anal (ds);
			}
			if ((ds->analop.type == R_ANAL_OP_TYPE_CALL || ds->analop.type & R_ANAL_OP_TYPE_UCALL) && ds->show_calls) {
				ds_print_calls_hints (ds);
			}
			ds_show_comments_describe (ds);
		}

		f = fcnIn (ds, ds->addr, 0);
		ds_begin_line (ds);
		ds_print_labels (ds, f);
		ds_setup_print_pre (ds, false, false);
		ds_print_lines_left (ds);
		core->print->resetbg = (ds->asm_highlight == UT64_MAX);
		ds_start_line_highlight (ds);
		if (ds->show_offseg) {
			core->print->flags |= R_PRINT_FLAGS_SEGOFF;
		} else {
			core->print->flags &= ~(R_PRINT_FLAGS_SEGOFF);
		}
		ds_print_offset (ds);
		////
		RAnalFunction *fcn = f;
		if (fcn) {
			RAnalBlock *bb = r_anal_function_bbget_in (core->anal, fcn, ds->at);
			if (!bb) {
				fcn = r_anal_get_function_at (core->anal, ds->at);
				if (fcn) {
					bb = r_anal_function_bbget_in (core->anal, fcn, ds->at);
				}
			}
			if (bb) {
				if (bb->folded) {
					r_cons_printf (core->cons, "[+] Folded BB [..0x%08"PFMT64x"]\n", ds->at + bb->size);
					inc = bb->size;
					continue;
				}
			}
		}
		////
		int mi_type;
		bool mi_found = ds_print_meta_infos (ds, buf, len, ds->index, &mi_type);
		if (ds->asm_hint_pos == 0) {
			if (mi_found) {
				r_cons_printf (core->cons, "      ");
			} else {
				ds_print_core_vmode (ds, ds->asm_hint_pos);
			}
		}
		ds_print_lines_split (ds);
		ds_print_op_size (ds);
		ds_print_trace (ds);
		ds_print_cycles (ds);
		ds_print_family (ds);
		ds_print_stackptr (ds);
		if (mi_found) {
			ds_print_dwarf (ds);
			ret = ds_print_middle (ds, ret);

			ds_print_asmop_payload (ds, ds_bufat (ds));
			if (core->rasm->config->syntax != R_ARCH_SYNTAX_INTEL) {
				RAnalOp ao; /* disassemble for the vm .. */
				int os = core->rasm->config->syntax;
				// r_asm_set_syntax (core->rasm, R_ARCH_SYNTAX_INTEL);
				r_arch_config_set_syntax (core->rasm->config, R_ARCH_SYNTAX_INTEL);
				r_asm_disassemble (core->rasm, &ao, ds_bufat (ds), ds_left (ds) + 5);
				// r_asm_set_syntax (core->rasm, os);
				r_arch_config_set_syntax (core->anal->config, os);
			}
#if 0
			if (mi_type == R_META_TYPE_FORMAT) {
				if ((ds->show_comments || ds->show_cmt_user) && ds->show_cmt_right) {
			//		haveMeta = false;
				}
			}
#endif
			if (mi_type != R_META_TYPE_FORMAT) {
				if (ds->asm_hint_pos > 0) {
					ds_print_core_vmode (ds, ds->asm_hint_pos);
				}
			}
			ds_end_line_highlight (ds);
			if ((ds->show_comments || ds->show_cmt_user) && ds->show_cmt_right) {
				ds_print_color_reset (ds);
				ds_print_comments_right (ds);
			}
		} else {
			// show cursor
			ds_print_show_cursor (ds);
			if (!ds->show_bytes_right) {
				if (ds->show_bytes_ascmt) {
					if (ds->show_color) {
						r_cons_printf (ds->core->cons, "%s;;", COLOR (ds, color_comment));
					} else {
						r_cons_print (ds->core->cons, ";;");
					}
				}
				ds_print_bytes (ds);
				if (ds->show_bytes_ascmt && ds->show_color) {
					r_cons_print (ds->core->cons, Color_RESET);
				}
			}
			ds_print_lines_right (ds);
			ds_print_optype (ds);
			ds_print_vliw (ds, false);
			ds_build_op_str (ds, true);
			ds_print_opstr (ds);
			ds_print_vliw (ds, true);
			ds_end_line_highlight (ds);
			ds_print_dwarf (ds);
			ret = ds_print_middle (ds, ret);

			ds_print_asmop_payload (ds, ds_bufat (ds));
			if (core->rasm->config->syntax != R_ARCH_SYNTAX_INTEL) {
				RAnalOp ao; // disassemble for the vm ..
				int os = core->rasm->config->syntax;
				// r_asm_set_syntax (core->rasm, R_ARCH_SYNTAX_INTEL);
				r_arch_config_set_syntax (core->anal->config, R_ARCH_SYNTAX_INTEL);
				r_asm_disassemble (core->rasm, &ao, ds_bufat (ds), ds_left (ds));
				// r_asm_set_syntax (core->rasm, os);
				r_arch_config_set_syntax (core->anal->config, os);
			}
			if (ds->show_bytes_right && ds->show_bytes) {
				const char *pfx = ds->show_bytes_ascmt? ";;": "";
				ds_comment (ds, true, pfx);
				ds_print_bytes (ds);
			}
			if (ds->asm_hint_emu) {
				ds_print_esil_anal (ds);
			}
			if (ds->asm_hint_pos > 0) {
				ds_print_core_vmode (ds, ds->asm_hint_pos);
			}
			// ds_print_cc_update (ds);

			ds_cdiv_optimization (ds);
			if ((ds->show_comments || ds->show_cmt_user) && ds->show_cmt_right) {
				if (ds->show_cmt_pseudo) {
					char *res = r_asm_parse_pseudo (core->rasm, ds->analop.mnemonic);
					if (res) {
						ds_comment (ds, true, "%s", res);
						free (res);
					}
				}
				if (ds->show_cmt_esil) {
					const char *esil = R_STRBUF_SAFEGET (&ds->analop.esil);
					if (ds->show_color) {
						ds_comment (ds, true, "%s %s%s%s", ds->cmtoken,
							ds->pal_comment, esil, Color_RESET);
					} else {
						ds_comment (ds, true, "%s %s", ds->cmtoken, esil);
					}
				}
				ds_print_ptr (ds, len + 256, ds->index);
				ds_print_sysregs (ds);
				ds_print_fcn_name (ds);
				ds_print_demangled (ds);
				ds_print_color_reset (ds);
				ds_print_comments_right (ds);
				if (!ds->asm_hint_emu) {
					ds_print_esil_anal (ds);
				}
				ds_show_refs (ds);
			}
		}
		core->print->resetbg = true;
		ds_newline (ds);
		if (ds->line) {
			if (ds->show_lines_ret && ds->analop.type == R_ANAL_OP_TYPE_RET) {
				if (strchr (ds->line, '>')) {
					memset (ds->line, ' ', r_str_len_utf8 (ds->line));
				}
				ds_begin_line (ds);
				ds_print_pre (ds, true);
				ds_print_ref_lines (ds, ds->line, ds->line_col, false);
				r_cons_printf (ds->core->cons, "%s --------------------------------------", ds->cmtoken);
				ds_newline (ds);
			}
			R_FREE (ds->line);
			R_FREE (ds->line_col);
			R_FREE (ds->refline);
			R_FREE (ds->refline2);
			R_FREE (ds->prev_line_col);
		}
		if (pdu_condition) {
			if (ds->opstr) {
				opstr_nocolor = ds->opstr;
				// we can't strcmp with color codes interfering
				r_str_ansi_filter (opstr_nocolor, &ds->opstr, NULL, -1);
				switch (pdu_condition_type) {
#if 0
				case esil:
					pdu_condition_met = true;
					break;
#endif
				case pdu_instruction:
					// match full instruction
					if (!strcmp (pdu_condition_instruction, opstr_nocolor)) {
						pdu_condition_met = true;
					}
					break;
				case pdu_opcode:
					// opcode must be followed by space or end of string
					if (!strncmp (pdu_condition_opcode, opstr_nocolor, opcode_len)
							&& (opstr_nocolor[opcode_len] == ' '
								|| !opstr_nocolor[opcode_len])) {
						pdu_condition_met = true;
					}
				}
			} else {
				// no more bytes - give up
				r_cons_reset (cons);
				r_cons_printf (cons, "Failed to find instruction meeting pdu condition.\n");
				pdu_condition_met = true;
			}
		}

		R_FREE (opstr_nocolor);
		R_FREE (ds->opstr);

		inc = ds->oplen;
		if (ds->midflags == R_MIDFLAGS_REALIGN && skip_bytes_flag) {
			inc = skip_bytes_flag;
		}
		if (skip_bytes_bb && skip_bytes_bb < inc) {
			inc = skip_bytes_bb;
		}
		if (inc < 1) {
			inc = 1;
		}
		inc += ds->asmop.payload + (ds->asmop.payload % ds->core->rasm->dataalign);
		r_anal_op_fini (&ds->analop);
	}

	R_FREE (nbuf);
	r_cons_break_pop (cons);

#if HASRETRY
	// if we come here without goto, never retry with count_bytes
	if (!count_bytes && ds->lines < ds->count
			&& (pdu_condition? !pdu_condition_met: true)) {
		ds->at = ds->addr = ds->at + inc;
		ds->index = 0;
	retry:
		R_LOG_DEBUG ("Retrying. ds->at,ds->addr=%#" PFMT64x ", ds->index=%d", ds->at, ds->index);
		if (len < max_op_size) {
			ds->len = len = max_op_size + 32;
		}
		R_FREE (nbuf);
		ds->buf = buf = nbuf = malloc (len);

		// only try again if we still need more lines
		if (buf && !count_bytes && ds->lines < ds->count) {
			ds->addr += ds->index;
			r_io_read_at (core->io, ds->addr, buf, len);

			goto toro;
		}
	}
#endif
	if (ds->pj) {
		r_cons_pop (ds->core->cons);
		if (!pj) {
			pj_end (ds->pj);
			r_cons_printf (ds->core->cons, "%s", pj_string (ds->pj));
			pj_free (ds->pj);
		}
	}
	r_print_set_rowoff (core->print, ds->lines, ds->at - addr, calc_row_offsets);
	r_print_set_rowoff (core->print, ds->lines + 1, UT32_MAX, calc_row_offsets);
	// TODO: this too (must review)
	ds_print_esil_anal_fini (ds);
	ds_reflines_fini (ds);
	R_FREE (nbuf);
	p->calc_row_offsets = calc_row_offsets;
	/* used by asm.emu */
	r_reg_arena_pop (core->anal->reg);
	ut64 res = ds_offset (ds); //-ds->lastfail;
	ds_free (ds);
	return res;
}

static inline bool check_end(int nb_opcodes, int nb_bytes, int i, int j) {
	if (nb_opcodes > 0) {
		if (nb_bytes > 0) {
#if 1
			const int maxinstrsz = 32;
			if (nb_bytes < maxinstrsz) {
				// XXX if bbsize <32 expect invalid in disasm
				return j < nb_opcodes && i < nb_bytes;
			}
			return j < nb_opcodes && i + maxinstrsz < nb_bytes;
#else
			return j < nb_opcodes && i < nb_bytes;
#endif
		}
		return j < nb_opcodes;
	}
	return i < nb_bytes;
}

R_API int r_core_print_disasm_instructions_with_buf(RCore *core, ut64 address, ut8 *buf, int nb_bytes, int nb_opcodes) {
	RDisasmState *ds = NULL;
	int i, j, ret, len = 0;
	const ut64 old_offset = core->addr;
	// bool hasanal = false;
	const size_t addrbytes = buf ? 1 : core->io->addrbytes;
	int skip_bytes_flag = 0, skip_bytes_bb = 0;

	if (nb_bytes < 1 && nb_opcodes < 1) {
		return 0;
	}

	r_reg_arena_push (core->anal->reg);

	ds = ds_init (core);
	if (!ds) {
		return 0;
	}
	ds->count = nb_opcodes;
	ds->len = nb_opcodes * 8;

	if (!buf) {
		r_core_seek (core, address, true);
		buf = core->block;
	}

	core->addr = address;

	r_cons_break_push (core->cons, NULL, NULL);
	//build ranges to map addr with bits
	j = 0;
	int opsize = 0;
toro:
	for (i = 0; check_end (nb_opcodes, nb_bytes, addrbytes * i, j); i += (opsize>0)?opsize: 1, j++) {
		ds->at = address + i;
		ds->vat = r_core_pava (core, ds->at);
		r_core_seek_arch_bits (core, ds->at);
		if (r_cons_is_breaked (core->cons)) {
			break;
		}
		ds_hint_begin (ds, ds->at);
		ds->has_description = false;
		r_anal_op_fini (&ds->analop);
		const size_t delta = addrbytes * i;
		r_anal_op_init (&ds->analop);
		const int oret = r_anal_op (core->anal, &ds->analop, ds->at,
			buf + delta, nb_bytes - delta, R_ARCH_OP_MASK_ALL);
		ret = oret;
		ds->oplen = ds->analop.size;
		if (ret > 0) {
			ret = ds->oplen;
			if (ds->analop.mnemonic) {
				free (ds->opstr);
				ds->opstr = strdup (ds->analop.mnemonic);
			}
		} else {
			if (!ds->opstr) {
				ds->opstr = strdup ("invalid");
			}
		}
		opsize = ds->oplen;
		skip_bytes_flag = handleMidFlags (core, ds, true);
		if (ds->midbb) {
			skip_bytes_bb = handleMidBB (core, ds);
		}
		if (skip_bytes_flag && ds->midflags > R_MIDFLAGS_SHOW) {
			ret = skip_bytes_flag;
			opsize = ret;
		}
		if (skip_bytes_bb && skip_bytes_bb < ret) {
			ret = skip_bytes_bb;
			opsize = ret;
		}
		if (ds_must_strip (ds)) {
			continue;
		}
		if (ds->hint && ds->hint->size > 0) {
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
		int codealign = core->anal->config->codealign;
		bool unaligned = (codealign > 1 && (ds->at % codealign));
		if (unaligned) {
			ds->analop.type = R_ANAL_OP_TYPE_ILL;
		}
		if (ds->hint && ds->hint->opcode) {
			free (ds->opstr);
			ds->opstr = strdup (ds->hint->opcode);
		} else {
			if (ds->decode && !ds->immtrim) {
				R_FREE (ds->opstr);
				char *tmpopstr = r_anal_op_tostring (core->anal, &ds->analop);
#if 0
				ds->opstr = tmpopstr? tmpopstr: strdup (ds->analop.mnemonic);
#else
				ds->opstr = (tmpopstr)? tmpopstr: strdup (ds->asmop.mnemonic);
#endif

			} else if (ds->immtrim) {
				free (ds->opstr);
				ds->opstr = strdup (ds->analop.mnemonic);
				char *res = r_asm_parse_immtrim (core->rasm, ds->opstr);
				if (res) {
					free (ds->opstr);
					ds->opstr = res;
				}
			} else if (ds->use_esil) {
				if (*R_STRBUF_SAFEGET (&ds->analop.esil)) {
					free (ds->opstr);
					ds->opstr = strdup (R_STRBUF_SAFEGET (&ds->analop.esil));
				}
			} else if (ds->subnames) {
				char *asm_str;
				RSpace *ofs = core->rasm->parse->flagspace;
				RSpace *fs = ds->flagspace_ports;
				if (ds->analop.type == R_ANAL_OP_TYPE_IO) {
					core->rasm->parse->notin_flagspace = NULL;
					core->rasm->parse->flagspace = fs;
				} else {
					if (fs) {
						core->rasm->parse->notin_flagspace = fs;
						core->rasm->parse->flagspace = fs;
					} else {
						core->rasm->parse->notin_flagspace = NULL;
						core->rasm->parse->flagspace = NULL;
					}
				}
				ds_build_op_str (ds, true);
				if (oret < 1) {
					free (ds->opstr);
					ds->opstr = strdup (ds->analop.mnemonic);
				}
				asm_str = colorize_asm_string (core, ds, true);
				if (asm_str) {
					core->rasm->parse->flagspace = ofs;
					free (ds->opstr);
					ds->opstr = asm_str;
				}
			} else {
				ds->opstr = strdup (ds->analop.mnemonic);
			}
			if (ds->immtrim) {
				free (ds->opstr);
				ds->opstr = r_asm_parse_immtrim (core->rasm, ds->analop.mnemonic);
			}
		}
		if (ds->asm_instr) {
			const char *opcolor = NULL;
			if (R_STR_ISEMPTY (ds->opstr)) {
				free (ds->opstr);
				ds->opstr = strdup (unaligned? "unaligned": "invalid");
			}
			if (ds->show_color) {
				opcolor = r_print_color_op_type (core->print, ds->analop.type);
				r_cons_printf (core->cons, "%s%s" Color_RESET "\n", opcolor, ds->opstr);
			} else {
				r_cons_println (core->cons, ds->opstr);
			}
			R_FREE (ds->opstr);
		}
		if (ds->hint) {
			r_anal_hint_free (ds->hint);
			ds->hint = NULL;
		}
	}
	if (buf == core->block && nb_opcodes > 0 && j < nb_opcodes) {
		r_core_seek (core, core->addr + i, true);
		i = 0;
		goto toro;
	}
	r_cons_break_pop (core->cons);
	ds_free (ds);
	core->addr = old_offset;
	r_reg_arena_pop (core->anal->reg);

	return len;
}

static bool handle_backwards_disasm(RCore *core, int *nb_opcodes, int *nb_bytes) {
	if (!*nb_opcodes && !*nb_bytes) {
		return false;
	}
	if (!*nb_bytes) {
		*nb_bytes = core->blocksize;
		if (*nb_opcodes < 0) {
			/* Backward disassembly of nb_opcodes opcodes
			 * - We compute the new starting offset
			 * - Read at the new offset */
			*nb_opcodes = -*nb_opcodes;

			const ut64 old_offset = core->addr;
			int nbytes = 0;

			// We have some anal_info.
			if (r_core_prevop_addr (core, core->addr, *nb_opcodes, &core->addr)) {
				nbytes = old_offset - core->addr;
			} else {
				// core->addr is modified by r_core_prevop_addr
				core->addr = old_offset;
				r_core_asm_bwdis_len (core, &nbytes, &core->addr, *nb_opcodes);
			}
			if (nbytes > core->blocksize) {
				r_core_block_size (core, nbytes);
			}
			if (nbytes < 1) {
				return false;
			}
			r_io_read_at (core->io, core->addr, core->block, nbytes);
		}
	} else {
		if (*nb_bytes < 0) { // Disassemble backward `nb_bytes` bytes
			*nb_bytes = -*nb_bytes;
			core->addr -= *nb_bytes;
			if (*nb_bytes > core->blocksize) {
				ut64 obsz = core->blocksize;
				r_core_block_size (core, *nb_bytes);
				if (core->blocksize == *nb_bytes) {
					r_io_read_at (core->io, core->addr, core->block, *nb_bytes);
				} else {
					R_LOG_ERROR ("Cannot read that much!");
					r_core_block_size (core, obsz);
					return false;
				}
				r_core_block_size (core, obsz);
			} else {
				r_io_read_at (core->io, core->addr, core->block, *nb_bytes);
			}
		} else {
			if (*nb_bytes > core->blocksize) {
				r_core_block_size (core, *nb_bytes);
				r_io_read_at (core->io, core->addr, core->block, *nb_bytes);
			}
		}
	}
	return true;
}

/* Disassemble either `nb_opcodes` instructions, or
 * `nb_bytes` bytes; both can be negative.
 * Set to 0 the parameter you don't use */
R_API int r_core_print_disasm_instructions(RCore *core, int nb_bytes, int nb_opcodes) {
	const ut64 ocore_offset = core->addr;
	int ret = -1;
	if (handle_backwards_disasm (core, &nb_opcodes, &nb_bytes)) {
		ret = r_core_print_disasm_instructions_with_buf (core, core->addr, NULL, nb_bytes, nb_opcodes);
	}
	r_core_seek (core, ocore_offset, true);
	return ret;
}


/* Disassemble `nb_opcodes` instructions, or bytes if `nb_bytes` is enabled (as JSON) */
R_IPI int r_core_print_disasm_json_ipi(RCore *core, ut64 addr, ut8 *buf, int nb_bytes, int nb_opcodes, PJ *pj, const void *pdu_condition) {
	RDisasmState *ds;
	RAnalFunction *f;
	int i, j, k, line;
	ut64 old_offset = core->addr;
	ut64 at;
	int dis_opcodes = 0;
	int limit_by = 'b';

	const char *pdu_condition_opcode = pdu_condition ? (const char *)pdu_condition : "";
	int opcode_len = strlen (pdu_condition_opcode);

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
				R_LOG_ERROR ("Too many backward instructions");
				return false;
			}
			if (r_core_prevop_addr (core, core->addr, nb_opcodes, &addr)) {
				nbytes = old_offset - addr;
			} else if (!r_core_asm_bwdis_len (core, &nbytes, &addr, nb_opcodes)) {
				/* workaround to avoid empty arrays */
#define BWRETRY 0
#if BWRETRY
				nb_opcodes ++;
				if (!r_core_asm_bwdis_len (core, &nbytes, &addr, nb_opcodes)) {
#endif
					pj_end (pj);
					return false;
#if BWRETRY
				}
#endif
			}
			count = R_MIN (nb_bytes, nbytes);
			if (count > 0) {
				r_io_read_at (core->io, addr, buf, count);
				r_io_read_at (core->io, addr + count, buf + count, nb_bytes - count);
			} else {
				if (nb_bytes > 0) {
					memset (buf, core->io->Oxff, nb_bytes);
				}
			}
		} else {
			// If we are disassembling a positive number of lines, enable dis_opcodes
			// to be used to finish the loop
			// If we are disasembling a negative number of lines, we just calculate
			// the equivalent addr and nb_size and scan a positive number of BYTES
			// so keep dis_opcodes = 0;
			dis_opcodes = 1;
			r_io_read_at (core->io, addr, buf, nb_bytes);
		}
	} else { // Disassemble `nb_bytes` bytes
		if (nb_bytes < 0) {
			//Backward disassembly of `nb_bytes` bytes
			nb_bytes = -nb_bytes;
			addr -= nb_bytes;
			r_io_read_at (core->io, addr, buf, nb_bytes);
		}
	}
	core->addr = addr;

	// TODO: add support for anal hints
	// If using #bytes i = j
	// If using #opcodes, j is the offset from start address. i is the
	// offset in current disassembly buffer (256 by default)
	i = k = j = line = 0;
	// i = number of bytes
	// j = number of instructions
	// k = delta from addr
	ds = ds_init (core);
	bool result = false;
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (core->rasm->config);

	r_cons_break_push (core->cons, NULL, NULL);
	for (;;) {
		if (r_cons_is_breaked (core->cons)) {
			break;
		}
		RAnalOp asmop;
		bool end_nbopcodes, end_nbbytes, end_pdu_condition;
		int skip_bytes_flag = 0, skip_bytes_bb = 0;

		at = addr + k;
		ds_hint_begin (ds, ds->at);
		r_asm_set_pc (core->rasm, at);
		// 32 is the biggest opcode length in intel
		// Make sure we have room for it
		if (dis_opcodes == 1 && i >= nb_bytes - 32) {
			// Read another nb_bytes bytes into buf from current offset
			r_io_read_at (core->io, at, buf, nb_bytes);
			i = 0;
		}

		if (limit_by == 'o') {
			if (j >= nb_opcodes) {
				break;
			}
		} else if (i >= nb_bytes) {
			break;
		}
		const bool opseudo = core->rasm->pseudo;
		core->rasm->pseudo = false;
		int ret = r_asm_disassemble (core->rasm, &asmop, buf + i, nb_bytes - i);
		if (ret < 1) {
			pj_o (pj);
			pj_kn (pj, "addr", at);
			pj_ki (pj, "size", 1);
			if (asmop.bytes) {
				char *hex = r_hex_bin2strdup (asmop.bytes, asmop.size);
				pj_ks (pj, "bytes", hex);
				free (hex);
			}
			pj_ks (pj, "type", "invalid");
			pj_end (pj);
			i++;
			k++;
			j++;
			result = true;
			continue;
		}

		char *opstr = strdup (asmop.mnemonic? asmop.mnemonic: "");
		core->rasm->pseudo = opseudo;

		ds->has_description = false;
		r_anal_op_fini (&ds->analop);
		r_anal_op (core->anal, &ds->analop, at, buf + i, nb_bytes - i, R_ARCH_OP_MASK_ALL);

		if (ds->pseudo) {
			char *res = r_asm_parse_pseudo (core->rasm, opstr);
			if (res) {
				free (opstr);
				opstr = res;
			}
		}

		// f = r_anal_get_fcn_in (core->anal, at,
		f = fcnIn (ds, at, R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM | R_ANAL_FCN_TYPE_LOC);
		if (ds->subvar && f) {
			char *res = r_asm_parse_subvar (core->rasm, f, at, ds->analop.size, asmop.mnemonic);
			if (res) {
				r_anal_op_set_mnemonic (&asmop, 0, res);
				free (res);
			}
		}
		ds->oplen = asmop.size;
		ds->at = at;
		skip_bytes_flag = handleMidFlags (core, ds, false);
		if (ds->midbb) {
			skip_bytes_bb = handleMidBB (core, ds);
		}
		if (skip_bytes_flag && ds->midflags > R_MIDFLAGS_SHOW) {
			ds->oplen = skip_bytes_flag;
		}
		if (skip_bytes_bb && skip_bytes_bb < ret) {
			ds->oplen = skip_bytes_bb;
		}
		{
			ut64 killme = UT64_MAX;
			if (r_io_read_i (core->io, ds->analop.ptr, &killme, ds->analop.refptr, be)) {
				core->rasm->parse->subrel_addr = killme;
			}
		}
		char *disasm = strdup (asmop.mnemonic? asmop.mnemonic: "");
		{
			char *buf = ds_sub_jumps (ds, disasm);
			if (buf) {
				free (disasm);
				disasm = buf;
			}
			char *res = r_asm_parse_filter (core->rasm, ds->vat, core->flags, ds->hint, disasm);
			if (res) {
				r_anal_op_set_mnemonic (&asmop, 0, res);
				free (disasm);
				disasm = res;
			}
		}

		pj_o (pj);
		pj_kn (pj, "addr", at);
		if (ds->analop.ptr != UT64_MAX) {
			pj_kn (pj, "ptr", ds->analop.ptr);
		}
		if (ds->analop.val != UT64_MAX) {
			pj_kn (pj, "val", ds->analop.val);
		}
		pj_k (pj, "esil"); // split key and value to allow empty strings
		pj_s (pj, R_STRBUF_SAFEGET (&ds->analop.esil));
		pj_ki (pj, "refptr", ds->analop.refptr);
		pj_kn (pj, "fcn_addr", f ? f->addr : 0);
		pj_kn (pj, "fcn_last", f ? r_anal_function_max_addr (f) - ds->oplen : 0);
		pj_ki (pj, "size", ds->analop.size);
		pj_ks (pj, "opcode", opstr);
		pj_ks (pj, "disasm", disasm);
		free (disasm);
		{
			char *hex = r_hex_bin2strdup (asmop.bytes, asmop.size);
			pj_ks (pj, "bytes", hex);
			free (hex);
		}
		pj_ks (pj, "family", r_anal_op_family_tostring (ds->analop.family));
		pj_ks (pj, "type", r_anal_optype_tostring (ds->analop.type));
		// indicate a relocated address
		RBinReloc *rel = r_core_getreloc (core, ds->at, ds->analop.size);
		// reloc is true if address in reloc table
		pj_kb (pj, "reloc", rel);
		// wanted the numerical values of the type information
		pj_kn (pj, "type_num", (ut64)(ds->analop.type & UT64_MAX));
		pj_kn (pj, "type2_num", (ut64)(ds->analop.type2 & UT64_MAX));
		// addr addrline info here
		{
			RBinAddrline *al = r_bin_addrline_get (core->bin, at);
			if (al) {
				pj_ko (pj, "addrline");
				pj_ks (pj, "file", al->file);
				pj_kn (pj, "line", al->line);
				pj_end (pj);
				r_bin_addrline_free (al);
			}
		}
		// handle switch statements
		if (ds->analop.switch_op && r_list_length (ds->analop.switch_op->cases) > 0) {
			// XXX - the java caseop will still be reported in the assembly,
			// this is an artifact to make ensure the disassembly is properly
			// represented during the analysis
			RListIter *iter;
			RAnalCaseOp *caseop;
			pj_k (pj, "switch");
			pj_a (pj);
			r_list_foreach (ds->analop.switch_op->cases, iter, caseop ) {
				pj_o (pj);
				pj_kn (pj, "addr", caseop->addr);
				pj_kN (pj, "value", (st64) caseop->value);
				pj_kn (pj, "jump", caseop->jump);
				pj_end (pj);
			}
			pj_end (pj);
		}
		if (ds->analop.jump != UT64_MAX ) {
			pj_kn (pj, "jump", ds->analop.jump);
			if (ds->analop.fail != UT64_MAX) {
				pj_kn (pj, "fail", ds->analop.fail);
			}
		}
		/* add flags */
		{
			const RList *flags = r_flag_get_list (core->flags, at);
			RFlagItem *flag;
			RListIter *iter;
			if (flags && !r_list_empty (flags)) {
				pj_k (pj, "flags");
				pj_a (pj);
				r_list_foreach (flags, iter, flag) {
					pj_s (pj, flag->name);
				}
				pj_end (pj);
			}
		}
		/* add comments */
		{
			// TODO: slow because we are encoding b64
			const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, at);
			if (comment) {
				char *b64comment = sdb_encode ((const ut8*)comment, -1);
				if (b64comment) {
					pj_ks (pj, "comment", b64comment);
					free (b64comment);
				}
			}
		}
		/* add refs */
		{
			RVecAnalRef *refs = r_anal_refs_get (core->anal, at);
			if (refs && !RVecAnalRef_empty (refs)) {
				pj_k (pj, "refs");
				pj_a (pj);
				RAnalRef *ref;
				R_VEC_FOREACH (refs, ref) {
					pj_o (pj);
					pj_kn (pj, "addr", ref->addr);
					pj_ks (pj, "type", r_anal_ref_type_tostring (ref->type));
					pj_ks (pj, "perm", r_anal_ref_perm_tostring (ref));
					pj_end (pj);
				}
				pj_end (pj);
			}
			RVecAnalRef_free (refs);
		}
		/* add xrefs */
		{
			RVecAnalRef *xrefs = r_anal_xrefs_get (core->anal, at);
			if (xrefs && !RVecAnalRef_empty (xrefs)) {
				pj_k (pj, "xrefs");
				pj_a (pj);
				RAnalRef *ref;
				R_VEC_FOREACH (xrefs, ref) {
					pj_o (pj);
					pj_kn (pj, "addr", ref->addr);
					pj_ks (pj, "type", r_anal_ref_type_tostring (ref->type));
					pj_ks (pj, "perm", r_anal_ref_perm_tostring (ref));
					pj_end (pj);
				}
				pj_end (pj);
			}
			RVecAnalRef_free (xrefs);
		}

		pj_end (pj);
		i += ds->oplen + asmop.payload + (ds->asmop.payload % ds->core->rasm->dataalign); // bytes
		k += ds->oplen + asmop.payload + (ds->asmop.payload % ds->core->rasm->dataalign); // delta from addr
		j++; // instructions
		line++;

		end_nbopcodes = dis_opcodes == 1 && nb_opcodes > 0 && line>=nb_opcodes;
		end_nbbytes = dis_opcodes == 0 && nb_bytes > 0 && i>=nb_bytes;
		end_pdu_condition = (!strncmp (pdu_condition_opcode, opstr, opcode_len)
								&& (opstr[opcode_len] == ' '
									|| !opstr[opcode_len]));
		result = true;
		r_anal_op_fini (&asmop);
		if (end_nbopcodes || end_nbbytes || end_pdu_condition) {
			break;
		}
		free (opstr);
	}
	r_cons_break_pop (core->cons);
	r_anal_op_fini (&ds->analop);
	core->addr = old_offset;
	ds_free (ds);
	if (!result) {
		pj_o (pj);
		pj_end (pj);
		result = true;
	}
	return result;
}

R_API int r_core_print_disasm_all(RCore *core, ut64 addr, int l, int len, int mode) {
	const bool scr_color = r_config_get_i (core->config, "scr.color") > 0;
	int i, ret, count = 0;
	ut8 *buf = core->block;
	if (l < 1) {
		l = len;
	}
	RDisasmState *ds = ds_init (core);
	if (l > core->blocksize || addr != core->addr) {
		buf = malloc (l + 1);
		if (!buf) {
			ds_free (ds);
			return 0;
		}
		r_io_read_at (core->io, addr, buf, l);
	}
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = r_core_pj_new (core);
		if (!pj) {
			ds_free (ds);
			return 0;
		}
		pj_a (pj);
	}
	int minopsz = r_anal_archinfo (core->anal, R_ARCH_INFO_MINOP_SIZE);
	int opalign = r_anal_archinfo (core->anal, R_ARCH_INFO_CODE_ALIGN);
	r_cons_break_push (core->cons, NULL, NULL);
	for (i = 0; i < l; i += minopsz) {
		RAnalOp asmop;
		ds->at = addr + i;
		if (opalign > 1) {
			// skip unaligned addresses
			if ((ds->at % opalign)) {
				i += (ds->at % opalign) - minopsz;
				continue;
			}
		}
		ds->vat = r_core_pava (core, ds->at);
		r_asm_set_pc (core->rasm, ds->vat);
		if (r_cons_is_breaked (core->cons)) {
			break;
		}
		ret = r_asm_disassemble (core->rasm, &asmop, buf + i, l - i);
		if (ret < 1) {
			const char *invcolor = r_print_color_op_type (core->print, R_ANAL_OP_TYPE_ILL);
			ret = asmop.size;
			switch (mode) {
			case 'j':
			case '=':
				break;
			case 'i':
				if (scr_color) {
					r_cons_printf (core->cons, "%sinvalid%s\n", invcolor, Color_RESET);
				} else {
					r_cons_printf (core->cons, "invalid\n");
				}
				break;
			default:
				if (scr_color) {
					r_cons_printf (core->cons, "0x%08"PFMT64x" %sinvalid%s\n",
							ds->vat, invcolor, Color_RESET);
				} else {
					r_cons_printf (core->cons, "0x%08"PFMT64x" invalid\n", ds->vat);
				}
				break;
			}
		} else {
			count ++;
			switch (mode) {
			case 'i':
				{
					char *res = r_asm_parse_filter (core->rasm, ds->vat, core->flags, ds->hint, asmop.mnemonic);

					if (scr_color) {
						RAnalOp aop;
						RAnalFunction *f = fcnIn (ds, ds->vat, R_ANAL_FCN_TYPE_NULL);
						r_anal_op (core->anal, &aop, addr, buf + i, l - i, R_ARCH_OP_MASK_ALL);
						char *buf_asm = r_print_colorize_opcode (core->print, res? res: asmop.mnemonic,
								core->cons->context->pal.reg, core->cons->context->pal.num, false, f ? f->addr : 0);
						if (buf_asm) {
							r_cons_printf (core->cons, "%s%s\n", r_print_color_op_type (core->print, aop.type), buf_asm);
							free (buf_asm);
						}
					} else {
						r_cons_println (core->cons, asmop.mnemonic);
					}
					free (res);
				}
				break;
			case '=':
				if (i < 28) {
					char *str = r_str_newf ("0x%08"PFMT64x" %60s  %s\n", ds->vat, "", asmop.mnemonic);
					char *sp = strchr (str, ' ');
					if (sp) {
						char *end = sp + 60 + 1;
						char *src = r_hex_bin2strdup (asmop.bytes, asmop.size);
						char *dst = sp + 1 + (i * 2);
						int len = strlen (src);
						if (dst < end) {
							if (dst + len >= end) {
								len = end - dst;
								dst[len] = '.';
							}
							memcpy (dst, src, len);
						}
						free (src);
					}
					r_cons_print (core->cons, str);
					free (str);
				}
				break;
			case 'j': {
				char *op_hex = r_hex_bin2strdup (asmop.bytes, asmop.size);
				pj_o (pj);
				pj_kn (pj, "addr", addr + i);
				pj_ks (pj, "bytes", op_hex);
				pj_ks (pj, "inst", asmop.mnemonic);
				pj_end (pj);
				free (op_hex);
				break;
			}
			default: {
				char *op_hex = r_hex_bin2strdup (asmop.bytes, asmop.size);
				r_cons_printf (core->cons, "0x%08"PFMT64x" %20s  %s\n",
						addr + i, op_hex,
						asmop.mnemonic);
				free (op_hex);
			}
			}
		}
		r_anal_op_fini (&asmop);
	}
	r_cons_break_pop (core->cons);
	if (buf != core->block) {
		free (buf);
	}
	if (mode == 'j') {
		pj_end (pj);
		r_cons_println (core->cons, pj_string (pj));
		pj_free (pj);
	}
	ds_free (ds);
	return count;
}

R_API int r_core_disasm_pdi_with_buf(RCore *core, ut64 address, ut8 *buf, ut32 nb_opcodes, ut32 nb_bytes, int fmt) {
	bool show_offset = r_config_get_b (core->config, "asm.addr");
	// bool show_offset_focus = r_config_get_b (core->config, "asm.addr.focus");
	bool show_bytes = r_config_get_b (core->config, "asm.bytes");
	bool decode = r_config_get_b (core->config, "asm.decode");
	bool subnames = r_config_get_b (core->config, "asm.sub.names");
	bool show_color = r_config_get_i (core->config, "scr.color") > 0;
	bool asm_ucase = r_config_get_b (core->config, "asm.ucase");
	bool asm_instr = r_config_get_i (core->config, "asm.instr");
	bool esil = r_config_get_b (core->config, "asm.esil");
	bool flags = r_config_get_b (core->config, "asm.flags");
	bool asm_immtrim = r_config_get_b (core->config, "asm.imm.trim");
	int i = 0, j, ret, err = 0;
	ut64 addr = core->addr;
	const char *color_reg = R_CONS_COLOR_DEF (reg, Color_YELLOW);
	const char *color_num = R_CONS_COLOR_DEF (num, Color_CYAN);
	const size_t addrbytes = buf ? 1 : core->io->addrbytes;

	if (fmt == 'e') {
		show_bytes = false;
		decode = 1;
	}

	if (nb_opcodes < 1 && nb_bytes < 1) {
		return 0;
	}
	bool mybuf = false;
	if (!buf) {
		buf = malloc (nb_bytes);
		mybuf = true;
		r_io_read_at (core->io, address, buf, nb_bytes);
	}
	addr = address;
	ut64 addr_end = address + nb_bytes;

	r_cons_break_push (core->cons, NULL, NULL);
	int midflags = r_config_get_i (core->config, "asm.flags.middle");
	int midbb = r_config_get_i (core->config, "asm.bbmiddle");
	int minopsz = r_anal_archinfo (core->anal, R_ARCH_INFO_MINOP_SIZE);
	int opalign = r_anal_archinfo (core->anal, R_ARCH_INFO_CODE_ALIGN);
	int opinc = (minopsz < opalign)? opalign: minopsz;
	bool asmmarks = r_config_get_i (core->config, "asm.marks");
	r_config_set_b (core->config, "asm.marks", false);
	i = 0;
	j = 0;
	RAnalMetaItem *meta = NULL;
	RAnalOp asmop = {0};
toro:
	if (!check_end (nb_opcodes, nb_bytes, addrbytes * i, j)) {
		// fix infinite loop
		j += opinc;
	} else for (; check_end (nb_opcodes, nb_bytes, addrbytes * i, j); j++) {
		if (r_cons_is_breaked (core->cons)) {
			err = 1;
			break;
		}
		ut64 at = addr + i;
		if (flags) {
			if (fmt != 'e') { // pie
				RFlagItem *item = r_flag_get_in (core->flags, at);
				if (item) {
					if (show_offset) {
						r_print_offset (core->print, at, 0, 0, NULL);
					}
					r_cons_printf (core->cons, "  %s:\n", item->name);
				}
			} // do not show flags in pie
		}
		if (show_offset) {
			r_print_offset (core->print, at, 0, 0, NULL);
		}
		ut64 meta_start = at;
		ut64 meta_size = 0;
		meta = r_meta_get_at (core->anal, meta_start, R_META_TYPE_ANY, &meta_size);
		if (meta) {
			switch (meta->type) {
			case R_META_TYPE_DATA:
				i += meta_size;
				{
					ut64 at = addr + i;
					int hexlen = nb_bytes - i;
					int delta = at - meta_start;
					if (meta_size < hexlen) {
						hexlen = meta_size;
					}
					core->print->flags &= ~R_PRINT_FLAGS_HEADER;
					int size = R_MIN (meta_size, nb_bytes - i);
					RDisasmState ds = {0};
					ds.core = core;
					ut8 *b = malloc (meta_size);
					if (b) {
						r_io_read_at (core->io, at, b, meta_size);
						if (size > 0 && !ds_print_data_type (&ds, b, 0, meta_size)) {
							r_cons_printf (core->cons, "hex length=%d delta=%d\n", size, delta);
							r_print_hexdump (core->print, at, buf + i, hexlen - delta, 16, 1, 1);
						} else {
							r_cons_newline (core->cons);
						}
						free (b);
					}
					ret = true;
				}
				continue;
			case R_META_TYPE_STRING:
			case R_META_TYPE_FORMAT:
			case R_META_TYPE_MAGIC:
				// r_cons_printf (core->cons, ".magic : %s\n", meta->str);
				i += meta_size;
				continue;
			case R_META_TYPE_RUN:
				/* TODO */
				break;
			default:
				break;
			}
		}
		r_asm_set_pc (core->rasm, addr + i);
		ret = r_asm_disassemble (core->rasm, &asmop, buf + addrbytes * i, nb_bytes - addrbytes * i);
		ret = asmop.size;
		if (midflags || midbb) {
			RDisasmState ds = {
				.oplen = ret,
				.at = addr + i,
				.midflags = midflags
			};
			int skip_bytes_flag = 0, skip_bytes_bb = 0;
			if (midflags) {
				skip_bytes_flag = handleMidFlags (core, &ds, true);
			}
			if (midbb) {
				skip_bytes_bb = handleMidBB (core, &ds);
			}
			if (skip_bytes_flag && midflags > R_MIDFLAGS_SHOW) {
				// asmop.size = ret = skip_bytes_flag;
				ret = skip_bytes_flag;
			}
			if (skip_bytes_bb && skip_bytes_bb < ret) {
				// asmop.size = ret = skip_bytes_bb;
				ret = skip_bytes_bb;
			}
		}
		if (fmt == 'C') {
			const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr + i);
			if (comment) {
				r_cons_printf (core->cons, "0x%08" PFMT64x " %s\n", addr + i, comment);
			}
			i += ret;
			continue;
		}
		// r_cons_printf (core->cons, "0x%08"PFMT64x"  ", core->addr+i);
		if (ret < 1) {
			err = 1;
			ret = asmop.size;
			if (ret < 1) {
				ret = 1;
			}
			if (show_bytes) {
				r_cons_printf (core->cons, "%18s%02x  ", "", buf[i]);
			}
			r_cons_println (core->cons, "invalid");
		} else {
			if (show_bytes && asmop.bytes) {
				char *op_hex = r_hex_bin2strdup (asmop.bytes, asmop.size);
				if (op_hex) {
					r_cons_printf (core->cons, "%20s  ", op_hex);
					free (op_hex);
				}
			}
			asmop.size = ret;
			ret = asmop.size;
			if (!asm_instr) {
				r_cons_newline (core->cons);
			} else if (!asm_immtrim && (decode || esil)) {
				RAnalOp analop = {
					0
				};
				char *opstr = NULL;
				r_anal_op (core->anal, &analop, addr + i,
					buf + addrbytes * i, nb_bytes - addrbytes * i, R_ARCH_OP_MASK_ALL);
				char *tmpopstr = r_anal_op_tostring (core->anal, &analop);
				if (fmt == 'e') { // pie
					const char *esil = R_STRBUF_SAFEGET (&analop.esil);
					r_cons_println (core->cons, esil);
				} else {
					if (decode) {
						opstr = tmpopstr? tmpopstr: asmop.mnemonic;
					} else if (esil) {
						opstr = (R_STRBUF_SAFEGET (&analop.esil));
					}
					if (asm_immtrim) {
						char *res = r_asm_parse_immtrim (core->rasm, opstr);
						if (res) {
							opstr = res;
						}
					}
					r_cons_println (core->cons, opstr);
				}
				free (tmpopstr);
			} else {
				char *asm_str = strdup (asmop.mnemonic);
				if (asm_ucase) {
					r_str_case (asm_str, 1);
				}
				if (asm_immtrim) {
					char *res = r_asm_parse_immtrim (core->rasm, asm_str);
					if (res) {
						free (asm_str);
						asm_str = res;
					}
				}
				if (subnames) {
					RAnalHint *hint = r_anal_hint_get (core->anal, at);
					char *res = r_asm_parse_filter (core->rasm, at, core->flags, hint, asm_str);
					if (res) {
						free (asm_str);
						asm_str = res;
					}
					r_anal_hint_free (hint);
				}
				if (show_color) {
					RAnalOp aop = { 0 };
					RAnalFunction *f = r_anal_get_fcn_in (core->anal, addr + i, R_ANAL_FCN_TYPE_NULL);
					r_anal_op_init (&aop);
					r_anal_op (core->anal, &aop, addr + i,
						buf + addrbytes * i, nb_bytes - addrbytes * i, R_ARCH_OP_MASK_BASIC);
					asm_str = r_print_colorize_opcode (core->print, asm_str, color_reg, color_num, false, f ? f->addr : 0);
					r_cons_printf (core->cons, "%s%s"Color_RESET "\n",
						r_print_color_op_type (core->print, aop.type),
						asm_str);
					r_anal_op_fini (&aop);
					free (asm_str);
				} else {
					r_cons_println (core->cons, asm_str);
				}
			}
		}
		i += ret;
	}
	r_anal_op_fini (&asmop);
	if ((nb_opcodes > 0 && j < nb_opcodes) && (addr + i < addr_end)) {
		addr += i;
		r_io_read_at (core->io, addr, buf, nb_bytes);
		i = 0;
		goto toro;
	}
	if (mybuf) {
		free (buf);
	}
	r_config_set_b (core->config, "asm.marks", asmmarks);
	r_cons_break_pop (core->cons);
	return err;
}

R_API int r_core_disasm_pdi(RCore *core, int nb_opcodes, int nb_bytes, int fmt) {
	const ut64 ocore_offset = core->addr;
	int ret = -1;
	if (handle_backwards_disasm(core, &nb_opcodes, &nb_bytes)) {
		ret = r_core_disasm_pdi_with_buf (core, core->addr, NULL, nb_opcodes, nb_bytes, fmt);
	}
	r_core_seek (core, ocore_offset, true);
	return ret;
}

static bool read_ahead(RIO *io, ut8 **buf, size_t *buf_sz, ut64 address, size_t offset_into_buf, size_t bytes_to_read) {
	if (offset_into_buf + bytes_to_read > *buf_sz) {
		const size_t new_sz = *buf_sz * 2;
		ut8 *tmp = realloc (*buf, new_sz);
		if (!tmp) {
			return false;
		}
		*buf_sz = new_sz;
		*buf = tmp;
	}
	return r_io_read_at (io, address, *buf + offset_into_buf, bytes_to_read);
}

R_API int r_core_disasm_pde(RCore *core, int nb_opcodes, int mode) {
	// R2R db/cmd/cmd_pde
	if (nb_opcodes < 1) {
		return 0;
	}
	RReg *reg = core->anal->reg;
	RRegItem *pc = r_reg_get (reg, "PC", R_REG_TYPE_ALL);
	if (!pc) {
		return -1;
	}
	PJ *pj = NULL;
	if (mode == R_MODE_JSON) {
		pj = r_core_pj_new (core);
		if (!pj) {
			return -1;
		}
		pj_a (pj);
	}
	REsil *esil = core->anal->esil;
	RConfigHold *chold = r_config_hold_new (core->config);
	r_config_hold (chold, "io.cache", "asm.lines", NULL);
	r_config_set_b (core->config, "io.cache", true);
	r_config_set_b (core->config, "asm.lines", false);
	r_io_cache_push (core->io);
	const char *strip = r_config_get (core->config, "asm.strip");
	const int max_op_size = r_anal_archinfo (core->anal, R_ARCH_INFO_MAXOP_SIZE);
	int min_op_size = r_anal_archinfo (core->anal, R_ARCH_INFO_MINOP_SIZE);
	min_op_size = min_op_size > 0 ? min_op_size : 1;
	const ut64 read_len = max_op_size > 0 ? max_op_size : 32;
	size_t buf_sz = 0x100, block_sz = 0, block_instr = 0;
	ut64 block_start = r_reg_get_value (reg, pc);
	size_t i = 0;
	const ut64 op_addr = r_reg_get_value (reg, pc);
	ut8 *buf = malloc (buf_sz);
	if (op_addr == 0) {
		const RList *entries = r_bin_get_entries (core->bin);
		if (entries && !r_list_empty (entries)) {
			RBinAddr *entry = (RBinAddr *)r_list_get_n (entries, 0);
			RBinInfo *info = r_bin_get_info (core->bin);
			block_start = info->has_va? entry->vaddr: entry->paddr;
			r_reg_set_value (reg, pc, block_start);
			r_core_cmd0 (core, ".dr*");
		}
	}
	r_reg_arena_push (reg);
	if (!buf) {
		goto leave;
	}
	for (i = 0; i < nb_opcodes; i++) {
		const ut64 op_addr = r_reg_get_value (reg, pc);
		if (!read_ahead (core->io, &buf, &buf_sz, op_addr, block_sz, read_len)) {
			break;
		}
		RAnalOp op;
		int ret = r_anal_op (core->anal, &op, op_addr, buf + block_sz, read_len, R_ARCH_OP_MASK_ESIL);
		const bool invalid_instr = ret < 1 || op.size < 1 || op.type == R_ANAL_OP_TYPE_ILL;
		bool end_of_block = false;
		switch (op.type & R_ANAL_OP_TYPE_MASK & ~R_ANAL_OP_HINT_MASK) {
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_UJMP:
		case R_ANAL_OP_TYPE_CALL:
		case R_ANAL_OP_TYPE_UCALL:
		case R_ANAL_OP_TYPE_RET:
			end_of_block = true;
			break;
		}
		if (R_STR_ISNOTEMPTY (strip) && strstr (strip, r_anal_optype_tostring (op.type))) {
			i--;
		} else {
			block_sz += invalid_instr? min_op_size: op.size;
			if (invalid_instr || (i + 1 >= nb_opcodes)) {
				end_of_block = true;
			}
			block_instr++;
		}
		if (end_of_block) {
			if (op.delay) {
				const ut64 ops_to_read = R_MIN (op.delay, nb_opcodes - (i + 1));
				const ut64 bytes_to_read = ops_to_read * read_len;
				ut64 next_addr = op_addr;
				// Prevent overflow when adding op.size
				if (UT64_MAX - op.size >= op_addr) {
					next_addr += op.size;
				}
				if (!read_ahead (core->io, &buf, &buf_sz, next_addr, block_sz, bytes_to_read)) {
					break;
				}
				block_instr += ops_to_read;
				block_sz += bytes_to_read;
				i += ops_to_read;
			}
			if (block_instr) {
				switch (mode) {
				case R_MODE_JSON:
					r_core_print_disasm_json_ipi (core, block_start, buf, block_sz, block_instr, pj, NULL);
					break;
				case R_MODE_SIMPLE:
					r_core_disasm_pdi_with_buf (core, block_start, buf, -1, block_sz, 0);
					break;
				case R_MODE_SIMPLEST:
					r_core_print_disasm_instructions_with_buf (core, block_start, buf, block_sz, block_instr);
					break;
				default:
					// ok
					r_core_print_disasm (core, block_start, buf, block_sz, block_instr, 0, NULL, false, false, NULL, NULL);
					break;
				}
			}
			block_sz = 0;
			block_instr = 0;
		}
		if (invalid_instr) {
			break;
		}
		r_esil_set_pc (core->anal->esil, op_addr);
		r_reg_set_value (reg, pc, op_addr + op.size);
		const char *e = r_strbuf_get (&op.esil);
		if (R_STR_ISNOTEMPTY (e)) {
			r_esil_parse (esil, e);
		}
		r_anal_op_fini (&op);

		if (end_of_block) {
			block_start = r_reg_get_value (reg, pc);
			r_core_seek_arch_bits (core, block_start);
		}
	}
	if (mode == R_MODE_JSON) {
		pj_end (pj);
		r_cons_print (core->cons, pj_string (pj));
		pj_free (pj);
	}
leave:
	free (buf);
	r_reg_arena_pop (reg);
	r_io_cache_pop (core->io);
	r_config_hold_restore (chold);
	r_config_hold_free (chold);
	return i;
}
