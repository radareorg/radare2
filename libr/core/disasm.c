/* radare - LGPL - Copyright 2009-2014 - nibble, pancake, dso */

#include "r_core.h"
#include "r_cons.h"

#define HASRETRY 1
#define HAVE_LOCALS 1

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
	char str[2048], strsub[2048];
	int use_esil;
	int show_color;
	int colorop;
	//int show_utf8;
	int acase;
	int atabs;
	int decode;
	int pseudo;
	int filter;
	int varsub;
	int show_lines;
	int linesright;
	int tracespace;
	int cyclespace;
	int show_indent;
	int show_dwarf;
	int show_linescall;
	int show_size;
	int show_trace;
	int linesout;
	int adistrick;
	int asm_demangle;
	int show_offset;
	int show_offseg;
	int show_flags;
	int show_bytes;
	int show_comments;
	int show_fcnlines;
	int show_cmtflgrefs;
	int show_cycles;
	int show_stackptr;
	int show_xrefs;
	int show_functions;
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

	RAnalHint *hint;
	RPrint *p;

	int l;
	int middle;
	int indent_level;
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

	const ut8 *buf;
	int len;

	int counter;
	int maxrefs;
} RDisasmState;

static void handle_reflines_init (RCore *core, RDisasmState *ds);
static RDisasmState * handle_init_ds (RCore * core);
static void handle_set_pre (RDisasmState *ds, const char * str);
static void handle_build_op_str (RCore *core, RDisasmState *ds);
static char *filter_refline2(RCore *core, const char *str);
static char *filter_refline(RCore *core, const char *str);
static void handle_show_xrefs (RCore *core, RDisasmState *ds);
static void handle_atabs_option(RCore *core, RDisasmState *ds);
static void handle_show_functions (RCore *core, RDisasmState *ds);
static void handle_show_comments_right (RCore *core, RDisasmState *ds);
static void handle_show_flags_option(RCore *core, RDisasmState *ds);
static void handle_update_ref_lines (RCore *core, RDisasmState *ds);
static int perform_disassembly(RCore *core, RDisasmState *ds, ut8 *buf, int len);
static void handle_control_flow_comments (RCore * core, RDisasmState *ds);
static void handle_print_lines_right (RCore *core, RDisasmState *ds);
static void handle_print_lines_left (RCore *core, RDisasmState *ds);
static void handle_print_cycles(RCore *core, RDisasmState *ds);
static void handle_print_stackptr (RCore *core, RDisasmState *ds);
static void handle_print_offset (RCore *core, RDisasmState *ds );
static void handle_print_op_size (RCore *core, RDisasmState *ds);
static void handle_print_trace (RCore *core, RDisasmState *ds);
static void handle_adistrick_comments (RCore *core, RDisasmState *ds);
static int handle_print_meta_infos (RCore * core, RDisasmState *ds, ut8* buf, int len, int idx );
static void handle_print_opstr (RCore *core, RDisasmState *ds);
static void handle_print_color_reset (RCore *core, RDisasmState *ds);
static int handle_print_middle (RCore *core, RDisasmState *ds, int ret);
static int handle_print_labels (RCore *core, RDisasmState *ds, RAnalFunction *f);
static void handle_print_import_name (RCore *core, RDisasmState *ds);
static void handle_print_fcn_name (RCore * core, RDisasmState *ds);
static void handle_print_as_string(RCore *core, RDisasmState *ds);
static void handle_print_core_vmode (RCore *core, RDisasmState *ds);
static void handle_print_cc_update (RCore *core, RDisasmState *ds);
static void handle_print_dwarf (RCore *core, RDisasmState *ds);
static void handle_print_asmop_payload (RCore *core, RDisasmState *ds);
static void handle_print_op_push_info (RCore *core, RDisasmState *ds);
static int handle_read_refptr (RCore *core, RDisasmState *ds, ut64 *word8, ut32 *word4);
static void handle_print_comments_right (RCore *core, RDisasmState *ds);
static void handle_print_refptr_meta_infos (RCore *core, RDisasmState *ds, ut64 word8 );
static void handle_print_refptr (RCore *core, RDisasmState *ds);
static void handle_print_ptr (RCore *core, RDisasmState *ds, int len, int idx);

static int cmpaddr (void *_a, void *_b) {
	RAnalBlock *a = _a, *b = _b;
	return (a->addr > b->addr);
}

static RDisasmState * handle_init_ds (RCore * core) {
	RDisasmState * ds = R_NEW0(RDisasmState);
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
	ds->color_num = P(num): Color_YELLOW;
	ds->color_mov = P(mov): Color_WHITE;
	ds->color_invalid = P(invalid): Color_BRED;

	ds->use_esil = r_config_get_i (core->config, "asm.esil");
	ds->show_color = r_config_get_i (core->config, "scr.color");
	ds->colorop = r_config_get_i (core->config, "scr.colorops");
	ds->show_utf8 = r_config_get_i (core->config, "scr.utf8");
	ds->acase = r_config_get_i (core->config, "asm.ucase");
	ds->atabs = r_config_get_i (core->config, "asm.tabs");
	ds->decode = r_config_get_i (core->config, "asm.decode");
	ds->pseudo = r_config_get_i (core->config, "asm.pseudo");
	ds->filter = r_config_get_i (core->config, "asm.filter");
	ds->varsub = r_config_get_i (core->config, "asm.varsub");
	ds->maxrefs = r_config_get_i (core->config, "asm.maxrefs");
	ds->show_lines = r_config_get_i (core->config, "asm.lines");
	ds->linesright = r_config_get_i (core->config, "asm.linesright");
	ds->show_indent = r_config_get_i (core->config, "asm.indent");
	ds->tracespace = r_config_get_i (core->config, "asm.tracespace");
	ds->cyclespace = r_config_get_i (core->config, "asm.cyclespace");
	ds->show_dwarf = r_config_get_i (core->config, "asm.dwarf");
	ds->show_linescall = r_config_get_i (core->config, "asm.linescall");
	ds->show_size = r_config_get_i (core->config, "asm.size");
	ds->show_trace = r_config_get_i (core->config, "asm.trace");
	ds->linesout = r_config_get_i (core->config, "asm.linesout");
	ds->adistrick = r_config_get_i (core->config, "asm.middle"); // TODO: find better name
	ds->asm_demangle = r_config_get_i (core->config, "asm.demangle");
	ds->show_offset = r_config_get_i (core->config, "asm.offset");
	ds->show_offseg = r_config_get_i (core->config, "asm.segoff");
	ds->show_flags = r_config_get_i (core->config, "asm.flags");
	ds->show_bytes = r_config_get_i (core->config, "asm.bytes");
	ds->show_fcnlines = r_config_get_i (core->config, "asm.fcnlines");
	ds->show_comments = r_config_get_i (core->config, "asm.comments");
	ds->show_cmtflgrefs = r_config_get_i (core->config, "asm.cmtflgrefs");
	ds->show_cycles = r_config_get_i (core->config, "asm.cycles");
	ds->show_stackptr = r_config_get_i (core->config, "asm.stackptr");
	ds->show_xrefs = r_config_get_i (core->config, "asm.xrefs");
	ds->show_functions = r_config_get_i (core->config, "asm.functions");
	ds->nbytes = r_config_get_i (core->config, "asm.nbytes");
	core->print->bytespace = r_config_get_i (core->config, "asm.bytespace");
	ds->cursor = 0;
	ds->nb = 0;
	ds->show_comment_right_default = r_config_get_i (core->config, "asm.cmtright");
	ds->flagspace_ports = r_flag_space_get (core->flags, "ports");
	ds->lbytes = r_config_get_i (core->config, "asm.lbytes");
	ds->show_comment_right = r_config_get_i (core->config, "asm.cmtright"); // XX conflict with show_comment_right_default
	ds->show_flag_in_bytes = r_config_get_i (core->config, "asm.cmtright"); // XX conflict with show_comment_right_default
	ds->pre = strdup ("  ");
	ds->ocomment = NULL;
	ds->linesopts = 0;
	ds->lastfail = 0;
	ds->oldbits = 0;
	ds->ocols = 0;
	ds->lcols = 0;
	ds->show_flag_in_bytes = r_config_get_i (core->config, "asm.flagsinbytes");
	if (ds->show_flag_in_bytes) {
		ds->show_flags = 0;
	}


	if (r_config_get_i (core->config, "asm.linesstyle"))
		ds->linesopts |= R_ANAL_REFLINE_TYPE_STYLE;
	if (r_config_get_i (core->config, "asm.lineswide"))
		ds->linesopts |= R_ANAL_REFLINE_TYPE_WIDE;

	if (ds->show_lines) ds->ocols += 10; // XXX
	if (ds->show_offset) ds->ocols += 14;
	ds->lcols = ds->ocols+2;
	if (ds->show_bytes) ds->ocols += 20;
	if (ds->show_trace) ds->ocols += 8;
	if (ds->show_stackptr) ds->ocols += 4;
	/* disasm */ ds->ocols += 20;
	ds->nb = (ds->nbytes*2);
	ds->tries = 3;

	if (core->print->cur_enabled) {
		if (core->print->cur<0)
			core->print->cur = 0;
		ds->cursor = core->print->cur;
	} else ds->cursor = -1;

	if (r_config_get_i (core->config, "asm.linesstyle"))
		ds->linesopts |= R_ANAL_REFLINE_TYPE_STYLE;
	if (r_config_get_i (core->config, "asm.lineswide"))
		ds->linesopts |= R_ANAL_REFLINE_TYPE_WIDE;

	return ds;
}

static void handle_reflines_init (RCore *core, RDisasmState *ds) {
	if (ds->show_lines) {
		// TODO: make anal->reflines implicit
		free (core->reflines); // TODO: leak
		free (core->reflines2); // TODO: leak
		core->reflines = r_anal_reflines_get (core->anal,
			ds->addr, ds->buf, ds->len, ds->l,
			ds->linesout, ds->show_linescall);
		core->reflines2 = r_anal_reflines_get (core->anal,
			ds->addr, ds->buf, ds->len, ds->l,
			ds->linesout, 1);
	} else core->reflines = core->reflines2 = NULL;
}

static void handle_reflines_fcn_init (RCore *core, RDisasmState *ds,  RAnalFunction *fcn, ut8* buf) {
	if (ds->show_lines) {
			// TODO: make anal->reflines implicit
			free (core->reflines); // TODO: leak
			free (core->reflines2); // TODO: leak
			core->reflines = r_anal_reflines_fcn_get (core->anal,
					fcn, -1, ds->linesout, ds->show_linescall);
			core->reflines2 = r_anal_reflines_fcn_get (core->anal,
					fcn, -1, ds->linesout, 1);
	} else core->reflines = core->reflines2 = NULL;
}

static void handle_deinit_ds (RCore *core, RDisasmState *ds) {
	if (!ds) return;
	if (core && ds->oldbits) {
		r_config_set_i (core->config, "asm.bits", ds->oldbits);
		ds->oldbits = 0;
	}
	r_anal_op_fini (&ds->analop);
	if (ds->hint) r_anal_hint_free (ds->hint);
	free (ds->comment);
	free (ds->pre);
	free (ds->line);
	free (ds->refline);
	free (ds->refline2);
	free (ds->opstr);
	free (ds->osl);
	free (ds->sl);
	free (ds);
}

static void handle_set_pre (RDisasmState *ds, const char * str) {
	if (!ds->show_fcnlines) {
		str = "";
		if (ds->pre && !*ds->pre)
			return;
	}
	free (ds->pre);
	ds->pre = strdup (str);
}

static char *colorize_asm_string(RCore *core, RDisasmState *ds) {
	char *spacer = NULL;
	char *source = ds->opstr? ds->opstr: ds->asmop.buf_asm;

	if (!(ds->show_color && ds->colorop))
		return strdup(source);

	r_cons_strcat (r_print_color_op_type (core->print, ds->analop.type));

	// workaround dummy colorizer in case of paired commands (tms320 & friends)

	spacer = strstr (source, "||");
	if (spacer) {
		char *scol1, *s1 = r_str_ndup (source, spacer - source);
		char *scol2, *s2 = strdup (spacer + 2);

		scol1 = r_print_colorize_opcode (s1, ds->color_reg, ds->color_num); free(s1);
		scol2 = r_print_colorize_opcode (s2, ds->color_reg, ds->color_num); free(s2);

		source = malloc (strlen(scol1) + strlen(scol2) + 2 + 1); // reuse source variable
		sprintf (source, "%s||%s", scol1, scol2);
		free (scol1);
		free (scol2);
		return source;
	}

	return r_print_colorize_opcode (source, ds->color_reg, ds->color_num);
}

static void handle_build_op_str (RCore *core, RDisasmState *ds) {
	char *asm_str = colorize_asm_string(core, ds);

	if (ds->decode) {
		char *tmpopstr = r_anal_op_to_string (core->anal, &ds->analop);
		// TODO: Use data from code analysis..not raw ds->analop here
		// if we want to get more information
		ds->opstr = tmpopstr? tmpopstr: asm_str? strdup (asm_str): strdup ("");
	}
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
#if 1
		r_parse_filter (core->parser, core->flags,
			asm_str, ds->str, sizeof (ds->str));
		core->parser->flagspace = ofs;
		free (ds->opstr);
		ds->opstr = strdup (ds->str);
#else
		ds->opstr = strdup (asm_str);
#endif
		core->parser->flagspace = ofs; // ???
	} else {
		if (!ds->opstr)
			ds->opstr = strdup (asm_str?asm_str:"");
	}
	if (ds->varsub) {
		RAnalFunction *f = r_anal_get_fcn_in (core->anal,
			ds->at, R_ANAL_FCN_TYPE_NULL);
		if (f) {
			r_parse_varsub (core->parser, f,
				ds->opstr, ds->strsub, sizeof (ds->strsub));
			free (ds->opstr);
			ds->opstr = strdup (ds->strsub);
		}
	}
	if (ds->use_esil) {
		if (*R_STRBUF_SAFEGET (&ds->analop.esil)) {
			free (ds->opstr);
			ds->opstr = strdup (R_STRBUF_SAFEGET (&ds->analop.esil));
		} else {
			char *p = malloc (strlen (ds->opstr)+6); /* What's up '\0' ? */
			strcpy (p, "TODO,");
			strcpy (p+5, ds->opstr);
			free (ds->opstr);
			ds->opstr = p;
		}
	}
	free (asm_str);
}

R_API RAnalHint *r_core_hint_begin (RCore *core, RAnalHint* hint, ut64 at) {
// XXX not here
	static char *hint_arch = NULL;
	static int hint_bits = 0;
	if (hint) {
		r_anal_hint_free (hint);
		hint = NULL;
	}
	hint = r_anal_hint_get (core->anal, at);
	if (hint_arch) {
		r_config_set (core->config, "asm.arch", hint_arch);
		hint_arch = NULL;
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
		/* bits */
		if (hint->bits) {
			if (!hint_bits) hint_bits =
				r_config_get_i (core->config, "asm.bits");
			r_config_set_i (core->config, "asm.bits", hint->bits);
		}
	}
	return hint;
}

// this is another random hack for reflines.. crappy stuff
static char *filter_refline2(RCore *core, const char *str) {
	char *p, *s = strdup (str);
	for (p=s; *p; p++) {
		switch (*p) {
		case '`': *p = '|'; break;
		case '-':
		case '>':
		case '<':
		case '.':
		case '=':
			  *p = ' '; break;
		}
	}
// XXX fix this? or just deprecate this function?
#if 0
	char *p;
	char n = '|';
	for (p=s; *p; p++) {
		if (!strncmp (p, core->cons->vline[LINE_VERT],
			strlen (core->cons->vline[LINE_VERT]))) {
				p += strlen(core->cons->vline[LINE_VERT]) - 1;
				continue;
			}
		switch (*p) {
		case '`':
		case '|':
			*p = n;
			break;
		case ',':
			if (p[1]=='|') n = ' ';
		default:
			*p = ' ';
			break;
		}
	}
	s = r_str_replace (s, "|", core->cons->vline[LINE_VERT], 1);
	s = r_str_replace (s, "`", core->cons->vline[LINE_VERT], 1);
#endif
	return s;
}

static char *filter_refline(RCore *core, const char *str) {
	char *p = strdup (str);

	p = r_str_replace (p, "`",
		core->cons->vline[LINE_VERT], 1); // "`" -> "|"
	p = r_str_replace (p,
		core->cons->vline[LINE_HORIZ], " ", 1); // "-" -> " "
	p = r_str_replace (p,
		core->cons->vline[LINE_HORIZ],
	    	core->cons->vline[LINE_VERT], 1); // "=" -> "|"
	p = r_str_replace (p, core->cons->vline[ARROW_RIGHT], " ", 0);
	p = r_str_replace (p, core->cons->vline[ARROW_LEFT], " ", 0);

	return p;
}
#if 0
static char *filter_refline(RCore *core, const char *str) {
	char *p, *s = strdup (str);
	p = s;
	p = r_str_replace (strdup (p), "`",
		core->cons->vline[LINE_VERT], 1); // "`" -> "|"
	p = r_str_replace (p, core->cons->vline[LINE_HORIZ], " ", 1); // "-" -> " "
	p = r_str_replace (p, core->cons->vline[LINE_HORIZ], core->cons->vline[LINE_VERT], 1); // "=" -> "|"
	s = strstr (p, core->cons->vline[ARROW_RIGHT]);
	if (s) p = r_str_replace (p, core->cons->vline[ARROW_RIGHT], " ", 0);
	s = strstr (p, core->cons->vline[ARROW_LEFT]);
	if (s) p = r_str_replace (p, core->cons->vline[ARROW_LEFT], " ", 0);
	return p;
}
#endif

static void beginline (RCore *core, RDisasmState *ds, RAnalFunction *f) {
	// THAT'S OK
	if (ds->show_color) {
		r_cons_printf ("%s%s "Color_RESET"%s%s"Color_RESET, ds->color_fline,
			((f&&f->type==R_ANAL_FCN_TYPE_FCN)&&f->addr==ds->at)
		?" ":core->cons->vline[LINE_VERT], ds->color_flow, ds->refline2);
	} else {
		r_cons_printf ("%s %s", ((f&&f->type==R_ANAL_FCN_TYPE_FCN)
				&& f->addr==ds->at)?" ":core->cons->vline[LINE_VERT], ds->refline2);
	}
}

static void handle_show_xrefs (RCore *core, RDisasmState *ds) {
	// Show xrefs
	if (ds->show_xrefs) {
		RAnalFunction *f = r_anal_get_fcn_in (core->anal, ds->at, R_ANAL_FCN_TYPE_NULL);
		RList *xrefs;
		RAnalRef *refi;
		RListIter *iter;

		/* show xrefs */
		int count = 0;
		xrefs = r_anal_xref_get (core->anal, ds->at);
		if (!xrefs)
			return;

		if (r_list_length (xrefs)> ds->maxrefs) {
			beginline (core, ds, f);
			r_cons_printf ("%s; XREFS: ", ds->show_color? ds->pal_comment: "");
			r_list_foreach (xrefs, iter, refi) {
				r_cons_printf ("%s 0x%08"PFMT64x"  ",
					r_anal_xrefs_type_tostring (refi->type), refi->addr);
				if (count == 2) {
					if (iter->n) {
						r_cons_newline ();
						beginline (core, ds, f);
						r_cons_printf ("%s; XREFS: ",
							ds->show_color? ds->pal_comment: "");
					}
					count = 0;
				} else count++;
			}
			r_cons_newline ();
			return;
		}
		r_list_foreach (xrefs, iter, refi) {
			if (refi->at == ds->at) {
				RAnalFunction *fun = r_anal_get_fcn_in (
					core->anal, refi->addr,
					R_ANAL_FCN_TYPE_FCN |
					R_ANAL_FCN_TYPE_ROOT);
				beginline (core, ds, fun);
				if (ds->show_color) {
					r_cons_printf ("%s; %s XREF from 0x%08"PFMT64x" (%s)"Color_RESET"\n",
						ds->pal_comment,
						r_anal_xrefs_type_tostring (refi->type),
						refi->addr,
						fun?fun->name:"unk");
				} else {
					r_cons_printf ("; %s XREF from 0x%08"PFMT64x" (%s)\n",
						r_anal_xrefs_type_tostring (refi->type),
						refi->addr,
						fun?fun->name: "unk");
				}
			}
		}
		r_list_free (xrefs);
	}
}

static void handle_atabs_option(RCore *core, RDisasmState *ds) {
	if (ds->atabs) {
		int n, i = 0, comma = 0, word = 0;
		int brackets = 0;
		char *t, *b;
		free (ds->opstr);
		ds->opstr = b = malloc (strlen (ds->asmop.buf_asm)* (ds->atabs+1)*4);
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
		}
	}
}

static void handle_print_show_cursor (RCore *core, RDisasmState *ds) {
	int q = core->print->cur_enabled &&
		ds->cursor >= ds->index &&
		ds->cursor < (ds->index+ds->asmop.size);
	void *p = r_bp_get_at (core->dbg->bp, ds->at);
	r_cons_printf (p&&q?"b*":p? "b ":q?"* ":"  ");
}

static void handle_show_functions (RCore *core, RDisasmState *ds) {
	if (ds->show_functions) {
		RAnalFunction *f = r_anal_get_fcn_in (core->anal, ds->at, R_ANAL_FCN_TYPE_NULL);
		if (f) {
			//TODO list from anal->sdb_fcns/fcn.0x%%x.v|a (vars/args)
			if (f->addr == ds->at) {
				r_core_cmdf (core, "afa @ 0x%llx", ds->at);
				r_core_cmdf (core, "afv @ 0x%llx", ds->at);
				//if (ds->at == f->addr)
				char *sign = r_anal_fcn_to_string (core->anal, f);
				if (f->type == R_ANAL_FCN_TYPE_LOC) {
					if (ds->show_color) {
						r_cons_printf ("%s%s ", ds->color_fline,
							core->cons->vline[LINE_CROSS]); // |-
						r_cons_printf ("%s%s"Color_RESET" %d\n",
							ds->color_floc, f->name, f->size);
						r_cons_printf ("%s%s "Color_RESET,
							ds->color_fline, core->cons->vline[LINE_VERT]); // |
					} else {
						r_cons_printf ("%s %s %d\n%s ", core->cons->vline[LINE_CROSS],
							f->name, f->size, core->cons->vline[LINE_VERT]); // |-
					}
				} else {
					const char* korner;
					const char *fmt = ds->show_color?
						"%s%s "Color_RESET"%s(%s) %s"Color_RESET" %d\n":
						"%s (%s) %s %d\n%s ";
					int corner = (f->size <= ds->analop.size)? RDWN_CORNER: LINE_VERT;
					corner = LINE_VERT; // 99% of cases
#if SLOW_BUT_OK
					RFlagItem *item = r_flag_get_i (core->flags, f->addr);
					corner = item? LINE_VERT: RDWN_CORNER;
					if (item)
						corner = 0;
#endif
					korner = ds->show_fcnlines? core->cons->vline[corner]: "";
					handle_set_pre (ds, core->cons->vline[RUP_CORNER]);
					if (ds->show_color) {
						r_cons_printf (fmt, ds->color_fline, ds->pre, ds->color_fname,
							(f->type==R_ANAL_FCN_TYPE_FCN || f->type==R_ANAL_FCN_TYPE_SYM)?"fcn":
							(f->type==R_ANAL_FCN_TYPE_IMP)?"imp":"loc",
							f->name, f->size, corner);
						r_cons_printf ("%s%s "Color_RESET,
							ds->color_fline, korner);
					} else {
						r_cons_printf (fmt, ds->pre,
							(f->type==R_ANAL_FCN_TYPE_FCN||f->type==R_ANAL_FCN_TYPE_SYM)?"fcn":
							(f->type==R_ANAL_FCN_TYPE_IMP)?"imp":"loc",
							f->name, f->size, korner);
					}
				}
				if (sign) r_cons_printf ("// %s\n", sign);
				free (sign);
				sign = NULL;
				//ds->pre = "| "; // TOFIX!
				handle_set_pre (ds, core->cons->vline[LINE_VERT]);
				ds->pre = r_str_concat (ds->pre, " ");
				ds->stackptr = 0;
			} else if (f->addr+f->size-ds->analop.size== ds->at) {
				handle_set_pre (ds, core->cons->vline[RDWN_CORNER]);
				if (ds->show_color) {
					r_cons_printf ("%s%s "Color_RESET, ds->color_fline, ds->pre);
				} else {
					r_cons_printf ("%s ", ds->pre);
				}
			} else if (ds->at > f->addr && ds->at < f->addr+f->size-1) {
				handle_set_pre (ds, core->cons->vline[LINE_VERT]);
				if (ds->show_color) {
					r_cons_printf ("%s%s "Color_RESET, ds->color_fline, ds->pre);
				} else {
					r_cons_printf ("%s ", ds->pre);
				}
				//ds->pre = "| "; // TOFIX!
				handle_set_pre (ds, core->cons->vline[LINE_VERT]);
				ds->pre = r_str_concat (ds->pre, " ");
			} else f = NULL;
			if (f && ds->at == f->addr+f->size-ds->analop.size) { // HACK
				//ds->pre = R_LINE_BOTTOM_DCORNER" ";
				handle_set_pre (ds, core->cons->vline[RDWN_CORNER]);
				ds->pre = r_str_concat (ds->pre, " ");
			}
		} else r_cons_printf ("  ");
	}
}

static void handle_show_comments_right (RCore *core, RDisasmState *ds) {
	/* show comment at right? */
	ds->show_comment_right = 0;
	if (ds->show_comments) {
		RAnalFunction *f = r_anal_get_fcn_in (core->anal, ds->at, R_ANAL_FCN_TYPE_NULL);
		RFlagItem *item = r_flag_get_i (core->flags, ds->at);
		ds->comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, ds->at);
		if (!ds->comment && item && item->comment) {
			ds->ocomment = item->comment;
			ds->comment = strdup (item->comment);
		}
		if (ds->comment) {
			int linelen, maxclen = strlen (ds->comment)+5;
			linelen = maxclen;
			if (ds->show_comment_right_default)
			if (ds->ocols+maxclen < core->cons->columns) {
				if (ds->comment && *ds->comment && strlen (ds->comment)<maxclen) {
					if (!strchr (ds->comment, '\n')) // more than one line?
						ds->show_comment_right = 1;
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
					char *str = strdup (ds->show_color?ds->color_fline: "");
					str = r_str_concat (str, core->cons->vline[LINE_VERT]);
					if (ds->show_color)
						str = r_str_concat (str, ds->color_flow);
// color refline
					str = r_str_concat (str, " ");
					str = r_str_concat (str, ds->refline2);
// color comment
					if (ds->show_color)
						str = r_str_concat (str, ds->color_comment);
					str = r_str_concat (str, ";  ");
					ds->comment = r_str_prefix_all (ds->comment, str);
					free (str);
				} else {
					ds->comment = r_str_prefix_all (ds->comment, "   ;      ");
				}
				r_cons_strcat (ds->comment);
#endif
				if (ds->show_color) handle_print_color_reset (core, ds);
				r_cons_newline ();
				free (ds->comment);
				ds->comment = NULL;

				/* flag one */
				if (item && item->comment && ds->ocomment != item->comment) {
					if (ds->show_color) r_cons_strcat (ds->pal_comment);
					r_cons_newline ();
					r_cons_strcat ("  ;  ");
					r_cons_strcat_justify (item->comment, mycols, ';');
					r_cons_newline ();
					if (ds->show_color) handle_print_color_reset (core, ds);
				}
			}
		}
	}
}

static void handle_show_flags_option(RCore *core, RDisasmState *ds) {
	if (ds->show_flags) {
		RAnalFunction *f = r_anal_get_fcn_in (core->anal, ds->at, R_ANAL_FCN_TYPE_NULL);
		RFlagItem *flag = r_flag_get_i (core->flags, ds->at);
		if (flag && (!f || (f && strcmp (f->name, flag->name)))) {
			if (ds->show_lines && ds->refline) {
				if (ds->show_color) {
					r_cons_printf ("%s%s"Color_RESET, ds->color_flow, ds->refline2);
				} else r_cons_printf (ds->refline);
			}
			if (ds->show_offset) r_cons_printf (";-- ");
			if (ds->show_color) r_cons_strcat (ds->color_flag);
			if (ds->asm_demangle) {
				if (ds->show_functions) r_cons_printf ("%s:\n", flag->realname);
				else r_cons_printf ("%s:\n", flag->realname);
			} else {
				if (ds->show_functions) r_cons_printf ("%s:\n", flag->name);
				else r_cons_printf ("%s:\n", flag->name);
			}
			//handle_set_pre (ds, "  ");
			if (ds->show_color) {
				r_cons_printf (Color_RESET"%s%s"Color_RESET, ds->color_fline,
					f ? ds->pre : "  ");
			} else r_cons_printf (f ? ds->pre : "  ");
		}
	}
}

static void handle_update_ref_lines (RCore *core, RDisasmState *ds) {
	if (ds->show_lines) {
		ds->line = r_anal_reflines_str (core, ds->at, ds->linesopts);
		ds->refline = filter_refline (core, ds->line);
		ds->refline2 = filter_refline2 (core, ds->refline);
		if (strchr (ds->line, '<'))
			ds->indent_level++;
		if (strchr (ds->line, '>'))
			ds->indent_level--;
	} else {
		free (ds->line);
		free (ds->refline);
		free (ds->refline2);
		ds->refline = strdup ("");
		ds->refline2 = strdup ("");
		ds->line = NULL;
	}
}

static int perform_disassembly(RCore *core, RDisasmState *ds, ut8 *buf, int len) {
	int ret;
	// TODO : line analysis must respect data types! shouldnt be interpreted as code
	ret = r_asm_disassemble (core->assembler, &ds->asmop, buf, len);
	if (ds->asmop.size<1) {
		ut32 *n32 = (ut32*)buf;
		ut64 *n64 = (ut64*)buf;
		// if arm or mips.. 32 or 64
		snprintf (ds->asmop.buf_asm,
			sizeof (ds->asmop.buf_asm),
			"0x%08x", *n32);
		snprintf (ds->asmop.buf_asm,
			sizeof (ds->asmop.buf_asm),
			"0x%08"PFMT64x, *n64);
		ds->asmop.size = 1;
	}
	ds->oplen = ds->asmop.size;
// replace buf_asm to highlight shit

	if (ret<1) { // XXX: move to r_asm_disassemble ()
		ret = -1;
		//eprintf ("** invalid opcode at 0x%08"PFMT64x" %d %d**\n",
		//	core->assembler->pc + ret, l, len);
#if HASRETRY
//eprintf ("~~~~~~LEN~~~~ %d %d %d\n", l, len, lines);
		if (!ds->cbytes && ds->tries>0) { //1||l < len)
//eprintf ("~~~~~~~~~~~~~ %d %d\n", idx, core->blocksize);
			ds->addr = core->assembler->pc;
			ds->tries--;
			//eprintf ("-- %d %d\n", len, r_core_read_at (core, ds->addr, buf, len));
			//eprintf ("REtry 0x%llx -- %x %x\n", ds->addr, buf[0], buf[1]);
			ds->idx = 0;
			ds->retry = 1;
			return ret;
		}
#endif
		ds->lastfail = 1;
		strcpy (ds->asmop.buf_asm, "invalid");
	//	sprintf (asmop.buf_hex, "%02x", buf[idx]);
	} else {
		ds->lastfail = 0;
		ds->asmop.size = (ds->hint && ds->hint->size)?
			ds->hint->size: r_asm_op_get_size (&ds->asmop);
	}
	if (ds->pseudo) {
		r_parse_parse (core->parser, ds->opstr?
			ds->opstr: ds->asmop.buf_asm, ds->str);
		free (ds->opstr);
		ds->opstr = strdup (ds->str);
	}

	//highlight ("eax", ds->asmop.buf_asm, sizeof (ds->asmop.buf_asm));

	if (ds->acase)
		r_str_case (ds->asmop.buf_asm, 1);

	return ret;
}

static void handle_control_flow_comments (RCore * core, RDisasmState *ds) {
	if (ds->show_comments && ds->show_cmtflgrefs) {
		RFlagItem *item;
		switch (ds->analop.type) {
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_CALL:
			item = r_flag_get_i (core->flags, ds->analop.jump);
			if (item && item->comment) {
				if (ds->show_color) r_cons_strcat (ds->pal_comment);
				r_cons_printf ("  ; ref to %s: %s\n", item->name, item->comment);
				handle_print_color_reset(core, ds);
			}
			break;
		}
	}
}

static void handle_print_lines_right (RCore *core, RDisasmState *ds){
	if (ds->linesright && ds->show_lines && ds->line) {
		if (ds->show_color) {
			r_cons_printf ("%s%s"Color_RESET, ds->color_flow, ds->line);
		} else r_cons_printf (ds->line);
	}
}
static void handle_print_lines_left (RCore *core, RDisasmState *ds){
	if (!ds->linesright && ds->show_lines && ds->line) {
		if (ds->show_color) {
// XXX line is too long wtf
			r_cons_printf ("%s%s"Color_RESET, ds->color_flow, ds->line);
		} else r_cons_printf (ds->line);
	}
}

static void handle_print_cycles (RCore *core, RDisasmState *ds) {
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

static void handle_print_stackptr (RCore *core, RDisasmState *ds) {
	if (ds->show_stackptr) {
		r_cons_printf ("%3d%s", ds->stackptr,
			ds->analop.type==R_ANAL_OP_TYPE_CALL?">":
			ds->stackptr>ds->ostackptr?"+":ds->stackptr<ds->ostackptr?"-":" ");
		ds->ostackptr = ds->stackptr;
		ds->stackptr += ds->analop.stackptr;
		/* XXX if we reset the stackptr 'ret 0x4' has not effect.
		 * Use RAnalFunction->RAnalOp->stackptr? */
		if (ds->analop.type == R_ANAL_OP_TYPE_RET)
			ds->stackptr = 0;
	}
}

static void handle_print_offset (RCore *core, RDisasmState *ds) {
	 if (core->screen_bounds) {
		int r, R;
		(void)r_cons_get_size (&R);
		(void)r_cons_get_cursor (&r);
		//r_cons_printf ("(%d,%d)/(%d,%d) ", r,c, R, C);
		if (r+1>=R) {
		//	r_cons_printf ("LAST (0x%llx)\n", ds->at);
			if (core->screen_bounds == 1LL)
				core->screen_bounds = ds->at;
		}
	 }
	 if (ds->show_offset)
		 r_print_offset (core->print, ds->at, (ds->at==ds->dest),
				 ds->show_offseg);
}

static void handle_print_op_size (RCore *core, RDisasmState *ds) {
	if (ds->show_size)
		r_cons_printf ("%d ", ds->analop.size);
}

static void handle_print_trace (RCore *core, RDisasmState *ds) {
	RDebugTracepoint *tp = NULL;
	if (ds->show_trace) {
		tp = r_debug_trace_get (core->dbg, ds->at);
		r_cons_printf ("%02x:%04x ", tp?tp->times:0, tp?tp->count:0);
	}
	if (ds->tracespace) {
		char spaces [32];
		int times;
		if (!tp)
			tp = r_debug_trace_get (core->dbg, ds->at);
		if (tp) {
			times = R_MIN (tp->times, 30); // limit to 30
			memset (spaces, ' ', sizeof (spaces));
			spaces[times] = 0;
			r_cons_strcat (spaces);
		}
	}
}

static void handle_adistrick_comments (RCore *core, RDisasmState *ds) {
	if (ds->adistrick)
		ds->middle = r_anal_reflines_middle (core->anal,
				core->reflines, ds->at, ds->analop.size);
}

static int handle_print_meta_infos (RCore * core, RDisasmState *ds, ut8* buf, int len, int idx) {
	int ret = 0;
	const char *infos, *metas;
	char *str, key[100];
	RAnalMetaItem MI, *mi = &MI;
	Sdb *s = core->anal->sdb_meta;

	snprintf (key, sizeof (key)-1, "meta.0x%"PFMT64x, ds->at);
	infos = sdb_const_get (s, key, 0);
	if (infos)
	for (;*infos; infos++) {
		if (*infos==',')
			continue;
		snprintf (key, sizeof (key)-1, "meta.%c.0x%"PFMT64x, *infos, ds->at);
		metas = sdb_const_get (s, key, 0);
		MI.size = sdb_array_get_num (s, key, 0, 0);
		MI.type = *infos;
		MI.from = ds->at;
		MI.to = ds->at + MI.size;
		str = metas ? strchr (metas, ',') : NULL;
		if (str) {
			MI.str = (char*)sdb_decode (str+1, 0);
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
				out = r_str_escape (mi->str);
				if (ds->show_color)
					r_cons_printf ("    .string "Color_YELLOW"\"%s\""
						Color_RESET" ; len=%"PFMT64d"\n", out, mi->size);
				else
					r_cons_printf ("    .string \"%s\" ; len=%"PFMT64d
						"\n", out, mi->size);
				free (out);
				delta = ds->at-mi->from;
				ds->oplen = mi->size-delta;
				ds->asmop.size = (int)mi->size;
				//i += mi->size-1; // wtf?
				free (ds->line);
				free (ds->refline);
				free (ds->refline2);
				ds->line = ds->refline = ds->refline2 = NULL;
				ds->mi_found = 1;
				break;
			case R_META_TYPE_HIDE:
				r_cons_printf ("(%d bytes hidden)\n", mi->size);
				ds->asmop.size = mi->size;
				ds->oplen = mi->size;
				ds->mi_found = 1;
				break;
			case R_META_TYPE_DATA:
				hexlen = len - idx;
				delta = ds->at-mi->from;
				if (mi->size<hexlen) hexlen = mi->size;
				ds->oplen = mi->size;
				core->print->flags &= ~R_PRINT_FLAGS_HEADER;
				switch (mi->size) {
				case 1:
					r_cons_printf (".byte 0x%02x\n", buf[idx]);
					break;
				case 2:
					{
					ut16 *data = (ut16*)(buf+idx);
					r_cons_printf (".word 0x%04x\n", *data);
					}
					break;
				case 4:
					{
					ut32 *data = (ut32*)(buf+idx);
					r_cons_printf (".dword 0x%08x\n", *data);
					}
					break;
				case 8:
					{
					ut64 *data = (ut64*)(buf+idx);
					r_cons_printf (".qword 0x%016x\n", *data);
					}
					break;
				default:
					r_cons_printf ("hex length=%lld delta=%d\n", mi->size , delta);
					r_print_hexdump (core->print, ds->at, buf+idx, hexlen-delta, 16, 1);
					break;
				}
				core->inc = 16;
				core->print->flags |= R_PRINT_FLAGS_HEADER;
				ds->asmop.size = ret = (int)mi->size; //-delta;
				free (ds->line);
				free (ds->refline);
				free (ds->refline2);
				ds->line = ds->refline = ds->refline2 = NULL;
				ds->mi_found = 1;
				break;
			case R_META_TYPE_FORMAT:
				r_cons_printf ("format %s {\n", mi->str);
				r_print_format (core->print, ds->at, buf+idx, len-idx, mi->str, -1, NULL);
				r_cons_printf ("} %d\n", mi->size);
				ds->oplen = ds->asmop.size = ret = (int)mi->size;
				free (ds->line);
				free (ds->refline);
				free (ds->refline2);
				ds->line = ds->refline = ds->refline2 = NULL;
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

static void handle_instruction_mov_lea (RCore *core, RDisasmState *ds, int idx) {
	RAnalValue *src;
	switch (ds->analop.type) {
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
					off = r_mem_get_num (b, src->memref, 1);
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
				off = r_mem_get_num (b, memref, 1);
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

static void handle_print_show_bytes (RCore * core, RDisasmState *ds) {
	char *nstr, *str = NULL, pad[64];
	RFlagItem *flag = NULL;
	char extra[64];
	int j,k;
	if (!ds->show_bytes)
		return;
	strcpy (extra, " ");
	if (ds->show_flag_in_bytes)
		flag = r_flag_get_i (core->flags, ds->at); // TODO: cache this into ds->flag ?
	if (flag) {
		str = strdup (flag->name);
		k = ds->nb-strlen (str)-1;
		if (k<0) k = 0;
		for (j=0; j<k; j++)
			pad[j] = ' ';
		pad[j] = '\0';
	} else {
		if (ds->show_flag_in_bytes) {
			k = ds->nb-1;
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
				*extra = 0;
			}
			ds->p->cur_enabled = (ds->cursor != -1);
			nstr = r_print_hexpair (ds->p, str, ds->index);
			if (ds->p->bytespace) {
				k = (ds->nb+ (ds->nb/2)) - r_str_ansi_len (nstr);
			} else {
				k = ds->nb - r_str_ansi_len (nstr);
			}
			if (k<0) k = 0;
			for (j=0; j<k; j++)
				pad[j] = ' ';
			pad[j] = 0;
			if (ds->lbytes) {
				// hack to align bytes left
				strcpy (extra, pad);
				*pad = 0;
			}
			free (str);
			str = nstr;
		}
	}
	if (ds->show_color)
		r_cons_printf ("%s %s %s"Color_RESET, pad, str, extra);
	else r_cons_printf ("%s %s %s", pad, str, extra);
	free (str);
}

static void handle_print_indent (RCore *core, RDisasmState *ds) {
	if (ds->show_indent) {
		char indent[128];
		int num = ds->indent_level;
		if (num<0) num = 0;
		if (num>=sizeof (indent))
			num = sizeof(indent)-1;
		memset (indent, ' ', num);
		indent[num] = 0;
		r_cons_strcat (indent);
	}
}

static void handle_print_opstr (RCore *core, RDisasmState *ds) {
	handle_print_indent (core, ds);
	r_cons_strcat (ds->opstr);
}

static void handle_print_color_reset (RCore *core, RDisasmState *ds) {
	if (ds->show_color)
		r_cons_strcat (Color_RESET);
}

static int handle_print_middle (RCore *core, RDisasmState *ds, int ret ){
	if (ds->middle != 0) {
		ret -= ds->middle;
		r_cons_printf (" ;  *middle* %d", ret);
	}
	return ret;
}

static int handle_print_labels (RCore *core, RDisasmState *ds, RAnalFunction *f) {
	const char *label;
	if (!core || !ds || !f)
		return R_FALSE;
	f = r_anal_get_fcn_in (core->anal, ds->at, 0);
	label = r_anal_fcn_label_at (core->anal, f, ds->at);
	if (label) {
		if (ds->show_color) {
			r_cons_strcat (ds->color_label);
			r_cons_printf (" .%s:  \n", label);
			handle_print_color_reset (core, ds);
		} else {
			r_cons_printf (" .%s:  \n", label);
		}
		return 1;
	}
	return 0;
}

static void handle_print_import_name (RCore * core, RDisasmState *ds) {
	RListIter *iter = NULL;
	RBinReloc *rel = NULL;
	switch (ds->analop.type) {
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_CALL:
			if (core->bin->cur->o->imports && core->bin->cur->o->relocs) {
				r_list_foreach(core->bin->cur->o->relocs, iter, rel) {
					if ((rel->vaddr == ds->analop.jump) &&
						(rel->import != NULL)) {
						if (ds->show_color)
							r_cons_strcat (ds->color_fname);
						// TODO: handle somehow ordinals import
						r_cons_printf (" ; (imp.%s)", rel->import->name);
						handle_print_color_reset (core, ds);
					}
				}
			}
	}
}

static void handle_print_fcn_name (RCore * core, RDisasmState *ds) {
	RAnalFunction *f;
	switch (ds->analop.type) {
		case R_ANAL_OP_TYPE_JMP:
	        //case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_CALL:
			f = r_anal_get_fcn_in (core->anal,
				ds->analop.jump, R_ANAL_FCN_TYPE_NULL);
			if (f && !strstr (ds->opstr, f->name)) {
				if (ds->show_color)
					r_cons_strcat (ds->color_fname);
				r_cons_printf (" ; (%s)", f->name);
				handle_print_color_reset (core, ds);
			}
			break;
	}
}

static void handle_print_core_vmode (RCore *core, RDisasmState *ds) {
	int i;
	if (core->vmode) {
		switch (ds->analop.type) {
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_CALL:
		case R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_CALL:
			if (ds->counter<9) {
				int found = 0;
				for (i=0; i<ds->counter+1; i++) {
					if (core->asmqjmps[i] == ds->analop.jump) {
						found = 1;
						break;
					}
				}
				if (!found)
					i = ++ds->counter;
				core->asmqjmps[i] = ds->analop.jump;
				r_cons_printf (" ;[%d]", i);
			} else r_cons_strcat (" ;[?]");
			break;
		}
	}
}

static void handle_print_cc_update (RCore *core, RDisasmState *ds) {
	// declare static since this variable is reused locally, and needs to maintain
	// state
	static RAnalCC cc = {0};
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
								snprintf (tmp, sizeof (tmp), " ; %s+%d", flag->name, delta);
							else snprintf (tmp, sizeof (tmp), " ; %s", flag->name);
						}
					} else {
						if (delta)
							snprintf (tmp, sizeof (tmp), " ; %s+%d", flag->name, delta);
						else snprintf (tmp, sizeof (tmp), " ; %s", flag->name);
					}
				}
				if (f) {
					handle_set_pre (ds, core->cons->vline[LINE_VERT]);
					ds->pre = r_str_concat (ds->pre, " ");
				} else {
					handle_set_pre (ds, "  ");
				}
				if (ds->show_color)
					r_cons_printf ("\n%s%s"Color_RESET"%s%s"Color_RESET"   %s%s"Color_RESET,
						ds->color_fline, ds->pre, ds->color_flow, ds->refline, ccstr, tmp);
				else r_cons_printf ("\n%s%s   %s%s", ds->pre, ds->refline, ccstr, tmp);
				free (ccstr);
			}
		}
		r_anal_cc_reset (&cc);
	}
}

static void handle_print_dwarf (RCore *core, RDisasmState *ds) {
	if (ds->show_dwarf) {
		ds->sl = r_bin_addr2text (core->bin, ds->at);
		int len = strlen (ds->opstr);
		if (len<30) len = 30-len;
		if (ds->sl) {
			if ((!ds->osl || (ds->osl && strcmp (ds->sl, ds->osl)))) {
				handle_set_pre (ds, "  ");
				if (ds->show_color)
					r_cons_printf ("%s  ; %s"Color_RESET"%s",
							ds->pal_comment, ds->sl, ds->pre);
				else r_cons_printf ("  ; %s%s", ds->sl, ds->pre);
				free (ds->osl);
				ds->osl = ds->sl;
				ds->sl = NULL;
			}
		}
	}
}

static void handle_print_asmop_payload (RCore *core, RDisasmState *ds) {
	if (ds->asmop.payload != 0)
		r_cons_printf ("\n; .. payload of %d bytes", ds->asmop.payload);
}

static void handle_print_op_push_info (RCore *core, RDisasmState *ds){
	switch (ds->analop.type) {
	case R_ANAL_OP_TYPE_PUSH:
		if (ds->analop.val) {
			RFlagItem *flag = r_flag_get_i (core->flags, ds->analop.val);
			if (flag) r_cons_printf (" ; %s", flag->name);
		}
		break;
	}
}

static int handle_read_refptr (RCore *core, RDisasmState *ds, ut64 *word8, ut32 *word4) {
	ut64 ret = 0;
	if (core->assembler->bits==64) {
		ret = r_io_read_at (core->io, ds->analop.ptr, (void *)word8,
			sizeof (ut64)) == sizeof (ut64);
	} else {
		ret = r_io_read_at (core->io, ds->analop.ptr,
			(void *)word4, sizeof (ut32)) == sizeof (ut32);
		*word8 = *word4;
	}
	return ret;
}

/* convert numeric value in opcode to ascii char or number */
static void handle_print_ptr (RCore *core, RDisasmState *ds, int len, int idx) {
	ut64 p = ds->analop.ptr;
	if (p != UT64_MAX && p) {
		char msg[32];
		RFlagItem *f;
		int bsz = len - idx;
		const char *kind = r_anal_data_kind (core->anal, p, ds->buf, bsz);
		*msg = 0;
		if (kind && !strcmp (kind, "text")) {
			*msg = '"';
			snprintf (msg+1, sizeof (msg)-2, "%d", idx);
			strcat (msg, "\"");
		}
		f = r_flag_get_i (core->flags, p);
		if (f) {
			r_cons_printf (" ; %s", f->name);
		} else {
			if (p==UT64_MAX || p==UT32_MAX) {
				r_cons_printf (" ; -1", p);
			} else if (p>='!' && p<='~') {
				r_cons_printf (" ; '%c'", p);
			} else if (p>10) {
				if ((st64)p<0) {
					// resolve local var if possible
					RAnalVar *v = r_anal_var_get (core->anal, ds->at, 'v', 1, (int)p);
					if (v) {
						r_cons_printf (" ; var %s", v->name);
						r_anal_var_free (v);
					} else {
						r_cons_printf (" ; var %d", (int)-p);
					}
				} else {
					r_cons_printf (" ; %s%s0x%08"PFMT64x" ",
						msg, msg[0]?" ":"", p);
				}
			}
		}
	} else handle_print_as_string (core, ds);
}

static void handle_print_comments_right (RCore *core, RDisasmState *ds) {
	if (ds->show_comments && ds->show_comment_right && ds->comment) {
		int c = r_cons_get_column ();
		if (c<ds->ocols)
			r_cons_memset (' ', ds->ocols-c);
		if (ds->show_color)
			r_cons_strcat (ds->color_comment);
		r_cons_strcat ("  ; ");
		//r_cons_strcat_justify (comment, strlen (ds->refline) + 5, ';');
		r_cons_strcat (ds->comment);
		if (ds->show_color)
			handle_print_color_reset (core, ds);
		free (ds->comment);
		ds->comment = NULL;
	}
}

static void handle_print_refptr_meta_infos (RCore *core, RDisasmState *ds, ut64 word8 ) {
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

static void handle_print_as_string(RCore *core, RDisasmState *ds) {
	char *str = r_num_as_string (NULL, ds->analop.ptr);
	if (str) {
		r_cons_printf (" ; \"%s\"", str);
	}
	free (str);
}

static void handle_print_refptr (RCore *core, RDisasmState *ds) {
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

// int l is for lines
R_API int r_core_print_disasm(RPrint *p, RCore *core, ut64 addr, ut8 *buf, int len, int l, int invbreak, int cbytes) {
	int ret, idx = 0, i;
	int continueoninvbreak = (len == l) && invbreak;
	int dorepeat = 1;
	RAnalFunction *f = NULL;
	ut8 *nbuf = NULL;
	RDisasmState *ds;
	//r_cons_printf ("len =%d l=%d ib=%d limit=%d\n", len, l, invbreak, p->limit);
	// TODO: import values from debugger is possible
	// TODO: allow to get those register snapshots from traces
	// TODO: per-function register state trace

	// XXX - is there a better way to reset a the analysis counter so that
	// when code is disassembled, it can actually find the correct offsets
	if (core->anal->cur && core->anal->cur->reset_counter)
		core->anal->cur->reset_counter (core->anal, addr);

	// TODO: All those ds must be print flags
	ds = handle_init_ds (core);
	ds->cbytes = cbytes;
	ds->p = p;
	ds->l = l;
	ds->buf = buf;
	ds->len = len;
	ds->addr = addr;

	handle_reflines_init (core, ds);
	core->inc = 0;
	/* reset jmp table if not a bad block */
	ds->counter = 0;
	if (buf[0] != 0xff) // hack
		for (i=0; i<10; i++)
			core->asmqjmps[i] = UT64_MAX;
toro:
	// uhm... is this necesary? imho can be removed
	r_asm_set_pc (core->assembler, ds->addr+idx);
#if 0
	/* find last function else ds->stackptr=0 */
	{
		RAnalFunction *fcni;
		RListIter *iter;

		r_list_foreach (core->anal.fcns, iter, fcni) {
			if (ds->addr >= fcni->addr && ds->addr<(fcni->addr+fcni->size)) {
				stack_ptr = fcni->stack;
				r_cons_printf ("/* function: %s (%d) */\n", fcni->name, fcni->size, stack_ptr);
				break;
			}
		}
	}
#endif
	core->cons->vline = r_config_get_i (core->config, "scr.utf8")?
		r_vline_u: r_vline_a;

	if (core->print->cur_enabled) {
		// TODO: support in-the-middle-of-instruction too
		if (r_anal_op (core->anal, &ds->analop, core->offset+core->print->cur,
			buf+core->print->cur, (int)(len-core->print->cur))) {
			// TODO: check for ds->analop.type and ret
			ds->dest = ds->analop.jump;
#if 0
			switch (ds->analop.type) {
			case R_ANAL_OP_TYPE_JMP:
			case R_ANAL_OP_TYPE_CALL:
				ds->dest = ds->analop.jump;
				break;
			}
#endif
		}
	} else {
		/* highlight eip */
		RFlagItem *item;
		const char *pc = core->anal->reg->name[R_REG_NAME_PC];
		item = r_flag_get (core->flags, pc);
		if (item)
			ds->dest = item->offset;
	}

	r_cons_break (NULL, NULL);
	for (i=idx=ret=0; idx < len && ds->lines < ds->l;
			idx+=ds->oplen,i++, ds->index+=ds->oplen, ds->lines++) {
		ds->at = ds->addr + idx;
		if (r_cons_singleton ()->breaked) {
			dorepeat = 0;
			break;
		}

		r_core_seek_archbits (core, ds->at); // slow but safe
		ds->hint = r_core_hint_begin (core, ds->hint, ds->at);
		//if (!ds->cbytes && idx>=l) { break; }
		r_asm_set_pc (core->assembler, ds->at);
		handle_update_ref_lines (core, ds);
		/* show type links */
		r_core_cmdf (core, "tf 0x%08"PFMT64x, ds->at);

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
		handle_show_xrefs (core, ds);
		handle_show_comments_right (core, ds);
		ret = perform_disassembly (core, ds, buf+idx, len-idx);
		if (ds->retry) {
			ds->retry = 0;
			goto retry;
		}
		handle_atabs_option (core, ds);
		// TODO: store previous oplen in core->dec
		if (core->inc == 0)
			core->inc = ds->oplen;

		r_anal_op_fini (&ds->analop);

		if (!ds->lastfail)
			r_anal_op (core->anal, &ds->analop, ds->at, buf+idx, (int)(len-idx));

		if (ret<1) {
			r_strbuf_init (&ds->analop.esil);
			ds->analop.type = R_ANAL_OP_TYPE_ILL;
		}
		if (ds->hint) {
			if (ds->hint->size) ds->analop.size = ds->hint->size;
			if (ds->hint->ptr) ds->analop.ptr = ds->hint->ptr;
		}
		handle_instruction_mov_lea (core, ds, idx);
		handle_control_flow_comments (core, ds);
		handle_adistrick_comments (core, ds);
		/* XXX: This is really cpu consuming.. need to be fixed */
		handle_show_functions (core, ds);
		 {
			RAnalFunction *fcn = r_anal_get_fcn_at (core->anal, ds->addr, 0);
			if (handle_print_labels (core, ds, fcn)) {
				handle_show_functions (core, ds);
			}
		 }
		handle_show_flags_option (core, ds);
		handle_print_lines_left (core, ds);
		handle_print_offset (core, ds);
		handle_print_op_size (core, ds);
		handle_print_trace (core, ds);
		handle_print_cycles (core, ds);
		handle_print_stackptr (core, ds);
		ret = handle_print_meta_infos (core, ds, buf, len, idx);
		if (ds->mi_found) {
			ds->mi_found = 0;
			continue;
		}
		/* show cursor */
		handle_print_show_cursor (core, ds);
		handle_print_show_bytes (core, ds);
		handle_print_lines_right (core, ds);
		handle_build_op_str (core, ds);
		handle_print_opstr (core, ds);
		handle_print_fcn_name (core, ds);
		handle_print_color_reset (core, ds);
		handle_print_dwarf (core, ds);
		ret = handle_print_middle (core, ds, ret);
		handle_print_asmop_payload (core, ds);
		if (core->assembler->syntax != R_ASM_SYNTAX_INTEL) {
			RAsmOp ao; /* disassemble for the vm .. */
			int os = core->assembler->syntax;
			r_asm_set_syntax (core->assembler, R_ASM_SYNTAX_INTEL);
			r_asm_disassemble (core->assembler, &ao, buf+idx, len-idx+5);
			r_asm_set_syntax (core->assembler, os);
		}
		handle_print_core_vmode (core, ds);
		handle_print_cc_update (core, ds);
		handle_print_op_push_info (core, ds);
		if (ds->analop.refptr) {
			handle_print_refptr (core, ds);
		} else {
			handle_print_ptr (core, ds, len, idx);
		}
		handle_print_comments_right (core, ds);
		if ( !(ds->show_comments &&
			   ds->show_comment_right &&
			   ds->comment))
			r_cons_newline ();

		if (ds->line) {
#if 0
			if (ds->show_lines && ds->analop.type == R_ANAL_OP_TYPE_RET) {
				if (strchr (ds->line, '>'))
					memset (ds->line, ' ', r_str_len_utf8 (ds->line));
				if (ds->show_color) {
					r_cons_printf ("%s %s%s"Color_RESET"; --\n",
						core->cons->vline[LINE_VERT], ds->color_flow, ds->line);
				} else
					r_cons_printf ("  %s; --\n", ds->line);
			}
#endif
			free (ds->line);
			free (ds->refline);
			free (ds->refline2);
			ds->line = ds->refline = ds->refline2 = NULL;
		}
		free (ds->opstr);
		ds->opstr = NULL;
	}
	if (nbuf == buf) {
		free (buf);
		buf = NULL;
	}
	r_cons_break_end ();

#if HASRETRY
	//if (!ds->cbytes && idx>=len) {// && (invbreak && !ds->lastfail)) {
	if (!ds->cbytes && ds->lines<ds->l && dorepeat) {
	retry:
		if (len<4) len = 4;
		buf = nbuf = malloc (len);
		if (ds->tries>0) {
			//ds->addr += idx;
			if (r_core_read_at (core, ds->addr, buf, len) ) {
				idx = 0;
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
		if (continueoninvbreak)
			goto toro;
	}
#endif
	if (ds->oldbits) {
		r_config_set_i (core->config, "asm.bits", ds->oldbits);
		ds->oldbits = 0;
	}
	r_anal_op_fini (&ds->analop);
	handle_deinit_ds (core, ds);
	return idx; //-ds->lastfail;
}

/* Disassemble either `nb_opcodes` instructions, or
 * `nb_bytes` bytes; both can be negative.
 * Set to 0 the parameter you don't use */
R_API int r_core_print_disasm_instructions (RCore *core, int nb_bytes, int nb_opcodes) {
	RDisasmState *ds = NULL;
	int bs = core->blocksize;
	int i, j, ret, err = 0;
	RAnalFunction *f;
	char *tmpopstr;
	const ut64 old_offset = core->offset;

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
	} else if (!nb_opcodes) {
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

	ds = handle_init_ds (core);
	ds->len = nb_bytes;
	ds->l = nb_opcodes;

	if (ds->len>core->blocksize)
		r_core_block_size (core, ds->len);

	if (ds->l == 0)
		ds->l = ds->len;

	r_cons_break (NULL, NULL);
	for (i=j=0; i<bs && i<ds->len && j<ds->l; i+=ret, j++) {
		ds->at = core->offset +i;
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
		//r_cons_printf ("0x%08"PFMT64x"  ", core->offset+i);
		if (ds->hint && ds->hint->size)
			ret = ds->hint->size;
		if (ds->hint && ds->hint->opcode) {
			free (ds->opstr);
			ds->opstr = strdup (ds->hint->opcode);
		} else {
			if (ds->use_esil) {
				r_anal_op (core->anal, &ds->analop, ds->at, core->block+i, core->blocksize-i);
				if (*R_STRBUF_SAFEGET (&ds->analop.esil)) {
					free (ds->opstr);
					ds->opstr = strdup (R_STRBUF_SAFEGET (&ds->analop.esil));
				}
			} else
			if (ds->decode) {
				free (ds->opstr);
				r_anal_op (core->anal, &ds->analop, ds->at, core->block+i, core->blocksize-i);
				tmpopstr = r_anal_op_to_string (core->anal, &ds->analop);
				ds->opstr = (tmpopstr)? tmpopstr: strdup (ds->asmop.buf_asm);
			} else {
				free (ds->opstr);
				ds->opstr = strdup (ds->asmop.buf_asm);
			}
		}
		if (ret<1) {
			err = 1;
			ret = 1;
			r_cons_printf ("invalid\n");//???\n");
		} else {
			r_cons_printf ("%s\n", ds->opstr);
			free (ds->opstr);
			ds->opstr = NULL;
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
	handle_deinit_ds (core, ds);
	core->offset = old_offset;
	return err;
}

R_API int r_core_print_disasm_json(RCore *core, ut64 addr, ut8 *buf, int nb_bytes, int nb_opcodes) {
	RAsmOp asmop;
	RAnalOp analop;
	int i, oplen, ret, line;
	const ut64 old_offset = core->offset;
	r_cons_printf ("[");

	if (!nb_bytes) { // Disassemble `nb_opcodes` opcodes.
		nb_bytes = core->blocksize;
		if (nb_opcodes < 0) {
			/* Backward disassembly of `nb_opcodes` opcodes:
			 * - We compute the new starting offset
			 * - Read at the new offset */
			nb_opcodes = -nb_opcodes;
			r_core_asm_bwdis_len (core, &nb_bytes, &addr, nb_opcodes);
			r_core_read_at (core, addr, buf, nb_bytes);
		}
	} else if (!nb_opcodes) { // Dissasemble `nb_bytes` bytes
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
	if (core->anal && core->anal->cur && core->anal->cur->reset_counter	) {
		core->anal->cur->reset_counter (core->anal, addr);
	}
	// TODO: add support for anal hints
	for (i=line=0; i<nb_bytes;) {
		ut64 at = addr +i;
		char *escaped_str = NULL;
		r_asm_set_pc (core->assembler, at);
		ret = r_asm_disassemble (core->assembler, &asmop, buf+i, nb_bytes-i);
		if (ret<1) {
			r_cons_printf (i>0? ",{": "{");
			r_cons_printf ("\"offset\":%"PFMT64d, at);
			r_cons_printf (",\"size\":1,\"type\":\"invalid\"}");
			i++;
			continue;
		}
		r_anal_op (core->anal, &analop, at, buf+i, nb_bytes-i);

		oplen = r_asm_op_get_size (&asmop);
		r_cons_printf (i>0? ",{": "{");
		r_cons_printf ("\"offset\":%"PFMT64d, at);
		r_cons_printf (",\"size\":%d", oplen);
		escaped_str = r_str_escape(asmop.buf_asm);
		r_cons_printf (",\"opcode\":\"%s\"", escaped_str);
		r_cons_printf (",\"bytes\":\"%s\"", asmop.buf_hex);
		//r_cons_printf (",\"family\":\"%s\"", asmop.family);
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
			r_cons_printf (",\"next\":%"PFMT64d, analop.jump);
			if (analop.fail != UT64_MAX)
				r_cons_printf (",\"fail\":%"PFMT64d, analop.fail);
		}
		r_cons_printf ("}");
		i += oplen;
		line++;
		if (nb_opcodes && line>=nb_opcodes)
			break;
	}
	r_cons_printf ("]");
	core->offset = old_offset;
	return R_TRUE;
}

R_API int r_core_print_fcn_disasm(RPrint *p, RCore *core, ut64 addr, int l, int invbreak, int cbytes) {
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
	ut32 cur_buf_sz = fcn->size+1;
	ut8 *buf = malloc (cur_buf_sz);
	ut32 len = fcn->size;
	int ret, idx = 0, i;
	RListIter *bb_iter;
	RAnalBlock *bb = NULL;
	RDisasmState *ds;
	RList *bb_list = r_list_new();
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
	ds = handle_init_ds (core);
	ds->cbytes = cbytes;
	ds->p = p;
	ds->l = l;
	ds->buf = buf;
	ds->len = fcn->size;
	ds->addr = fcn->addr;

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

	handle_reflines_fcn_init (core, ds, fcn, buf);
	core->inc = 0;

	core->cons->vline = r_config_get_i (core->config, "scr.utf8")?
			r_vline_u: r_vline_a;

	r_cons_break (NULL, NULL);
	i = 0;
	idx = 0;

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

			handle_update_ref_lines (core, ds);
			/* show type links */
			r_core_cmdf (core, "tf 0x%08"PFMT64x, ds->at);

			handle_show_xrefs (core, ds);
			handle_show_comments_right (core, ds);
			ret = perform_disassembly (core, ds, buf+idx, len - bb_size_consumed);
			handle_atabs_option (core, ds);
			// TODO: store previous oplen in core->dec
			if (core->inc == 0) core->inc = ds->oplen;

			r_anal_op_fini (&ds->analop);

			if (!ds->lastfail)
				r_anal_op (core->anal, &ds->analop,
					ds->at+bb_size_consumed, buf+idx,
					len-bb_size_consumed);

			if (ret<1) {
				r_strbuf_init (&ds->analop.esil);
				ds->analop.type = R_ANAL_OP_TYPE_ILL;
			}

			handle_instruction_mov_lea (core, ds, idx);
			handle_control_flow_comments (core, ds);
			handle_adistrick_comments (core, ds);
			/* XXX: This is really cpu consuming.. need to be fixed */
			handle_show_functions (core, ds);
			if (handle_print_labels (core, ds, fcn)) {
				handle_show_functions (core, ds);
			}
			handle_show_flags_option (core, ds);
			handle_print_lines_left (core, ds);
			handle_print_offset (core, ds);
			handle_print_op_size (core, ds);
			handle_print_trace (core, ds);
			handle_print_cycles (core, ds);
			handle_print_stackptr (core, ds);
			ret = handle_print_meta_infos (core, ds, buf, len, idx);
			if (ds->mi_found) {
				ds->mi_found = 0;
				continue;
			}
			/* show cursor */
			handle_print_show_cursor (core, ds);
			handle_print_show_bytes (core, ds);
			handle_print_lines_right (core, ds);
			handle_build_op_str (core, ds);
			handle_print_opstr (core, ds);
			handle_print_fcn_name (core, ds);
			handle_print_import_name (core, ds);
			handle_print_color_reset (core, ds);
			handle_print_dwarf (core, ds);
			ret = handle_print_middle (core, ds, ret);
			handle_print_asmop_payload (core, ds);
			if (core->assembler->syntax != R_ASM_SYNTAX_INTEL) {
				RAsmOp ao; /* disassemble for the vm .. */
				int os = core->assembler->syntax;
				r_asm_set_syntax (core->assembler,
					R_ASM_SYNTAX_INTEL);
				r_asm_disassemble (core->assembler, &ao,
					buf+idx, len-bb_size_consumed);
				r_asm_set_syntax (core->assembler, os);
			}
			handle_print_core_vmode (core, ds);
			handle_print_cc_update (core, ds);
			handle_print_op_push_info (core, ds);
			/*if (ds->analop.refptr) {
					handle_print_refptr (core, ds);
			} else {
					handle_print_ptr (core, ds, len, idx);
			}*/
			handle_print_comments_right (core, ds);
			if ( !(ds->show_comments && ds->show_comment_right &&
					ds->show_comment_right && ds->comment))
				r_cons_newline ();

			if (ds->line) {
				free (ds->line);
				free (ds->refline);
				free (ds->refline2);
				ds->line = ds->refline = ds->refline2 = NULL;
			}
			bb_size_consumed += ds->oplen;
			ds->index += ds->oplen;
			idx += ds->oplen;
			ds->at += ds->oplen;
			ds->addr += ds->oplen;
			ds->lines++;

			free (ds->opstr);
			ds->opstr = NULL;
		} while (bb_size_consumed < len);
		i++;
	}
	free (buf);
	r_cons_break_end ();

	if (ds->oldbits) {
		r_config_set_i (core->config, "asm.bits", ds->oldbits);
		ds->oldbits = 0;
	}
	r_anal_op_fini (&ds->analop);
	handle_deinit_ds (core, ds);
	r_list_free (bb_list);
	return idx;
}
