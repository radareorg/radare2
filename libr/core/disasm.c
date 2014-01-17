/* radare - LGPL - Copyright 2009-2013 - nibble, pancake */

#include "r_core.h"
#include "r_cons.h"

#define HASRETRY 1

#define USE_REFACTORED 0
#define USE_OLD 1

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
};


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
	int show_dwarf;
	int show_linescall;
	int show_size;
	int show_trace;
	int linesout;
	int adistrick;
	int show_offset;
	int show_offseg;
	int show_flags;
	int show_bytes;
	int show_comments;
	int show_cmtflgrefs;
	int show_stackptr;
	int show_xrefs;
	int show_functions;
	int cursor;
	int show_comment_right_default;
	int flagspace_ports;
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
	const char *color_invalid;

	RAnalHint *hint;
	RPrint *p;

	int l;
	int middle;
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

} RDisasmState;

static void handle_reflines_init (RCore *core, RDisasmState *disasm_state);
static void handle_add_show_color ( RCore *core, RDisasmState *disasm_state);
static RDisasmState * handle_init_disasm_state (RCore * core);
static void handle_set_pre (RDisasmState *disasm_state, const char * str);
static void handle_build_op_str (RCore *core, RDisasmState *disasm_state);
static char *filter_refline2(RCore *core, const char *str);
static char *filter_refline(RCore *core, const char *str);
static void colorize_opcode (char *p, const char *reg, const char *num);
static void handle_show_xrefs (RCore *core, RDisasmState *disasm_state);
static void handle_atabs_option(RCore *core, RDisasmState *disasm_state);
static void handle_show_functions (RCore *core, RDisasmState *disasm_state);
static void handle_show_comments_right (RCore *core, RDisasmState *disasm_state);
static void handle_show_flags_option(RCore *core, RDisasmState *disasm_state);
static void handle_update_ref_lines (RCore *core, RDisasmState *disasm_state);
static int perform_disassembly(RCore *core, RDisasmState *disasm_state, ut8 *buf, int len);
static void handle_control_flow_comments (RCore * core, RDisasmState *disasm_state);
static void handle_print_lines_right (RCore *core, RDisasmState *disasm_state);
static void handle_print_lines_left (RCore *core, RDisasmState *disasm_state);
static void handle_print_stackptr (RCore *core, RDisasmState *disasm_state);
static void handle_print_offset (RCore *core, RDisasmState *disasm_state );
static void handle_print_op_size (RCore *core, RDisasmState *disasm_state);
static void handle_print_trace (RCore *core, RDisasmState *disasm_state);
static void handle_colorize_opcode (RCore *core, RDisasmState *disasm_state);
static void handle_adistrick_comments (RCore *core, RDisasmState *disasm_state);
static int handle_print_meta_infos (RCore * core, RDisasmState *disasm_state, ut8* buf, int len, int idx );
static void handle_print_opstr (RCore *core, RDisasmState *disasm_state);
static void handle_print_color_reset (RCore *core, RDisasmState *disasm_state);
static int handle_print_middle (RCore *core, RDisasmState *disasm_state, int ret );
static int handle_print_fcn_locals (RCore *core, RDisasmState *disasm_state, RAnalFunction *f, RAnalFunction *cf);
static void handle_print_fcn_name (RCore * core, RDisasmState *disasm_state);
static void handle_print_core_vmode (RCore *core, RDisasmState *disasm_state);
static void handle_print_cc_update (RCore *core, RDisasmState *disasm_state);
static void handle_print_dwarf (RCore *core, RDisasmState *disasm_state);
static void handle_print_asmop_payload (RCore *core, RDisasmState *disasm_state);
static void handle_print_op_push_info (RCore *core, RDisasmState *disasm_state);
static int handle_read_refptr (RCore *core, RDisasmState *disasm_state, ut64 *word8, ut32 *word4);
static void handle_print_comments_right (RCore *core, RDisasmState *disasm_state);
static void handle_print_refptr_meta_infos (RCore *core, RDisasmState *disasm_state, ut64 word8 );
static void handle_print_refptr (RCore *core, RDisasmState *disasm_state);
static void handle_print_ptr (RCore *core, RDisasmState *disasm_state, int len, int idx);





static void handle_add_show_color ( RCore *core, RDisasmState *disasm_state) {
	if (disasm_state->show_color) {
		switch (disasm_state->analop.type) {
		case R_ANAL_OP_TYPE_NOP:
			r_cons_strcat (disasm_state->color_nop);
			break;
		case R_ANAL_OP_TYPE_ADD:
		case R_ANAL_OP_TYPE_SUB:
		case R_ANAL_OP_TYPE_MUL:
		case R_ANAL_OP_TYPE_DIV:
			r_cons_strcat (disasm_state->color_math);
			break;
		case R_ANAL_OP_TYPE_AND:
		case R_ANAL_OP_TYPE_OR:
		case R_ANAL_OP_TYPE_XOR:
		case R_ANAL_OP_TYPE_NOT:
		case R_ANAL_OP_TYPE_SHL:
		case R_ANAL_OP_TYPE_SHR:
		case R_ANAL_OP_TYPE_ROL:
		case R_ANAL_OP_TYPE_ROR:
			r_cons_strcat (disasm_state->color_bin);
			break;
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_UJMP:
			r_cons_strcat (disasm_state->color_jmp);
			break;
		case R_ANAL_OP_TYPE_CJMP:
			r_cons_strcat (disasm_state->color_cjmp);
			break;
		case R_ANAL_OP_TYPE_CMP:
			r_cons_strcat (disasm_state->color_cmp);
			break;
		case R_ANAL_OP_TYPE_UCALL:
		case R_ANAL_OP_TYPE_CALL:
			r_cons_strcat (disasm_state->color_call);
			break;
		case R_ANAL_OP_TYPE_SWI:
			r_cons_strcat (disasm_state->color_swi);
			break;
		case R_ANAL_OP_TYPE_ILL:
		case R_ANAL_OP_TYPE_TRAP:
			r_cons_strcat (disasm_state->color_trap);
			break;
		case R_ANAL_OP_TYPE_CRET:
		case R_ANAL_OP_TYPE_RET:
			r_cons_strcat (disasm_state->color_ret);
			break;
		case R_ANAL_OP_TYPE_PUSH:
		case R_ANAL_OP_TYPE_UPUSH:
		case R_ANAL_OP_TYPE_LOAD:
			r_cons_strcat (disasm_state->color_push);
			break;
		case R_ANAL_OP_TYPE_POP:
		case R_ANAL_OP_TYPE_STORE:
			r_cons_strcat (disasm_state->color_pop);
			break;
		case R_ANAL_OP_TYPE_NULL:
			r_cons_strcat (disasm_state->color_other);
			break;
		case R_ANAL_OP_TYPE_UNK:
			r_cons_strcat (disasm_state->color_invalid);
			break;
		}
	}
}

static RDisasmState * handle_init_disasm_state (RCore * core) {
	RDisasmState * disasm_state = R_NEW0(RDisasmState);
	disasm_state->pal_comment = core->cons->pal.comment;
	#define P(x) (core->cons && core->cons->pal.x)? core->cons->pal.x

	disasm_state->use_esil = r_config_get_i (core->config, "asm.esil");
	disasm_state->show_color = r_config_get_i (core->config, "scr.color");
	disasm_state->colorop = r_config_get_i (core->config, "scr.colorops");
	disasm_state->show_utf8 = r_config_get_i (core->config, "scr.utf8");
	disasm_state->acase = r_config_get_i (core->config, "asm.ucase");
	disasm_state->atabs = r_config_get_i (core->config, "asm.tabs");
	disasm_state->decode = r_config_get_i (core->config, "asm.decode");
	disasm_state->pseudo = r_config_get_i (core->config, "asm.pseudo");
	disasm_state->filter = r_config_get_i (core->config, "asm.filter");
	disasm_state->varsub = r_config_get_i (core->config, "asm.varsub");
	disasm_state->show_lines = r_config_get_i (core->config, "asm.lines");
	disasm_state->linesright = r_config_get_i (core->config, "asm.linesright");
	disasm_state->show_dwarf = 0; // r_config_get_i (core->config, "asm.dwarf");
	disasm_state->show_linescall = r_config_get_i (core->config, "asm.linescall");
	disasm_state->show_size = r_config_get_i (core->config, "asm.size");
	disasm_state->show_trace = r_config_get_i (core->config, "asm.trace");
	disasm_state->linesout = r_config_get_i (core->config, "asm.linesout");
	disasm_state->adistrick = r_config_get_i (core->config, "asm.middle"); // TODO: find better name
	disasm_state->show_offset = r_config_get_i (core->config, "asm.offset");
	disasm_state->show_offseg = r_config_get_i (core->config, "asm.segoff");
	disasm_state->show_flags = r_config_get_i (core->config, "asm.flags");
	disasm_state->show_bytes = r_config_get_i (core->config, "asm.bytes");
	disasm_state->show_comments = r_config_get_i (core->config, "asm.comments");
	disasm_state->show_cmtflgrefs = r_config_get_i (core->config, "asm.cmtflgrefs");
	disasm_state->show_stackptr = r_config_get_i (core->config, "asm.stackptr");
	disasm_state->show_xrefs = r_config_get_i (core->config, "asm.xrefs");
	disasm_state->show_functions = r_config_get_i (core->config, "asm.functions");
	disasm_state->nbytes = r_config_get_i (core->config, "asm.nbytes");
	disasm_state->cursor = 0;
	disasm_state->nb = 0;
	disasm_state->show_comment_right_default = r_config_get_i (core->config, "asm.cmtright");
	disasm_state->flagspace_ports = r_flag_space_get (core->flags, "ports");
	disasm_state->lbytes = r_config_get_i (core->config, "asm.lbytes");
	disasm_state->show_comment_right = 0;
	disasm_state->pre = strdup("  ");
	disasm_state->ocomment = NULL;
	disasm_state->linesopts = 0;
	disasm_state->lastfail = 0;
	disasm_state->oldbits = 0;
	disasm_state->ocols = 0;
	disasm_state->lcols = 0;
	disasm_state->color_comment = P(comment): Color_CYAN;
	disasm_state->color_fname = P(fname): Color_RED;
	disasm_state->color_floc = P(floc): Color_MAGENTA;
	disasm_state->color_fline = P(fline): Color_CYAN;
	disasm_state->color_flow = P(flow): Color_CYAN;
	disasm_state->color_flag = P(flag): Color_CYAN;
	disasm_state->color_label = P(label): Color_CYAN;
	disasm_state->color_other = P(other): Color_WHITE;
	disasm_state->color_nop = P(nop): Color_BLUE;
	disasm_state->color_bin = P(bin): Color_YELLOW;
	disasm_state->color_math = P(math): Color_YELLOW;
	disasm_state->color_jmp = P(jmp): Color_GREEN;
	disasm_state->color_cjmp = P(cjmp): Color_GREEN;
	disasm_state->color_call = P(call): Color_BGREEN;
	disasm_state->color_cmp = P(cmp): Color_MAGENTA;
	disasm_state->color_swi = P(swi): Color_MAGENTA;
	disasm_state->color_trap = P(trap): Color_BRED;
	disasm_state->color_ret = P(ret): Color_RED;
	disasm_state->color_push = P(push): Color_YELLOW;
	disasm_state->color_pop = P(pop): Color_BYELLOW;
	disasm_state->color_reg = P(reg): Color_YELLOW;
	disasm_state->color_num = P(num): Color_YELLOW;
	disasm_state->color_invalid = P(invalid): Color_BRED;

	if (r_config_get_i (core->config, "asm.linesstyle"))
		disasm_state->linesopts |= R_ANAL_REFLINE_TYPE_STYLE;
	if (r_config_get_i (core->config, "asm.lineswide"))
		disasm_state->linesopts |= R_ANAL_REFLINE_TYPE_WIDE;

	if (disasm_state->show_lines) disasm_state->ocols += 10; // XXX
	if (disasm_state->show_offset) disasm_state->ocols += 14;
	disasm_state->lcols = disasm_state->ocols+2;
	if (disasm_state->show_bytes) disasm_state->ocols += 20;
	if (disasm_state->show_trace) disasm_state->ocols += 8;
	if (disasm_state->show_stackptr) disasm_state->ocols += 4;
	/* disasm */ disasm_state->ocols += 20;
	disasm_state->nb = (disasm_state->nbytes*2);
	disasm_state->tries = 3;

	if (core->print->cur_enabled) {
		if (core->print->cur<0)
			core->print->cur = 0;
		disasm_state->cursor = core->print->cur;
	} else disasm_state->cursor = -1;

	if (r_config_get_i (core->config, "asm.linesstyle"))
		disasm_state->linesopts |= R_ANAL_REFLINE_TYPE_STYLE;
	if (r_config_get_i (core->config, "asm.lineswide"))
		disasm_state->linesopts |= R_ANAL_REFLINE_TYPE_WIDE;

	return disasm_state;
}

void handle_reflines_init (RCore *core, RDisasmState *disasm_state) {
	if (disasm_state->show_lines) {
		// TODO: make anal->reflines implicit
		free (core->reflines); // TODO: leak
		free (core->reflines2); // TODO: leak
		core->reflines = r_anal_reflines_get (core->anal,
			disasm_state->addr, disasm_state->buf, disasm_state->len, -1,
			disasm_state->linesout, disasm_state->show_linescall);
		core->reflines2 = r_anal_reflines_get (core->anal,
			disasm_state->addr, disasm_state->buf, disasm_state->len, -1,
			disasm_state->linesout, 1);
	} else core->reflines = core->reflines2 = NULL;

}

void handle_deinit_disasm_state (RCore *core, RDisasmState *disasm_state) {
	if (!disasm_state) return;
	if (core && disasm_state->oldbits) {
		r_config_set_i (core->config, "asm.bits", disasm_state->oldbits);
		disasm_state->oldbits = 0;
	}
	r_anal_op_fini (&disasm_state->analop);
	if (disasm_state->hint) r_anal_hint_free (disasm_state->hint);
	free (disasm_state->comment);
	free (disasm_state->pre);
	free (disasm_state->line);
	free (disasm_state->refline);
	free (disasm_state->refline2);
	free (disasm_state->opstr);
	free (disasm_state->osl);
	free (disasm_state->sl);
	free (disasm_state);
}

static void handle_set_pre (RDisasmState *disasm_state, const char * str) {
	free (disasm_state->pre);
	disasm_state->pre = strdup (str);
}

static void handle_build_op_str (RCore *core, RDisasmState *disasm_state) {
	if (disasm_state->decode) {
		char *tmpopstr = r_anal_op_to_string (core->anal, &disasm_state->analop);
		// TODO: Use data from code analysis..not raw disasm_state->analop here
		// if we want to get more information
		disasm_state->opstr = tmpopstr? tmpopstr: strdup (disasm_state->asmop.buf_asm);
	}
	if (disasm_state->hint && disasm_state->hint->opcode) {
		free (disasm_state->opstr);
		disasm_state->opstr = strdup (disasm_state->hint->opcode);
	}
	if (disasm_state->filter) {
		int ofs = core->parser->flagspace;
		int fs = disasm_state->flagspace_ports;
		if (disasm_state->analop.type == R_ANAL_OP_TYPE_IO) {
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
			disasm_state->opstr? disasm_state->opstr: disasm_state->asmop.buf_asm, disasm_state->str, sizeof (disasm_state->str));
		core->parser->flagspace = ofs;
		free (disasm_state->opstr);
		disasm_state->opstr = strdup (disasm_state->str);
		core->parser->flagspace = ofs; // ???
	} else {
		if (!disasm_state->opstr)
			disasm_state->opstr = strdup (disasm_state->asmop.buf_asm);
	}
	if (disasm_state->varsub) {
		RAnalFunction *f = r_anal_fcn_find (core->anal,
			disasm_state->at, R_ANAL_FCN_TYPE_NULL);
		if (f) {
			r_parse_varsub (core->parser, f,
				disasm_state->opstr, disasm_state->strsub, sizeof (disasm_state->strsub));
			free (disasm_state->opstr);
			disasm_state->opstr = strdup (disasm_state->strsub);
		}
	}
	if (disasm_state->use_esil) {
		if (*R_STRBUF_SAFEGET (&disasm_state->analop.esil)) {
			free (disasm_state->opstr);
			disasm_state->opstr = strdup (R_STRBUF_SAFEGET (&disasm_state->analop.esil));
		} else {
			char *p = malloc (strlen (disasm_state->opstr)+3); /* What's up '\0' ? */
			strcpy (p, ": ");
			strcpy (p+2, disasm_state->opstr);
			free (disasm_state->opstr);
			disasm_state->opstr = p;
		}
	}
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
	char n = '|';
	for (p=s; *p; p++) {
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
	return s;
}

static char *filter_refline(RCore *core, const char *str) {
	char *p, *s = strdup (str);

	p = s;
	p = r_str_replace (strdup (p), "`",
		core->cons->vline[LINE_VERT], 1); // "`" -> "|"
	p = r_str_replace (strdup (p),
		core->cons->vline[LINE_HORIZ], " ", 1); // "-" -> " "
	p = r_str_replace (strdup (p),
		core->cons->vline[LINE_HORIZ],
		core->cons->vline[LINE_VERT], 1); // "=" -> "|"
	p = strstr (s, core->cons->vline[ARROW_RIGHT]);
	if (p)
		p = r_str_replace (strdup (p), core->cons->vline[ARROW_RIGHT], " ", 0);

	p = strstr (s, core->cons->vline[ARROW_LEFT]);
	if (p)
		p = r_str_replace (strdup (p), core->cons->vline[ARROW_LEFT], " ", 0);
	return s;
}

static void colorize_opcode (char *p, const char *reg, const char *num) {
	int i, j, k, is_mod, is_arg = 0;
	int is_jmp = (*p == 'j' || ((*p == 'c') && (p[1] == 'a')))? 1: 0;
	char *o;
	if (is_jmp)
		return;
	o = malloc (1024);
	for (i=j=0; p[i]; i++,j++) {
		/* colorize numbers */
		switch (p[i]) {
		case 0x1b:
			/* skip until 'm' */
			for (++i;p[i] && p[i]!='m'; i++)
				o[j] = p[i];
			continue;
		case '+':
		case '-':
		case '/':
		case '>':
		case '<':
		case '(':
		case ')':
		case '*':
		case '%':
		case ']':
		case '[':
		case ',':
			if (is_arg) {
				strcpy (o+j, Color_RESET);
				j += strlen (Color_RESET);
				o[j++] = p[i];
				if (p[i]=='$' || ((p[i] > '0') && (p[i] < '9'))) {
					strcpy (o+j, num);
					j += strlen (num)-1;
				} else {
					strcpy (o+j, reg);
					j += strlen (reg)-1;
				}
				continue;
			}
			break;
		case ' ':
			is_arg = 1;
			// find if next ',' before ' ' is found
			is_mod = 0;
			for (k = i+1; p[k]; k++) {
				if (p[k]==' ')
					break;
				if (p[k]==',') {
					is_mod = 1;
					break;
				}
			}
			if (!p[k]) is_mod = 1;
			if (!is_jmp && is_mod) {
				// COLOR FOR REGISTER
				strcpy (o+j, reg);
				j += strlen (reg);
			}
			break;
		case '0':
			if (!is_jmp && p[i+1]== 'x') {
				strcpy (o+j, num);
				j += strlen (num);
			}
			break;
		}
		o[j] = p[i];
	}
	// decolorize at the end
	strcpy (o+j, Color_RESET);
	strcpy (p, o); // may overflow .. but shouldnt because asm.buf_asm is big enought
	free (o);
}

static void handle_show_xrefs (RCore *core, RDisasmState *disasm_state) {
	// Show xrefs
	if (disasm_state->show_xrefs) {
		RAnalFunction *f = r_anal_fcn_find (core->anal, disasm_state->at, R_ANAL_FCN_TYPE_NULL);
		RList *xrefs;
		RAnalRef *refi;
		RListIter *iter;

		/* show reverse refs */

		/* show xrefs */
		if ((xrefs = r_anal_xref_get (core->anal, disasm_state->at))) {
			r_list_foreach (xrefs, iter, refi) {
#if 0
		r_list_foreach (core->anal->refs, iter, refi)
#endif
			if (refi->addr == disasm_state->at) {
				RAnalFunction *fun = r_anal_fcn_find (
					core->anal, refi->at,
					R_ANAL_FCN_TYPE_FCN |
					R_ANAL_FCN_TYPE_ROOT);
#if 1
// THAT'S OK
				if (disasm_state->show_color) {
					r_cons_printf ("%s%s "Color_RESET"%s%s"Color_RESET, disasm_state->color_fline,
						((f&&f->type==R_ANAL_FCN_TYPE_FCN)&&f->addr==disasm_state->at)
						?" ":core->cons->vline[LINE_VERT], disasm_state->color_flow, disasm_state->refline2);
				} else {
					r_cons_printf ("%s %s", ((f&&f->type==R_ANAL_FCN_TYPE_FCN)
						&& f->addr==disasm_state->at)?" ":core->cons->vline[LINE_VERT], disasm_state->refline2);
				}
#endif
				if (disasm_state->show_color) {
					r_cons_printf ("%s; %s XREF from 0x%08"PFMT64x" (%s)"Color_RESET"\n",
						disasm_state->pal_comment, refi->type==R_ANAL_REF_TYPE_CODE?"CODE (JMP)":
						refi->type=='C'?"CODE (CALL)":"DATA", refi->at,
						fun?fun->name:"unk");
				} else {
					r_cons_printf ("; %s XREF from 0x%08"PFMT64x" (%s)\n",
						refi->type=='c'?"CODE (JMP)":
						refi->type=='C'?"CODE (CALL)":"DATA", refi->at,
						fun?fun->name: "unk");
				}
			}
		}
			r_list_free (xrefs);
		}
	}
}

static void handle_atabs_option(RCore *core, RDisasmState *disasm_state) {
	if (disasm_state->atabs) {
		int n, i = 0, comma = 0, word = 0;
		int brackets = 0;
		char *t, *b;
		free (disasm_state->opstr);
		disasm_state->opstr = b = malloc (strlen (disasm_state->asmop.buf_asm)* (disasm_state->atabs+1)*4);
		strcpy (b, disasm_state->asmop.buf_asm);
		for (; *b; b++, i++) {
			if (*b=='(' || *b=='[') brackets++;
			if (*b==')' || *b==']') brackets--;
			if (*b==',') comma = 1;
			if (*b!=' ') continue;
			if (word>0 && !comma) continue; //&& b[1]=='[') continue;
			if (brackets>0) continue;
			comma = 0;
			brackets = 0;
			n = (disasm_state->atabs-i);
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

void handle_print_show_cursor (RCore *core, RDisasmState *disasm_state) {
	int q = core->print->cur_enabled && 
		disasm_state->cursor >= disasm_state->index && 
		disasm_state->cursor < (disasm_state->index+disasm_state->asmop.size);
	
	void *p = r_bp_get (core->dbg->bp, disasm_state->at);
	r_cons_printf (p&&q?"b*":p? "b ":q?"* ":"  ");
}

static void handle_show_functions (RCore *core, RDisasmState *disasm_state) {
	if (disasm_state->show_functions) {
		RAnalFunction *f = r_anal_fcn_find (core->anal, disasm_state->at, R_ANAL_FCN_TYPE_NULL);
		//disasm_state->pre = "  ";
		if (f) {
			if (f->locals != NULL) {
				RAnalFcnLocal *f_loc;
				RListIter *l_iter;
				r_list_foreach (f->locals, l_iter, f_loc) {
					if (f_loc && f_loc->addr == disasm_state->at) {
						handle_set_pre (disasm_state, core->cons->vline[LINE_VERT]);
						if (disasm_state->show_color) {
							r_cons_printf ("%s%s"Color_RESET, disasm_state->color_fline, disasm_state->pre); // "|"
						} else {
							disasm_state->pre = r_str_concat (disasm_state->pre, " ");
							r_cons_printf (disasm_state->pre); //"| "
						}
						if (disasm_state->show_lines && disasm_state->refline) {
							r_cons_printf ("%s%s"Color_RESET, disasm_state->color_flow, disasm_state->refline);
						}
						if (disasm_state->show_offset)
							r_cons_printf ("; -- ");
						if (disasm_state->show_color)
							r_cons_printf ("%s %s"Color_RESET"\n",
								disasm_state->color_label, f_loc->name?f_loc->name:"unk");
						else r_cons_printf (" %s\n", f_loc->name?f_loc->name:"unk");
					}
				}
			}
			if (f->addr == disasm_state->at) {
				char *sign = r_anal_fcn_to_string (core->anal, f);
				if (f->type == R_ANAL_FCN_TYPE_LOC) {
					if (disasm_state->show_color) {
						r_cons_printf ("%s%s ", disasm_state->color_fline,
							core->cons->vline[LINE_CROSS]); // |-
						r_cons_printf ("%s%s"Color_RESET" %d\n",
							disasm_state->color_floc, f->name, f->size);
						r_cons_printf ("%s%s "Color_RESET,
							disasm_state->color_fline, core->cons->vline[LINE_VERT]); // |
					} else {
						r_cons_printf ("%s %s %d\n| ", core->cons->vline[LINE_CROSS],
							f->name, f->size); // |-

					}
				} else {
					int corner = (f->size <= disasm_state->analop.size)? RDWN_CORNER: LINE_VERT;
					const char *fmt = disasm_state->show_color?
						"%s%s "Color_RESET"%s(%s) %s"Color_RESET" %d\n":
						"%s (%s) %s %d\n%s ";
					if (disasm_state->show_color) {
						r_cons_printf (fmt, disasm_state->color_fline,
							core->cons->vline[RUP_CORNER], disasm_state->color_fname,
							(f->type==R_ANAL_FCN_TYPE_FCN || f->type==R_ANAL_FCN_TYPE_SYM)?"fcn":
							(f->type==R_ANAL_FCN_TYPE_IMP)?"imp":"loc",
							f->name, f->size, corner);
						r_cons_printf ("%s%s "Color_RESET,
							disasm_state->color_fline, core->cons->vline[corner]);
					} else {
						r_cons_printf (fmt, core->cons->vline[RUP_CORNER],
							(f->type==R_ANAL_FCN_TYPE_FCN||f->type==R_ANAL_FCN_TYPE_SYM)?"fcn":
							(f->type==R_ANAL_FCN_TYPE_IMP)?"imp":"loc",
							f->name, f->size, core->cons->vline[corner]);
					}
				}
				if (sign) r_cons_printf ("// %s\n", sign);
				free (sign);
				sign = NULL;
				//disasm_state->pre = "| "; // TOFIX!
				handle_set_pre (disasm_state, core->cons->vline[LINE_VERT]);
				disasm_state->pre = r_str_concat (disasm_state->pre, " ");
				disasm_state->stackptr = 0;
			} else if (f->addr+f->size-disasm_state->analop.size== disasm_state->at) {
				if (disasm_state->show_color) {
					r_cons_printf ("%s%s "Color_RESET,
						disasm_state->color_fline, core->cons->vline[RDWN_CORNER]);
				} else {
					r_cons_printf ("%s ", core->cons->vline[RDWN_CORNER]);
				}
			} else if (disasm_state->at > f->addr && disasm_state->at < f->addr+f->size-1) {
				if (disasm_state->show_color) {
					r_cons_printf ("%s%s "Color_RESET,
						disasm_state->color_fline, core->cons->vline[LINE_VERT]);
				} else {
					r_cons_printf ("%s ", core->cons->vline[LINE_VERT]);
				}
				//disasm_state->pre = "| "; // TOFIX!
				handle_set_pre (disasm_state, core->cons->vline[LINE_VERT]);
				disasm_state->pre = r_str_concat (disasm_state->pre, " ");
			} else f = NULL;
			if (f && disasm_state->at == f->addr+f->size-disasm_state->analop.size) { // HACK
				//disasm_state->pre = R_LINE_BOTTOM_DCORNER" ";
				handle_set_pre (disasm_state, core->cons->vline[RDWN_CORNER]);
				disasm_state->pre = r_str_concat (disasm_state->pre, " ");
			}
		} else r_cons_printf ("  ");
	}
}

static void handle_show_comments_right (RCore *core, RDisasmState *disasm_state) {
	/* show comment at right? */
	disasm_state->show_comment_right = 0;
	if (disasm_state->show_comments) {
		RAnalFunction *f = r_anal_fcn_find (core->anal, disasm_state->at, R_ANAL_FCN_TYPE_NULL);
		RFlagItem *item = r_flag_get_i (core->flags, disasm_state->at);
		disasm_state->comment = r_meta_get_string (core->anal->meta, R_META_TYPE_COMMENT, disasm_state->at);
		if (!disasm_state->comment && item && item->comment) {
			disasm_state->ocomment = item->comment;
			disasm_state->comment = strdup (item->comment);
		}
		if (disasm_state->comment) {
			int linelen, maxclen = strlen (disasm_state->comment)+5;
			linelen = maxclen;
			if (disasm_state->show_comment_right_default)
			if (disasm_state->ocols+maxclen < core->cons->columns) {
				if (disasm_state->comment && *disasm_state->comment && strlen (disasm_state->comment)<maxclen) {
					char *p = strchr (disasm_state->comment, '\n');
					if (p) {
						linelen = p-disasm_state->comment;
						if (!strchr (p+1, '\n')) // more than one line?
							disasm_state->show_comment_right = 1;
					}
				}
			}
			if (!disasm_state->show_comment_right) {
				int infun, mycols = disasm_state->lcols;
				if (mycols + linelen + 10 > core->cons->columns)
					mycols = 0;
				mycols /= 2;
				if (disasm_state->show_color) r_cons_strcat (disasm_state->pal_comment);
#if OLD_COMMENTS
				r_cons_strcat ("; ");
				// XXX: always prefix with ; the comments
				if (*disasm_state->comment != ';') r_cons_strcat ("  ;  ");
				r_cons_strcat_justify (disasm_state->comment, mycols, ';');
#else
				infun = f && (f->addr != disasm_state->at);
				if (infun) {
					char *str = strdup (disasm_state->show_color?disasm_state->color_fline: "");
					str = r_str_concat (str, core->cons->vline[LINE_VERT]);
					if (disasm_state->show_color)
						str = r_str_concat (str, disasm_state->color_flow);
// color refline
					str = r_str_concat (str, " ");
					str = r_str_concat (str, disasm_state->refline2);
// color comment
					if (disasm_state->show_color)
						str = r_str_concat (str, disasm_state->color_comment);
					str = r_str_concat (str, ";  ");
					disasm_state->comment = r_str_prefix_all (disasm_state->comment, str);
					free (str);
				} else {
					disasm_state->comment = r_str_prefix_all (disasm_state->comment, "   ;      ");
				}
				r_cons_strcat (disasm_state->comment);
#endif
				if (disasm_state->show_color) handle_print_color_reset(core, disasm_state);
				if (!strchr (disasm_state->comment, '\n')) r_cons_newline ();
				free (disasm_state->comment);
				disasm_state->comment = NULL;

				/* flag one */
				if (item && item->comment && disasm_state->ocomment != item->comment) {
					if (disasm_state->show_color) r_cons_strcat (disasm_state->pal_comment);
					r_cons_newline ();
					r_cons_strcat ("  ;  ");
					r_cons_strcat_justify (item->comment, mycols, ';');
					r_cons_newline ();
					if (disasm_state->show_color) handle_print_color_reset(core, disasm_state);
				}
			}
		}
	}
}

static void handle_show_flags_option(RCore *core, RDisasmState *disasm_state) {
	if (disasm_state->show_flags) {
		RAnalFunction *f = r_anal_fcn_find (core->anal, disasm_state->at, R_ANAL_FCN_TYPE_NULL);

		RFlagItem *flag = r_flag_get_i (core->flags, disasm_state->at);
		if (flag && 
			(!f || (f 
				&& strcmp (f->name, flag->name)))) {

			if (disasm_state->show_lines && disasm_state->refline) {
				if (disasm_state->show_color) {
					r_cons_printf ("%s%s"Color_RESET, disasm_state->color_flow, disasm_state->refline2);
				} else r_cons_printf (disasm_state->refline);
			}
			if (disasm_state->show_offset) r_cons_printf (";-- ");
			if (disasm_state->show_color) r_cons_strcat (disasm_state->color_flag);
			if (disasm_state->show_functions) r_cons_printf ("%s:\n", flag->name);
			else r_cons_printf ("%s:\n", flag->name);
			handle_set_pre (disasm_state, "  ");
			if (disasm_state->show_color) {
				r_cons_printf (Color_RESET"%s%s"Color_RESET, disasm_state->color_fline,
					f ? disasm_state->pre : "  ");
			} else r_cons_printf (f ? disasm_state->pre : "  ");
		}
	}
}

static void handle_update_ref_lines (RCore *core, RDisasmState *disasm_state) {
	if (disasm_state->show_lines) {
		disasm_state->line = r_anal_reflines_str (core, disasm_state->at, disasm_state->linesopts);
		disasm_state->refline = filter_refline (core, disasm_state->line);
		disasm_state->refline2 = filter_refline2 (core, disasm_state->refline);
	} else {
		free (disasm_state->line);
		free (disasm_state->refline);
		free (disasm_state->refline2);
		disasm_state->refline = strdup("");
		disasm_state->refline2 = strdup("");
		disasm_state->line = NULL;
	}
}

static int perform_disassembly(RCore *core, RDisasmState *disasm_state, ut8 *buf, int len) {
	int ret;

	// TODO : line analysis must respect data types! shouldnt be interpreted as code
	ret = r_asm_disassemble (core->assembler, &disasm_state->asmop, buf, len);
	if (disasm_state->asmop.size<1) disasm_state->asmop.size = 1;
	disasm_state->oplen = disasm_state->asmop.size;

	if (ret<1) { // XXX: move to r_asm_disassemble ()
		ret = -1;
		//eprintf ("** invalid opcode at 0x%08"PFMT64x" %d %d**\n",
		//	core->assembler->pc + ret, l, len);
#if HASRETRY
//eprintf ("~~~~~~LEN~~~~ %d %d %d\n", l, len, lines);
		if (!disasm_state->cbytes && disasm_state->tries>0) { //1||l < len)
//eprintf ("~~~~~~~~~~~~~ %d %d\n", idx, core->blocksize);
			disasm_state->addr = core->assembler->pc;
			disasm_state->tries--;
			//eprintf ("-- %d %d\n", len, r_core_read_at (core, disasm_state->addr, buf, len));
			//eprintf ("REtry 0x%llx -- %x %x\n", disasm_state->addr, buf[0], buf[1]);
			disasm_state->idx = 0;
			disasm_state->retry = 1;
			return ret;
		}
#endif
		disasm_state->lastfail = 1;
		strcpy (disasm_state->asmop.buf_asm, "invalid");
	//	sprintf (asmop.buf_hex, "%02x", buf[idx]);
	} else {
		disasm_state->lastfail = 0;
		disasm_state->asmop.size = (disasm_state->hint && disasm_state->hint->size)?
			disasm_state->hint->size: r_asm_op_get_size (&disasm_state->asmop);
	}
	if (disasm_state->pseudo) {
		r_parse_parse (core->parser, disasm_state->opstr?
			disasm_state->opstr: disasm_state->asmop.buf_asm, disasm_state->str);
		free (disasm_state->opstr);
		disasm_state->opstr = strdup (disasm_state->str);
	}

	if (disasm_state->acase)
		r_str_case (disasm_state->asmop.buf_asm, 1);

	return ret;
}

static void handle_control_flow_comments (RCore * core, RDisasmState *disasm_state) {
	if (disasm_state->show_comments && disasm_state->show_cmtflgrefs) {
		RFlagItem *item;
		switch (disasm_state->analop.type) {
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_CALL:
			item = r_flag_get_i (core->flags, disasm_state->analop.jump);
			if (item && item->comment) {
				if (disasm_state->show_color) r_cons_strcat (disasm_state->pal_comment);
				r_cons_printf ("  ; ref to %s: %s\n", item->name, item->comment);
				handle_print_color_reset(core, disasm_state);
			}
			break;
		}
	}
}

static void handle_print_lines_right (RCore *core, RDisasmState *disasm_state){	
	if (disasm_state->linesright && disasm_state->show_lines && disasm_state->line) {
		if (disasm_state->show_color) {
			r_cons_printf ("%s%s"Color_RESET, disasm_state->color_flow, disasm_state->line);
		} else r_cons_printf (disasm_state->line);
	}
}
static void handle_print_lines_left (RCore *core, RDisasmState *disasm_state){
	if (!disasm_state->linesright && disasm_state->show_lines && disasm_state->line) {
		if (disasm_state->show_color) {
// XXX line is too long wtf
			r_cons_printf ("%s%s"Color_RESET, disasm_state->color_flow, disasm_state->line);
		} else r_cons_printf (disasm_state->line);
	}
}

static void handle_print_stackptr (RCore *core, RDisasmState *disasm_state) {
	if (disasm_state->show_stackptr) {
		r_cons_printf ("%3d%s", disasm_state->stackptr,
			disasm_state->analop.type==R_ANAL_OP_TYPE_CALL?">":
			disasm_state->stackptr>disasm_state->ostackptr?"+":disasm_state->stackptr<disasm_state->ostackptr?"-":" ");
		disasm_state->ostackptr = disasm_state->stackptr;
		disasm_state->stackptr += disasm_state->analop.stackptr;
		/* XXX if we reset the stackptr 'ret 0x4' has not effect.
		 * Use RAnalFunction->RAnalOp->stackptr? */
		if (disasm_state->analop.type == R_ANAL_OP_TYPE_RET)
			disasm_state->stackptr = 0;
	}
}

static void handle_print_offset (RCore *core, RDisasmState *disasm_state ) {
	if (disasm_state->show_offset)
		r_print_offset (core->print, disasm_state->at, (disasm_state->at==disasm_state->dest), 
						disasm_state->show_offseg);
}

static void handle_print_op_size (RCore *core, RDisasmState *disasm_state) {
	if (disasm_state->show_size)
		r_cons_printf ("%d ", disasm_state->analop.size);
}

static void handle_print_trace (RCore *core, RDisasmState *disasm_state) {
	if (disasm_state->show_trace) {
		RDebugTracepoint *tp = r_debug_trace_get (core->dbg, disasm_state->at);
		r_cons_printf ("%02x:%04x ", tp?tp->times:0, tp?tp->count:0);
	}
}

static void handle_colorize_opcode (RCore *core, RDisasmState *disasm_state) {
	if (disasm_state->show_color && disasm_state->colorop)
		colorize_opcode (disasm_state->asmop.buf_asm, disasm_state->color_reg, disasm_state->color_num);
}

static void handle_adistrick_comments (RCore *core, RDisasmState *disasm_state) {
	if (disasm_state->adistrick)
		disasm_state->middle = r_anal_reflines_middle (core->anal,
				core->reflines, disasm_state->at, disasm_state->analop.size);
}

static int handle_print_meta_infos (RCore * core, RDisasmState *disasm_state, ut8* buf, int len, int idx ) {
	// TODO: implement ranged meta find (if not at the begging of function..
	RMetaItem *mi = r_meta_find (core->anal->meta, disasm_state->at, R_META_TYPE_ANY,
		R_META_WHERE_HERE);
	char *out = NULL;
	int hexlen;
	int delta;
 	disasm_state->mi_found = 0;
 	int ret = 0;
	if (mi) {
		switch (mi->type) {
		case R_META_TYPE_STRING:
			out = r_str_unscape (mi->str);
			if (disasm_state->show_color)
				r_cons_printf ("    .string "Color_YELLOW"\"%s\""
					Color_RESET" ; len=%"PFMT64d"\n", out, mi->size);
			else
				r_cons_printf ("    .string \"%s\" ; len=%"PFMT64d
					"\n", out, mi->size);
			free (out);
			disasm_state->asmop.size = (int)mi->size;
			//i += mi->size-1; // wtf?
			free (disasm_state->line);
			free (disasm_state->refline);
			free (disasm_state->refline2);
			disasm_state->line = disasm_state->refline = disasm_state->refline2 = NULL;
			disasm_state->mi_found = 1;

		case R_META_TYPE_HIDE:
			r_cons_printf ("(%d bytes hidden)\n", mi->size);
			disasm_state->asmop.size = mi->size;
			disasm_state->mi_found = 1;

		case R_META_TYPE_DATA:
			hexlen = len - idx;
			delta = disasm_state->at-mi->from;
			if (mi->size<hexlen) hexlen = mi->size;

			core->print->flags &= ~R_PRINT_FLAGS_HEADER;
			r_cons_printf ("hex length=%lld delta=%d\n", mi->size , delta);
			r_print_hexdump (core->print, disasm_state->at, buf+idx, hexlen-delta, 16, 1);
			core->inc = 16;
			core->print->flags |= R_PRINT_FLAGS_HEADER;
			disasm_state->asmop.size = ret = (int)mi->size; //-delta;
			free (disasm_state->line);
			free (disasm_state->refline);
			free (disasm_state->refline2);
			disasm_state->line = disasm_state->refline = disasm_state->refline2 = NULL;
			disasm_state->mi_found = 1;

		case R_META_TYPE_FORMAT:
			r_cons_printf ("format %s {\n", mi->str);
			r_print_format (core->print, disasm_state->at, buf+idx, len-idx, mi->str, -1, NULL);
			r_cons_printf ("} %d\n", mi->size);
			disasm_state->asmop.size = ret = (int)mi->size;
			free (disasm_state->line);
			free (disasm_state->refline);
			free (disasm_state->refline2);
			disasm_state->line = disasm_state->refline = disasm_state->refline2 = NULL;
			disasm_state->mi_found = 1;
		}
	}
	return ret;
}

void handle_instruction_mov_lea (RCore *core, RDisasmState *disasm_state, int idx) {
	RAnalValue *src;
	switch (disasm_state->analop.type) {
	case R_ANAL_OP_TYPE_MOV:
		src = disasm_state->analop.src[0];
		if (src && src->memref>0 && src->reg) {
			if (core->anal->reg && core->anal->reg->name) {
				const char *pc = core->anal->reg->name[R_REG_NAME_PC];
				RAnalValue *dst = disasm_state->analop.dst;
				if (dst && dst->reg && dst->reg->name)
				if (!strcmp (src->reg->name, pc)) {
					RFlagItem *item;
					ut8 b[8];
					ut64 ptr = idx+disasm_state->addr+src->delta+disasm_state->analop.size;
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
#if 1
// TODO: get from meta anal?
	case R_ANAL_OP_TYPE_LEA:
		src = disasm_state->analop.src[0];
		if (src && src->reg && core->anal->reg && core->anal->reg->name) {
			const char *pc = core->anal->reg->name[R_REG_NAME_PC];
			RAnalValue *dst = disasm_state->analop.dst;
			if (dst && dst->reg && !strcmp (src->reg->name, pc)) {
				int memref = core->assembler->bits/8;
				RFlagItem *item;
				ut8 b[64];
				ut64 ptr = index+disasm_state->addr+src->delta+disasm_state->analop.size;
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
#endif
	}
}

void handle_print_show_bytes (RCore * core, RDisasmState *disasm_state) {
	if (disasm_state->show_bytes) {
		int j,k;
		char *str = NULL, pad[64];
		char extra[64];
		strcpy (extra, " ");
		RFlagItem *flag = NULL;
		if (!flag) {

			str = strdup (disasm_state->asmop.buf_hex);
			if (r_str_ansi_len (str) > disasm_state->nb) {
				char *p = (char *)r_str_ansi_chrn (str, disasm_state->nb);
				if (p)  {
					p[0] = '.';
					p[1] = '\0';
				}
				*extra = 0;
			}
			k = disasm_state->nb-r_str_ansi_len (str);
			if (k<0) k = 0;
			for (j=0; j<k; j++)
				pad[j] = ' ';
			pad[j] = 0;
			if (disasm_state->lbytes) {
				// hack to align bytes left
				strcpy (extra, pad);
				*pad = 0;
			}
		//	if (disasm_state->show_color) {
				char *nstr;
				disasm_state->p->cur_enabled = disasm_state->cursor!=-1;
				//disasm_state->p->cur = disasm_state->cursor;
				nstr = r_print_hexpair (disasm_state->p, str, disasm_state->index);
				free (str);
				str = nstr;
		//	}
		} else {
			str = strdup (flag->name);
			k = disasm_state->nb-strlen (str)-2;
			if (k<0) k = 0;
			for (j=0; j<k; j++)
				pad[j] = ' ';
			pad[j] = '\0';
		}
		if (disasm_state->show_color)
			r_cons_printf ("%s %s %s"Color_RESET, pad, str, extra);
		else r_cons_printf ("%s %s %s", pad, str, extra);
		free (str);
	}
}

static void handle_print_opstr (RCore *core, RDisasmState *disasm_state) {
	r_cons_strcat (disasm_state->opstr);
}

static void handle_print_color_reset (RCore *core, RDisasmState *disasm_state) {
	if (disasm_state->show_color)
		r_cons_strcat (Color_RESET);
}

static int handle_print_middle (RCore *core, RDisasmState *disasm_state, int ret ){
	if (disasm_state->middle != 0) {
		ret -= disasm_state->middle;
		r_cons_printf (" ;  *middle* %d", ret);
	}
	return ret;
}


static int handle_print_fcn_locals (RCore *core, RDisasmState *disasm_state, RAnalFunction *f, RAnalFunction *cf) {
	RAnalFcnLocal *l;
	RListIter *iter;
	ut8 have_local = 0;
	r_list_foreach (f->locals, iter, l) {
		if (disasm_state->analop.jump == l->addr) {
			if ((cf != NULL) && (f->addr == cf->addr)) {
				if (disasm_state->show_color) {
					r_cons_strcat (disasm_state->color_label);
					r_cons_printf ("; (%s)", l->name);
					handle_print_color_reset(core, disasm_state);
				} else {
					r_cons_printf ("; (%s)", l->name);
				}
			} else {
				if (disasm_state->show_color) {
					r_cons_strcat (disasm_state->color_fname);
					r_cons_printf ("; (%s", f->name);
					//handle_print_color_reset(core, disasm_state);
					r_cons_strcat (disasm_state->color_label);
					r_cons_printf (".%s)", l->name);
					handle_print_color_reset(core, disasm_state);
				} else {
					r_cons_printf ("; (%s.%s)", f->name, l->name);
				}
			}
			have_local = 1;
			break;
		}
	}
	return have_local;
}

static void handle_print_fcn_name (RCore * core, RDisasmState *disasm_state) {
	RAnalFunction *f, *cf;
	int have_local = 0;
	switch (disasm_state->analop.type) {
		case R_ANAL_OP_TYPE_JMP:
	//	case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_CALL:
			cf = r_anal_fcn_find (core->anal, /* current function */
				disasm_state->at, R_ANAL_FCN_TYPE_NULL);
			f = r_anal_fcn_find (core->anal,
				disasm_state->analop.jump, R_ANAL_FCN_TYPE_NULL);
			if (f && !strstr (disasm_state->opstr, f->name)) {
				if (f->locals != NULL) {
					have_local = handle_print_fcn_locals (core, disasm_state, f, cf);
				}
				if (!have_local) {
					if (disasm_state->show_color)
						r_cons_strcat (disasm_state->color_fname);
					r_cons_printf (" ; (%s)", f->name);
					handle_print_color_reset(core, disasm_state);
				}
			}
			break;
	}
}
static void handle_print_core_vmode (RCore *core, RDisasmState *disasm_state) {
	if (core->vmode) {
		switch (disasm_state->analop.type) {
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_CALL:
			disasm_state->counter++;
			if (disasm_state->counter<10) {
				core->asmqjmps[disasm_state->counter] = disasm_state->analop.jump;
				r_cons_printf (" ;[%d]", disasm_state->counter);
			} else r_cons_strcat (" ;[?]");
			break;
		}
	}
}

static void handle_print_cc_update (RCore *core, RDisasmState *disasm_state) {
	// declare static since this variable is reused locally, and needs to maintain
	// state
	static RAnalCC cc = {0};
	if (!r_anal_cc_update (core->anal, &cc, &disasm_state->analop)) {
		if (disasm_state->show_functions) {
			RAnalFunction *f = r_anal_fcn_find (core->anal, disasm_state->at, R_ANAL_FCN_TYPE_NULL);
			char tmp[128];
			char *ccstr = r_anal_cc_to_string (core->anal, &cc);
			tmp[0] = 0;
			r_anal_cc_update (core->anal, &cc, &disasm_state->analop);
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
					handle_set_pre (disasm_state, core->cons->vline[LINE_VERT]);
					disasm_state->pre = r_str_concat (disasm_state->pre, " ");
				} else {
					handle_set_pre (disasm_state, "  ");
				}
				if (disasm_state->show_color)
					r_cons_printf ("\n%s%s"Color_RESET"%s%s"Color_RESET"   %s%s"Color_RESET,
						disasm_state->color_fline, disasm_state->pre, disasm_state->color_flow, disasm_state->refline, ccstr, tmp);
				else r_cons_printf ("\n%s%s   %s%s", disasm_state->pre, disasm_state->refline, ccstr, tmp);
				free (ccstr);
			}
		}
		r_anal_cc_reset (&cc);
	}
}

static void handle_print_dwarf (RCore *core, RDisasmState *disasm_state) {
	if (disasm_state->show_dwarf) {
		disasm_state->sl = r_bin_meta_get_source_line (core->bin, disasm_state->at);
		int len = strlen (disasm_state->opstr);
		if (len<30) len = 30-len;
		if (disasm_state->sl) {
			if ((!disasm_state->osl || (disasm_state->osl && strcmp (disasm_state->sl, disasm_state->osl)))) {
				while (len--)
					r_cons_strcat (" ");

				handle_set_pre (disasm_state, "  ");
				if (disasm_state->show_color)
					r_cons_printf ("%s  ; %s"Color_RESET"%s",
							disasm_state->pal_comment, disasm_state->l, disasm_state->pre);
				else r_cons_printf ("  ; %s\n%s", disasm_state->sl, disasm_state->pre);
				free (disasm_state->osl);
				disasm_state->osl = disasm_state->sl;
				disasm_state->sl = NULL;
			}
		} else {
			eprintf ("Warning: Forced asm.dwarf=false because of error\n");
			disasm_state->show_dwarf = R_FALSE;
			r_config_set (core->config, "asm.dwarf", "false");
		}
	}
}

static void handle_print_asmop_payload (RCore *core, RDisasmState *disasm_state) {
	if (disasm_state->asmop.payload != 0)
		r_cons_printf ("\n; .. payload of %d bytes", disasm_state->asmop.payload);
}

static void handle_print_op_push_info (RCore *core, RDisasmState *disasm_state){
	switch (disasm_state->analop.type) {
	case R_ANAL_OP_TYPE_PUSH:
		if (disasm_state->analop.val) {
			RFlagItem *flag = r_flag_get_i (core->flags, disasm_state->analop.val);
			if (flag) r_cons_printf (" ; %s", flag->name);
		}
		break;
	}
}


static int handle_read_refptr (RCore *core, RDisasmState *disasm_state, ut64 *word8, ut32 *word4) {
	ut64 ret = 0;
	if (core->assembler->bits==64) {
		ret = r_io_read_at (core->io, disasm_state->analop.ptr, (void *)word8,
			sizeof (ut64)) == sizeof (ut64);
	} else {
		ret = r_io_read_at (core->io, disasm_state->analop.ptr,
			(void *)word4, sizeof (ut32)) == sizeof (ut32);
		*word8 = *word4;
	}
	return ret;
}

void static handle_print_ptr (RCore *core, RDisasmState *disasm_state, int len, int idx) {
	if (disasm_state->analop.ptr != UT64_MAX && disasm_state->analop.ptr) {
		char msg[32];
		int bsz = len - idx;
		const char *kind = r_anal_data_kind (core->anal, disasm_state->analop.ptr, 	disasm_state->buf, bsz);
		*msg = 0;
		if (kind && !strcmp (kind, "text")) {
			*msg = '"';
			snprintf (msg+1, sizeof (msg)-2, "%s", disasm_state->buf+idx);
			strcat (msg, "\"");
		}
		r_cons_printf (" ; %s 0x%08"PFMT64x" ", msg, disasm_state->analop.ptr);
	}
}

static void handle_print_comments_right (RCore *core, RDisasmState *disasm_state) {
	if (disasm_state->show_comments && disasm_state->show_comment_right && disasm_state->comment) {
		int c = r_cons_get_column ();
		if (c<disasm_state->ocols)
			r_cons_memset (' ', disasm_state->ocols-c);
		r_cons_strcat (disasm_state->color_comment);
		r_cons_strcat ("  ; ");
		//r_cons_strcat_justify (comment, strlen (disasm_state->refline) + 5, ';');
		r_cons_strcat (disasm_state->comment);
		handle_print_color_reset(core, disasm_state);
		free (disasm_state->comment);
		disasm_state->comment = NULL;
	}
}
static void handle_print_refptr_meta_infos (RCore *core, RDisasmState *disasm_state, ut64 word8 ) {
	RMetaItem *mi2 = r_meta_find (core->anal->meta, word8, R_META_TYPE_ANY, R_META_WHERE_HERE);
	if (mi2) {
		switch (mi2->type) {
		case R_META_TYPE_STRING:
			{ char *str = r_str_unscape (mi2->str);
			r_cons_printf (" (at=0x%08"PFMT64x") (len=%"PFMT64d
				") \"%s\" ", word8, mi2->size, str);
			free (str);
			}
			break;
		case 'd':
			r_cons_printf (" (data)");
			break;
		default:
			eprintf ("unknown type '%c'\n", mi2->type);
			break;
		} 
	} else {
		mi2 = r_meta_find (core->anal->meta, (ut64)disasm_state->analop.ptr,
			R_META_TYPE_ANY, R_META_WHERE_HERE);
		if (mi2) {
			char *str = r_str_unscape (mi2->str);
			r_cons_printf (" \"%s\" @ 0x%08"PFMT64x":%"PFMT64d,
					str, disasm_state->analop.ptr, mi2->size);
			free (str);
		} else r_cons_printf (" ; 0x%08x [0x%"PFMT64x"]",
				word8, disasm_state->analop.ptr);
	}
}
static void handle_print_refptr (RCore *core, RDisasmState *disasm_state) {
	ut64 word8 = 0;
	ut32 word4 = 0;
	int ret;
	ret = handle_read_refptr (core, disasm_state, &word8, &word4);
	if (ret) {
		handle_print_refptr_meta_infos (core, disasm_state, word8);
	} else {
		st64 sref = disasm_state->analop.ptr;
		if (sref>0)
			r_cons_printf (" ; 0x%08"PFMT64x"\n", disasm_state->analop.ptr);
	}
}
#if USE_REFACTORED
// int l is for lines
R_API int r_core_print_disasm(RPrint *p, RCore *core, ut64 addr, ut8 *buf, int len, int l, int invbreak, int cbytes) {

	/* other */
	int ret, idx = 0, i;
	int continueoninvbreak = (len == l) && invbreak;
	RAnalFunction *f = NULL;
	ut8 *nbuf = NULL;
	RDisasmState *disasm_state;
	//r_cons_printf ("len =%d l=%d ib=%d limit=%d\n", len, l, invbreak, p->limit);
	// TODO: import values from debugger is possible
	// TODO: allow to get those register snapshots from traces
	// TODO: per-function register state trace

	// TODO: All those disasm_state must be print flags
	disasm_state = handle_init_disasm_state (core);
	disasm_state->cbytes = cbytes;
	disasm_state->p = p;
	disasm_state->l = l;
	disasm_state->buf = buf;
	disasm_state->len = len;
	disasm_state->addr = addr;

	handle_reflines_init (core, disasm_state);
	core->inc = 0;
	/* reset jmp table if not a bad block */
	if (buf[0] != 0xff) // hack
		for (i=0; i<10; i++)
			core->asmqjmps[i] = UT64_MAX;


toro:
	// uhm... is this necesary? imho can be removed
	r_asm_set_pc (core->assembler, disasm_state->addr+idx);
#if 0
	/* find last function else disasm_state->stackptr=0 */
	{
		RAnalFunction *fcni;
		RListIter *iter;

		r_list_foreach (core->anal.fcns, iter, fcni) {
			if (disasm_state->addr >= fcni->addr && disasm_state->addr<(fcni->addr+fcni->size)) {
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
		if (r_anal_op (core->anal, &disasm_state->analop, core->offset+core->print->cur,
			buf+core->print->cur, (int)(len-core->print->cur))) {
			// TODO: check for disasm_state->analop.type and ret
			disasm_state->dest = disasm_state->analop.jump;
#if 0
			switch (disasm_state->analop.type) {
			case R_ANAL_OP_TYPE_JMP:
			case R_ANAL_OP_TYPE_CALL:
				disasm_state->dest = disasm_state->analop.jump;
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
			disasm_state->dest = item->offset;
	}

	r_cons_break (NULL, NULL);
	for (i=idx=ret=0; idx < len && disasm_state->lines < disasm_state->l; idx+=disasm_state->oplen,i++, disasm_state->index+=disasm_state->oplen,disasm_state->lines++) {
		disasm_state->at = disasm_state->addr + idx;
		if (r_cons_singleton ()->breaked)
			break;

		r_core_seek_archbits (core, disasm_state->at); // slow but safe
		disasm_state->hint = r_core_hint_begin (core, disasm_state->hint, disasm_state->at);
		//if (!disasm_state->cbytes && idx>=l) { break; }
		r_asm_set_pc (core->assembler, disasm_state->at);
		handle_update_ref_lines (core, disasm_state);
		/* show type links */
		r_core_cmdf (core, "tf 0x%08"PFMT64x, disasm_state->at);

		f = r_anal_fcn_find (core->anal, disasm_state->at, R_ANAL_FCN_TYPE_NULL);
		if (!disasm_state->hint || !disasm_state->hint->bits) {
			if (f) {
				if (f->bits) {
					if (!disasm_state->oldbits)
						disasm_state->oldbits = r_config_get_i (core->config, "asm.bits");
					if (disasm_state->oldbits != f->bits) {
						r_config_set_i (core->config, "asm.bits", f->bits);
					}
				} else {
					if (disasm_state->oldbits) {
						r_config_set_i (core->config, "asm.bits", disasm_state->oldbits);
						disasm_state->oldbits = 0;
					}
				}
			} else {
				if (disasm_state->oldbits) {
					r_config_set_i (core->config, "asm.bits", disasm_state->oldbits);
					disasm_state->oldbits = 0;
				}
			}
		}
		handle_show_xrefs (core, disasm_state);
		handle_show_comments_right (core, disasm_state);
		ret = perform_disassembly (core, disasm_state, buf+idx, len-idx);
		if (disasm_state->retry) {
			disasm_state->retry = 0;
			goto retry;
		}
		handle_atabs_option (core, disasm_state);
		handle_colorize_opcode (core, disasm_state);
		// TODO: store previous oplen in core->dec
		if (core->inc == 0)
			core->inc = disasm_state->oplen;

		r_anal_op_fini (&disasm_state->analop);

		if (!disasm_state->lastfail)
			r_anal_op (core->anal, &disasm_state->analop, disasm_state->at, buf+idx, (int)(len-idx));

		if (ret<1) {
			r_strbuf_init (&disasm_state->analop.esil);
			disasm_state->analop.type = R_ANAL_OP_TYPE_ILL;
		}
		if (disasm_state->hint) {
			if (disasm_state->hint->size) disasm_state->analop.size = disasm_state->hint->size;
			if (disasm_state->hint->ptr) disasm_state->analop.ptr = disasm_state->hint->ptr;
		}
		handle_instruction_mov_lea (core, disasm_state, idx);
		handle_control_flow_comments (core, disasm_state);
		handle_adistrick_comments (core, disasm_state);
		/* XXX: This is really cpu consuming.. need to be fixed */
		handle_show_functions (core, disasm_state);
		handle_show_flags_option (core, disasm_state);
		handle_print_lines_left (core, disasm_state);
		handle_print_offset (core, disasm_state);
		handle_print_op_size (core, disasm_state);
		handle_print_trace (core, disasm_state);
		handle_print_stackptr (core, disasm_state);
		ret  = handle_print_meta_infos (core, disasm_state, buf,len, idx);
		if (disasm_state->mi_found) {
			disasm_state->mi_found = 0;
			continue;
		}
		/* show cursor */
		handle_print_show_cursor (core, disasm_state);
		handle_print_show_bytes (core, disasm_state);
		handle_print_lines_right (core, disasm_state);
		handle_add_show_color (core, disasm_state);
		handle_build_op_str (core, disasm_state);
		handle_print_opstr (core, disasm_state);
		handle_print_fcn_name (core, disasm_state);
		handle_print_color_reset( core, disasm_state);
		handle_print_dwarf (core, disasm_state);
		ret = handle_print_middle (core, disasm_state, ret );
		handle_print_asmop_payload (core, disasm_state);
		if (core->assembler->syntax != R_ASM_SYNTAX_INTEL) {
			RAsmOp ao; /* disassemble for the vm .. */
			int os = core->assembler->syntax;
			r_asm_set_syntax (core->assembler, R_ASM_SYNTAX_INTEL);
			r_asm_disassemble (core->assembler, &ao, buf+idx, len-idx+5);
			r_asm_set_syntax (core->assembler, os);
		}
		handle_print_core_vmode (core, disasm_state);
		handle_print_cc_update (core, disasm_state);
		handle_print_op_push_info (core, disasm_state);
		if (disasm_state->analop.refptr) {
			handle_print_refptr (core, disasm_state);
		} else {
			handle_print_ptr (core, disasm_state, len, idx);
		}
		handle_print_comments_right (core, disasm_state);
		if ( !(disasm_state->show_comments && 
			   disasm_state->show_comment_right && 
			   disasm_state->comment)) 
			r_cons_newline ();

		if (disasm_state->line) {
#if 0
			if (disasm_state->show_lines && disasm_state->analop.type == R_ANAL_OP_TYPE_RET) {
				if (strchr (disasm_state->line, '>'))
					memset (disasm_state->line, ' ', r_str_len_utf8 (disasm_state->line));
				if (disasm_state->show_color) {
					r_cons_printf ("%s %s%s"Color_RESET"; --\n",
						core->cons->vline[LINE_VERT], disasm_state->color_flow, disasm_state->line);
				} else
					r_cons_printf ("  %s; --\n", disasm_state->line);
			}
#endif
			free (disasm_state->line);
			free (disasm_state->refline);
			free (disasm_state->refline2);
			disasm_state->line = disasm_state->refline = disasm_state->refline2 = NULL;
		}
		free (disasm_state->opstr);
		disasm_state->opstr = NULL;
	}
	if (nbuf == buf) {
		free (buf);
		buf = NULL;
	}
	r_cons_break_end ();

#if HASRETRY
	//if (!disasm_state->cbytes && idx>=len) {// && (invbreak && !disasm_state->lastfail)) {
	if (!disasm_state->cbytes && disasm_state->lines<disasm_state->l) {
	retry:
		if (len<4) len = 4;
		buf = nbuf = malloc (len);
		if (disasm_state->tries>0) {
			disasm_state->addr += idx;
			if (r_core_read_at (core, disasm_state->addr, buf, len) ) {
				idx = 0;
				goto toro;
			}
		}
		if (disasm_state->lines<disasm_state->l) {
			disasm_state->addr += idx;
			if (r_core_read_at (core, disasm_state->addr, buf, len) != len) {
				//disasm_state->tries = -1;
			}
			goto toro;
		}
		if (continueoninvbreak)
			goto toro;
	}
#endif

	if (disasm_state->oldbits) {
		r_config_set_i (core->config, "asm.bits", disasm_state->oldbits);
		disasm_state->oldbits = 0;
	}
	r_anal_op_fini (&disasm_state->analop);
	handle_deinit_disasm_state (core, disasm_state);
	return idx; //-disasm_state->lastfail;
}

R_API int r_core_print_disasm_instructions (RCore *core, int len, int l) {

	RDisasmState *disasm_state = R_NEW0(RDisasmState);
	const ut8 *buf = core->block;
	int bs = core->blocksize;
	char *tmpopstr;
	int i, j, ret, err = 0;
	RAnalFunction *f;
	//memset (disasm_state, 0, sizeof(RDisasmState));

	disasm_state = handle_init_disasm_state (core);
	disasm_state->len = len;
	disasm_state->l = l;

	if (disasm_state->len>core->blocksize)
		r_core_block_size (core, disasm_state->len);

	if (disasm_state->l==0) disasm_state->l = disasm_state->len;

	for (i=j=0; i<bs && i<disasm_state->len && j<disasm_state->l; i+=ret, j++) {
		disasm_state->at = core->offset +i;
		r_core_seek_archbits (core, disasm_state->at);
		if (disasm_state->hint) {
			r_anal_hint_free (disasm_state->hint);
			disasm_state->hint = NULL;
		}
		disasm_state->hint = r_core_hint_begin (core, disasm_state->hint, disasm_state->at);
		r_asm_set_pc (core->assembler, disasm_state->at);
		// XXX copypasta from main disassembler function
		f = r_anal_fcn_find (core->anal, disasm_state->at, R_ANAL_FCN_TYPE_NULL);
		if (!disasm_state->hint || !disasm_state->hint->bits) {
			if (f) {
				if (f->bits) {
					if (!disasm_state->oldbits)
						disasm_state->oldbits = r_config_get_i (core->config, "asm.bits");
					if (disasm_state->oldbits != f->bits) {
						r_config_set_i (core->config, "asm.bits", f->bits);
					}
				} else {
					if (disasm_state->oldbits != 0) {
						r_config_set_i (core->config, "asm.bits", disasm_state->oldbits);
						disasm_state->oldbits = 0;
					}
				}
			} else {
				if (disasm_state->oldbits) {
					r_config_set_i (core->config, "asm.bits", disasm_state->oldbits);
					disasm_state->oldbits = 0;
				}
			}
		}
		ret = r_asm_disassemble (core->assembler,
			&disasm_state->asmop, buf+i, core->blocksize-i);
		//r_cons_printf ("0x%08"PFMT64x"  ", core->offset+i);
		if (disasm_state->hint && disasm_state->hint->size)
			ret = disasm_state->hint->size;
		if (disasm_state->hint && disasm_state->hint->opcode) {
			if (disasm_state->opstr) free (disasm_state->opstr);
			disasm_state->opstr = strdup (disasm_state->hint->opcode);
		} else {
			if (disasm_state->use_esil) {
				r_anal_op (core->anal, &disasm_state->analop, disasm_state->at, buf+i, core->blocksize-i);
				if (*R_STRBUF_SAFEGET (&disasm_state->analop.esil)) {
					if (disasm_state->opstr) free (disasm_state->opstr);
					disasm_state->opstr = strdup (R_STRBUF_SAFEGET (&disasm_state->analop.esil));
				}
			} else
			if (disasm_state->decode) {
				if (disasm_state->opstr) free (disasm_state->opstr);
				r_anal_op (core->anal, &disasm_state->analop, disasm_state->at, buf+i, core->blocksize-i);
				tmpopstr = r_anal_op_to_string (core->anal, &disasm_state->analop);
				disasm_state->opstr = (tmpopstr)? tmpopstr: strdup (disasm_state->asmop.buf_asm);
			} else {
				if (disasm_state->opstr) free (disasm_state->opstr);
				disasm_state->opstr = strdup (disasm_state->asmop.buf_asm);
			}
		}
		if (ret<1) {
			err = 1;
			ret = 1;
			r_cons_printf ("???\n");
		} else {
			r_cons_printf ("%s\n", disasm_state->opstr);
			free (disasm_state->opstr);
			disasm_state->opstr = NULL;
		}
	}
	if (disasm_state->oldbits) {
		r_config_set_i (core->config, "asm.bits", disasm_state->oldbits);
		disasm_state->oldbits = 0;
	}
	handle_deinit_disasm_state (core, disasm_state);
	return 0;
}
#endif

#if USE_OLD
// int l is for lines
R_API int r_core_print_disasm(RPrint *p, RCore *core, ut64 addr, ut8 *buf, int len, int l, int invbreak, int cbytes) {
	RAnalHint *hint = NULL;
	const char *pal_comment = core->cons->pal.comment;
	/* other */
	int ret, index, idx = 0, i, j, k, lines, ostackptr = 0, stackptr = 0;
	char *line = NULL, *comment = NULL, *opstr, *osl = NULL; // old source line
	int continueoninvbreak = (len == l) && invbreak;
	char str[512], strsub[512];
	RAnalFunction *f = NULL;
	char *refline = NULL;
	char *refline2 = NULL;
	RAnalCC cc = {0};
	ut8 *nbuf = NULL;
	int counter = 0;
	int middle = 0;
	ut64 dest = UT64_MAX;
	RAsmOp asmop;
	RAnalOp analop = {0};
	RFlagItem *flag;
	RMetaItem *mi;
	int oplen = 0;
	int tries = 3;

	opstr = NULL;
	memset (str, 0, sizeof (str));

	//r_cons_printf ("len =%d l=%d ib=%d limit=%d\n", len, l, invbreak, p->limit);
	// TODO: import values from debugger is possible
	// TODO: allow to get those register snapshots from traces
	// TODO: per-function register state trace

	// TODO: All those options must be print flags
	int use_esil = r_config_get_i (core->config, "asm.esil");
	int show_color = r_config_get_i (core->config, "scr.color");
	int colorop = r_config_get_i (core->config, "scr.colorops");
	//int show_utf8 = r_config_get_i (core->config, "scr.utf8");
	int acase = r_config_get_i (core->config, "asm.ucase");
	int atabs = r_config_get_i (core->config, "asm.tabs");
	int decode = r_config_get_i (core->config, "asm.decode");
	int pseudo = r_config_get_i (core->config, "asm.pseudo");
	int filter = r_config_get_i (core->config, "asm.filter");
	int varsub = r_config_get_i (core->config, "asm.varsub");
	int show_lines = r_config_get_i (core->config, "asm.lines");
	int linesright = r_config_get_i (core->config, "asm.linesright");
#warning asm.dwarf is now marked as experimental and disabled
	int show_dwarf = 0; // r_config_get_i (core->config, "asm.dwarf");
	int show_linescall = r_config_get_i (core->config, "asm.linescall");
	int show_size = r_config_get_i (core->config, "asm.size");
	int show_trace = r_config_get_i (core->config, "asm.trace");
	int linesout = r_config_get_i (core->config, "asm.linesout");
	int adistrick = r_config_get_i (core->config, "asm.middle"); // TODO: find better name
	int show_offset = r_config_get_i (core->config, "asm.offset");
	int show_offseg = r_config_get_i (core->config, "asm.segoff");
	int show_flags = r_config_get_i (core->config, "asm.flags");
	int show_bytes = r_config_get_i (core->config, "asm.bytes");
	int show_comments = r_config_get_i (core->config, "asm.comments");
	int show_cmtflgrefs = r_config_get_i (core->config, "asm.cmtflgrefs");
	int show_stackptr = r_config_get_i (core->config, "asm.stackptr");
	int show_xrefs = r_config_get_i (core->config, "asm.xrefs");
	int show_functions = r_config_get_i (core->config, "asm.functions");
	int cursor, nb, nbytes = r_config_get_i (core->config, "asm.nbytes");
	int show_comment_right_default = r_config_get_i (core->config, "asm.cmtright");
	int flagspace_ports = r_flag_space_get (core->flags, "ports");
	int lbytes = r_config_get_i (core->config, "asm.lbytes");
	int show_comment_right = 0;
	char *pre = "  ";
	char *ocomment = NULL;
	int linesopts = 0;
	int lastfail = 0;
	int oldbits = 0;
	int ocols = 0;
	int lcols = 0;

/* color palette */
#define P(x) (core->cons && core->cons->pal.x)? core->cons->pal.x
	// TODO: only if show_color?
	const char *color_comment = P(comment): Color_CYAN;
	const char *color_fname = P(fname): Color_RED;
	const char *color_floc = P(floc): Color_MAGENTA;
	const char *color_fline = P(fline): Color_CYAN;
	const char *color_flow = P(flow): Color_CYAN;
	const char *color_flag = P(flag): Color_CYAN;
	const char *color_label = P(label): Color_CYAN;
	const char *color_other = P(other): Color_WHITE;
	const char *color_nop = P(nop): Color_BLUE;
	const char *color_bin = P(bin): Color_YELLOW;
	const char *color_math = P(math): Color_YELLOW;
	const char *color_jmp = P(jmp): Color_GREEN;
	const char *color_cjmp = P(cjmp): Color_GREEN;
	const char *color_call = P(call): Color_BGREEN;
	const char *color_cmp = P(cmp): Color_MAGENTA;
	const char *color_swi = P(swi): Color_MAGENTA;
	const char *color_trap = P(trap): Color_BRED;
	const char *color_ret = P(ret): Color_RED;
	const char *color_push = P(push): Color_YELLOW;
	const char *color_pop = P(pop): Color_BYELLOW;
	const char *color_reg = P(reg): Color_YELLOW;
	const char *color_num = P(num): Color_YELLOW;
	const char *color_invalid = P(invalid): Color_BRED;

	if (show_lines) ocols += 10; // XXX
	if (show_offset) ocols += 14;
	lcols = ocols+2;
	if (show_bytes) ocols += 20;
	if (show_trace) ocols += 8;
	if (show_stackptr) ocols += 4;
	/* disasm */ ocols += 20;

	nb = (nbytes*2);
	core->inc = 0;

	if (core->print->cur_enabled) {
		if (core->print->cur<0)
			core->print->cur = 0;
		cursor = core->print->cur;
	} else cursor = -1;

	if (r_config_get_i (core->config, "asm.linesstyle"))
		linesopts |= R_ANAL_REFLINE_TYPE_STYLE;
	if (r_config_get_i (core->config, "asm.lineswide"))
		linesopts |= R_ANAL_REFLINE_TYPE_WIDE;
	lines = 0;
	index = 0;
	/* reset jmp table if not a bad block */
	if (buf[0] != 0xff) // hack
		for (i=0; i<10; i++)
			core->asmqjmps[i] = UT64_MAX;
toro:
	// uhm... is this necesary? imho can be removed
	r_asm_set_pc (core->assembler, addr+idx);
#if 0
	/* find last function else stackptr=0 */
	{
		RAnalFunction *fcni;
		RListIter *iter;

		r_list_foreach (core->anal.fcns, iter, fcni) {
			if (addr >= fcni->addr && addr<(fcni->addr+fcni->size)) {
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
		if (r_anal_op (core->anal, &analop, core->offset+core->print->cur,
			buf+core->print->cur, (int)(len-core->print->cur))) {
			// TODO: check for analop.type and ret
			dest = analop.jump;
#if 0
			switch (analop.type) {
			case R_ANAL_OP_TYPE_JMP:
			case R_ANAL_OP_TYPE_CALL:
				dest = analop.jump;
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
			dest = item->offset;
	}
	if (show_lines) {
		// TODO: make anal->reflines implicit
		free (core->reflines); // TODO: leak
		free (core->reflines2); // TODO: leak
		core->reflines = r_anal_reflines_get (core->anal,
			addr, buf, len, -1, linesout, show_linescall);
		core->reflines2 = r_anal_reflines_get (core->anal,
			addr, buf, len, -1, linesout, 1);
	} else core->reflines = core->reflines2 = NULL;

	oplen = 1;
	r_cons_break (NULL, NULL);
	for (i=idx=ret=0; idx < len && lines < l; idx+=oplen,i++, index+=oplen,lines++) {
		ut64 at = addr + idx;
		if (r_cons_singleton ()->breaked)
			break;

		r_core_seek_archbits (core, at); // slow but safe
		hint = r_core_hint_begin (core, hint, at);
		//if (!cbytes && idx>=l) { break; }
		r_asm_set_pc (core->assembler, at);
		if (show_lines) {
			line = r_anal_reflines_str (core, at, linesopts);
			refline = filter_refline (core, line);
			refline2 = filter_refline2 (core, refline);
		} else {
			line = NULL;
			refline = strdup ("");
			refline2 = strdup ("");
		}

		/* show type links */
		r_core_cmdf (core, "tf 0x%08"PFMT64x, at);

		f = show_functions? r_anal_fcn_find (core->anal, at,
			R_ANAL_FCN_TYPE_NULL): NULL;
		if (!hint || !hint->bits) {
			if (f) {
				if (f->bits) {
					if (!oldbits)
						oldbits = r_config_get_i (core->config, "asm.bits");
					if (oldbits != f->bits) {
						r_config_set_i (core->config, "asm.bits", f->bits);
					}
				} else {
					if (oldbits) {
						r_config_set_i (core->config, "asm.bits", oldbits);
						oldbits = 0;
					}
				}
			} else {
				if (oldbits) {
					r_config_set_i (core->config, "asm.bits", oldbits);
					oldbits = 0;
				}
			}
		}
		// Show xrefs
		if (show_xrefs) {
			RList *xrefs;
			RAnalRef *refi;
			RListIter *iter;

			/* show reverse refs */

			/* show xrefs */
			if ((xrefs = r_anal_xref_get (core->anal, at))) {
				r_list_foreach (xrefs, iter, refi) {
#if 0
			r_list_foreach (core->anal->refs, iter, refi)
#endif
				if (refi->addr == at) {
					RAnalFunction *fun = r_anal_fcn_find (
						core->anal, refi->at,
						R_ANAL_FCN_TYPE_FCN |
						R_ANAL_FCN_TYPE_ROOT);
#if 1
// THAT'S OK
					if (show_color) {
						r_cons_printf ("%s%s "Color_RESET"%s%s"Color_RESET, color_fline,
							((f&&f->type==R_ANAL_FCN_TYPE_FCN)&&f->addr==at)
							?" ":core->cons->vline[LINE_VERT], color_flow, refline2);
					} else {
						r_cons_printf ("%s %s", ((f&&f->type==R_ANAL_FCN_TYPE_FCN)
							&& f->addr==at)?" ":core->cons->vline[LINE_VERT], refline2);
					}
#endif
					if (show_color) {
						r_cons_printf ("%s; %s XREF from 0x%08"PFMT64x" (%s)"Color_RESET"\n",
							pal_comment, refi->type==R_ANAL_REF_TYPE_CODE?"CODE (JMP)":
							refi->type=='C'?"CODE (CALL)":"DATA", refi->at,
							fun?fun->name:"unk");
					} else {
						r_cons_printf ("; %s XREF from 0x%08"PFMT64x" (%s)\n",
							refi->type=='c'?"CODE (JMP)":
							refi->type=='C'?"CODE (CALL)":"DATA", refi->at,
							fun?fun->name: "unk");
					}
				}
			}
				r_list_free (xrefs);
			}
		}

		/* show comment at right? */
		show_comment_right = 0;
		if (show_comments) {
			RFlagItem *item = r_flag_get_i (core->flags, at);
			comment = r_meta_get_string (core->anal->meta, R_META_TYPE_COMMENT, at);
			if (!comment && item && item->comment) {
				ocomment = item->comment;
				comment = strdup (item->comment);
			}
			if (comment) {
				int linelen, maxclen = strlen (comment)+5;
				linelen = maxclen;
				if (show_comment_right_default)
				if (ocols+maxclen < core->cons->columns) {
					if (comment && *comment && strlen (comment)<maxclen) {
						char *p = strchr (comment, '\n');
						if (p) {
							linelen = p-comment;
							if (!strchr (p+1, '\n')) // more than one line?
								show_comment_right = 1;
						}
					}
				}
				if (!show_comment_right) {
					int infun, mycols = lcols;
					if (mycols + linelen + 10 > core->cons->columns)
						mycols = 0;
					mycols /= 2;
					if (show_color) r_cons_strcat (pal_comment);
#if OLD_COMMENTS
					r_cons_strcat ("; ");
					// XXX: always prefix with ; the comments
					if (*comment != ';') r_cons_strcat ("  ;  ");
					r_cons_strcat_justify (comment, mycols, ';');
#else
					infun = f && (f->addr != at);
					if (infun) {
						char *str = strdup (show_color?color_fline: "");
						str = r_str_concat (str, core->cons->vline[LINE_VERT]);
						if (show_color)
							str = r_str_concat (str, color_flow);
// color refline
						str = r_str_concat (str, " ");
						str = r_str_concat (str, refline2);
// color comment
						if (show_color)
							str = r_str_concat (str, color_comment);
						str = r_str_concat (str, ";  ");
						comment = r_str_prefix_all (comment, str);
						free (str);
					} else {
						comment = r_str_prefix_all (comment, "   ;      ");
					}
					r_cons_strcat (comment);
#endif
					if (show_color) r_cons_strcat (Color_RESET);
					if (!strchr (comment, '\n')) r_cons_newline ();
					free (comment);
					comment = NULL;

					/* flag one */
					if (item && item->comment && ocomment != item->comment) {
						if (show_color) r_cons_strcat (pal_comment);
						r_cons_newline ();
						r_cons_strcat ("  ;  ");
						r_cons_strcat_justify (item->comment, mycols, ';');
						r_cons_newline ();
						if (show_color) r_cons_strcat (Color_RESET);
					}
				}
			}
		}
		// TODO : line analysis must respect data types! shouldnt be interpreted as code
		ret = r_asm_disassemble (core->assembler, &asmop, buf+idx, len-idx);
		oplen = asmop.size;
		if (oplen<1) oplen = 1;
		if (ret<1) { // XXX: move to r_asm_disassemble ()
			ret = -1;
			//eprintf ("** invalid opcode at 0x%08"PFMT64x" %d %d**\n",
			//	core->assembler->pc + ret, l, len);
#if HASRETRY
//eprintf ("~~~~~~LEN~~~~ %d %d %d\n", l, len, lines);
			if (!cbytes && tries>0) { //1||l < len)
//eprintf ("~~~~~~~~~~~~~ %d %d\n", idx, core->blocksize);
				addr = core->assembler->pc;
				tries--;
				//eprintf ("-- %d %d\n", len, r_core_read_at (core, addr, buf, len));
				//eprintf ("REtry 0x%llx -- %x %x\n", addr, buf[0], buf[1]);
				idx = 0;
				goto retry;
			}
#endif
			lastfail = 1;
			strcpy (asmop.buf_asm, "invalid");
		//	sprintf (asmop.buf_hex, "%02x", buf[idx]);
		} else {
			lastfail = 0;
			oplen = (hint && hint->size)?
				hint->size: r_asm_op_get_size (&asmop);
		}
		if (pseudo) {
			r_parse_parse (core->parser, opstr?
				opstr: asmop.buf_asm, str);
			free (opstr);
			opstr = strdup (str);
		}
		if (acase)
			r_str_case (asmop.buf_asm, 1);
		if (atabs) {
			int n, i = 0, comma = 0, word = 0;
			int brackets = 0;
			char *t, *b;
			free (opstr);
			opstr = b = malloc (strlen (asmop.buf_asm)* (atabs+1)*4);
			strcpy (b, asmop.buf_asm);
			for (; *b; b++, i++) {
				if (*b=='(' || *b=='[') brackets++;
				if (*b==')' || *b==']') brackets--;
				if (*b==',') comma = 1;
				if (*b!=' ') continue;
				if (word>0 && !comma) continue; //&& b[1]=='[') continue;
				if (brackets>0) continue;
				comma = 0;
				brackets = 0;
				n = (atabs-i);
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
		if (show_color && colorop)
			colorize_opcode (asmop.buf_asm, color_reg, color_num);
		// TODO: store previous oplen in core->dec
		if (core->inc == 0)
			core->inc = oplen;

		r_anal_op_fini (&analop);
		if (!lastfail)
			r_anal_op (core->anal, &analop, at, buf+idx, (int)(len-idx));
		if (ret<1) {
			r_strbuf_init (&analop.esil);
			analop.type = R_ANAL_OP_TYPE_ILL;
		}
		if (hint) {
			if (hint->size) analop.size = hint->size;
			if (hint->ptr) analop.ptr = hint->ptr;
		}
		{
			RAnalValue *src;
			switch (analop.type) {
			case R_ANAL_OP_TYPE_MOV:
				src = analop.src[0];
				if (src && src->memref>0 && src->reg) {
					if (core->anal->reg && core->anal->reg->name) {
						const char *pc = core->anal->reg->name[R_REG_NAME_PC];
						RAnalValue *dst = analop.dst;
						if (dst && dst->reg && dst->reg->name)
						if (!strcmp (src->reg->name, pc)) {
							RFlagItem *item;
							ut8 b[8];
							ut64 ptr = idx+addr+src->delta+analop.size;
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
#if 1
// TODO: get from meta anal?
			case R_ANAL_OP_TYPE_LEA:
				src = analop.src[0];
				if (src && src->reg && core->anal->reg && core->anal->reg->name) {
					const char *pc = core->anal->reg->name[R_REG_NAME_PC];
					RAnalValue *dst = analop.dst;
					if (dst && dst->reg && !strcmp (src->reg->name, pc)) {
						int memref = core->assembler->bits/8;
						RFlagItem *item;
						ut8 b[64];
						ut64 ptr = index+addr+src->delta+analop.size;
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
#endif
			}
		}
		if (show_comments && show_cmtflgrefs) {
			RFlagItem *item;
			switch (analop.type) {
			case R_ANAL_OP_TYPE_JMP:
			case R_ANAL_OP_TYPE_CJMP:
			case R_ANAL_OP_TYPE_CALL:
				item = r_flag_get_i (core->flags, analop.jump);
				if (item && item->comment) {
					if (show_color) r_cons_strcat (pal_comment);
					r_cons_printf ("  ; ref to %s: %s\n", item->name, item->comment);
					if (show_color) r_cons_strcat (Color_RESET);
				}
				break;
			}
		}
		if (adistrick)
			middle = r_anal_reflines_middle (core->anal,
					core->reflines, at, analop.size);
		/* XXX: This is really cpu consuming.. need to be fixed */
		if (show_functions) {
			//pre = "  ";
			if (f) {
				if (f->locals != NULL) {
					RAnalFcnLocal *f_loc;
					RListIter *l_iter;
					r_list_foreach (f->locals, l_iter, f_loc) {
						if (f_loc && f_loc->addr == at) {
							if (show_color) {
								r_cons_printf ("%s%s"Color_RESET, color_fline, pre); // "|"
							} else
								r_cons_printf (pre); //"| "
							if (show_lines && refline) {
								r_cons_printf ("%s%s"Color_RESET, color_flow, refline);
							}
							if (show_offset)
								r_cons_printf ("; -- ");
							if (show_color)
								r_cons_printf ("%s %s"Color_RESET"\n",
									color_label, f_loc->name?f_loc->name:"unk");
							else r_cons_printf (" %s\n", f_loc->name?f_loc->name:"unk");
						}
					}
				}
				if (f->addr == at) {
					char *sign = r_anal_fcn_to_string (core->anal, f);
					if (f->type == R_ANAL_FCN_TYPE_LOC) {
						if (show_color) {
							r_cons_printf ("%s%s ", color_fline,
								core->cons->vline[LINE_CROSS]); // |-
							r_cons_printf ("%s%s"Color_RESET" %d\n",
								color_floc, f->name, f->size);
							r_cons_printf ("%s%s "Color_RESET,
								color_fline, core->cons->vline[LINE_VERT]); // |
						} else {
							r_cons_printf ("%s %s %d\n| ", core->cons->vline[LINE_CROSS],
								f->name, f->size); // |-

						}
					} else {
						int corner = (f->size <= analop.size)? RDWN_CORNER: LINE_VERT;
						const char *fmt = show_color?
							"%s%s "Color_RESET"%s(%s) %s"Color_RESET" %d\n":
							"%s (%s) %s %d\n%s ";
						if (show_color) {
							r_cons_printf (fmt, color_fline,
								core->cons->vline[RUP_CORNER], color_fname,
								(f->type==R_ANAL_FCN_TYPE_FCN || f->type==R_ANAL_FCN_TYPE_SYM)?"fcn":
								(f->type==R_ANAL_FCN_TYPE_IMP)?"imp":"loc",
								f->name, f->size, corner);
							r_cons_printf ("%s%s "Color_RESET,
								color_fline, core->cons->vline[corner]);
						} else {
							r_cons_printf (fmt, core->cons->vline[RUP_CORNER],
								(f->type==R_ANAL_FCN_TYPE_FCN||f->type==R_ANAL_FCN_TYPE_SYM)?"fcn":
								(f->type==R_ANAL_FCN_TYPE_IMP)?"imp":"loc",
								f->name, f->size, core->cons->vline[corner]);
						}
					}
					if (sign) r_cons_printf ("// %s\n", sign);
					free (sign);
					//pre = "| "; // TOFIX!
					pre = strdup (core->cons->vline[LINE_VERT]);
					pre = r_str_concat (pre, " ");
					stackptr = 0;
				} else if (f->addr+f->size-analop.size== at) {
					if (show_color) {
						r_cons_printf ("%s%s "Color_RESET,
							color_fline, core->cons->vline[RDWN_CORNER]);
					} else {
						r_cons_printf ("%s ", core->cons->vline[RDWN_CORNER]);
					}
				} else if (at > f->addr && at < f->addr+f->size-1) {
					if (show_color) {
						r_cons_printf ("%s%s "Color_RESET,
							color_fline, core->cons->vline[LINE_VERT]);
					} else {
						r_cons_printf ("%s ", core->cons->vline[LINE_VERT]);
					}
					//pre = "| "; // TOFIX!
					pre = strdup (core->cons->vline[LINE_VERT]);
					pre = r_str_concat (pre, " ");
				} else f = NULL;
				if (f && at == f->addr+f->size-analop.size) { // HACK
					//pre = R_LINE_BOTTOM_DCORNER" ";
					pre = strdup (core->cons->vline[RDWN_CORNER]);
					pre = r_str_concat (pre, " ");
				}
			} else r_cons_printf ("  ");
		}
		if (show_flags) {
			flag = r_flag_get_i (core->flags, at);
			if (flag && (!f || (f && strcmp (f->name, flag->name)))) {
				if (show_lines && refline) {
					if (show_color) {
						r_cons_printf ("%s%s"Color_RESET, color_flow, refline2);
					} else r_cons_printf (refline);
				}
				if (show_offset) r_cons_printf (";-- ");
				if (show_color) r_cons_strcat (color_flag);
				if (show_functions) r_cons_printf ("%s:\n", flag->name);
				else r_cons_printf ("%s:\n", flag->name);
				if (show_color) {
					r_cons_printf (Color_RESET"%s%s"Color_RESET, color_fline,
						f ? pre : "  ");
				} else r_cons_printf (f ? pre : "  ");
			}
		}
		if (!linesright && show_lines && line) {
			if (show_color) {
// XXX line is too long wtf
				r_cons_printf ("%s%s"Color_RESET, color_flow, line);
			} else r_cons_printf (line);
		}
		if (show_offset)
			r_print_offset (core->print, at, (at==dest), show_offseg);
		if (show_size)
			r_cons_printf ("%d ", analop.size);
		if (show_trace) {
			RDebugTracepoint *tp = r_debug_trace_get (core->dbg, at);
			r_cons_printf ("%02x:%04x ", tp?tp->times:0, tp?tp->count:0);
		}
		if (show_stackptr) {
			r_cons_printf ("%3d%s", stackptr,
				analop.type==R_ANAL_OP_TYPE_CALL?">":
				stackptr>ostackptr?"+":stackptr<ostackptr?"-":" ");
			ostackptr = stackptr;
			stackptr += analop.stackptr;
			/* XXX if we reset the stackptr 'ret 0x4' has not effect.
			 * Use RAnalFunction->RAnalOp->stackptr? */
			if (analop.type == R_ANAL_OP_TYPE_RET)
				stackptr = 0;
		}
		// TODO: implement ranged meta find (if not at the begging of function..
		mi = r_meta_find (core->anal->meta, at, R_META_TYPE_ANY,
			R_META_WHERE_HERE);
		if (mi)
		switch (mi->type) {
		case R_META_TYPE_STRING:
			{
			char *out = r_str_unscape (mi->str);
			if (show_color)
				r_cons_printf ("    .string "Color_YELLOW"\"%s\""
					Color_RESET" ; len=%"PFMT64d"\n", out, mi->size);
			else r_cons_printf ("    .string \"%s\" ; len=%"PFMT64d
					"\n", out, mi->size);
			free (out);
			}
			oplen = ret = (int)mi->size;
			i += mi->size-1; // wtf?
			free (line);
			free (refline);
			free (refline2);
			line = refline = refline2 = NULL;
			continue;
		case R_META_TYPE_HIDE:
			r_cons_printf ("(%d bytes hidden)\n", mi->size);
			oplen = mi->size;
			continue;
		case R_META_TYPE_DATA:
			{
				int hexlen = len - idx;
				int delta = at-mi->from;
				if (mi->size<hexlen)
					hexlen = mi->size;
				core->print->flags &= ~R_PRINT_FLAGS_HEADER;
				r_cons_printf ("hex length=%lld delta=%d\n", mi->size , delta);
				r_print_hexdump (core->print, at,
					buf+idx, hexlen-delta, 16, 1);
			core->inc = 16;
				core->print->flags |= R_PRINT_FLAGS_HEADER;
				oplen = ret = (int)mi->size; //-delta;
				free (line);
				free (refline);
				free (refline2);
				line = refline = refline2 = NULL;
			}
			continue;
		case R_META_TYPE_FORMAT:
			r_cons_printf ("format %s {\n", mi->str);
			r_print_format (core->print, at, buf+idx, len-idx, mi->str, -1, NULL);
			r_cons_printf ("} %d\n", mi->size);
			oplen = ret = (int)mi->size;
			free (line);
			free (refline);
			free (refline2);
			line = refline = refline2 = NULL;
			continue;
		}
		/* show cursor */
		{
			int q = core->print->cur_enabled && cursor >= index && cursor < (index+oplen);
			void *p = r_bp_get (core->dbg->bp, at);
			r_cons_printf (p&&q?"b*":p? "b ":q?"* ":"  ");
		}
		if (show_bytes) {
			char *str = NULL, pad[64];
			char extra[64];
			strcpy (extra, " ");
			flag = NULL; // HACK
			if (!flag) {

				str = strdup (asmop.buf_hex);
				if (r_str_ansi_len (str) > nb) {
					char *p = (char *)r_str_ansi_chrn (str, nb);
					if (p)  {
						p[0] = '.';
						p[1] = '\0';
					}
					*extra = 0;
				}
				k = nb-r_str_ansi_len (str);
				if (k<0) k = 0;
				for (j=0; j<k; j++)
					pad[j] = ' ';
				pad[j] = 0;
				if (lbytes) {
					// hack to align bytes left
					strcpy (extra, pad);
					*pad = 0;
				}
			//	if (show_color) {
					char *nstr;
					p->cur_enabled = cursor!=-1;
					//p->cur = cursor;
					nstr = r_print_hexpair (p, str, index);
					free (str);
					str = nstr;
			//	}
			} else {
				str = strdup (flag->name);
				k = nb-strlen (str)-2;
				if (k<0) k = 0;
				for (j=0; j<k; j++)
					pad[j] = ' ';
				pad[j] = '\0';
			}
			if (show_color)
				r_cons_printf ("%s %s %s"Color_RESET, pad, str, extra);
			else r_cons_printf ("%s %s %s", pad, str, extra);
			free (str);
		}

		if (linesright && show_lines && line) {
			if (show_color) {
				r_cons_printf ("%s%s"Color_RESET, color_flow, line);
			} else r_cons_printf (line);
		}
		if (show_color) {
			switch (analop.type) {
			case R_ANAL_OP_TYPE_NOP:
				r_cons_strcat (color_nop);
				break;
			case R_ANAL_OP_TYPE_ADD:
			case R_ANAL_OP_TYPE_SUB:
			case R_ANAL_OP_TYPE_MUL:
			case R_ANAL_OP_TYPE_DIV:
				r_cons_strcat (color_math);
				break;
			case R_ANAL_OP_TYPE_AND:
			case R_ANAL_OP_TYPE_OR:
			case R_ANAL_OP_TYPE_XOR:
			case R_ANAL_OP_TYPE_NOT:
			case R_ANAL_OP_TYPE_SHL:
			case R_ANAL_OP_TYPE_SHR:
			case R_ANAL_OP_TYPE_ROL:
			case R_ANAL_OP_TYPE_ROR:
				r_cons_strcat (color_bin);
				break;
			case R_ANAL_OP_TYPE_JMP:
			case R_ANAL_OP_TYPE_UJMP:
				r_cons_strcat (color_jmp);
				break;
			case R_ANAL_OP_TYPE_CJMP:
				r_cons_strcat (color_cjmp);
				break;
			case R_ANAL_OP_TYPE_CMP:
				r_cons_strcat (color_cmp);
				break;
			case R_ANAL_OP_TYPE_UCALL:
			case R_ANAL_OP_TYPE_CALL:
				r_cons_strcat (color_call);
				break;
			case R_ANAL_OP_TYPE_SWI:
				r_cons_strcat (color_swi);
				break;
			case R_ANAL_OP_TYPE_ILL:
			case R_ANAL_OP_TYPE_TRAP:
				r_cons_strcat (color_trap);
				break;
			case R_ANAL_OP_TYPE_CRET:
			case R_ANAL_OP_TYPE_RET:
				r_cons_strcat (color_ret);
				break;
			case R_ANAL_OP_TYPE_PUSH:
			case R_ANAL_OP_TYPE_UPUSH:
			case R_ANAL_OP_TYPE_LOAD:
				r_cons_strcat (color_push);
				break;
			case R_ANAL_OP_TYPE_POP:
			case R_ANAL_OP_TYPE_STORE:
				r_cons_strcat (color_pop);
				break;
			case R_ANAL_OP_TYPE_NULL:
				r_cons_strcat (color_other);
				break;
			case R_ANAL_OP_TYPE_UNK:
				r_cons_strcat (color_invalid);
				break;
			}
		}
		if (decode) {
			char *tmpopstr = r_anal_op_to_string (core->anal, &analop);
			// TODO: Use data from code analysis..not raw analop here
			// if we want to get more information
			opstr = tmpopstr? tmpopstr: strdup (asmop.buf_asm);
		}
		if (hint && hint->opcode) {
			free (opstr);
			opstr = strdup (hint->opcode);
		}
		if (filter) {
			int ofs = core->parser->flagspace;
			int fs = flagspace_ports;
			if (analop.type == R_ANAL_OP_TYPE_IO) {
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
				opstr? opstr: asmop.buf_asm, str, sizeof (str));
			core->parser->flagspace = ofs;
			if (opstr)
				free (opstr);
			opstr = strdup (str);
			core->parser->flagspace = ofs; // ???
		} else {
			if (!opstr)
				opstr = strdup (asmop.buf_asm);
		}
		if (varsub) {
			RAnalFunction *f = r_anal_fcn_find (core->anal,
				at, R_ANAL_FCN_TYPE_NULL);
			if (f) {
				r_parse_varsub (core->parser, f,
					opstr, strsub, sizeof (strsub));
				free (opstr);
				opstr = strdup (strsub);
			}
		}
		if (use_esil) {
			if (*R_STRBUF_SAFEGET (&analop.esil)) {
				free (opstr);
				opstr = strdup (R_STRBUF_SAFEGET (&analop.esil));
			} else {
				char *p = malloc (strlen (opstr)+3); /* What's up '\0' ? */
				strcpy (p, ": ");
				strcpy (p+2, opstr);
				free (opstr);
				opstr = p;
			}
		}

		r_cons_strcat (opstr);

		{ /* show function name */
			ut8 have_local = 0;
			RAnalFunction *f, *cf;
			switch (analop.type) {
			case R_ANAL_OP_TYPE_JMP:
		//	case R_ANAL_OP_TYPE_CJMP:
			case R_ANAL_OP_TYPE_CALL:
				cf = r_anal_fcn_find (core->anal, /* current function */
					at, R_ANAL_FCN_TYPE_NULL);
				f = r_anal_fcn_find (core->anal,
					analop.jump, R_ANAL_FCN_TYPE_NULL);
				if (f && !strstr (opstr, f->name)) {
					if (f->locals != NULL) {
						RAnalFcnLocal *l;
						RListIter *iter;
						r_list_foreach (f->locals, iter, l) {
							if (analop.jump == l->addr) {
								if ((cf != NULL) && (f->addr == cf->addr)) {
									if (show_color) {
										r_cons_strcat (color_label);
										r_cons_printf ("; (%s)", l->name);
										r_cons_strcat (Color_RESET);
									} else {
										r_cons_printf ("; (%s)", l->name);
									}
								} else {
									if (show_color) {
										r_cons_strcat (color_fname);
										r_cons_printf ("; (%s", f->name);
										//r_cons_strcat (Color_RESET);
										r_cons_strcat (color_label);
										r_cons_printf (".%s)", l->name);
										r_cons_strcat (Color_RESET);
									} else {
										r_cons_printf ("; (%s.%s)", f->name, l->name);
									}
								}
								have_local = 1;
								break;
							}
						}
					}
					if (!have_local) {
						if (show_color)
							r_cons_strcat (color_fname);
						r_cons_printf (" ; (%s)", f->name);
						if (show_color)
							r_cons_strcat (Color_RESET);
					}
				}
				break;
			}
		}
		free (opstr);
		opstr = NULL;

		if (show_color)
			r_cons_strcat (Color_RESET);

		if (show_dwarf) {
			char *sl = r_bin_meta_get_source_line (core->bin, at);
			int len = strlen (opstr);
			if (len<30) len = 30-len;
			if (sl) {
				if ((!osl || (osl && strcmp (sl, osl)))) {
					while (len--)
						r_cons_strcat (" ");
					if (show_color)
						r_cons_printf ("%s  ; %s"Color_RESET"%s",
								pal_comment, l, pre);
					else r_cons_printf ("  ; %s\n%s", sl, pre);
					free (osl);
					osl = sl;
				}
			} else {
				eprintf ("Warning: Forced asm.dwarf=false because of error\n");
				show_dwarf = R_FALSE;
				r_config_set (core->config, "asm.dwarf", "false");
			}
		}
		if (middle != 0) {
			ret -= middle;
			r_cons_printf (" ;  *middle* %d", ret);
		}
		if (asmop.payload != 0)
			r_cons_printf ("\n; .. payload of %d bytes", asmop.payload);
		if (core->assembler->syntax != R_ASM_SYNTAX_INTEL) {
			RAsmOp ao; /* disassemble for the vm .. */
			int os = core->assembler->syntax;
			r_asm_set_syntax (core->assembler, R_ASM_SYNTAX_INTEL);
			r_asm_disassemble (core->assembler, &ao, buf+idx, len-idx+5);
			r_asm_set_syntax (core->assembler, os);
		}

		if (core->vmode) {
			switch (analop.type) {
			case R_ANAL_OP_TYPE_JMP:
			case R_ANAL_OP_TYPE_CJMP:
			case R_ANAL_OP_TYPE_CALL:
				counter++;
				if (counter<10) {
					core->asmqjmps[counter] = analop.jump;
					r_cons_printf (" ;[%d]", counter);
				} else r_cons_strcat (" ;[?]");
				break;
			}
		}
		if (!r_anal_cc_update (core->anal, &cc, &analop)) {
			if (show_functions) {
				char tmp[128];
				char *ccstr = r_anal_cc_to_string (core->anal, &cc);
				tmp[0] = 0;
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
					if (show_color)
						r_cons_printf ("\n%s%s"Color_RESET"%s%s"Color_RESET"   %s%s"Color_RESET,
							color_fline, pre, color_flow, refline, ccstr, tmp);
					else r_cons_printf ("\n%s%s   %s%s", pre, refline, ccstr, tmp);
					free (ccstr);
				}
			}
			r_anal_cc_reset (&cc);
		}
		switch (analop.type) {
		case R_ANAL_OP_TYPE_PUSH:
			if (analop.val) {
				RFlagItem *flag = r_flag_get_i (core->flags, analop.val);
				if (flag) r_cons_printf (" ; %s", flag->name);
			}
			break;
		}

		if (analop.refptr) {
			ut64 word8 = 0;
			ut32 word4 = 0;
			int ret;
			if (core->assembler->bits==64) {
				ret = r_io_read_at (core->io, analop.ptr, (void *)&word8,
					sizeof (word8)) == sizeof (word8);
			} else {
				ret = r_io_read_at (core->io, analop.ptr,
					(void *)&word4, sizeof (word4))
					== sizeof (word4);
				word8 = word4;
			}

			if (ret) {
				RMetaItem *mi2 = r_meta_find (core->anal->meta, word8,
					R_META_TYPE_ANY, R_META_WHERE_HERE);
				if (mi2) {
					switch (mi2->type) {
					case R_META_TYPE_STRING:
						{ char *str = r_str_unscape (mi2->str);
						r_cons_printf (" (at=0x%08"PFMT64x") (len=%"PFMT64d
							") \"%s\" ", word8, mi2->size, str);
						free (str);
						}
						break;
					case 'd':
						r_cons_printf (" (data)");
						break;
					default:
						eprintf ("unknown type '%c'\n", mi2->type);
						break;
					} 
				} else {
					mi2 = r_meta_find (core->anal->meta, (ut64)analop.ptr,
						R_META_TYPE_ANY, R_META_WHERE_HERE);
					if (mi2) {
						char *str = r_str_unscape (mi2->str);
						r_cons_printf (" \"%s\" @ 0x%08"PFMT64x":%"PFMT64d,
								str, analop.ptr, mi2->size);
						free (str);
					} else r_cons_printf (" ; 0x%08x [0x%"PFMT64x"]",
							word8, analop.ptr);
				}
			} else {
				st64 sref = analop.ptr;
				if (sref>0)
					r_cons_printf (" ; 0x%08"PFMT64x"\n", analop.ptr);
			}
		} else {
			if (analop.ptr != UT64_MAX && analop.ptr) {
				char msg[32];
				int bsz = len-idx;
				const char *kind = r_anal_data_kind (core->anal, analop.ptr, buf, bsz);
				*msg = 0;
				if (kind && !strcmp (kind, "text")) {
					*msg = '"';
					snprintf (msg+1, sizeof (msg)-2, "%s", buf+idx);
					strcat (msg, "\"");
				}
				r_cons_printf (" ; %s 0x%08"PFMT64x" ", msg, analop.ptr);
			}
		}
		if (show_comments && show_comment_right && comment) {
			int c = r_cons_get_column ();
			if (c<ocols)
				r_cons_memset (' ', ocols-c);
			if (show_color) r_cons_strcat (color_comment);
			r_cons_strcat ("  ; ");
	//		r_cons_strcat_justify (comment, strlen (refline) + 5, ';');
			r_cons_strcat (comment);
			if (show_color) r_cons_strcat (Color_RESET);
			free (comment);
			comment = NULL;
		} else r_cons_newline ();
		if (line) {
#if 0
			if (show_lines && analop.type == R_ANAL_OP_TYPE_RET) {
				if (strchr (line, '>'))
					memset (line, ' ', r_str_len_utf8 (line));
				if (show_color) {
					r_cons_printf ("%s %s%s"Color_RESET"; --\n",
						core->cons->vline[LINE_VERT], color_flow, line);
				} else
					r_cons_printf ("  %s; --\n", line);
			}
#endif
			free (line);
			free (refline);
			free (refline2);
			line = refline = refline2 = NULL;
		}
	}
	if (nbuf == buf) {
		free (buf);
		buf = NULL;
	}
	r_cons_break_end ();
#if HASRETRY
	//if (!cbytes && idx>=len) {// && (invbreak && !lastfail)) {
	if (!cbytes && lines<l) {
	retry:
		if (len<4) len = 4;
		buf = nbuf = malloc (len);
		if (tries>0) {
			addr += idx;
			if (r_core_read_at (core, addr, buf, len) ) {
				idx = 0;
				goto toro;
			}
		}
		if (lines<l) {
			addr += idx;
			if (r_core_read_at (core, addr, buf, len) != len) {
				//tries = -1;
			}
			goto toro;
		}
		if (continueoninvbreak)
			goto toro;
	}
#endif
	if (oldbits) {
		r_config_set_i (core->config, "asm.bits", oldbits);
		oldbits = 0;
	}
	r_anal_op_fini (&analop);
	if (hint) r_anal_hint_free (hint);
	free (osl);
	return idx; //-lastfail;
}


R_API int r_core_print_disasm_instructions (RCore *core, int len, int l) {
	int esil = r_config_get_i (core->config, "asm.esil");
	int decode = r_config_get_i (core->config, "asm.decode");
	const ut8 *buf = core->block;
	int bs = core->blocksize;
	RAnalHint *hint = NULL;
	char *opstr, *tmpopstr;
	int i, j, ret, err = 0;
	RAnalOp analop = {0};
	RAnalFunction *f;
	int oldbits = 0;
	RAsmOp asmop;
	ut64 at;

	if (len>core->blocksize)
		r_core_block_size (core, len);
	if (l==0) l = len;
	for (i=j=0; i<bs && i<len && j<l; i+=ret, j++) {
		at = core->offset +i;
		r_core_seek_archbits (core, at);
		if (hint) {
			r_anal_hint_free (hint);
			hint = NULL;
		}
		hint = r_core_hint_begin (core, hint, at);
		r_asm_set_pc (core->assembler, at);
	// XXX copypasta from main disassembler function
		f = r_anal_fcn_find (core->anal, at, R_ANAL_FCN_TYPE_NULL);
		if (!hint || !hint->bits) {
			if (f) {
				if (f->bits) {
					if (!oldbits)
						oldbits = r_config_get_i (core->config, "asm.bits");
					if (oldbits != f->bits) {
						r_config_set_i (core->config, "asm.bits", f->bits);
					}
				} else {
					if (oldbits != 0) {
						r_config_set_i (core->config, "asm.bits", oldbits);
						oldbits = 0;
					}
				}
			} else {
				if (oldbits) {
					r_config_set_i (core->config, "asm.bits", oldbits);
					oldbits = 0;
				}
			}
		}
		ret = r_asm_disassemble (core->assembler,
			&asmop, buf+i, core->blocksize-i);
		//r_cons_printf ("0x%08"PFMT64x"  ", core->offset+i);
		if (hint && hint->size)
			ret = hint->size;
		if (hint && hint->opcode) {
			opstr = strdup (hint->opcode);
		} else {
			if (esil) {
				r_anal_op (core->anal, &analop, at, buf+i, core->blocksize-i);
				if (*R_STRBUF_SAFEGET (&analop.esil))
					opstr = strdup (R_STRBUF_SAFEGET (&analop.esil));
			} else
			if (decode) {
				r_anal_op (core->anal, &analop, at, buf+i, core->blocksize-i);
				tmpopstr = r_anal_op_to_string (core->anal, &analop);
				opstr = (tmpopstr)? tmpopstr: strdup (asmop.buf_asm);
			} else opstr = strdup (asmop.buf_asm);
		}
		if (ret<1) {
			err = 1;
			ret = asmop.size;
			r_cons_printf ("???\n");
		} else {
			r_cons_printf ("%s\n", opstr);
			free (opstr);
		}
	}
	if (oldbits) {
		r_config_set_i (core->config, "asm.bits", oldbits);
		oldbits = 0;
	}
	if (hint) r_anal_hint_free (hint);
	return 0;
}
#endif

R_API int r_core_print_disasm_json(RCore *core, ut64 addr, ut8 *buf, int len) {
	RAsmOp asmop;
	RAnalOp analop;
	int i, oplen, ret;
	r_cons_printf ("[");
	// TODO: add support for anal hints
	for (i=0; i<len;) {
		ut64 at = addr +i;
		r_asm_set_pc (core->assembler, at);
		ret = r_asm_disassemble (core->assembler, &asmop, buf+i, len-i+5);
		if (ret<1) {
			r_cons_printf ("%s{", i>0? ",": "");
			r_cons_printf ("\"offset\":%"PFMT64d, at);
			r_cons_printf (",\"size\":1,\"type\":\"invalid\"}");
			i++;
			continue;
		}
		r_anal_op (core->anal, &analop, at, buf+i, len-i+5);

		oplen = r_asm_op_get_size (&asmop);
		r_cons_printf ("%s{", i>0? ",": "");
		r_cons_printf ("\"offset\":%"PFMT64d, at);
		r_cons_printf (",\"size\":%d", oplen);
		r_cons_printf (",\"opcode\":\"%s\"", asmop.buf_asm);
		r_cons_printf (",\"bytes\":\"%s\"", asmop.buf_hex);
		//r_cons_printf (",\"family\":\"%s\"", asmop.family);
		r_cons_printf (",\"type\":\"%s\"", r_anal_optype_to_string (analop.type));
		if (analop.jump != UT64_MAX) {
			r_cons_printf (",\"next\":%"PFMT64d, analop.jump);
			if (analop.fail != UT64_MAX)
				r_cons_printf (",\"fail\":%"PFMT64d, analop.fail);
		}
		r_cons_printf ("}");
		i += oplen;
	}
	r_cons_printf ("]");
	return R_TRUE;
}





