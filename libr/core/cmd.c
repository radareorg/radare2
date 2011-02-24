/* radare - LGPL - Copyright 2009-2011 // nibble<.ds@gmail.com>, pancake<nopcode.org> */

#include "r_core.h"
#include "r_io.h"
#include "r_flags.h"
#include "r_hash.h"
#include "r_asm.h"
#include "r_anal.h"
#include "r_util.h"
#include "r_bp.h"

#include <sys/types.h>
#include <stdarg.h>
#if HAVE_LIB_MAGIC
#include <magic.h>
#endif

static int printzoomcallback(void *user, int mode, ut64 addr, ut8 *bufz, ut64 size) {
	RCore *core = (RCore *) user;
	int j, ret = 0;
	RListIter *iter;
	RFlagItem *flag;

	switch (mode) {
	case 'p':
		for (j=0; j<size; j++)
			if (IS_PRINTABLE (bufz[j]))
				ret++;
		break;
	case 'f':
		r_list_foreach (core->flags->flags, iter, flag)
			if (flag->offset <= addr  && addr < flag->offset+flag->size)
				ret++;
		break;
	case 's':
		j = r_flag_space_get (core->flags, "strings");
		r_list_foreach (core->flags->flags, iter, flag) {
			if (flag->space == j && ((addr <= flag->offset
					&& flag->offset < addr+size)
					|| (addr <= flag->offset+flag->size
					&& flag->offset+flag->size < addr+size)))
				ret++;
		}
		break;
	case 'F': // 0xFF
		for (j=0; j<size; j++)
			if (bufz[j] == 0xff)
				ret++;
		break;
	case 'e': // entropy
		ret = (unsigned char) r_hash_entropy (bufz, size);
		break;
	case 'h': //head
	default:
		ret = *bufz;
	}
	return ret;
}

static int checkbpcallback(RCore *core) {
	ut64 pc = r_debug_reg_get (core->dbg, "pc");
	RBreakpointItem *bpi = r_bp_get (core->dbg->bp, pc);
	if (bpi) {
		if (bpi->data)
			r_core_cmd (core, bpi->data, 0);
		return R_TRUE;
	}
	return R_FALSE;
}

static int bypassbp(RCore *core) {
	ut64 addr;
	r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE);
	addr = r_debug_reg_get (core->dbg, "pc");
	RBreakpointItem *bpi = r_bp_get (core->dbg->bp, addr);
	if (!bpi)
		return R_FALSE;
	/* XXX 2 if libr/debug/debug.c:226 is enabled */
	r_debug_step (core->dbg, 1);
	return R_TRUE;
}

static void printoffset(ut64 off, int show_color) {
	if (show_color)
		r_cons_printf (Color_GREEN"0x%08"PFMT64x"  "Color_RESET, off);
	else r_cons_printf ("0x%08"PFMT64x"  ", off);
}

// TODO: move somewhere else
R_API RAsmAop *r_core_disassemble (RCore *core, ut64 addr) {
	ut8 buf[4096];
	static RBuffer *b = NULL; // XXX: never freed and non-thread safe. move to RCore
	RAsmAop *aop = R_NEW (RAsmAop);
	if (b == NULL) {
		b = r_buf_new ();
		if (r_core_read_at (core, addr, buf, sizeof (buf))) {
			b->base = addr;
			r_buf_set_bytes (b, buf, 4096);
		} else return NULL;
	} else {
		if (addr < b->base || addr > b->base+b->length-32) {
			if (r_core_read_at (core, addr, buf, sizeof (buf))) {
				b->base = addr;
				r_buf_set_bytes (b, buf, 4096);
			} else return NULL;
		}
	}
	if (r_asm_disassemble (core->assembler, aop, b->buf, b->length)<1) {
		free (aop);
		return NULL;
	}
	return aop;
}

/* TODO: move to print/disasm.c */
static void r_print_disasm(RPrint *p, RCore *core, ut64 addr, ut8 *buf, int len, int l) {
	RAnalCC cc = {0};
	RAnalFcn *f = NULL;
	int ret, idx, i, j, k, lines, ostackptr, stackptr = 0;
	int counter = 0;
	int middle = 0;
	char str[128], strsub[128];
	char *line = NULL, *comment, *opstr, *osl = NULL; // old source line
	RAsmAop asmop;
	RAnalOp analop;
	RFlagItem *flag;
	RMetaItem *mi;
	ut64 dest = UT64_MAX;

	// TODO: import values from debugger is possible
	// TODO: allow to get those register snapshots from traces
	// TODO: per-function register state trace

	// TODO: All those options must be print flags
	int show_color = r_config_get_i (core->config, "scr.color");
	int decode = r_config_get_i (core->config, "asm.decode");
	int pseudo = r_config_get_i (core->config, "asm.pseudo");
	int filter = r_config_get_i (core->config, "asm.filter");
	int varsub = r_config_get_i (core->config, "asm.varsub");
	int show_lines = r_config_get_i (core->config, "asm.lines");
	int show_dwarf = r_config_get_i (core->config, "asm.dwarf");
	int show_linescall = r_config_get_i (core->config, "asm.linescall");
	int show_trace = r_config_get_i (core->config, "asm.trace");
	int linesout = r_config_get_i (core->config, "asm.linesout");
	int adistrick = r_config_get_i (core->config, "asm.middle"); // TODO: find better name
	int show_offset = r_config_get_i (core->config, "asm.offset");
	int show_bytes = r_config_get_i (core->config, "asm.bytes");
	int show_comments = r_config_get_i (core->config, "asm.comments");
	int show_stackptr = r_config_get_i (core->config, "asm.stackptr");
	int show_xrefs = r_config_get_i (core->config, "asm.xrefs");
	int show_functions = r_config_get_i (core->config, "asm.functions");
	int cursor, nb, nbytes = r_config_get_i (core->config, "asm.nbytes");
	int linesopts = 0;
	const char *pre = "";
	nb = nbytes*2;
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

	// uhm... is this necesary? imho can be removed
	r_asm_set_pc (core->assembler, addr);
#if 0
	/* find last function else stackptr=0 */
	{
		RAnalFcn *fcni;
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
	if (core->print->cur_enabled) {
		// TODO: support in-the-middle-of-instruction too
		if (r_anal_aop (core->anal, &analop, core->offset+core->print->cur,
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
	}
	// TODO: make anal->reflines implicit
	free (core->reflines); // TODO: leak
	free (core->reflines2); // TODO: leak
	core->reflines = r_anal_reflines_get (core->anal, addr, buf, len, -1, linesout, show_linescall);
	core->reflines2 = r_anal_reflines_get (core->anal, addr, buf, len, -1, linesout, 1);
	for (lines=i=idx=ret=0; idx < len && lines < l; idx+=ret,i++, lines++) {
		ut64 at = addr + idx;
		r_asm_set_pc (core->assembler, at);
		if (show_comments)
		if ((comment = r_meta_get_string (core->meta, R_META_COMMENT, at))) {
			r_cons_strcat (comment);
			free (comment);
		}
		// TODO : line analysis must respect data types! shouldnt be interpreted as code
		line = r_anal_reflines_str (core->anal, core->reflines, at, linesopts);
		ret = r_asm_disassemble (core->assembler, &asmop, buf+idx, len-idx);
		if (ret<1) {
			ret = 1;
			eprintf ("** invalid opcode at 0x%08"PFMT64x" **\n",
				core->assembler->pc + ret);
			continue;
		}
if (core->inc == 0)
	core->inc = ret;
		r_anal_aop (core->anal, &analop, at, buf+idx, (int)(len-idx));
		// Show xrefs
		if (show_xrefs) {
			RList *xrefs;
			RAnalRef *refi;
			RListIter *iter;
			if ((xrefs = r_anal_xref_get (core->anal, at))) {
				r_list_foreach (xrefs, iter, refi) {
					f = r_anal_fcn_find (core->anal, refi->addr, R_ANAL_FCN_TYPE_NULL);
r_cons_printf ("%s                             ", pre);
					if (show_color)
					r_cons_printf (Color_TURQOISE"; %s XREF 0x%08"PFMT64x" (%s)"Color_RESET"\n",
							refi->type==R_ANAL_REF_TYPE_CODE?"CODE (JMP)":
							refi->type==R_ANAL_REF_TYPE_CALL?"CODE (CALL)":"DATA", refi->addr,
							f?f->name:"unk");
					else
					r_cons_printf ("; %s XREF 0x%08"PFMT64x" (%s)\n",
							refi->type==R_ANAL_REF_TYPE_CODE?"CODE (JMP)":
							refi->type==R_ANAL_REF_TYPE_CALL?"CODE (CALL)":"DATA", refi->addr,
							f?f->name:"unk");
				}
				r_list_destroy (xrefs);
			}
		}
		if (adistrick)
			middle = r_anal_reflines_middle (core->anal,
					core->reflines, at, analop.length);
		/* XXX: This is really cpu consuming.. need to be fixed */
		if (show_functions) {
			f = r_anal_fcn_find (core->anal, at, R_ANAL_FCN_TYPE_NULL);
			if (f) {
				pre = "";
				if (f->addr == at) {
					char *sign = r_anal_fcn_to_string (core->anal, f);
					r_cons_printf ("/* %s: %s (%d) */\n",
							f->type == R_ANAL_FCN_TYPE_FCN?"function":"loc", f->name, f->size);
					if (sign) r_cons_printf ("// %s\n", sign);
					free (sign);
					stackptr = 0;
				} else if (f->addr+f->size-1 == at) {
					r_cons_printf ("\\*");
				} else if (at > f->addr && at < f->addr+f->size-1) {
					r_cons_printf (": ");
					pre = ": ";
				} else f = NULL;
			}
		}
		flag = r_flag_get_i (core->flags, at);
		if (flag && !show_bytes) {
			if (show_lines && line)
				r_cons_strcat (line);
			//if (show_offset)
			//	printoffset (at, show_color);
			r_cons_printf ("%s:\n%s", flag->name, pre);
		}
		if (show_lines && line)
			r_cons_strcat (line);
		if (show_offset) {
			if (at == dest)
				r_cons_invert (R_TRUE, R_TRUE);
			printoffset (at, show_color);
		}
		if (show_trace) {
			RDebugTracepoint *tp = r_debug_trace_get (core->dbg, at);
			r_cons_printf ("%02x:%04x ", tp?tp->times:0, tp?tp->count:0);
		}
		if (show_stackptr) {
			r_cons_printf ("%3d%s  ", stackptr,
				analop.type==R_ANAL_OP_TYPE_CALL?">":
				stackptr>ostackptr?"+":stackptr<ostackptr?"-":" ");
			ostackptr = stackptr;
			stackptr += analop.stackptr;
			/* XXX if we reset the stackptr 'ret 0x4' has not effect.
			 * Use RAnalFcn->RAnalAop->stackptr? */
			if (analop.type == R_ANAL_OP_TYPE_RET)
				stackptr = 0;
		}
		// TODO: implement ranged meta find (if not at the begging of function..
		mi = r_meta_find (core->meta, at, R_META_ANY, R_META_WHERE_HERE);
		if (mi)
		switch (mi->type) {
		case R_META_STRING:
			// TODO: filter string (r_str_unscape)
			{
			char *out = r_str_unscape (mi->str);
			r_cons_printf ("string(%"PFMT64d"): \"%s\"\n%s", mi->size, out, pre);
			free (out);
			}
			ret = (int)mi->size;
			free (line);
			continue;
		case R_META_DATA:
			{
			int delta = at-mi->from;
				core->print->flags &= ~R_PRINT_FLAGS_HEADER;
				r_cons_printf ("hex length=%lld delta=%d\n", mi->size , delta);
				r_print_hexdump (core->print, at, buf+idx, mi->size-delta, 16, 1);
			core->inc = 16;
				core->print->flags |= R_PRINT_FLAGS_HEADER;
				ret = (int)mi->size-delta;
				free (line);
				line = NULL;
			}
			continue;
		case R_META_STRUCT:
			r_print_format (core->print, at, buf+idx, len-idx, mi->str);
			ret = (int)mi->size;
			free (line);
			line = NULL;
			continue;
		}
		if (show_bytes) {
			char *str, pad[64];
			const char *extra = " ";
			if (!flag) {
				str = strdup (asmop.buf_hex);
				if (strlen (str) > nb) {
					str[nb] = '.';
					str[nb+1] = '\0';
					extra = "";
				}
				k = nb-strlen (str);
				if (k<0) k = 0;
				for (j=0; j<k; j++)
					pad[j] = ' ';
				pad[j] = '\0';
				if (show_color) {
					char *nstr;
					p->cur_enabled = cursor!=-1;
					//p->cur = cursor;
					nstr = r_print_hexpair (p, str, idx);
					free (str);
					str = nstr;
				}
			} else {
				str = strdup (flag->name);
				k = nb-strlen (str)-2;
				if (k<0) k = 0;
				for (j=0; j<k; j++)
					pad[j] = ' ';
				pad[j] = '\0';
			}
			if (flag) {
				if (show_color)
					r_cons_printf (Color_BWHITE"*[ %s%s]  "Color_RESET, pad, str);
				else r_cons_printf ("*[ %s%s]  ", pad, str);
			} else {
				if (show_color)
					r_cons_printf (" %s %s %s"Color_RESET, pad, str, extra);
				else r_cons_printf (" %s %s %s", pad, str, extra);
			}
			free (str);
		}

		if (show_color) {
			switch (analop.type) {
			case R_ANAL_OP_TYPE_NOP:
				r_cons_printf (Color_BLUE);
				break;
			case R_ANAL_OP_TYPE_JMP:
			case R_ANAL_OP_TYPE_CJMP:
			case R_ANAL_OP_TYPE_UJMP:
				r_cons_printf (Color_GREEN);
				break;
			case R_ANAL_OP_TYPE_CMP:
				r_cons_printf (Color_BMAGENTA);
				break;
			case R_ANAL_OP_TYPE_UCALL:
			case R_ANAL_OP_TYPE_CALL:
				r_cons_printf (Color_BGREEN);
				break;
			case R_ANAL_OP_TYPE_SWI:
				r_cons_printf (Color_MAGENTA);
				break;
			case R_ANAL_OP_TYPE_RET:
				r_cons_printf (Color_RED);
				break;
			case R_ANAL_OP_TYPE_LOAD:
				r_cons_printf (Color_YELLOW);
				break;
			case R_ANAL_OP_TYPE_STORE:
				r_cons_printf (Color_BYELLOW);
				break;
			}
		}
		if (decode) {
			// TODO: Use data from code analysis..not raw analop here
			// if we want to get more information
			opstr = r_anal_aop_to_string (core->anal, &analop);
		} else
		if (pseudo) {
			r_parse_parse (core->parser, asmop.buf_asm, str);
			opstr = str;
		} else if (filter) {
			r_parse_filter (core->parser, core->flags, asmop.buf_asm, str, sizeof (str));
			opstr = str;
		} else opstr = asmop.buf_asm;
		if (varsub) {
			RAnalFcn *f = r_anal_fcn_find (core->anal, at, R_ANAL_FCN_TYPE_NULL);
			if (f) {
				r_parse_varsub (core->parser, f, opstr, strsub, sizeof (strsub));
				opstr = strsub;
			}
		}
		r_cons_strcat (opstr);
		if (decode)
			free (opstr);
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
						r_cons_printf (Color_TURQOISE"  ; %s"Color_RESET"%s", sl, pre);
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
		if (core->assembler->syntax != R_ASM_SYNTAX_INTEL) {
			RAsmAop ao; /* disassemble for the vm .. */
			int os = core->assembler->syntax;
			r_asm_set_syntax (core->assembler, R_ASM_SYNTAX_INTEL);
			ret = r_asm_disassemble (core->assembler, &ao, buf+idx, len-idx);
			r_asm_set_syntax (core->assembler, os);
		}

		if (!r_anal_cc_update (core->anal, &cc, &analop)) {
			if (show_functions) {
				char *ccstr = r_anal_cc_to_string (core->anal, &cc);
				r_cons_printf ("\n%s    ; %s", pre, ccstr);
				free (ccstr);
			}
			r_anal_cc_reset (&cc);
		}

		switch (analop.type) {
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_CALL:
			counter++;
			if (counter>9) r_cons_strcat (" [?]");
			else r_cons_printf (" [%d]", counter);
			break;
		}

		if (analop.refptr) {
			ut32 word = 0;
			int ret = r_io_read_at (core->io, analop.ref, (void *)&word, sizeof (word));
			if (ret == sizeof (word)) {
				RMetaItem *mi2 = r_meta_find (core->meta, (ut64)word,
					R_META_ANY, R_META_WHERE_HERE);
				if (!mi2) {
					mi2 = r_meta_find (core->meta, (ut64)analop.ref,
						R_META_ANY, R_META_WHERE_HERE);
					if (mi2) {
						char *str = r_str_unscape (mi2->str);
						r_cons_printf (" (at=0x%08"PFMT64x") (len=%"PFMT64d") \"%s\" ", analop.ref, mi2->size, str);
						free (str);
					} else r_cons_printf ("; => 0x%08x ", word);
				} else {
					if (mi2->type == R_META_STRING) {
						char *str = r_str_unscape (mi2->str);
						r_cons_printf (" (at=0x%08x) (len=%"PFMT64d") \"%s\" ", word, mi2->size, str);
						free (str);
					} else r_cons_printf ("unknown type '%c'\n", mi2->type);
				}
			} else r_cons_printf ("; err [0x%"PFMT64x"]", analop.ref);
		}
		r_cons_newline ();
		if (line) {
			if (show_lines && analop.type == R_ANAL_OP_TYPE_RET) {
				if (strchr (line, '>'))
					memset (line, ' ', strlen (line));
				r_cons_printf ("%s; ------------\n%s", line, pre);
			}
			free (line);
		}
	}
	free (osl);
}

static int cmd_project(void *data, const char *input) {
	RCore *core = (RCore *)data;
	const char *arg = input+1;
	char *str = strdup (r_config_get (core->config, "file.project"));
	if (*arg==' ') arg++;
	switch (input[0]) {
	case 'o': r_core_project_open (core, input[1]?arg:str); break;
	case 's': r_core_project_save (core, input[1]?arg:str); break;
	case 'i': free (r_core_project_info (core, input[1]?arg:str)); break;
	default:
		r_cons_printf (
		"Usage: P[osi] [file]\n"
		" Po [file]  open project\n"
		" Ps [file]  save project\n"
		" Pi [file]  info\n");
		break;
	}
	free (str);
	return R_TRUE;
}

static int cmd_zign(void *data, const char *input) {
	RCore *core = (RCore *)data;
	RAnalFcn *fcni;
	RListIter *iter;
	RSignItem *item;
	int i, fd, len;
	char *ptr, *name;

	switch (input[0]) {
	case 'g':
		if (input[1]==' ' && input[2]) {
			ptr = strchr (input+2, ' ');
			if (ptr) {
				*ptr = '\0';
				fd = open (ptr+1, O_RDWR|O_CREAT|O_TRUNC, 0644);
				if (fd == -1) {
					eprintf ("Cannot open %s in read-write\n", ptr+1);
					return R_FALSE;
				}
				r_cons_singleton ()->fdout = fd;
				r_cons_strcat ("# Signatures\n");
			}
			r_cons_printf ("zp %s\n", input+2);
			r_list_foreach (core->anal->fcns, iter, fcni) {
				ut8 buf[128];
				if (r_io_read_at (core->io, fcni->addr, buf, sizeof (buf)) == sizeof (buf)) {
					RFlagItem *flag = r_flag_get_i (core->flags, fcni->addr);
					if (flag) {
						name = flag->name;
						r_cons_printf ("zb %s ", name);
						len = (fcni->size>sizeof (buf))?sizeof (buf):fcni->size;
						for (i=0; i<len; i++) {
							r_cons_printf ("%02x", buf[i]);
						}
						r_cons_newline ();
					} else eprintf ("Unnamed function at 0x%08"PFMT64x"\n", fcni->addr);
				} else eprintf ("Cannot read at 0x%08"PFMT64x"\n", fcni->addr);
			}
			r_cons_strcat ("zp-\n");
			if (ptr) {
				r_cons_flush ();
				r_cons_singleton ()->fdout = 1;
				close (fd);
			}
		} else eprintf ("Usage: zg libc [libc.sig]\n");
		break;
	case 'p':
		if (!input[1])
			r_cons_printf ("%s", core->sign->prefix);
		else if (!strcmp ("-", input+1))
			r_sign_prefix (core->sign, "");
		else r_sign_prefix (core->sign, input+2);
		break;
	case 'a':
	case 'b':
	case 'h':
	case 'f':
		ptr = strchr (input+3, ' ');
		if (ptr) {
			*ptr = 0;
			r_sign_add (core->sign, core->anal, (int)*input, input+2, ptr+1);
		} else eprintf ("Usage: z%c [name] [arg]\n", *input);
		break;
	case 'c':
		item = r_sign_check (core->sign, core->block, core->blocksize);
		if (item)
			r_cons_printf ("f sign.%s @ 0x%08"PFMT64x"\n", item->name, core->offset);
		break;
	case '-':
		if (input[1] == '*')
			r_sign_reset (core->sign);
		else eprintf ("TODO\n");
		break;
	case '/':
		{
			// TODO: parse arg0 and arg1
			ut8 *buf;
			int len, idx;
			ut64 ini, fin;
			RSignItem *si;
			RIOSection *s;
			if (input[1]) {
				char *ptr = strchr (input+2, ' ');
				if (ptr) {
					*ptr = '\0';
					ini = r_num_math (core->num, input+2);
					fin = r_num_math (core->num, ptr+1);
				} else {
					ini = core->offset;
					fin = ini+r_num_math (core->num, input+2);
				}
			} else {
				s = r_io_section_get (core->io, core->io->off);
				if (s) {
					ini = core->io->va?s->vaddr:s->offset;
					fin = ini + (core->io->va?s->vsize:s->size);
				} else {
					eprintf ("No section identified, please provide range.\n");
					return R_FALSE;
				}
			}
			if (ini>=fin) {
				eprintf ("Invalid range (0x%"PFMT64x"-0x%"PFMT64x").\n", ini, fin);
				return R_FALSE;
			}
			len = fin-ini;
			buf = malloc (len);
			if (buf != NULL) {
				eprintf ("Ranges are: 0x%08"PFMT64x" 0x%08"PFMT64x"\n", ini, fin);
				r_cons_printf ("f-sign*\n");
				if (r_io_read_at (core->io, ini, buf, len) == len) {
					for (idx=0; idx<len; idx++) {
						si = r_sign_check (core->sign, buf+idx, len-idx);
						if (si) {
							if (si->type == 'f')
								r_cons_printf ("f sign.fun_%s_%d @ 0x%08"PFMT64x"\n",
									si->name, idx, ini+idx); //core->offset);
							else r_cons_printf ("f sign.%s @ 0x%08"PFMT64x"\n",
								si->name, ini+idx); //core->offset+idx);
						}
					}
				} else eprintf ("Cannot read %d bytes at 0x%08"PFMT64x"\n", len, ini);
				free (buf);
			} else eprintf ("Cannot alloc %d bytes\n", len);
		}
		break;
	case '\0':
	case '*':
		r_sign_list (core->sign, (input[0]=='*'));
		break;
	default:
	case '?':
		r_cons_printf (
			"Usage: z[abcp/*-] [arg]\n"
			" z              show status of zignatures\n"
			" z*             display all zignatures\n"
			" zp             display current prefix\n"
			" zp prefix      define prefix for following zignatures\n"
			" zp-            unset prefix\n"
			" z-prefix       unload zignatures prefixed as\n"
			" z-*            unload all zignatures\n"
			" za ...         define new zignature for analysis\n"
			" zf name fmt    define function zignature (fast/slow, args, types)\n"
			" zb name bytes  define zignature for bytes\n"
			" zh name bytes  define function header zignature\n"
			" zg pfx [file]  generate signature for current file\n"
			" .zc @ fcn.foo  flag signature if matching (.zc@@fcn)\n"
			" z/ [ini] [end] search zignatures between these regions\n"
			"NOTE: bytes can contain '.' (dots) to specify a binary mask\n");
		break;
	}
	return 0;
}

static int cmd_rap(void *data, const char *input) {
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case '\0':
		r_core_rtr_list(core);
		break;
	case '?':
		r_core_rtr_help(core);
		break;
	case '+':
		r_core_rtr_add(core, input+1);
		break;
	case '-':
		r_core_rtr_remove(core, input+1);
		break;
	case '=':
		r_core_rtr_session(core, input+1);
		break;
	case '<':
		r_core_rtr_pushout (core, input+1);
		break;
	case '!':
		r_io_system (core->io, input+1);
		break;
	default:
		r_core_rtr_cmd (core, input);
	}
#if 0
	switch (input[0]) {
	case '\0':
		r_lib_list (core->lib);
		r_io_plugin_list (core->io);
		break;
	case '?':
		eprintf ("usage: =[fd] [cmd]\n"
			"TODO: import the rest of functionality from r1\n");
		break;
	default:
		r_io_set_fd (core->io, core->file->fd);
		if (input[0]==' ')
			input++;
		r_io_system (core->io, input);
		break;
	}
#endif
	return R_TRUE;
}

static void cmd_reg(RCore *core, const char *str) {
	struct r_reg_item_t *r;
	const char *name;
	char *arg;
	int size, i, type = R_REG_TYPE_GPR;
	switch (str[0]) {
	case '?':
		if (str[1]) {
			r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE);
			r = r_reg_get (core->dbg->reg, str+1, R_REG_TYPE_GPR);
			if (r == NULL) eprintf ("Unknown register (%s)\n", str+1);
			else r_cons_printf ("0x%08"PFMT64x"\n", r_reg_get_value (core->dbg->reg, r));
		} else
		eprintf ("Usage: dr[*] [type] [size] - get/set registers\n"
			" dr?        display this help message\n"
			" dr         show registers in rows\n"
			" dr=        show registers in columns\n"
			" dr?eax     show value of eax register\n"
			" .dr*       include common register values in flags\n"
			" .dr-       unflag all registers\n"
			" drp [file] load register metadata file\n"
			" drp        display current register profile\n"
			" drb [type] display hexdump of gpr arena (WIP)\n"
			" dr         show 'gpr' registers\n"
			" drt        show all register types\n"
			" drn [pc]   get register name for pc,sp,bp,a0-3\n"
			" dro        show previous (old) values of registers\n"
			" dr all     show all registers\n"
			" dr flg 1   show flag registers ('flg' is type, see drt)\n"
			" dr 16      show 16 bit registers\n"
			" dr 32      show 32 bit registers\n"
			" dr eax=33  set register value. eax = 33\n");
		// TODO: 'drs' to swap register arenas and display old register valuez
		break;
	case 'b':
		{ // WORK IN PROGRESS // DEBUG COMMAND
		int len;
		const ut8 *buf = r_reg_get_bytes (core->dbg->reg, R_REG_TYPE_GPR, &len);
		r_print_hexdump (core->print, 0LL, buf, len, 16, 16);
		}
		break;
	case 'p':
		if (!str[1]) {
			if (core->dbg->reg_profile)
				r_cons_printf ("%s\n", core->dbg->reg_profile);
			else eprintf ("No register profile defined. Try 'dr.'\n");
		} else r_reg_set_profile (core->dbg->reg, str+2);
		core->anal->reg = core->dbg->reg;
		break;
	case 't':
		for (i=0; (name=r_reg_get_type (i));i++)
			r_cons_printf ("%s\n", name);
		break;
	case 'n':
		name = r_reg_get_name (core->dbg->reg, r_reg_get_name_idx (str+2));
		if (name && *name)
			r_cons_printf ("%s\n", name);
		else eprintf ("Oops. try dn [pc|sp|bp|a0|a1|a2|a3]\n");
		break;
	case 'd':
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, 32, 3); // XXX detect which one is current usage
		break;
	case 'o':
		r_reg_arena_swap (core->dbg->reg, R_FALSE);
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, 32, 0); // XXX detect which one is current usage
		r_reg_arena_swap (core->dbg->reg, R_FALSE);
		break;
	case '=':
		if (r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE)) {
			r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, 32, 2); // XXX detect which one is current usage
			r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, 64, 2);
		} else eprintf ("Cannot retrieve registers from pid %d\n", core->dbg->pid);
		break;
	case '*':
		if (r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE)) {
			r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, 32, 1); // XXX detect which one is current usage
			r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, 64, 1);
		} else eprintf ("Cannot retrieve registers from pid %d\n", core->dbg->pid);
		break;
	case '\0':
		if (r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE)) {
			r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, 32, 0);
			r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, 64, 0);
		} else eprintf ("Cannot retrieve registers from pid %d\n", core->dbg->pid);
		break;
	case ' ':
		arg = strchr (str+1, '=');
		if (arg) {
			*arg = 0;
			r = r_reg_get (core->dbg->reg, str+1, R_REG_TYPE_GPR);
			if (r) {
				//eprintf ("SET(%s)(%s)\n", str, arg+1);
				r_cons_printf ("0x%08"PFMT64x" ->", str,
					r_reg_get_value (core->dbg->reg, r));
				r_reg_set_value (core->dbg->reg, r,
					r_num_math (core->num, arg+1));
				r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_TRUE);
				r_cons_printf ("0x%08"PFMT64x"\n",
					r_reg_get_value (core->dbg->reg, r));
			} else eprintf ("Unknown register '%s'\n", str+1);
			return;
		}
		size = atoi (str+1);
		if (size==0) {
			arg = strchr (str+1, ' ');
			if (arg && size==0) {
				*arg='\0';
				size = atoi (arg);
			} else size = 32;
			//eprintf ("ARG(%s)\n", str+1);
			type = r_reg_type_by_name (str+1);
		}
		//printf("type = %d\nsize = %d\n", type, size);
		if (type != R_REG_TYPE_LAST) {
			r_debug_reg_sync (core->dbg, type, R_FALSE);
			r_debug_reg_list (core->dbg, type, size, str[0]=='*');
		} else eprintf ("cmd_reg: Unknown type\n");
	}
}

static void r_core_cmd_bp(RCore *core, const char *input) {
	RBreakpointItem *bp;
	int hwbp = r_config_get_i (core->config, "dbg.hwbp");
	switch (input[1]) {
	case 't':
		{
		int i = 0;
		RList *list = r_debug_frames (core->dbg);
		RListIter *iter = r_list_iterator (list);
		while (r_list_iter_next (iter)) {
			RDebugFrame *frame = r_list_iter_get (iter);
			r_cons_printf ("%d  0x%08"PFMT64x"  %d\n", i++, frame->addr, frame->size);
		}
		r_list_destroy (list);
		}
		break;
	case '\0':
		r_bp_list (core->dbg->bp, input[1]=='*');
		break;
	case '-':
		r_bp_del (core->dbg->bp, r_num_math (core->num, input+2));
		break;
	case 'c': {
			ut64 off = r_num_math (core->num, input+2);
			RBreakpointItem *bpi = r_bp_get (core->dbg->bp, off);
			if (bpi) {
				char *arg = strchr (input+2, ' ');
				if (arg) {
					free (bpi->data);
					bpi->data = strdup (arg+1);
				} else {
					free (bpi->data);
					bpi->data = NULL;
				}
			} else eprintf ("No breakpoint defined at 0x%08"PFMT64x"\n", off);
		}
		break;
	case 'e':
		r_bp_enable (core->dbg->bp, r_num_math (core->num, input+2), 1);
		break;
	case 'd':
		r_bp_enable (core->dbg->bp, r_num_math (core->num, input+2), 0);
		break;
	case 'h':
		if (input[2]==' ') {
			if (!r_bp_use (core->dbg->bp, input+3))
				eprintf ("Invalid name: '%s'.\n", input+3);
		} else r_bp_plugin_list (core->dbg->bp);
		break;
	case '?':
		r_cons_printf (
		"Usage: db[ecdht] [[-]addr] [len] [rwx] [condstring]\n"
		"db                ; list breakpoints\n"
		"db sym.main       ; add breakpoint into sym.main\n"
		"db 0x804800       ; add breakpoint\n"
		"db -0x804800      ; remove breakpoint\n"
		"dbe 0x8048000     ; enable breakpoint\n"
		"dbc 0x8048000 cmd ; run command when breakpoint is hit\n"
		"dbd 0x8048000     ; disable breakpoint\n"
		"dbh x86           ; set/list breakpoint plugin handlers\n"
		"Unrelated:\n"
		"dbt               ; debug backtrace\n");
		break;
	default:
		{
			ut64 addr = r_num_math (core->num, input+2);
			if (hwbp) bp = r_bp_add_hw (core->dbg->bp, addr, 1, R_BP_PROT_EXEC);
			else bp = r_bp_add_sw (core->dbg->bp, addr, 1, R_BP_PROT_EXEC);
			if (!bp) eprintf ("Cannot set breakpoint (%s)\n", input+2);
		}
		break;
	}
}

/* TODO: this should be moved to the core->yank api */
// TODO: arg must be const !!! use strdup here
static int cmd_yank_to(RCore *core, char *arg) {
	ut64 src = core->offset;
	ut64 len = 0;
	ut64 pos = -1;
	char *str;
	ut8 *buf;

	while (*arg==' ')
		arg = arg+1;
	str = strchr (arg, ' ');
	if (str) {
		str[0]='\0';
		len = r_num_math (core->num, arg);
		pos = r_num_math (core->num, str+1);
		str[0]=' ';
	}
	if ((str == NULL) || (pos == -1) || (len == 0)) {
		eprintf ("Usage: yt [len] [dst-addr]\n");
		return 1;
	}
#if 0
	if (!config_get("file.write")) {
		eprintf("You are not in read-write mode.\n");
		return 1;
	}
#endif
	buf = (ut8*)malloc (len);
	r_core_read_at (core, src, buf, len);
	r_core_write_at (core, pos, buf, len);
	free (buf);

	core->offset = src;
	r_core_block_read (core, 0);
	return 0;
}

static int cmd_mount(void *data, const char *_input) {
	ut64 off = 0;
	char *input, *oinput, *ptr, *ptr2;
	RList *list;
	RListIter *iter;
	RFSFile *file;
	RFSRoot *root;
	RFSPlugin *plug;
	RFSPartition *part;
	RCore *core = (RCore *)data;
	input = oinput = strdup (_input);

	switch (*input) {
	case ' ':
		input++;
		if (input[0]==' ')
			input++;
		ptr = strchr (input, ' ');
		if (ptr) {
			*ptr = 0;
			ptr++;
			ptr2 = strchr (ptr, ' ');
			if (ptr2) {
				*ptr2 = 0;
				off = r_num_math (core->num, ptr2+1);
			}
			//r_io_bind (core->io, &(core->fs->iob));
			r_fs_mount (core->fs, input, ptr, off);
		} else eprintf ("Usage: m ext2 /mnt");
		break;
	case '-':
		r_fs_umount (core->fs, input+1);
		break;
	case '*':
		eprintf ("List commands in radare format\n");
		r_list_foreach (core->fs->roots, iter, root) {
			r_cons_printf ("m %s 0x%"PFMT64x" %s\n", root->p->name, root->delta, root->path);
		}
		break;
	case '\0':
		r_list_foreach (core->fs->roots, iter, root) {
			r_cons_printf ("%s\t0x%"PFMT64x"\t%s\n", root->p->name, root->delta, root->path);
		}
		break;
	case 'l': // list of plugins
		r_list_foreach (core->fs->plugins, iter, plug) {
			r_cons_printf ("%s\t%s\n", plug->name, plug->desc);
		}
		break;
	case 'd':
		input++;
		if (input[0]==' ')
			input++;
		list = r_fs_dir (core->fs, input);
		if (list) {
			r_list_foreach (list, iter, file) {
				r_cons_printf ("%c %s\n", file->type, file->name);
			}
			r_list_free (list);
		} else eprintf ("Cannot open '%s' directory\n", input);
		break;
	case 'p':
		input++;
		if (*input == ' ')
			input++;
		ptr = strchr (input, ' ');
		if (ptr) {
			*ptr = 0;
			off = r_num_math (core->num, ptr+1);
		}
		list = r_fs_partitions (core->fs, input, off);
		if (list) {
			r_list_foreach (list, iter, part) {
				r_cons_printf ("%d %02x 0x08%"PFMT64x" 0x08%"PFMT64x"\n", part->number,
					part->type, part->start, part->start+part->length);
			}
			r_list_free (list);
		} else eprintf ("Cannot read partition\n");
		break;
	case 'o':
		input++;
		if (input[0]==' ')
			input++;
		file = r_fs_open (core->fs, input);
		if (file) {
			// XXX: dump to file or just pipe?
			r_fs_read (core->fs, file, 0, file->size);
			r_cons_printf ("f file %d 0x%08"PFMT64x"\n", file->size, file->off);
			r_fs_close (core->fs, file);
		} else eprintf ("Cannot open file\n");
		break;
	case 'g':
		input++;
		if (input[0]==' ')
			input++;
		file = r_fs_open (core->fs, input);
		if (file) {
			// XXX: dump to file or just pipe?
			r_fs_read (core->fs, file, 0, file->size);
			write (1, file->data, file->size);
			r_fs_close (core->fs, file);
			write (1, "\n", 1);
		} else eprintf ("Cannot open file\n");
		break;
	case 's':
		input++;
		if (input[0]==' ')
			input++;
		r_fs_prompt (core->fs, input);
		break;
	case 'y':
		eprintf ("TODO\n");
		break;
	case '?':
		r_cons_printf (
		"Usage: m[-?*dgy] [...]\n"
		" m              ; list all mountpoints in human readable format\n"
		" m*             ; same as above, but in r2 commands\n"
		" ml             ; list filesystem plugins\n"
		" m ext2 /mnt 0  ; mount ext2 fs at /mnt with delta 0 on IO\n"
		" m-/            ; umount given path (/)\n"
		" my             ; yank contents of file into clipboard\n"
		" mo /foo        ; get offset and size of given file\n"
		" mg /foo        ; get contents of file dumped to disk (XXX?)\n"
		" md /           ; list directory contents for path\n"
		" mp             ; list all supported partition types\n"
		" mp msdos 0     ; show partitions in msdos format at offset 0\n"
		" ms /mnt        ; open filesystem prompt at /mnt\n"
		" m?             ; show this help\n"
		"TODO: support multiple mountpoints and RFile IO's (need io+core refactor)\n"
		);
		break;
	}
	free (oinput);
	return 0;
}

static int cmd_yank(void *data, const char *input) {
	int i;
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case ' ':
		r_core_yank (core, core->offset, atoi(input+1));
		break;
	case 'y':
		r_core_yank_paste (core, r_num_math(core->num, input+2), 0);
		break;
	case 'p':
		r_cons_memcat ((const char*)core->yank, core->yank_len);
		r_cons_newline ();
		break;
	case 't':
		{ /* hacky implementation */
			char *arg = strdup(input+1);
			cmd_yank_to(core, arg);
			free(arg);
		}
		break;
	case '\0':
		if (core->yank) {
			r_cons_printf ("0x%08"PFMT64x" %d ",
				core->yank_off, core->yank_len);
			for (i=0; i<core->yank_len; i++)
				r_cons_printf ("%02x", core->yank[i]);
			r_cons_newline ();
		} else eprintf ("No buffer yanked already\n");
		break;
	default:
		r_cons_printf (
		"Usage: y[y] [len] [[@]addr]\n"
		" y            ; show yank buffer information (srcoff len bytes)\n"
		" y 16         ; copy 16 bytes into clipboard\n"
		" y 16 0x200   ; copy 16 bytes into clipboard from 0x200\n"
		" y 16 @ 0x200 ; copy 16 bytes into clipboard from 0x200\n"
		" yp           ; print contents of clipboard\n"
		" yt 0x200     ; paste clipboard to 0x200\n"
		" yy 0x3344    ; paste clipboard\n");
		break;
	}
	return R_TRUE;
}

static int cmd_quit(void *data, const char *input) {
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case '?':
		r_cons_printf (
		"Usage: q[!] [retvalue]\n"
		" q     ; quit program\n"
		" q!    ; force quit (no questions)\n"
		" q 1   ; quit with return value 1\n"
		" q a-b ; quit with return value a-b\n");
		break;
	case ' ':
	case '!':
		input++;
	case '\0':
		// TODO
	default:
		r_line_hist_save (".radare2_history");
		if (*input)
			r_num_math (core->num, input);
		else core->num->value = 0LL;
		//exit (*input?r_num_math (core->num, input+1):0);
		return -2;
	}
	return R_FALSE;
}

static int cmd_interpret(void *data, const char *input) {
	char *str, *ptr, *eol;
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case '\0':
		/* repeat last command */
		/* NOTE: Plugind in r_core_cmd with ugly strcmp */
		break;
	case ' ':
		if (!r_core_cmd_file (core, input+1))
			eprintf ("Cannot interpret file.\n");
		break;
	case '!':
		/* from command */
		r_core_cmd_command (core, input+1);
		break;
	case '(':
		//eprintf ("macro call (%s)\n", input+1);
		r_cmd_macro_call (&core->cmd->macro, input+1);
		break;
	case '?':
		r_cons_printf (
		"Usage: . [file] | [!command] | [(macro)]\n"
		" . foo.rs          ; interpret r script\n"
		" .!rabin -ri $FILE ; interpret output of command\n"
		" .(foo 1 2 3)      ; run macro 'foo' with args 1, 2, 3\n"
		" ./m ELF           ; interpret output of command /m ELF as r. commands\n");
		break;
	default:
		ptr = str = r_core_cmd_str (core, input);
		for (;;) {
			eol = strchr (ptr, '\n');
			if (eol) eol[0]='\0';
			r_core_cmd (core, ptr, 0);
			if (!eol) break;
			ptr = eol+1;
		}
		free (str);
		break;
	}
	return 0;
}

static int cmd_section(void *data, const char *input) {
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case '?':
		r_cons_printf (
		" S                ; list sections\n"
		" S*               ; list sections (in radare commands)\n"
		" S=               ; list sections (in nice ascii-art bars)\n"
		" S [offset] [vaddr] [size] [vsize] [name] [rwx] ; adds new section\n"
		" S -[offset]      ; remove this section definition\n");
		break;
	case ' ':
		switch (input[1]) {
		case '-': // remove
			if (input[2]=='?' || input[2]=='\0')
				eprintf ("Usage: S -N   # where N is the section index\n");
			else r_io_section_rm (core->io, atoi (input+1));
			break;
		default:
			{
			int i, rwx = 7;
			char *ptr = strdup(input+1);
			const char *name = NULL;
			ut64 vaddr = 0LL;
			ut64 offset = 0LL;
			ut64 size = 0LL;
			ut64 vsize = 0LL;

			i = r_str_word_set0 (ptr);
			switch (i) {
			case 6: // get rwx
				rwx = r_str_rwx (r_str_word_get0 (ptr, 5));
			case 5: // get name
				name = r_str_word_get0 (ptr, 4);
			case 4: // get vsize
				vsize = r_num_math (core->num, r_str_word_get0 (ptr, 3));
			case 3: // get size
				size = r_num_math (core->num, r_str_word_get0 (ptr, 2));
			case 2: // get vaddr
				vaddr = r_num_math (core->num, r_str_word_get0 (ptr, 1));
			case 1: // get offset
				offset = r_num_math (core->num, r_str_word_get0 (ptr, 0));
			}
			r_io_section_add (core->io, offset, vaddr, size, vsize, rwx, name);
			free (ptr);
			}
			break;
		}
		break;
	case '=':
		r_io_section_list_visual (core->io, core->offset, core->blocksize);
		break;
	case '\0':
		r_io_section_list (core->io, core->offset, 0);
		break;
	case '*':
		r_io_section_list (core->io, core->offset, 1);
		break;
	}
	return 0;
}

static int cmd_seek(void *data, const char *input) {
	RCore *core = (RCore *)data;
	char *cmd, *p;
	ut64 off;

	if (input[0]=='r') {
		if (input[1] && input[2]) {
			off = r_debug_reg_get (core->dbg, input+2);
			r_core_seek (core, off, 1);
			r_io_sundo_push (core->io);
		} else eprintf ("Usage: 'sr pc' ; seek to register\n");
	} else
	if (input[0]) { // && input[1]) {
		st32 delta = (input[1]==' ')?2:1;
		off = r_num_math (core->num, input + delta);
		if (input[0]==' ' && (input[1]=='+'||input[1]=='-'))
			input = input+1;
		switch (input[0]) {
		case ' ':
			r_core_seek (core, off, 1);
			r_io_sundo_push (core->io);
			break;
		case '*':
			r_io_sundo_list (core->io);
			break;
		case '+':
			if (input[1]!='\0') {
				if (input[1]=='+') delta = core->blocksize; else delta = off;
				r_core_seek_delta (core, delta);
			} else if (r_io_sundo_redo (core->io))
				r_core_seek (core, core->io->off, 0);
			break;
		case '-':
			if (input[1]!='\0') {
				if (input[1]=='-') delta = -core->blocksize; else delta = -off;
				r_core_seek_delta (core, delta);
			} else if (r_io_sundo (core->io))
				r_core_seek (core, core->io->off, 0);
			break;
		case 'a':
			off = core->blocksize;
			if (input[1]&&input[2]) {
				cmd = strdup (input);
				p = strchr (cmd+2, ' ');
				if (p) {
					off = r_num_math (core->num, p+1);;
					*p = '\0';
				}
				cmd[0] = 's';
				// perform real seek if provided
				r_cmd_call (core->cmd, cmd);
				free (cmd);
			}
			r_core_seek_align (core, off, 0);
			break;
		case 'b':
			r_core_anal_bb_seek (core, off);
			break;
		case '?':
			r_cons_printf (
			"Usage: s[+-] [addr]\n"
			" s 0x320    ; seek to this address\n"
			" s-         ; undo seek\n"
			" s+         ; redo seek\n"
			" s*         ; list undo seek history\n"
			" s++        ; seek blocksize bytes forward\n"
			" s--        ; seek blocksize bytes backward\n"
			" s+ 512     ; seek 512 bytes forward\n"
			" s- 512     ; seek 512 bytes backward\n"
			" sa [[+-]a] [asz] ; seek asz (or bsize) aligned to addr\n"
			" sb         ; seek aligned to bb start\n"
			" sr pc      ; seek to register\n");
			break;
		}
	} else r_cons_printf ("0x%"PFMT64x"\n", core->offset);
	return 0;
}

static int cmd_help(void *data, const char *input) {
	RCore *core = (RCore *)data;
	char out[65];
	ut64 n;
	switch (input[0]) {
	case 'b':
		{
		n = r_num_get (core->num, input+1);
		r_num_to_bits (out, n);
		r_cons_printf ("%s\n", out);
		}
		break;
	case 'f':
		if (input[1]==' ') {
			char *q, *p = strdup (input+2);
			if (!p) {
				eprintf ("Cannot strdup\n");
				return 0;
			}
			q = strchr (p, ' ');
			if (q) {
				*q = 0;
				n = r_num_get (core->num, p);
				r_str_bits (out, (const ut8*)&n, sizeof (n), q+1);
				r_cons_printf ("%s\n", out);
			} else eprintf ("Usage: \"?b value bitstring\"\n");
			free (p);
		} else eprintf ("Whitespace expected after '?b'\n");
		break;
	case ' ':
		n = r_num_math (core->num, input+1);
		r_cons_printf ("%"PFMT64d" 0x%"PFMT64x"\n", n,n);
		break;
	case '=':
		r_num_math (core->num, input+1);
		break;
	case '+':
		if (input[1]) {
			if (core->num->value & UT64_GT0)
				r_core_cmd (core, input+1, 0);
		} else r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		break;
	case '-':
		if (input[1]) {
			if (core->num->value & UT64_LT0)
				r_core_cmd (core, input+1, 0);
		} else r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		break;
	case '!': // ??
		if (input[1]) {
			if (core->num->value != UT64_MIN)
				r_core_cmd (core, input+1, 0);
		} else r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		break;
	case '$':
		return cmd_help (data, " $?");
	case 'V':
		r_cons_printf ("r2-%s\n", R2_VERSION);
		break;
	case 'z':
		for (input=input+1; input[0]==' '; input=input+1);
		core->num->value = strlen (input);
		break;
	case 't': {
		struct r_prof_t prof;
		r_prof_start (&prof);
		r_core_cmd (core, input+1, 0);
		r_prof_end (&prof);
		core->num->value = (ut64)prof.result;
		eprintf ("%lf\n", prof.result);
		} break;
	case '?': // ???
		if (input[1]=='?') {
			r_cons_printf (
			"Usage: ?[?[?]] expression\n"
			" ? eip-0x804800  ; calculate result for this math expr\n"
			" ?= eip-0x804800 ; same as above without user feedback\n"
			" ?? [cmd]        ; ? == 0  run command when math matches\n"
			" ?b [num]        ; show binary value of number\n"
			" ?f [num] [str]  ; map each bit of the number as flag string index\n"
			" ?z str          ; returns the length of string (0 if null)\n"
			" ?t cmd          ; returns the time to run a command\n"
			" ?! [cmd]        ; ? != 0\n"
			" ?+ [cmd]        ; ? > 0\n"
			" ?- [cmd]        ; ? < 0\n"
			" ???             ; show this help\n"
			"$variables:\n"
			" $$  = here (current seek)\n"
			" $s  = file size\n"
			" $b  = block size\n"
			" $j  = jump address\n"
			" $f  = address of next opcode\n"
			" $r  = opcode reference pointer\n"
			" $e  = 1 if end of block, else 0\n"
			" ${eval} = get value of eval variable\n"
			" $?  = last comparision value\n");
			return 0;
		} else
		if (input[1]) {
			if (core->num->value == UT64_MIN)
				r_core_cmd (core, input+1, 0);
		} else r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		break;
	case '\0':
	default:
		r_cons_printf (
		" a                 ; perform analysis of code\n"
		" b [bsz]           ; get or change block size\n"
		" c[dqxXfg] [arg]   ; compare block with given data\n"
		" C[Cf..]           ; Code metadata management\n"
		" d[hrscb]          ; debugger commands\n"
		" e [a[=b]]         ; list/get/set config evaluable vars\n"
		" f [name][sz][at]  ; set flag at current address\n"
		" s [addr]          ; seek to address\n"
		" S?[size] [vaddr]  ; IO section manipulation information\n"
		" i [file]          ; get info about opened file\n"
		" o [file] (addr)   ; open file at optional address\n"
		" p?[len]           ; print current block with format and length\n"
		" V[vcmds]          ; enter visual mode (vcmds=visualvisual  keystrokes)\n"
		" w[mode] [arg]     ; multiple write operations\n"
		" x [len]           ; alias for 'px' (print hexadecimal)\n"
		" y [len] [off]     ; yank/paste bytes from/to memory\n"
		" r[+- ][len]       ; resize file\n"
		" ? [expr]          ; help or evaluate math expression\n"
		" /[xmp/]           ; search for bytes, regexps, patterns, ..\n"
		" ![cmd]            ; run given command as in system(3)\n"
		" = [cmd]           ; run this command via rap://\n"
		" #[algo] [len]     ; calculate hash checksum of current block\n"
		" .[ file|!cmd|cmd|(macro)]  ; interpret as radare cmds\n"
		" :command          ; list or execute a plugin command\n"
		" (macro arg0 arg1) ; define scripting macros\n"
		" q [ret]           ; quit program with a return value\n"
		"Use '?""?""?' evaluation, special vars and scripting facilities\n"
		"Append '?' to any char command to get detailed help\n"
		"Suffix '@ addr[:bsize]' for a temporary seek and/or bsize\n"
		"Suffix '~string:linenumber[column]' to filter output\n"
		);
		break;
	}
	return 0;
}

static int cmd_bsize(void *data, const char *input) {
	RFlagItem *flag;
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case 'f':
		if (input[1]==' ') {
			flag = r_flag_get (core->flags, input+2);
			if (flag)
				r_core_block_size (core, flag->size);
			else eprintf ("bf: Cannot find flag named '%s'\n", input+2);
		} else eprintf ("Usage: bf [flagname]\n");
		break;
	case '\0':
		r_cons_printf ("0x%x\n", core->blocksize);
		break;
	case '?':
		r_cons_printf ("Usage: b[f] [arg]\n"
			" b        # display current block size\n"
			" b 33     # set block size to 33\n"
			" b eip+4  # numeric argument can be an expression\n"
			" bf foo   # set block size to flag size\n");
		break;
	default:
		//input = r_str_clean(input);
		r_core_block_size (core, r_num_math (core->num, input));
		break;
	}
	return 0;
}

// move it out // r_diff maybe?
static int radare_compare(RCore *core, const ut8 *f, const ut8 *d, int len) {
	int i, eq = 0;
	for (i=0;i<len;i++) {
		if (f[i]==d[i]) {
			eq++;
			continue;
		}
		r_cons_printf ("0x%08"PFMT64x" (byte=%.2d)   %02x '%c'  ->  %02x '%c'\n",
			core->offset+i, i+1,
			f[i], (IS_PRINTABLE(f[i]))?f[i]:' ',
			d[i], (IS_PRINTABLE(d[i]))?d[i]:' ');
	}
	eprintf ("Compare %d/%d equal bytes\n", eq, len);
	return len-eq;
}

static int cmd_cmp(void *data, const char *input) {
	RCore *core = data;
	FILE *fd;
	ut8 *buf;
	int ret;
	ut32 v32;
	ut64 v64;

	switch (*input) {
	case ' ':
		radare_compare (core, core->block, (ut8*)input+1, strlen (input+1)+1);
		break;
	case 'x':
		if (input[1]!=' ') {
			eprintf ("Usage: cx 001122'\n");
			return 0;
		}
		buf = (ut8*)malloc (strlen (input+2));
		ret = r_hex_str2bin (input+2, buf);
		if (ret<1) eprintf ("Cannot parse hexpair\n");
		else radare_compare (core, core->block, buf, ret);
		free (buf);
		break;
	case 'X':
		buf = malloc (core->blocksize);
		ret = r_io_read_at (core->io, r_num_math (core->num, input+1), buf, core->blocksize);
		radare_compare (core, core->block, buf, ret);
		free (buf);
		break;
	case 'f':
		if (input[1]!=' ') {
			eprintf ("Please. use 'cf [file]'\n");
			return 0;
		}
		fd = fopen (input+2, "rb");
		if (fd == NULL) {
			eprintf ("Cannot open file '%s'\n", input+2);
			return 0;
		}
		buf = (ut8 *)malloc (core->blocksize);
		fread (buf, 1, core->blocksize, fd);
		fclose (fd);
		radare_compare (core, core->block, buf, core->blocksize);
		free (buf);
		break;
	case 'q':
		v64 = (ut64) r_num_math (core->num, input+1);
		radare_compare (core, core->block, (ut8*)&v64, sizeof (v64));
		break;
	case 'd':
		v32 = (ut32) r_num_math (core->num, input+1);
		radare_compare (core, core->block, (ut8*)&v32, sizeof (v32));
		break;
#if 0
	case 'c':
		radare_compare_code (
			r_num_math (core->num, input+1),
			core->block, core->blocksize);
		break;
	case 'D':
		{ // XXX ugly hack
		char cmd[1024];
		sprintf (cmd, "radiff -b %s %s", ".curblock", input+2);
		r_file_dump (".curblock", config.block, config.block_size);
		radare_system(cmd);
		unlink(".curblock");
		}
		break;
#endif
	case 'g':
		{
		RCore *core2;
		char *file2 = (char*)r_str_chop_ro (input+1);

		if (!(core2 = r_core_new ())) {
			eprintf ("Cannot init diff core\n");
			return R_FALSE;
		}
		core2->io->va = core->io->va;
		core2->anal->split = core->anal->split;
		if (!r_core_file_open (core2, file2, 0, 0LL)) {
			eprintf ("Cannot open diff file '%s'\n", file2);
			r_core_free (core2);
			return R_FALSE;
		}
		r_core_bin_load (core2, file2);
		r_core_gdiff (core, core2);
		r_core_free (core2);
		}
		break;
	case '?':
		r_cons_strcat (
		"Usage: c[?cdfx] [argument]\n"
		" c  [string]   Compares a plain with escaped chars string\n"
		//" cc [offset]   Code bindiff current block against offset\n"
		" cd [value]    Compare a doubleword from a math expression\n"
		//" cD [file]     Like above, but using radiff -b\n");
		" cq [value]    Compare a quadword from a math expression\n"
		" cx [hexpair]  Compare hexpair string\n"
		" cX [addr]     Like 'cc' but using hexdiff output\n"
		" cf [file]     Compare contents of file at current seek\n"
		" cg [file]     Graphdiff current file and [file]\n");
		break;
	default:
		eprintf ("Usage: c[?Ddxf] [argument]\n");
	}

	return 0;
}

static int cmd_info(void *data, const char *input) {
	RCore *core = (RCore *)data;
	char buf[1024];
	switch (*input) {
	case 's':
	case 'i':
	case 'I':
	case 'e':
	case 'S':
	case 'z':
		snprintf (buf, sizeof (buf), "rabin2 -%c%s%s '%s'", input[0],
			input[1]=='*'?"r":"", core->io->va?"v":"", core->file->filename);
		r_sys_cmd (buf);
		break;
	case '?':
		r_cons_printf (
		"Usage: i[eiIsSz]*      ; get info from opened file (rabin2)\n"
		"; Append a '*' to get the output in radare commands\n"
		" ii    ; imports\n"
		" iI    ; binary info\n"
		" ie    ; entrypoint\n"
		" is    ; symbols\n"
		" iS    ; sections\n"
		" iz    ; strings\n");
		break;
	case '*':
		break;
	default:
		if (core->file) {
			r_cons_printf ("uri: %s\n", core->file->uri);
			r_cons_printf ("fd: %d\n", core->file->fd->fd);
			r_cons_printf ("filesize: 0x%x\n", core->file->size);
			r_cons_printf ("blocksize: 0x%x\n", core->blocksize);
		} else eprintf ("No selected file\n");
	}
	return 0;
}

static void do_magic_here(RCore *core, const char *file) {
#if HAVE_LIB_MAGIC
	magic_t ck;
	if (*file == ' ') file++;
	if (!*file) file = NULL;
	ck = magic_open (0);
	magic_load (ck, file);
	r_cons_printf ("%s\n", magic_buffer (ck, core->block, core->blocksize));
	magic_close (ck);
#else
	eprintf ("Compiled without magic :(\n");
#endif
}

static int cmd_print(void *data, const char *input) {
	RCore *core = (RCore *)data;
	int i, l, len = core->blocksize;
	ut32 tbs = core->blocksize;

	/* TODO: Change also blocksize for 'pd'.. */
	if (input[0] && input[1]) {
		l = (int) r_num_math (core->num, input+2);
		/* except disasm and memoryfmt (pd, pm) */
		if (input[0] != 'd' && input[0] != 'm') {
			if (l>0) len = l;
			if (l>tbs) r_core_block_size (core, l);
			l = len;
		}
	} else l = len;

	switch (input[0]) {
	case '%':
		{
			ut64 off = core->offset;
			ut64 s = core->file?core->file->size:0;
			ut64 piece = 0;
			int w = core->print->cols * 4;
			piece = s/w;
			r_cons_strcat ("  [");
			for (i=0; i<w; i++) {
				ut64 from = (piece*i);
				ut64 to = from+piece;
				if (off>=from && off<to)
					r_cons_memcat ("#", 1);
				else r_cons_memcat (".", 1);
				// TODO: print where flags are.. code, ..
			}
			r_cons_strcat ("]\n");
		}
		break;
	case '=':
		for (i=0; i<core->blocksize; i++) {
			int pc = (core->block[i]*100)/255;
			r_print_addr (core->print, core->offset+i);
			r_cons_printf ("%02x", core->block[i]);
			r_print_progressbar (core->print, pc, 70);
			r_cons_newline ();
		}
		break;
	case 'b':
		{
		char *buf;
		int size = core->blocksize * 8;
		buf = malloc (size);
		if (buf) {
			r_str_bits (buf, core->block, size, NULL);
			r_cons_printf ("%s\n", buf);
			free (buf);
		} else eprintf ("ERROR: Cannot malloc %d bytes\n", size);
		}
		break;
	case 'D':
	case 'd':
		if (input[1]=='f') {
			RAnalFcn *f = r_anal_fcn_find (core->anal, core->offset,
					R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
			if (f) {
				ut8 *block = malloc (f->size+1);
				if (block) {
					r_core_read_at (core, f->addr, block, f->size);
					r_print_disasm (core->print, core, f->addr, block, f->size, 9999);
					free (block);
				}
			} else eprintf ("Cannot find function at 0x%08"PFMT64x"\n", core->offset);
		} if (l<0) {
			RList *bwdhits;
			RListIter *iter;
			RCoreAsmHit *hit;
			ut8 *block = malloc (core->blocksize);
			if (block) {
				l = -l;
				bwdhits = r_core_asm_bwdisassemble (core, core->offset, l, core->blocksize);
				if (bwdhits) {
					r_list_foreach (bwdhits, iter, hit) {
						r_core_read_at (core, hit->addr, block, core->blocksize);
						r_print_disasm (core->print, core, hit->addr, block, core->blocksize, l);
						r_cons_printf ("------\n");
					}
					r_list_free (bwdhits);
				}
				free (block);
			}
		} else r_print_disasm (core->print, core, core->offset, core->block, len, l);
		break;
	case 's':
		if (input[1]=='p') {
			int mylen = core->block[0];
			// TODO: add support for 2-4 byte length pascal strings
			r_print_string (core->print, core->offset, core->block+1, mylen, 0, 1, 0); //, 78, 1);
		} else r_print_string (core->print, core->offset, core->block, len, 0, 1, 0); //, 78, 1);
		break;
	case 'S':
		r_print_string (core->print, core->offset, core->block, len, 1, 1, 0); //, 78, 1);
		break;
	case 'm':
		do_magic_here (core, input+1);
		break;
	case 'u':
		r_print_string (core->print, core->offset, core->block, len, 0, 1, 1); //, 78, 1);
		break;
	case 'U':
		r_print_string (core->print, core->offset, core->block, len, 1, 1, 1); //, 78, 1);
		break;
	case 'c':
		r_print_code (core->print, core->offset, core->block, len); //, 78, 1);
		break;
	case 'r':
		r_print_raw (core->print, core->block, len);
		break;
	case 'o':
		r_print_hexdump (core->print, core->offset, core->block, len, 8, 1); //, 78, !(input[1]=='-'));
		break;
	case 'x':
		r_print_hexdump (core->print, core->offset, core->block, len, 16, 1); //, 78, !(input[1]=='-'));
		break;
	case '6':
		{
		int malen = (core->blocksize*4)+1;
		ut8 *buf = malloc (malen);
		memset (buf, 0, malen);
		switch (input[1]) {
		case 'e':
			r_base64_encode (buf, core->block, core->blocksize);
			printf ("%s\n", buf);
			break;
		case 'd':
			if (r_base64_decode (buf, core->block, core->blocksize))
				printf ("%s\n", buf);
			else eprintf ("r_base64_decode: invalid stream\n");
			break;
		default:
			eprintf ("Usage: p6[ed] [len]  ; base 64 encode/decode\n");
			break;
		}
		free (buf);
		}
		break;
	case '8':
		r_print_bytes (core->print, core->block, len, "%02x");
		break;
	case 'f':
		r_print_format (core->print, core->offset, core->block, len, input+1);
		break;
	case 'n': // easter penis
		for (l=0; l<10; l++) {
			printf ("\r8");
			for (len=0;len<l;len++)
				printf ("=");
			printf ("D");
			r_sys_usleep (100000);
			fflush (stdout);
		}
		for (l=0; l<3; l++) {
			printf ("~");
			fflush (stdout);
			r_sys_usleep (100000);
		}
		printf ("\n");
		break;
	case 't':
		switch (input[1]) {
			case ' ':
			case '\0':
				for (l=0; l<len; l+=sizeof (time_t))
					r_print_date_unix (core->print, core->block+l, sizeof (time_t));
				break;
			case 'd':
				for (l=0; l<len; l+=4)
					r_print_date_dos (core->print, core->block+l, 4);
				break;
			case 'n':
				for (l=0; l<len; l+=sizeof (ut64))
					r_print_date_w32 (core->print, core->block+l, sizeof (ut64));
				break;
		case '?':
			r_cons_printf (
			"Usage: pt[dn?]\n"
			" pt      print unix time\n"
			" ptd     print dos time\n"
			" ptn     print ntfs time\n"
			" pt?     show help message\n");
			break;
		}
		break;
	case 'Z':
		{
			const char *mode = r_config_get (core->config, "zoom.byte");
			ut64 from = r_config_get_i (core->config, "zoom.from");
			ut64 to = r_config_get_i (core->config, "zoom.to");
			if (mode) r_print_zoom (core->print, core, printzoomcallback,
				from, to, *mode, core->blocksize);
			else eprintf ("No zoom.byte defined\n");
		}
		break;
	default:
		r_cons_printf (
		"Usage: p[fmt] [len]\n"
		" p= [len]     print byte percentage bars\n"
		" p6[de] [len] base64 decode/encode\n"
		" p8 [len]     8bit hexpair list of bytes\n"
		" pb [len]     bitstream of N bytes\n"
		" pd [len]     disassemble N opcodes\n"
		" pD [len]     disassemble N bytes\n"
		" po [len]     octal dump of N bytes\n"
		" pc [len]     output C format\n"
		" pf [fmt]     print formatted data\n"
		" pm [magic]   print libmagic data\n"
		" ps [len]     print string\n"
		" psp          print pascal string\n"
		" pS [len]     print wide string\n"
		" pt [len]     print diferent timestamps\n"
		" pr [len]     print N raw bytes\n"
		" pu [len]     print N url encoded bytes\n"
		" pU [len]     print N wide url encoded bytes\n",
		" px [len]     hexdump of N bytes\n"
		" pZ [len]     print zoom view\n");
		break;
	}
	if (tbs != core->blocksize)
		r_core_block_size (core, tbs);
	return 0;
}

static int cmd_hexdump(void *data, const char *input) {
	return cmd_print (data, input-1);
}

static int cmd_flag(void *data, const char *input) {
	RCore *core = (RCore *)data;
	int len = strlen (input)+1;
	char *str = alloca (len);
	ut64 off = core->offset;
	memcpy (str, input+1, len);

	switch (input[0]) {
	case '+':
		r_flag_set (core->flags, str, off, core->blocksize, 1);
		break;
	case ' ': {
		char *s = NULL, *s2 = NULL;
		ut32 bsze = core->blocksize;
		s = strchr (str, ' ');
		if (s) {
			*s = '\0';
			s2 = strchr (s+1, ' ');
			if (s2) {
				*s2 = '\0';
				if (s2[1]&&s2[2])
					off = r_num_math (core->num, s2+1);
			}
			bsze = r_num_math (core->num, s+1);
		}
		r_flag_set (core->flags, str, off, bsze, 0);
		if (s) *s=' ';
		if (s2) *s2=' ';
		}
		break;
	case '-':
		if (input[1]) r_flag_unset (core->flags, input+1);
		else r_flag_unset_i (core->flags, off);
		break;
	case 'S':
		r_flag_sort (core->flags, (input[1]=='n'));
		break;
	case 's':
		if (input[1]==' ') r_flag_space_set (core->flags, input+2);
		else r_flag_space_list (core->flags);
		break;
	case 'o':
		{
			char *file = PREFIX"/share/doc/radare2/fortunes";
			char *line = r_file_slurp_random_line (file);
			if (line) {
				r_cons_printf (" -- %s\n", line);
				free (line);
			}
		}
		break;
	case 'r':
		{
			char *old, *new;
			RFlagItem *item;
			old = str+1;
			new = strchr (old, ' ');
			if (new) {
				*new = 0;
				new++;
				item = r_flag_get (core->flags, old);
			} else {
				new = old;
				item = r_flag_get_i (core->flags, core->offset);
			}
			if (item) r_flag_item_rename (item, new);
			else eprintf ("Cannot find flag\n");
		}
		break;
	case '*':
		r_flag_list (core->flags, 1);
		break;
	case '\0':
		r_flag_list (core->flags, 0);
		break;
	case '?':
		r_cons_printf (
		"Usage: f[?] [flagname]\n"
		" f name 12 @ 33   ; set flag 'name' with size 12 at 33\n"
		" f name 12 33     ; same as above\n"
		" f+name 12 @ 33   ; like above but creates new one if doesnt exist\n"
		" f-name           ; remove flag 'name'\n"
		" f-@addr          ; remove flag at address expression\n"
		" f                ; list flags\n"
		" f*               ; list flags in r commands\n"
		" fr [old] [new]   ; rename flag\n"
		" fs functions     ; set flagspace\n"
		" fs *             ; set no flagspace\n"
		" fs               ; display flagspaces\n"
		" fS[on]           ; sort flags by offset or name\n");
		break;
	}
	return 0;
}

static void cmd_syscall_do(RCore *core, int num) {
	int i;
	char str[64];
	RSyscallItem *item = r_syscall_get (core->anal->syscall, num, -1);
	if (item == NULL) {
		r_cons_printf ("%d = unknown ()", num);
		return;
	}
	r_cons_printf ("%d = %s (", item->num, item->name);
	// TODO: move this to r_syscall
	for (i=0; i<item->args; i++) {
		ut64 arg = r_debug_arg_get (core->dbg, R_TRUE, i+1);
		if (item->sargs==NULL)
			r_cons_printf ("0x%08"PFMT64x"", arg);
		else
		switch (item->sargs[i]) {
		case 'p': // pointer
			r_cons_printf ("0x%08"PFMT64x"", arg);
			break;
		case 'i':
			r_cons_printf ("%"PFMT64d"", arg);
			break;
		case 'z':
			r_io_read_at (core->io, arg, (ut8*)str, sizeof (str));
			// TODO: filter zero terminated string
			str[63] = '\0';
			r_str_filter (str, strlen (str));
			r_cons_printf ("\"%s\"", str);
			break;
		default:
			r_cons_printf ("0x%08"PFMT64x"", arg);
			break;
		}
		if (i+1<item->args)
			r_cons_printf (", ");
	}
	r_cons_printf (")\n");
}


#if 1
/* TODO: Move into cmd_anal() */
static void var_help() {
	eprintf("Try afv?\n");
	eprintf(" afv 12 int buffer[3]\n");
	eprintf(" afv 12 byte buffer[1024]\n");
	eprintf("Try af[aAv][gs] [delta] [[addr]]\n");
	eprintf(" afag 0  = arg0 get\n");
	eprintf(" afvs 12 = var12 set\n");
	eprintf("a = arg, A = fastarg, v = var\n");
	eprintf("TODO: [[addr]] is not yet implemented. use @\n");
}

static int var_cmd(RCore *core, const char *str) {
	RAnalFcn *fcn = r_anal_fcn_find (core->anal, core->offset,
			R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
	char *p,*p2,*p3;
	int type, delta, len = strlen(str)+1;

	p = alloca(len);
	memcpy(p, str, len);
	str = p;

	switch(*str) {
	case 'V': // show vars in human readable format
		r_anal_var_list_show(core->anal, fcn, core->offset);
		return 0;
	case '?':
		var_help();
		return 0;
	case 'v': // frame variable
	case 'a': // stack arg
	case 'A': // fastcall arg
		// XXX nested dup
		switch (*str) {
		case 'v': type = R_ANAL_VAR_TYPE_LOCAL|R_ANAL_VAR_DIR_NONE; break;
		case 'a': type = R_ANAL_VAR_TYPE_ARG|R_ANAL_VAR_DIR_IN; break;
		case 'A': type = R_ANAL_VAR_TYPE_ARGREG|R_ANAL_VAR_DIR_IN; break;
		default:
			eprintf ("Unknown type\n");
			return 0;
		}

		/* Variable access CFvs = set fun var */
		switch(str[1]) {
		case '\0': r_anal_var_list (core->anal, fcn, 0, 0); return 0;
		case '?': var_help(); return 0;
		case '.':  r_anal_var_list (core->anal, fcn, core->offset, 0); return 0;
		case 's':
		case 'g':
			if (str[2]!='\0') {
				RAnalVar *var = r_anal_var_get (core->anal, fcn, atoi (str+2), R_ANAL_VAR_TYPE_LOCAL);
				return r_anal_var_access_add (core->anal, var, atoi (str+2), (str[1]=='g')?0:1);
			}
			break;
		}
		str++;
		if (str[0]==' ') str++;
		delta = atoi (str);
		p = strchr (str, ' ');
		if (p==NULL) {
			var_help();
			return 0;
		}
		p[0]='\0'; p++;
		p2 = strchr (p, ' ');
		if (p2) {
			p2[0]='\0'; p2 = p2+1;
			p3 = strchr (p2,'[');
			if (p3 != NULL) {
				p3[0]='\0';
				p3=p3+1;
			}
			r_anal_var_add (core->anal, fcn, core->offset, delta, type, p, p2, p3?atoi(p3):0);
		} else var_help();
		break;
	default:
		var_help();
		break;
	}
	return 0;
}
#endif

static int cmd_anal(void *data, const char *input) {
	const char *ptr;
	RCore *core = (RCore *)data;
	int l, len = core->blocksize;
	ut64 addr = core->offset;
	ut32 tbs = core->blocksize;

	if (input[0] && input[1]) {
		l = (int) r_num_get (core->num, input+2);
		if (l>0) len = l;
		if (l>tbs) {
			r_core_block_size (core, l);
			len = l;
		}
	}

	switch (input[0]) {
	case 'o':
		if (input[1] == '?') {
			r_cons_printf (
			"Usage: ao[e?] [len]\n"
			" aoe      ; emulate opcode at current offset\n"
			" aoe 4    ; emulate 4 opcodes starting at current offset\n"
			" ao 5     ; display opcode analysis of 5 opcodes\n");
		} else
		if (input[1] == 'e') {
			eprintf ("TODO: r_anal_aop_execute\n");
		} else {
			int ret, idx;
			ut8 *buf = core->block;
			RAnalOp aop;

			for (idx=ret=0; idx<len; idx+=ret) {
				ret = r_anal_aop (core->anal, &aop,
					core->offset+idx, buf + idx, (len-idx));
				if (ret<1) {
					eprintf ("Oops at 0x%08"PFMT64x"\n", core->offset+idx);
					break;
				}
				r_cons_printf ("addr: 0x%08"PFMT64x"\n", core->offset+idx);
				r_cons_printf ("size: %d\n", aop.length);
				r_cons_printf ("type: %d\n", aop.type); // TODO: string
				r_cons_printf ("eob: %d\n", aop.eob);
				r_cons_printf ("jump: 0x%08"PFMT64x"\n", aop.jump);
				r_cons_printf ("fail: 0x%08"PFMT64x"\n", aop.fail);
				r_cons_printf ("stack: %d\n", aop.stackop); // TODO: string
				r_cons_printf ("cond: %d\n", aop.cond); // TODO: string
				r_cons_printf ("family: %d\n", aop.family);
				r_cons_printf ("\n");
				//r_cons_printf ("false: 0x%08"PFMT64x"\n", core->offset+idx);
			}
		}
		break;
	case 'f':
		switch (input[1]) {
		case '-':
			r_anal_fcn_del (core->anal, r_num_math (core->num, input+2));
			break;
		case '+':
			{
			char *ptr = strdup(input+3), *ptr2;
			int n = r_str_word_set0 (ptr);
			const char *name = NULL;
			ut64 addr = -1LL;
			ut64 size = 0LL;
			RAnalDiff *diff = NULL;
			int type = R_ANAL_FCN_TYPE_FCN;
			
			if (n > 2) {
				switch(n) {
				case 5:
					ptr2 = r_str_word_get0 (ptr, 4);
					if (!(diff = r_anal_diff_new ())) {
						eprintf ("error: Cannot init RAnalDiff\n");
						free (ptr);
						return R_FALSE;
					}
					if (ptr2[0] == 'm')
						diff->type = R_ANAL_DIFF_TYPE_MATCH;
					else if (ptr2[0] == 'u')
						diff->type = R_ANAL_DIFF_TYPE_UNMATCH;
				case 4:
					ptr2 = r_str_word_get0 (ptr, 3);
					if (strchr (ptr2, 'l'))
						type = R_ANAL_FCN_TYPE_LOC;
					else if (strchr (ptr2, 'i'))
						type = R_ANAL_FCN_TYPE_IMP;
					else if (strchr (ptr2, 's'))
						type = R_ANAL_FCN_TYPE_SYM;
					else type = R_ANAL_FCN_TYPE_FCN;
				case 3:
					name = r_str_word_get0 (ptr, 2);
				case 2:
					size = r_num_math (core->num, r_str_word_get0 (ptr, 1));
				case 1:
					addr = r_num_math (core->num, r_str_word_get0 (ptr, 0));
				}
				if (!r_anal_fcn_add (core->anal, addr, size, name, type, diff))
					eprintf ("Cannot add function (duplicated)\n");
			}
			r_anal_diff_free (diff);
			free (ptr);
			}
			break;
		case 'l':
			r_core_anal_fcn_list (core, input+2, 0);
			break;
		case '*':
			r_core_anal_fcn_list (core, input+2, 1);
			break;
		case 's': {
			ut64 addr;
			RAnalFcn *f;
			const char *arg = input+3;
			if (input[2] && (addr = r_num_math (core->num, arg))) {
				arg = strchr (arg, ' ');
				if (arg) arg++;
			} else addr = core->offset;
			if ((f = r_anal_fcn_find (core->anal, addr, R_ANAL_FCN_TYPE_NULL))) {
				if (arg && *arg) {
					r_anal_fcn_from_string (core->anal, f, arg);
				} else {
					char *str = r_anal_fcn_to_string (core->anal, f);
					r_cons_printf ("%s\n", str);
					free (str);
				}
			} else eprintf("No function defined at 0x%08"PFMT64x"\n", addr);
			}
			break;
		case 'a':
		case 'A':
		case 'v':
			var_cmd (core, input+1);
			break;
		case 'c':
			{
			RAnalFcn *fcn;
			int cc;
			if ((fcn = r_anal_get_fcn_at (core->anal, core->offset)) != NULL) {
				cc = r_anal_fcn_cc (fcn);
				r_cons_printf ("Cyclomatic Complexity at 0x%08"PFMT64x" = %i\n", core->offset, cc);
			} else r_cons_printf ("Error: function not found\n");
			}
			break;
		case 'b':
			{
			char *ptr = strdup(input+3), *ptr2 = NULL;
			ut64 fcnaddr = -1LL, addr = -1LL;
			ut64 size = 0LL;
			ut64 jump = -1LL;
			ut64 fail = -1LL;
			int type = R_ANAL_BB_TYPE_NULL;
			RAnalFcn *fcn = NULL;
			RAnalDiff *diff = NULL;

			switch(r_str_word_set0 (ptr)) {
			case 7:
				ptr2 = r_str_word_get0 (ptr, 6);
				if (!(diff = r_anal_diff_new ())) {
					eprintf ("error: Cannot init RAnalDiff\n");
					free (ptr);
					return R_FALSE;
				}
				if (ptr2[0] == 'm')
					diff->type = R_ANAL_DIFF_TYPE_MATCH;
				else if (ptr2[0] == 'u')
					diff->type = R_ANAL_DIFF_TYPE_UNMATCH;
			case 6:
				ptr2 = r_str_word_get0 (ptr, 5);
				if (strchr (ptr2, 'h'))
					type |= R_ANAL_BB_TYPE_HEAD;
				if (strchr (ptr2, 'b'))
					type |= R_ANAL_BB_TYPE_BODY;
				if (strchr (ptr2, 'l'))
					type |= R_ANAL_BB_TYPE_LAST;
				if (strchr (ptr2, 'f'))
					type |= R_ANAL_BB_TYPE_FOOT;
			case 5: // get fail
				fail = r_num_math (core->num, r_str_word_get0 (ptr, 4));
			case 4: // get jump
				jump = r_num_math (core->num, r_str_word_get0 (ptr, 3));
			case 3: // get size
				size = r_num_math (core->num, r_str_word_get0 (ptr, 2));
			case 2: // get addr
				addr = r_num_math (core->num, r_str_word_get0 (ptr, 1));
			case 1: // get fcnaddr
				fcnaddr = r_num_math (core->num, r_str_word_get0 (ptr, 0));
			}
			if ((fcn = r_anal_get_fcn_at (core->anal, fcnaddr)) == NULL ||
				!r_anal_fcn_add_bb (fcn, addr, size, jump, fail, type, diff))
				eprintf ("Error: Cannot add bb\n");
			r_anal_diff_free (diff);
			free (ptr);
			}
			break;
		case '?':
			r_cons_printf (
			"Usage: af[?+-l*]\n"
			" af @ [addr]               ; Analyze functions (start at addr)\n"
			" af+ addr size name [type] [diff] ; Add function\n"
			" afb fcnaddr addr size name [type] [diff] ; Add bb to function @ fcnaddr\n"
			" af- [addr]                ; Clean all function analysis data (or function at addr)\n"
			" afl [fcn name]            ; List functions\n"
			" afs [addr] [fcnsign]      ; Get/set function signature at current address\n"
			" af[aAv][?] [arg]          ; Manipulate args, fastargs and variables in function\n"
			" afc @ [addr]              ; Calculate the Cyclomatic Complexity (starting at addr)\n"
			" af*                       ; Output radare commands\n");
			break;
		default:
			r_core_anal_fcn (core, core->offset, -1, R_ANAL_REF_TYPE_NULL,
					r_config_get_i (core->config, "anal.depth"));
		}
		break;
	case 'g':
		switch (input[1]) {
		case 'c':
			r_core_anal_refs (core, r_num_math (core->num, input+2), 1);
			break;
		case 'l':
			r_core_anal_graph (core, r_num_math (core->num, input+2), R_CORE_ANAL_GRAPHLINES);
			break;
		case 'a':
			r_core_anal_graph (core, r_num_math (core->num, input+2), 0);
			break;
		case 'd':
			r_core_anal_graph (core, r_num_math (core->num, input+2),
					R_CORE_ANAL_GRAPHBODY|R_CORE_ANAL_GRAPHDIFF);
			break;
		case '?':
			r_cons_printf (
			"Usage: ag[?f]\n"
			" ag [addr]       ; Output graphviz code (bb at addr and childs)\n"
			" aga [addr]      ; Idem, but only addresses\n"
			" agc [addr]      ; Output graphviz call graph of function\n"
			" agl [fcn name]  ; Output graphviz code using meta-data\n"
			" agd [fcn name]  ; Output graphviz code of diffed function\n"
			" agfl [fcn name] ; Output graphviz code of function using meta-data\n");
			break;
		default:
			r_core_anal_graph (core, r_num_math (core->num, input+1),
				R_CORE_ANAL_GRAPHBODY);
		}
		break;
	case 't':
		switch (input[1]) {
		case '?':
			r_cons_strcat ("Usage: at[*] [addr]\n"
			" at?                ; show help message\n"
			" at                 ; list all traced opcode ranges\n"
			" at-                ; reset the tracing information\n"
			" at*                ; list all traced opcode offsets\n"
			" at+ [addr] [times] ; add trace for address N times\n"
			" at [addr]          ; show trace info at address\n"
			" att [tag]          ; select trace tag (no arg unsets)\n"
			" at%                ; TODO\n"
			" ata 0x804020 ...   ; only trace given addresses\n"
			" atr                ; show traces as range commands (ar+)\n"
			" atd                ; show disassembly trace\n"
			" atD                ; show dwarf trace (at*|rsc dwarf-traces $FILE)\n");
			eprintf ("Current Tag: %d\n", core->dbg->trace->tag);
			break;
		case 'a':
			eprintf ("NOTE: Ensure given addresses are in 0x%%08llx format\n");
			r_debug_trace_at (core->dbg, input+2);
			break;
		case 't':
			r_debug_trace_tag (core->dbg, atoi (input+2));
			break;
		case 'd':
			//trace_show (2, trace_tag_get());
			eprintf ("TODO\n");
			break;
		case 'D':
			// XXX: not yet tested..and rsc dwarf-traces comes from r1
			r_core_cmd (core, "at*|rsc dwarf-traces $FILE", 0);
			break;
		case '+':
			ptr = input+3;
			addr = r_num_math (core->num, ptr);
			ptr = strchr (ptr, ' ');
			if (ptr != NULL) {
				RAnalOp *aop = r_core_op_anal (core, addr);
				if (aop != NULL) {
					//eprintf("at(0x%08llx)=%d (%s)\n", addr, atoi(ptr+1), ptr+1);
					//trace_set_times(addr, atoi(ptr+1));
					RDebugTracepoint *tp = r_debug_trace_add (core->dbg, addr, aop->length);
					tp->count = atoi (ptr+1);
					r_anal_trace_bb (core->anal, addr);
					r_anal_aop_free (aop);
				} else eprintf ("Cannot analyze opcode at 0x%"PFMT64x"\n", addr);
			}
			break;
		case '-':
			r_debug_trace_free (core->dbg);
			core->dbg->trace = r_debug_trace_new (core->dbg);
			break;
		case ' ': {
			RDebugTracepoint *t = r_debug_trace_get (core->dbg,
				r_num_math (core->num, input+1));
			if (t != NULL) {
				r_cons_printf ("offset = 0x%"PFMT64x"\n", t->addr);
				r_cons_printf ("opsize = %d\n", t->size);
				r_cons_printf ("times = %d\n", t->times);
				r_cons_printf ("count = %d\n", t->count);
				//TODO cons_printf("time = %d\n", t->tm);
			} }
			break;
		case '*':
			r_debug_trace_list (core->dbg, 1);
			break;
		case 'r':
			eprintf ("TODO\n");
			//trace_show(-1, trace_tag_get());
			break;
		default:
			r_debug_trace_list (core->dbg, 0);
		}
		break;
	case 's':
		switch (input[1]) {
		case 'l':
			r_syscall_list (core->anal->syscall);
			break;
		case '\0': {
			int a0 = (int)r_debug_reg_get (core->dbg, "oeax"); //XXX
			cmd_syscall_do (core, a0);
			} break;
		case ' ':
			cmd_syscall_do (core, (int)r_num_get (core->num, input+2));
			break;
		default:
		case '?':
			r_cons_printf (
			"Usage: as[?]\n"
			" as       Display syscall and arguments\n"
			" as 4     Show syscall 4 based on asm.os\n"
			" asl      List of syscalls by asm.os and asm.arch\n");
			break;
		}
		break;
	case 'r':
		switch(input[1]) {
		case '?':
			r_cons_printf (
			"Usage: ar[?d-l*]\n"
			" ar addr [at]   ; Add code ref\n"
			" ard addr [at]  ; Add dara ref\n"
			" ar- [at]       ; Clean all refs (or refs from addr)\n"
			" arl            ; List refs\n"
			" ar*            ; Output radare commands\n");
			break;
		case '-':
			r_anal_ref_del (core->anal, r_num_math (core->num, input+2));
			break;
		case 'l':
			r_core_anal_ref_list (core, R_FALSE);
			break;
		case '*':
			r_core_anal_ref_list (core, R_TRUE);
			break;
		default:
			{
			char *ptr = strdup (r_str_trim_head ((char*)input+2));
			int n = r_str_word_set0 (ptr);
			ut64 at = core->offset;
			ut64 addr = -1LL;
			switch (n) {
			case 2: // get at
				at = r_num_math (core->num, r_str_word_get0 (ptr, 1));
			case 1: // get addr
				addr = r_num_math (core->num, r_str_word_get0 (ptr, 0));
				break;
			default:
				return R_FALSE;
			}
			r_anal_ref_add (core->anal, addr, at,
					input[1]=='d'?R_ANAL_REF_TYPE_DATA:R_ANAL_REF_TYPE_CODE);
			free (ptr);
			}
		}
		break;
	case 'a':
		r_core_anal_all (core);
		break;
	case 'p':
		{
			const char *arch = r_config_get (core->config, "asm.arch");
			int bits = r_config_get_i (core->config, "asm.bits");
			// TODO: this is x86 only
			// TODO: allow interruptible search
			char *o = strdup (r_config_get (core->config, "search.prefix"));
			r_config_set (core->config, "search.prefix", "pre.");
			r_core_cmd0 (core, "fs preludes");
			if (!strstr (arch, "x86")) {
				switch (bits) {
				case 32:
					r_core_cmd0 (core, "./x 5589e5 && af @@ pre.");
					break;
				case 64:
					r_core_cmd0 (core, "./x 554989e5 && af @@ pre.");
					break;
				}
			} else {
				eprintf ("ap: Unsupported asm.arch and asm.bits\n");
			}
			r_config_set (core->config, "search.prefix", o);
			free (o);
		}
		break;
	default:
		r_cons_printf (
		"Usage: a[?obfrgtv]\n"
		" aa              ; Analyze all (fcns + bbs)\n"
		" ap              ; Find and analyze function preludes\n"
		" as [num]        ; Analyze syscall using dbg.reg\n"
		" ao[e?] [len]    ; Analyze Opcodes (or emulate it)\n"
		" ab[?+-l*]       ; Analyze Basic blocks\n"
		" af[?+-l*]       ; Analyze Functions\n"
		" ar[?d-l*]       ; Manage refs/xrefs\n"
		" ag[?f]          ; Output Graphviz code\n"
		" at[trd+-*?] [.] ; Analyze execution Traces\n");
		break;
	}
	if (tbs != core->blocksize)
		r_core_block_size (core, tbs);
	return 0;
}

/* TODO: simplify using r_write */
static int cmd_write(void *data, const char *input) {
	int size;
	const char *arg;
	ut8 *buf;
	int i, len = strlen (input);
	char *tmp, *str = alloca (len)+1;
	RCore *core = (RCore *)data;
	memcpy (str, input+1, len);
	switch (input[0]) {
	case 'A':
		switch (input[1]) {
		case ' ':
			if (input[2]&&input[3]==' ') {
				r_asm_set_pc (core->assembler, core->offset);
				eprintf ("modify (%c)=%s\n", input[2], input+4);
				len = r_asm_modify (core->assembler, core->block, input[2],
					r_num_math (core->num, input+4));
				eprintf ("len=%d\n", len);
				if (len>0)
					r_core_write_at (core, core->offset, core->block, len);
				else eprintf ("r_asm_modify = %d\n", len);
			} else eprintf ("Usage: wA [type] [value]\n");
			break;
		case '?':
		default:
			r_cons_printf ("Usage: wA [type] [value]\n"
			"Types:\n"
			" r   raw write value\n"
			" v   set value (taking care of current address)\n"
			" d   destination register\n"
			" 0   1st src register \n"
			" 1   2nd src register\n"
			"Example: wA r 0 # e800000000\n");
			break;
		}
		break;
	case 'c':
		switch (input[1]) {
		case 'i':
			r_io_cache_commit (core->io);
			break;
		case 'r':
			r_io_cache_reset (core->io, R_TRUE);
			break;
		case '?':
			r_cons_printf (
			"Usage: wc[ir*?]\n"
			" wc       list all write changes\n"
			" wc*      \"\" in radare commands\n"
			" wcr      reset all write changes in cache\n"
			" wci      commit write cache\n"
			"NOTE: Needs io.cache=true\n");
			break;
		case '*':
			r_io_cache_list (core->io, R_TRUE);
			break;
		case '\0':
			r_io_cache_list (core->io, R_FALSE);
			break;
		}
		break;
	case ' ':
		/* write string */
		len = r_str_escape (str);
		r_io_set_fd (core->io, core->file->fd);
		r_io_write_at (core->io, core->offset, (const ut8*)str, len);
		r_core_block_read (core, 0);
		break;
	case 't':
		/* TODO: support userdefined size? */
		arg = (const char *)(input+((input[1]==' ')?2:1));
		r_file_dump (arg, core->block, core->blocksize);
		break;
	case 'T':
		eprintf ("TODO\n");
		break;
	case 'f':
		arg = (const char *)(input+((input[1]==' ')?2:1));
		if ((buf = (ut8*) r_file_slurp (arg, &size))) {
			r_io_set_fd (core->io, core->file->fd);
			r_io_write_at (core->io, core->offset, buf, size);
			free(buf);
			r_core_block_read (core, 0);
		} else eprintf ("Cannot open file '%s'\n", arg);
		break;
	case 'F':
		arg = (const char *)(input+((input[1]==' ')?2:1));
		if ((buf = r_file_slurp_hexpairs (arg, &size))) {
			r_io_set_fd (core->io, core->file->fd);
			r_io_write_at (core->io, core->offset, buf, size);
			free (buf);
			r_core_block_read (core, 0);
		} else eprintf ("Cannot open file '%s'\n", arg);
		break;
	case 'w':
		str = str+1;
		len = (len-1)<<1;
		tmp = alloca (len);
		for (i=0;i<len;i++) {
			if (i%2) tmp[i] = 0;
			else tmp[i] = str[i>>1];
		}
		str = tmp;
		r_io_set_fd (core->io, core->file->fd);
		r_io_write_at (core->io, core->offset, (const ut8*)str, len);
		r_core_block_read (core, 0);
		break;
	case 'x':
		{
		int len = strlen (input);
		ut8 *buf = alloca (len);
		len = r_hex_str2bin (input+1, buf);
		r_core_write_at (core, core->offset, buf, len);
		r_core_block_read (core, 0);
		}
		break;
	case 'a':
		{
		RAsmCode *acode;
		/* XXX ULTRAUGLY , needs fallback support in rasm */
		r_asm_use (core->assembler, "x86.olly");
		r_asm_set_pc (core->assembler, core->offset);
		if (input[1]==' ') input=input+1;
		acode = r_asm_massemble (core->assembler, input+1);
		if (acode) {
			eprintf ("Written %d bytes (%s)=wx %s\n", acode->len, input+1, acode->buf_hex);
			r_core_write_at (core, core->offset, acode->buf, acode->len);
			r_asm_code_free (acode);
			r_core_block_read (core, 0);
			r_asm_use (core->assembler, "x86"); /* XXX */
			r_core_block_read (core, 0);
		}
		}
		break;
	case 'b':
		{
		int len = strlen (input);
		ut8 *buf = alloca (len);
		len = r_hex_str2bin (input+1, buf);
		r_mem_copyloop (core->block, buf, core->blocksize, len);
		r_core_write_at (core, core->offset, core->block, core->blocksize);
		r_core_block_read (core, 0);
		}
		break;
	case 'm':
		size = r_hex_str2bin (input+1, (ut8*)str);
		switch (input[1]) {
		case '\0':
			eprintf ("Current write mask: TODO\n");
			// TODO
			break;
		case '?':
			break;
		case '-':
			r_io_set_write_mask(core->io, 0, 0);
			eprintf ("Write mask disabled\n");
			break;
		case ' ':
			if (size>0) {
				r_io_set_fd (core->io, core->file->fd);
				r_io_set_write_mask (core->io, (const ut8*)str, size);
				eprintf ("Write mask set to '");
				for (i=0;i<size;i++)
					eprintf ("%02x", str[i]);
				eprintf ("'\n");
			} else eprintf ("Invalid string\n");
			break;
		}
		break;
	case 'v':
		{
		ut64 off = r_num_math (core->num, input+1);
		r_io_set_fd (core->io, core->file->fd);
		r_io_seek (core->io, core->offset, R_IO_SEEK_SET);
		if (off&UT64_32U) {
			/* 8 byte addr */
			ut64 addr8;
			memcpy((ut8*)&addr8, (ut8*)&off, 8); // XXX needs endian here
		//	endian_memcpy((ut8*)&addr8, (ut8*)&off, 8);
			r_io_write(core->io, (const ut8 *)&addr8, 8);
		} else {
			/* 4 byte addr */
			ut32 addr4, addr4_ = (ut32)off;
			//drop_endian((ut8*)&addr4_, (ut8*)&addr4, 4); /* addr4_ = addr4 */
			//endian_memcpy((ut8*)&addr4, (ut8*)&addr4_, 4); /* addr4 = addr4_ */
			memcpy ((ut8*)&addr4, (ut8*)&addr4_, 4); // XXX needs endian here too
			r_io_write (core->io, (const ut8 *)&addr4, 4);
		}
		r_core_block_read (core, 0);
		}
		break;
	case 'o':
                switch (input[1]) {
                case 'a':
                case 's':
                case 'A':
                case 'x':
                case 'r':
                case 'l':
                case 'm':
                case 'd':
                case 'o':
                        if (input[2]!=' ') {
                                eprintf ("Usage: 'wo%c 00 11 22'\n", input[1]);
                                return 0;
                        }
                case '2':
                case '4':
                        r_core_write_op (core, input+3, input[1]);
			r_core_block_read (core, 0);
                        break;
                case '\0':
                case '?':
                default:
                        r_cons_printf (
                        "Usage: wo[xrlasmd] [hexpairs]\n"
                        "Example: wox 90    ; xor cur block with 90\n"
                        "Example: woa 02 03 ; add 2, 3 to all bytes of cur block\n"
                        "Supported operations:\n"
                        "  woa  addition            +=\n"
                        "  wos  substraction        -=\n"
                        "  wom  multiply            *=\n"
                        "  wod  divide              /=\n"
                        "  wox  xor                 ^=\n"
                        "  woo  or                  |=\n"
                        "  woA  and                 &=\n"
                        "  wor  shift right         >>=\n"
                        "  wol  shift left          <<=\n"
                        "  wo2  2 byte endian swap  2=\n"
                        "  wo4  4 byte endian swap  4=\n"
                        );
                        break;
                }
                break;
	default:
	case '?':
		if (core->oobi) {
			eprintf ("Writing oobi buffer!\n");
			r_io_set_fd (core->io, core->file->fd);
			r_io_write (core->io, core->oobi, core->oobi_len);
			r_core_block_read (core, 0);
		} else r_cons_printf (
			"Usage: w[x] [str] [<file] [<<EOF] [@addr]\n"
			" w foobar     write string 'foobar'\n"
			" ww foobar    write wide string 'f\\x00o\\x00o\\x00b\\x00a\\x00r\\x00'\n"
			" wa push ebp  write opcode, separated by ';' (use '\"' around the command)\n"
			" wA r 0       alter/modify opcode at current seek (see wA?)\n"
			" wb 010203    fill current block with cyclic hexpairs\n"
			" wc[ir*?]     write cache commit/reset/list\n"
			" wx 9090      write two intel nops\n"
			" wv eip+34    write 32-64 bit value\n"
			" wo[] hex     write in block with operation. 'wo?' fmi\n"
			" wm f0ff      set binary mask hexpair to be used as cyclic write mask\n"
			" wf file      write contents of file at current offset\n"
			" wF file      write contents of hexpairs file here\n"
			" wt file      write current block to file\n");
			//TODO: add support for offset+seek
			// " wf file o s ; write contents of file from optional offset 'o' and size 's'.\n"
		break;
	}
	return 0;
}

static int cmd_resize(void *data, const char *input) {
	RCore *core = (RCore *)data;
	st64 delta=0;
	int grow;
	ut64 oldsize,newsize;

	oldsize = core->file->size;

	switch (input[0]) {
	case ' ':
		newsize = r_num_math (core->num, input+1);
		break;
	case '+':
	case '-':
		delta = (st64)r_num_math (NULL, input);
		newsize = oldsize + delta;
		break;
	case '?':
	default:
		r_cons_printf (
			"Usage: r[ size|+insert|-remove]\n"
			" r size   set filesize to size, extending or truncating\n"
			" r-num    remove num bytes, move following data down\n"
			" r+num    insert num bytes, move following data up\n");
		return R_TRUE;
	}

	grow = (newsize > oldsize);

	if (grow) {
		r_io_resize (core->io, newsize);
		core->file->size = newsize;
	}

	if (delta && core->offset < newsize)
		r_io_shift (core->io, core->offset, grow?newsize:oldsize, delta);

	if (!grow) {
		r_io_resize (core->io, newsize);
		core->file->size = newsize;
	}

	if (newsize < core->offset+core->blocksize ||
			oldsize < core->offset+core->blocksize)
		r_core_block_read (core, 0);

	return R_TRUE;
}

static const char *cmdhit = NULL;
static const char *searchprefix = NULL;

static int __cb_hit(RSearchKeyword *kw, void *user, ut64 addr) {
	RCore *core = (RCore *)user;
	r_cons_printf ("f %s%d_%d %d 0x%08"PFMT64x"\n", searchprefix,
		kw->kwidx, kw->count, kw->keyword_length, addr);
	if (!strnull (cmdhit)) {
		ut64 here = core->offset;
		r_core_seek (core, addr, R_FALSE);
		r_core_cmd (core, cmdhit, 0);
		r_core_seek (core, here, R_TRUE);
	}
	return R_TRUE;
}

static int cmd_search(void *data, const char *input) {
	RCore *core = (RCore *)data;
	ut64 at, from, to;
	//RIOSection *section;
	int ret, dosearch = R_FALSE;
	int aes_search = R_FALSE;
	ut32 n32;
	ut8 *buf;

	// TODO: repeat last search doesnt works for /a
	from = r_config_get_i (core->config, "search.from");
	to = r_config_get_i (core->config, "search.to");
	core->search->align = r_config_get_i (core->config, "search.align");
	//TODO: handle section ranges if from&&to==0
/*
	section = r_io_section_get (core->io, core->offset);
	if (section) {
		from += section->vaddr;
		//fin = ini + s->size;
	}
*/
	searchprefix = r_config_get (core->config, "search.prefix");
	/* XXX: Think how to get the section ranges here */
	if (from == 0LL)
		from = core->offset;
	if (to == 0LL)
		to = 0xFFFFFFFF; //core->file->size+0x8048000;

	switch (input[0]) {
	case 'a':
		if (input[1]==' ')
			r_core_anal_search (core, from, to, r_num_math (core->num, input+2));
		else r_core_anal_search (core, from, to, core->offset);
		break;
	case 'A':
		dosearch = aes_search = R_TRUE;
		break;
	case '/':
		r_search_begin (core->search);
		dosearch = R_TRUE;
		break;
	case 'v':
		r_search_reset (core->search, R_SEARCH_KEYWORD);
		r_search_set_distance (core->search, (int)
			r_config_get_i (core->config, "search.distance"));
		n32 = (ut32)r_num_math (core->num, input+1);
// TODO: Add support for /v4 /v8 /v2
		r_search_kw_add (core->search, 
			r_search_keyword_new ((const ut8*)&n32, 4, NULL, 0, NULL));
		r_search_begin (core->search);
		dosearch = 1;
		break;
	case 'w': /* search wide string */
		if (input[1]==' ') {
			int len = strlen (input+2);
			const char *p2;
			char *p, *str = malloc ((len+1)*2);
			for (p2=input+2,p=str; *p2; p+=2, p2++) {
				p[0] = *p2;
				p[1] = 0;
			}
			r_search_reset (core->search, R_SEARCH_KEYWORD);
			r_search_set_distance (core->search, (int)
				r_config_get_i (core->config, "search.distance"));
			r_search_kw_add (core->search, 
				r_search_keyword_new ((const ut8*)str, len*2, NULL, 0, NULL));
			r_search_begin (core->search);
			dosearch = 1;
		}
		break;
	case ' ': /* search string */
		r_search_reset (core->search, R_SEARCH_KEYWORD);
		r_search_set_distance (core->search, (int)
			r_config_get_i (core->config, "search.distance"));
		r_search_kw_add (core->search, 
			r_search_keyword_new_str (input+1, "", NULL));
		r_search_begin (core->search);
		dosearch = 1;
		break;
	case 'm': /* match regexp */
		{
		char *inp = strdup (input+2);
		char *res = r_str_lchr (inp+1, inp[0]);
		char *opt = NULL;
		if (res > inp) {
			opt = strdup(res+1);
			res[1]='\0';
		}
		r_search_reset (core->search, R_SEARCH_REGEXP);
		r_search_set_distance (core->search, (int)
			r_config_get_i (core->config, "search.distance"));
		r_search_kw_add (core->search, 
			r_search_keyword_new_str (inp, opt, NULL));
		r_search_begin (core->search);
		dosearch = 1;
		free(inp);
		free(opt);
		}
		break;
	case 'x': /* search hex */
		r_search_reset (core->search, R_SEARCH_KEYWORD);
		r_search_set_distance (core->search, (int)
			r_config_get_i (core->config, "search.distance"));
		r_search_kw_add (core->search, 
			r_search_keyword_new_hexmask (input+2, NULL));
		r_search_begin (core->search);
		dosearch = 1;
		break;
	case 'c': /* search asm */
		{
		/* TODO: Move to a separate function */
		int asmstr = r_config_get_i (core->config, "search.asmstr");
		if (asmstr) {
			RCoreAsmHit *hit;
			RListIter *iter;
			int count = 0;
			RList *hits;
			if ((hits = r_core_asm_strsearch (core, input+2, from, to))) {
				r_list_foreach (hits, iter, hit) {
					r_cons_printf ("f %s_%i @ 0x%08"PFMT64x"   # %s (%i)\n",
						searchprefix, count, hit->addr, hit->code, hit->len);
					count++;
				}
				r_list_destroy (hits);
			}
			dosearch = 0;
		} else {
			char *kwd;
			if (!(kwd = r_core_asm_search (core, input+2, from, to)))
				return R_FALSE;
			r_search_reset (core->search, R_SEARCH_KEYWORD);
			r_search_set_distance (core->search, (int)
					r_config_get_i (core->config, "search.distance"));
			r_search_kw_add (core->search, 
					r_search_keyword_new_hexmask (kwd, NULL));
			r_search_begin (core->search);
			free (kwd);
			dosearch = 1;
		}
		}
		break;
	default:
		r_cons_printf (
		"Usage: /[amx/] [arg]\n"
		" / foo           ; search for string 'foo'\n"
		" /w foo          ; search for wide string 'f\\0o\\0o'\n"
		" /m /E.F/i       ; match regular expression\n"
		" /x ff0033       ; search for hex string\n"
		" /c jmp [esp]    ; search for asm code (see search.asmstr)\n"
		" /A              ; search for AES expanded keys\n"
		" /a sym.printf   ; analyze code referencing an offset\n"
		" /v num          ; look for a asm.bigendian 32bit value\n"
		" //              ; repeat last search\n"
		" ./ hello        ; search 'hello string' and import flags\n"
		"Configuration:\n"
		" e search.distance = 0 ; search string distance\n"
		" e search.align = 4    ; only catch aligned search hits\n"
		" e search.from = 0     ; start address\n"
		" e search.to = 0       ; end address\n"
		" e search.asmstr = 0   ; search string instead of assembly\n");
		break;
	}
	if (dosearch) {
		if (core->search->n_kws>0 || aes_search) {
			RSearchKeyword aeskw;
			if (aes_search) {
				memset (&aeskw, 0, sizeof (aeskw));
				aeskw.keyword_length = 31;
			}
			/* set callback */
			/* TODO: handle last block of data */
			/* TODO: handle ^C */
			/* TODO: launch search in background support */
			buf = (ut8 *)malloc (core->blocksize);
			r_search_set_callback (core->search, &__cb_hit, core);
			cmdhit = r_config_get (core->config, "cmd.hit");
			r_cons_break (NULL, NULL);
			// XXX required? imho nor_io_set_fd (core->io, core->file->fd);
			for (at = from; at < to; at += core->blocksize) {
				if (r_cons_singleton ()->breaked)
					break;
				ret = r_io_read_at (core->io, at, buf, core->blocksize);
				if (ret != core->blocksize)
					break;
				if (aes_search) {
					int delta = r_search_aes_update (core->search, at, buf, ret);
					if (delta != -1) {
						r_search_hit_new (core->search, &aeskw, at+delta);
						aeskw.count++;
					}
				} else
				if (r_search_update (core->search, &at, buf, ret) == -1) {
					eprintf ("search: update read error\n");
					break;
				}
			}
			r_cons_break_end ();
			free (buf);
		} else eprintf ("No keywords defined\n");
	}
	return R_TRUE;
}

static int cmd_eval(void *data, const char *input) {
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case '\0':
		r_config_list (core->config, NULL, 0);
		break;
	case '!':
		input = r_str_chop_ro(input+1);
		if (!r_config_swap (core->config, input))
			eprintf ("r_config: '%s' is not a boolean variable.\n", input);
		break;
	case '-':
		r_core_config_init (core);
		eprintf ("BUG: 'e-' command locks the eval hashtable. patches are welcome :)\n");
		break;
	case '*':
		r_config_list (core->config, NULL, 1);
		break;
	case '?':
		r_cons_printf (
		"Usage: e[?] [var[=value]]\n"
		"  e     ; list config vars\n"
		"  e-    ; reset config vars\n"
		"  e*    ; dump config vars in r commands\n"
		"  e!a   ; invert the boolean value of 'a' var\n"
		"  e a   ; get value of var 'a'\n"
		"  e a=b ; set var 'a' the 'b' value\n");
		//r_cmd_help(core->cmd, "e");
		break;
	case ' ':
		r_config_eval (core->config, input+1);
		break;
	default:
		r_config_eval (core->config, input);
	}
	return 0;
}

static int cmd_hash(void *data, const char *input) {
	char *p, algo[32];
	RCore *core = (RCore *)data;
	ut32 i, len = core->blocksize;
	const char *ptr;

	if (input[0]=='!') {
#if 0
	TODO: Honor OOBI
		#!lua < file
		#!lua <<EOF
		#!lua
		#!lua foo bar
                        //r_lang_run (core->lang, p+1, strlen (p+1));
                                //core->oobi, core->oobi_len);
#endif
		if (input[1]=='?' || input[1]=='*' || input[1]=='\0') {
			r_lang_list (core->lang);
			return R_TRUE;
		}
		p = strchr (input+1, ' ');
		if (p) *p=0;
		// TODO: set argv here
		if (r_lang_use (core->lang, input+1)) {
			r_lang_setup (core->lang);
			if (p) r_lang_run_file (core->lang, p+1);
			else r_lang_prompt (core->lang);
		} else eprintf ("Invalid hashbang plugin name. Try '#!'\n");
		return R_TRUE;
	}

	ptr = strchr (input, ' ');
	sscanf (input, "%31s", algo);
	if (ptr != NULL)
		len = r_num_math (core->num, ptr+1);
	/* TODO: Simplify this spaguetti monster */
	if (!r_str_ccmp (input, "md4", ' ')) {
		RHash *ctx = r_hash_new (R_TRUE, R_HASH_MD4);
		const ut8 *c = r_hash_do_md4 (ctx, core->block, len);
		for (i=0; i<R_HASH_SIZE_MD4; i++) r_cons_printf ("%02x", c[i]);
		r_cons_newline ();
		r_hash_free (ctx);
	} else
	if (!r_str_ccmp (input, "md5", ' ')) {
		RHash *ctx = r_hash_new (R_TRUE, R_HASH_MD5);
		const ut8 *c = r_hash_do_md5 (ctx, core->block, len);
		for (i=0; i<R_HASH_SIZE_MD5; i++) r_cons_printf ("%02x", c[i]);
		r_cons_newline ();
		r_hash_free (ctx);
	} else
	if (!r_str_ccmp (input, "sha1", ' ')) {
		RHash *ctx = r_hash_new (R_TRUE, R_HASH_SHA1);
		const ut8 *c = r_hash_do_sha1 (ctx, core->block, len);
		for (i=0; i<R_HASH_SIZE_SHA1;i++) r_cons_printf ("%02x", c[i]);
		r_cons_newline ();
		r_hash_free (ctx);
	} else
	if (!r_str_ccmp (input, "sha256", ' ')) {
		RHash *ctx = r_hash_new (R_TRUE, R_HASH_SHA256);
		const ut8 *c = r_hash_do_sha256 (ctx, core->block, len);
		for (i=0; i<R_HASH_SIZE_SHA256;i++) r_cons_printf ("%02x", c[i]);
		r_cons_newline ();
		r_hash_free (ctx);
	} else
	if (!r_str_ccmp (input, "sha512", ' ')) {
		RHash *ctx = r_hash_new (R_TRUE, R_HASH_SHA512);
		const ut8 *c = r_hash_do_sha512 (ctx, core->block, len);
		for (i=0; i<R_HASH_SIZE_SHA512;i++) r_cons_printf ("%02x", c[i]);
		r_cons_newline ();
		r_hash_free (ctx);
	} else
	if (!r_str_ccmp (input, "entropy", ' ')) {
		r_cons_printf ("%lf\n", r_hash_entropy (core->block, len));
	} else
	if (!r_str_ccmp (input, "hamdist", ' ')) {
		r_cons_printf ("%d\n", r_hash_hamdist (core->block, len));
	} else
	if (!r_str_ccmp (input, "pcprint", ' ')) {
		r_cons_printf ("%d\n", r_hash_pcprint (core->block, len));
	} else
	if (!r_str_ccmp (input, "crc32", ' ')) {
		r_cons_printf ("%04x\n", r_hash_crc32 (core->block, len));
	} else
	if (!r_str_ccmp (input, "xor", ' ')) {
		r_cons_printf ("%02x\n", r_hash_xor (core->block, len));
	} else
	if (!r_str_ccmp (input, "crc16", ' ')) {
		r_cons_printf ("%02x\n", r_hash_crc16 (0, core->block, len));
	} else
	if (input[0]=='?') {
		r_cons_printf (
		"Usage: #algo <size> @ addr\n"
		" #xor                 ; calculate xor of all bytes in current block\n"
		" #crc32               ; calculate crc32 of current block\n"
		" #crc32 < /etc/fstab  ; calculate crc32 of this file\n"
		" #pcprint             ; count printable chars in current block\n"
		" #hamdist             ; calculate hamming distance in current block\n"
		" #entropy             ; calculate entropy of current block\n"
		" #md4                 ; calculate md4\n"
		" #md5 128K @ edi      ; calculate md5 of 128K from 'edi'\n"
		" #sha1                ; calculate SHA-1\n"
		" #sha256              ; calculate SHA-256\n"
		" #sha512              ; calculate SHA-512\n"
		"Usage #!interpreter [<args>] [<file] [<<eof]\n"
		" #!                   ; list all available interpreters\n"
		" #!python             ; run python commandline\n"
		" #!python < foo.py    ; run foo.py python script\n"
		" #!python <<EOF       ; get python code until 'EOF' mark\n"
		" #!python arg0 a1 <<q ; set arg0 and arg1 and read until 'q'\n"
		"Comments:\n"
		" # this is a comment  ; note the space after the sharp sign\n");
	}

	return 0;
}

static int cmd_visual(void *data, const char *input) {
	return r_core_visual ((RCore *)data, input);
}

static int cmd_system(void *data, const char *input) {
	int ret = 0;
	if (*input!='?') {
		char *cmd = r_core_sysenv_begin ((RCore*)data, input);
		if (cmd) {
			ret = r_sys_cmd (cmd);
			r_core_sysenv_end ((RCore*)data, input);
			free (cmd);
		} else eprintf ("Error setting up system environment\n");
	} else r_core_sysenv_help ();
	return ret;
}

static int cmd_open(void *data, const char *input) {
	RCore *core = (RCore*)data;
	RCoreFile *file;
	ut64 addr;
	char *ptr;
	int num;

	switch (*input) {
	case '\0':
		r_core_file_list (core);
		break;
	case ' ':
		ptr = strchr (input+1, ' ');
		if (ptr) {
			*ptr = '\0';
			addr = r_num_math (core->num, ptr+1);
		} else {
			num = atoi (input+1);
			addr = 0LL;
		}
		if (num<=0) {
			file = r_core_file_open (core, input+1, R_IO_READ, addr);
			if (file) {
				//eprintf ("Map '%s' in 0x%08"PFMT64x" with size 0x%"PFMT64x"\n",
				//	input+1, addr, file->size);
			} else eprintf ("Cannot open file '%s'\n", input+1);
		} else r_io_raise (core->io, num);
		r_core_block_read (core, 0);
		break;
	case '-':
		if (!r_core_file_close_fd (core, atoi (input+1)))
			eprintf ("Unable to find filedescriptor %d\n", atoi (input+1));
		r_core_block_read (core, 0);
		break;
	case '?':
	default:
		eprintf ("Usage: o [file] ([offset])\n"
		" o                   ; list opened files\n"
		" o /bin/ls           ; open /bin/ls file\n"
		" o /bin/ls 0x8048000 ; map file\n"
		" o 4                 ; priorize io on fd 4 (bring to front)\n"
		" o-1                 ; close file index 1\n");
		break;
	}
	return 0;
}

// XXX this command is broken. output of _list is not compatible with input
static int cmd_meta(void *data, const char *input) {
	RAnalVarType *var;
	RListIter *iter;
	RCore *core = (RCore*)data;
	int i, ret, line = 0;
	ut64 addr_end = 0LL;
	ut64 addr = core->offset;
	char file[1024];
	switch (*input) {
	case '*':
		r_meta_list (core->meta, R_META_ANY);
		break;
	case 't':
		switch (input[1]) {
		case '-':
			r_anal_var_type_del (core->anal, input+2);
			break;
		case ' ':
			{
			int size;
			const char *fmt = NULL;
			const char *ptr, *name = input+2;
			ptr = strchr (name, ' ');
			if (ptr) {
				size = atoi (ptr+1);
				ptr = strchr (ptr+2, ' ');
				if (ptr)
					fmt = ptr+1;
			}
			if (fmt==NULL)
				eprintf ("Usage: Ct name size format\n");
			else r_anal_var_type_add (core->anal, name, size, fmt);
			}
			break;
		case '\0':
			r_list_foreach (core->anal->vartypes, iter, var) {
				r_cons_printf ("Ct %s %d %s\n", var->name, var->size, var->fmt);
			}
			break;
		default:
			eprintf ("Usage: Ct[..]\n"
				" Ct-int       : remove 'int' type\n"
				" Ct int 4 d   : define int type\n");
			break;
		}
		break;
	case 'L': // debug information of current offset
		ret = r_bin_meta_get_line (core->bin, core->offset, file, 1023, &line);
		if (ret) {
			r_cons_printf ("file %s\nline %d\n", file, line);
			ret = (line<5)? 5-line: 5;
			line -= 2;
			for (i = 0; i<ret; i++) {
				char *row = r_file_slurp_line (file, line+i, 0);
				r_cons_printf ("%c %.3x  %s\n", (i==2)?'>':' ', line+i, row);
				free (row);
			}
		} else eprintf ("Cannot find meta information at 0x%08"PFMT64x"\n", core->offset);
		break;
	case 'C':
	case 'S':
	case 's':
	case 'd': /* data */
	case 'm': /* struct */
		switch (input[1]) {
		case '-':
			if (input[2]==' ')
				addr = r_num_math (core->num, input+3);
			r_meta_del (core->meta, input[0], addr, addr+1, NULL);
			break;
		case '\0':
		case '*':
			r_meta_list (core->meta, input[0]);
			break;
		default: {
			char *t, *p, name[128];
			int type = input[0];
			t = strdup (input+2);
			p = strchr (t, ' ');
			if (p) {
				*p = '\0';
				strncpy (name, p+1, sizeof (name));
			} else
			switch (type) {
			case 's':
				// TODO: filter \n and so on :)
				r_core_read_at (core, addr, (ut8*)name, sizeof (name));
				break;
			default:
				{
				RFlagItem *fi = r_flag_get_i (core->flags, addr);
				if (fi) strncpy (name, fi->name, sizeof (name));
				else sprintf (name, "ptr_%08"PFMT64x"", addr);
				}
			}
			addr_end = addr + atoi (input+1);
			free (t);
			r_meta_add (core->meta, type, addr, addr_end, name);
			}
		}
		break;
	case 'v':
		switch (input[1]) {
		case '-':
			{
			RAnalFcn *f;
			ut64 offset;
			if (input[2]==' ')
				offset = r_num_math (core->num, input+3);
			if ((f = r_anal_fcn_find (core->anal, offset, R_ANAL_FCN_TYPE_NULL)) != NULL) {
				memset (f->varnames, 0, sizeof(f->varnames));
				memset (f->varnames, 0, sizeof(f->varnames));
			}
			}
			break;
		case '*':
			{
			RAnalFcn *f;
			RListIter *iter;
			r_list_foreach (core->anal->fcns, iter, f) {
				for (i = 0; i < R_ANAL_MAX_VARSUB; i++) {
					if (f->varnames[i][0] != '\0')
						r_cons_printf ("Cv 0x%08llx %s %s\n", f->addr, f->varnames[i], f->varsubs[i]);
					else break;
				}
			}
			}
			break;
		default:
			{
			RAnalFcn *f;
			char *ptr = strdup(input+2), *varname, *varsub;
			ut64 offset = -1LL;
			int n = r_str_word_set0 (ptr), i;
			
			if (n > 2) {
				switch(n) {
				case 3:
					varsub = r_str_word_get0 (ptr, 2);
				case 2:
					varname = r_str_word_get0 (ptr, 1);
				case 1:
					offset = r_num_math (core->num, r_str_word_get0 (ptr, 0));
				}
				if ((f = r_anal_fcn_find (core->anal, offset, R_ANAL_FCN_TYPE_NULL)) != NULL) {
					for (i = 0; i < R_ANAL_MAX_VARSUB; i++)
						if (f->varnames[i][0] == '\0' || !strcmp (f->varnames[i], varname)) {
							strncpy (f->varnames[i], varname, 1024);
							strncpy (f->varsubs[i], varsub, 1024);
							break;
						}
				} else eprintf ("Error: Function not found\n");
			}
			free (ptr);
			}
		break;
		}
	case '-':
		if (input[1]!='*') {
			if (input[1]==' ')
				addr = r_num_math (core->num, input+2);
			r_meta_del (core->meta, R_META_ANY, addr, 1, "");
		} else r_meta_cleanup (core->meta, 0LL, UT64_MAX);
		break;
	case '\0':
	case '?':
		eprintf (
		"Usage: C[-LCsSmxX?] [...]\n"
		" C*                     # List meta info in r2 commands\n"
		" C-[@][ addr]           # delete metadata at given address\n"
		" CL[-] [addr]           # show 'code line' information (bininfo)\n"
		" CC [string]            # add comment\n"
		" Cv[-] offset reg name  # add var substitution\n"
		" Cs[-] [size] [[addr]]  # add string\n"
		" CS[-] [size]           # ...\n"
		" Cd[-] [fmt] [..]       # hexdump data\n"
		" Cm[-] [fmt] [..]       # format memory\n");
		break;
	case 'F':
		{
		RAnalFcn *f = r_anal_fcn_find (core->anal, core->offset,
				R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
		r_anal_fcn_from_string (core->anal, f, input+2);
		}
		break;
	}
	return R_TRUE;
}

static int cmd_macro(void *data, const char *input) {
	char *buf = NULL;
	char *p, *ptr = (char *)input;
	RCore *core = (RCore*)data;
	switch (*input) {
	case ')':
		r_cmd_macro_break (&core->cmd->macro, input+1);
		break;
	case '-':
		r_cmd_macro_rm (&core->cmd->macro, input+1);
		break;
	case '\0':
		r_cmd_macro_list (&core->cmd->macro);
		break;
	case '?':
		eprintf (
		"Usage: (foo\\n..cmds..\\n)\n"
		" Record macros grouping commands\n"
		" (foo args\\n ..)     ; define a macro\n"
		" (-foo)              ; remove a macro\n"
		" .(foo)              ; to call it\n"
		" ()                  ; break inside macro\n"
		" (                   ; list all defined macros\n"
		"Argument support:\n"
		" (foo x y\\n$1 @ $2)  ; define fun with args\n"
		" .(foo 128 0x804800) ; call it with args\n"
		"Iterations:\n"
		" .(foo\\n() $@)       ; define iterator returning iter index\n"
		" x @@ .(foo)         ; iterate over them\n"
		);
		break;
	default:
		if (input[strlen (input)-1] != ')') {
			buf = malloc (4096); // XXX: possible heap overflow here
			strcpy (buf, input);
			do {
				ptr = buf + strlen (buf);
				strcpy (ptr, ",");
				ptr++;
				fgets (ptr, 1024, stdin); // XXX: possible overflow // TODO: use r_cons here
				p = strchr (ptr, '#');
				if (p) *p = 0;
				else ptr[strlen (ptr)-1] = 0; // chop \n
				if (feof (stdin))
					break;
			} while (ptr[strlen (ptr)-1] != ')');
			ptr = buf;
		}
		r_cmd_macro_add (&core->cmd->macro, ptr);
		free (buf);
		break;
	}
	return 0;
}

static int r_core_cmd_pipe(RCore *core, char *radare_cmd, char *shell_cmd) {
#if __UNIX__
	int fds[2];
	int stdout_fd, status;

	stdout_fd = dup (1);
	pipe (fds);
	radare_cmd = r_str_trim_head (radare_cmd);
	shell_cmd = r_str_trim_head (shell_cmd);
	if (fork()) {
		dup2(fds[1], 1);
		close (fds[1]);
		close (fds[0]);
		r_core_cmd (core, radare_cmd, 0);
		r_cons_flush ();
		close (1);
		wait (&status);
		dup2 (stdout_fd, 1);
		close (stdout_fd);
	} else {
		close (fds[1]);
		dup2 (fds[0], 0);
		dup2 (2, 1);
		execl ("/bin/sh", "sh", "-c", shell_cmd, NULL);
	}
	return status;
#else
#warning r_core_cmd_pipe UNIMPLEMENTED FOR THIS PLATFORM
	eprintf ("r_core_cmd_pipe: unimplemented for this platform\n");
	return -1;
#endif
}

static int r_core_cmd_subst(RCore *core, char *cmd) {
	char *ptr, *ptr2, *str;
	int i, len = strlen(cmd), pipefd, ret;

	if (!*cmd || cmd[0]=='\0')
		return 0;
	cmd = r_str_trim_head_tail (cmd);

	/* quoted / raw command */
	if (cmd[0] =='.' && cmd[1] == '"') { /* interpret */
		ret = r_cmd_call (core->cmd, cmd);
		return ret;
	}
	if (cmd[0] == '"') {
		if (cmd[len-1] != '"') {
			eprintf ("parse: Missing ending '\"'\n");
			return -1;
		}
		cmd[len-1]='\0';
		ret = r_cmd_call (core->cmd, cmd+1);
		return ret;
	}

	/* comments */
	if (*cmd!='#') {
		ptr = strrchr (cmd, '#');
		if (ptr) ptr[0]='\0';
	}

	/* multiple commands */
	ptr = strrchr (cmd, ';');
	if (ptr) {
		ptr[0]='\0';
		if (r_core_cmd_subst (core, cmd) == -1) 
			return -1;
		cmd = ptr+1;
		r_cons_flush ();
	}

	/* pipe console to shell process */
	ptr = strchr (cmd, '|');
	if (ptr) {
		ptr[0] = '\0';
		cmd = r_str_clean (cmd);
		if (*cmd) r_core_cmd_pipe (core, cmd, ptr+1);
		else r_io_system (core->io, ptr+1);
		return 0;
	}

	/* bool conditions */
	ptr = strchr(cmd, '&');
	while (ptr&&ptr[1]=='&') {
		ptr[0]='\0';
		ret = r_cmd_call (core->cmd, cmd);
		if (ret == -1){
			eprintf ("command error(%s)\n", cmd);
			return ret;
		}
		for (cmd=ptr+2;cmd&&cmd[0]==' ';cmd=cmd+1);
		ptr = strchr (cmd, '&');
	}

	/* Out Of Band Input */
	free (core->oobi);
	core->oobi = NULL;
	ptr = strchr (cmd, '<');
	if (ptr) {
		ptr[0] = '\0';
		if (ptr[1]=='<') {
			/* this is a bit mess */
			const char *oprompt = r_line_singleton ()->prompt;
			oprompt = ">";
			for (str=ptr+2; str[0]==' '; str=str+1);
			eprintf ("==> Reading from stdin until '%s'\n", str);
			free (core->oobi);
			core->oobi = malloc (1);
			core->oobi[0] = '\0';
			core->oobi_len = 0;
			for (;;) {
				char buf[1024];
				int ret;
				printf ("> "); fflush (stdout);
				fgets (buf, sizeof (buf)-1, stdin); // XXX use r_line ??
				if (feof (stdin))
					break;
				buf[strlen (buf)-1]='\0';
				ret = strlen (buf);
				core->oobi_len+=ret;
				core->oobi = realloc (core->oobi, core->oobi_len+1);
				if (!strcmp (buf, str))
					break;
				strcat ((char *)core->oobi, buf);
			}
			r_line_singleton ()->prompt = oprompt;
		} else {
			for (str=ptr+1;str[0]== ' ';str=str+1);
			eprintf ("SLURPING FILE '%s'\n", str);
			core->oobi = (ut8*)r_file_slurp (str, &core->oobi_len);
			if (core->oobi == NULL)
				eprintf ("Cannot open file\n");
			else if (ptr == cmd)
				return r_core_cmd_buffer (core, (const char *)core->oobi);
		}
	}

	/* pipe console to file */
	ptr = strchr (cmd, '>');
	if (ptr) {
		ptr[0] = '\0';
		str = r_str_trim_head_tail (ptr+1+(ptr[1]=='>'));
		pipefd = r_cons_pipe_open (str, ptr[1]=='>');
		ret = r_core_cmd_subst (core, cmd);
		r_cons_flush ();
		r_cons_pipe_close (pipefd);
		return ret;
	}

	/* sub commands */
	ptr = strchr (cmd, '`');
	if (ptr) {
		ptr2 = strchr (ptr+1, '`');
		if (!ptr2) {
			eprintf ("parse: Missing '´' in expression.\n");
			return -1;
		} else {
			ptr[0] = '\0';
			ptr2[0] = '\0';
			str = r_core_cmd_str (core, ptr+1);
			for(i=0;str[i];i++)
				if (str[i]=='\n') str[i]=' ';
			cmd = r_str_concat (strdup (cmd), r_str_concat (str, ptr2+1));
			ret = r_core_cmd_subst (core, cmd);
			free (cmd);
			free (str);
			return ret;
		}
	}

	/* grep the content */
	ptr = strchr (cmd, '~');
	if (ptr) {
		ptr[0]='\0';
		r_cons_grep (ptr+1);
	} else r_cons_grep (NULL);

	/* seek commands */
	if (cmd[0]!='('&& cmd[0]!='"')
		ptr = strchr (cmd, '@');
	else ptr = NULL;
	if (ptr) {
		ut64 tmpoff, tmpbsz;
		char *ptr2 = strchr (ptr+1, ':');
		*ptr = '\0';
		cmd = r_str_clean (cmd);
		tmpoff = core->offset;
		tmpbsz = core->blocksize;
		if (ptr2) {
			*ptr2 = '\0';
			r_core_block_size (core, r_num_math (core->num, ptr2+1));
		}

		if (ptr[1]=='@') {
			// TODO: remove temporally seek (should be done by cmd_foreach)
			ret = r_core_cmd_foreach (core, cmd, ptr+2);
			//ret = -1; /* do not run out-of-foreach cmd */
		} else {
			if (!ptr[1] || r_core_seek (core, r_num_math (core->num, ptr+1), 1))
				ret = r_cmd_call (core->cmd, r_str_trim_head (cmd));
			else ret = 0;
		}
		if (ptr2) {
			*ptr2 = ':';
			r_core_block_size (core, tmpbsz);
		}
		r_core_seek (core, tmpoff, 1);
		*ptr = '@';
		return ret;
	}

	ret = r_cmd_call (core->cmd, r_str_trim_head (cmd));
	return ret;
}

R_API int r_core_cmd_foreach(RCore *core, const char *cmd, char *each) {
	int i=0,j;
	char ch;
	char *word = NULL;
	char *str, *ostr;
	RListIter *iter;
	RFlagItem *flag;
	ut64 oseek, addr;

	for (; *each==' '; each++);
	for (; *cmd==' '; cmd++);

	oseek = core->offset;
	ostr = str = strdup(each);
	//radare_controlc();

	switch (each[0]) {
	case '?':
		r_cons_printf (
		"Foreach '@@' iterator command:\n"
		" This command is used to repeat a command over a list of offsets.\n"
		" x @@ sym.           Run 'x' over all flags matching 'sym.'\n"
		" x @@.file           \"\" over the offsets specified in the file (one offset per line)\n"
		" x @@=off1 off2 ..   Manual list of offsets\n"
		" x @@=`pdf~call[0]`  Run 'x' at every call offset of the current function\n");
		break;
	case '=':
		/* foreach list of items */
		each = str+1;
		do {
			while (each[0]==' ')
				each = each+1;
			if (!*each) break;
			str = strchr (each, ' ');
			if (str) {
				str[0]='\0';
				addr = r_num_math (core->num, each);
				str[0]=' ';
			} else addr = r_num_math (core->num, each);
			eprintf ("; 0x%08"PFMT64x":\n", addr);
			each = str+1;
			r_core_seek (core, addr, 1);
			r_core_cmd (core, cmd, 0);
			r_cons_flush ();
		} while (str != NULL);
		break;
	case '.':
		if (each[1]=='(') {
			char cmd2[1024];
			// TODO: use controlc() here
			// XXX whats this 999 ?
			for(core->cmd->macro.counter=0;i<999;core->cmd->macro.counter++) {
				r_cmd_macro_call (&core->cmd->macro, each+2);
				if (core->cmd->macro.brk_value == NULL)
					break;

				addr = core->cmd->macro._brk_value;
				sprintf (cmd2, "%s @ 0x%08"PFMT64x"", cmd, addr);
				eprintf ("0x%08"PFMT64x" (%s)\n", addr, cmd2);
				r_core_seek (core, addr, 1);
				r_core_cmd (core, cmd2, 0);
				i++;
			}
		} else {
			char buf[1024];
			char cmd2[1024];
			FILE *fd = fopen (each+1, "r");
			if (fd) {
				core->cmd->macro.counter=0;
				while (!feof (fd)) {
					buf[0] = '\0';
					if (fgets (buf, 1024, fd) == NULL)
						break;
					addr = r_num_math (core->num, buf);
					eprintf ("0x%08"PFMT64x": %s\n", addr, cmd);
					sprintf (cmd2, "%s @ 0x%08"PFMT64x"", cmd, addr);
					r_core_seek (core, addr, 1); // XXX
					r_core_cmd (core, cmd2, 0);
					core->cmd->macro.counter++;
				}
				fclose (fd);
			} else eprintf ("Cannot open file '%s' to read offsets\n", each+1);
		}
		break;
	default:
		core->cmd->macro.counter = 0;
		//while(str[i]) && !core->interrupted) {
		while (str[i]) {
			j = i;
			for (;str[j]&&str[j]==' ';j++); // skip spaces
			for (i=j;str[i]&&str[i]!=' ';i++); // find EOS
			ch = str[i];
			str[i] = '\0';
			word = strdup (str+j);
			if (word == NULL)
				break;
			str[i] = ch;
			if (strchr (word, '*')) {
#if 0
				/* for all flags in current flagspace */
				list_for_each(pos, &flags) {
					flag_t *flag = (flag_t *)list_entry(pos, flag_t, list);
					//if (core->interrupted)
					//	break;
					/* filter per flag spaces */
	//				if ((flag_space_idx != -1) && (flag->space != flag_space_idx))
	//					continue;

					core->offset = flag->offset;
					radare_read(0);
					cons_printf("; @@ 0x%08"PFMT64x" (%s)\n", core->offset, flag->name);
					radare_cmd(cmd,0);
				}
#else
				eprintf ("No flags foreach implemented\n");
#endif
			} else {
				/* for all flags in current flagspace */
				r_list_foreach (core->flags->flags, iter, flag) {
					if (r_cons_singleton()->breaked)
						break;
					/* filter per flag spaces */
					if ((core->flags->space_idx != -1) && (flag->space != core->flags->space_idx))
						continue;
					if (word[0]=='\0' || strstr(flag->name, word) != NULL) {
						r_core_seek (core, flag->offset, 1);
						// TODO: Debug mode print
						//r_cons_printf ("# @@ 0x%08"PFMT64x" (%s)\n", core->offset, flag->name);
						r_core_cmd (core, cmd, 0);
					}
				}
	#if 0
				/* ugly copypasta from tmpseek .. */
				if (strstr(word, each)) {
					if (word[i]=='+'||word[i]=='-')
						core->offset = core->offset + r_num_math (get_math(core->num, word);
					else	core->offset = r_num_math (get_math(core->num, word);
					radare_read(0);
					cons_printf("; @@ 0x%08"PFMT64x"\n", core->offset);
					radare_cmd(cmd,0);
				}
	#endif
				r_cons_break (NULL, NULL);

				core->cmd->macro.counter++ ;
				free (word);
				word = NULL;
			}
		}
	}
	r_cons_break_end ();
	// XXX: use r_core_seek here
	core->offset = oseek;

	free (word);
	free (ostr);
	return R_TRUE;
}

R_API int r_core_cmd(RCore *core, const char *command, int log) {
	int len, rep, ret = R_FALSE;
	char *cmd, *ocmd;
	if (command != NULL) {
		/* list command plugins */
		if (!strcmp (command, ":")) {
			RListIter *iter = r_list_iterator (core->cmd->plist);
			while (r_list_iter_next (iter)) {
				RCmdPlugin *cp = (RCmdPlugin*) r_list_iter_get (iter);
				r_cons_printf ("%s: %s\n", cp->name, cp->desc);
			}
			return 0;
		}
		len = strlen (command)+1;
		ocmd = cmd = malloc (len+8192);
		if (ocmd == NULL)
			return R_FALSE;
		memcpy (cmd, command, len);
		cmd = r_str_trim_head_tail (cmd);

		rep = atoi (cmd);
		if (rep<1) rep = 1;
		if (rep>0) {
			ret = R_TRUE;
			while (*cmd>='0'&&*cmd<='9')
				cmd++;
			while (rep--) {
				ret = r_core_cmd_subst (core, cmd);
				if (ret<0)
					break;
			}
		}

		if (log) r_line_hist_add (command);

		free (core->oobi);
		free (ocmd);
		core->oobi = NULL;
		core->oobi_len = 0;
	}
	return ret;
}

R_API int r_core_cmd_file(RCore *core, const char *file) {
	int ret = R_TRUE;
	char *data, *odata = r_file_slurp (file, NULL);
	if (odata != NULL) {
		char *nl = strchr (odata, '\n');
		if (nl) {
			data = odata;
			do {
				*nl = '\0';
				if (r_core_cmd (core, data, 0) == -1) {
					eprintf ("r_core_cmd_file: Failed to run '%s'\n", data);
					ret = R_FALSE;
					break;
				}
				data = nl+1;
			} while ((nl = strchr (data, '\n')));
		}
		free (odata);
	} else ret = R_FALSE;
	return ret;
}

R_API int r_core_cmd_command(RCore *core, const char *command) {
	int len;
	char *buf, *rcmd, *ptr;
	rcmd = ptr = buf = r_sys_cmd_str (command, 0, &len);
	if (buf == NULL)
		return -1;
	while ((ptr = strstr (rcmd, "\n"))) {
		*ptr = '\0';
		if (r_core_cmd (core, rcmd, 0) == -1) {
			eprintf ("Error running command '%s'\n", rcmd);
			break;
		}
		rcmd += strlen (rcmd)+1;
	}
	r_str_free(buf);
	return 0;
}

static void cmd_dm(RCore *core, const char *input) {
	switch (input[0]) {
	case '?':
		r_cons_printf (
		"Usage: dm [size]\n"
		" dm         List memory maps of target process\n"
		" dm*        Same as above but in radare commands\n"
		" dm 4096    Allocate 4096 bytes in child process\n"
		" dm-0x8048  Deallocate memory map of address 0x8048\n"
		" dmi [addr|libname] [symname]   List symbols of target lib\n"
		" dmi* [addr|libname] [symname]  Same as above but in radare commands\n"
		//" dm rw- esp 9K  set 9KB of the stack as read+write (no exec)\n"
		"TODO: map files in process memory.\n");
		break;
	case 'i':
		{ // Move to a separate function
		ut64 addr = 0LL;
		char *libname = NULL, *symname = NULL;
		char *ptr = strdup (r_str_trim_head ((char*)input+2));
		char cmd[1024], *cmdret;
		int i, len;

		i = r_str_word_set0 (ptr);
		switch (i) {
			case 2: // get symname
				symname = r_str_word_get0 (ptr, 1);
			case 1: // get addr|libname
				addr = r_num_math (core->num, r_str_word_get0 (ptr, 0));
				if (!addr) libname = r_str_word_get0 (ptr, 0);
		}
		r_debug_map_sync (core->dbg); // update process memory maps
		RListIter *iter = r_list_iterator (core->dbg->maps);
		while (r_list_iter_next (iter)) {
			RDebugMap *map = r_list_iter_get (iter);
			if ((addr != -1 && (addr >= map->addr && addr < map->addr_end)) ||
				(libname != NULL && (strstr (map->name, libname)))) {
				if (symname)
					snprintf (cmd, sizeof (cmd), "rabin2 -b 0x%08"PFMT64x" -s%svn %s %s",
							map->addr, input[1]=='*'?"r":"", symname, map->name);
				else
					snprintf (cmd, sizeof (cmd), "rabin2 -b 0x%08"PFMT64x" -s%sv %s",
							map->addr, input[1]=='*'?"r":"", map->name);
				if ((cmdret = r_sys_cmd_str (cmd, 0, &len))) {
					r_cons_printf (cmdret);
					free (cmdret);
				}
				break;
			}
		}
		free (ptr);
		}
		break;
	case '*':
	case '-':
	case ' ':
		eprintf ("TODO\n");
		break;
	default:
		r_debug_map_sync (core->dbg); // update process memory maps
		r_debug_map_list (core->dbg, core->offset);
		break;
	}
}

static int step_until(RCore *core, ut64 addr) {
	ut64 off = r_debug_reg_get (core->dbg, "pc");
	if (off == 0LL) {
		eprintf ("Cannot 'drn pc'\n");
		return R_FALSE;
	}
	if (addr == 0LL) {
		eprintf ("Cannot continue until address 0\n");
		return R_FALSE;
	}
	do {
		r_debug_step (core->dbg, 1);
		if (checkbpcallback (core)) {
			eprintf ("Interrupted by a breakpoint\n");
			break;
		}
		off = r_debug_reg_get (core->dbg, "pc");
		// check breakpoint here
	} while (off != addr);
	return R_TRUE;
	
}

static int step_line(RCore *core, int times) {
	char file[512], file2[512];
	int find_meta, line, line2;
	ut64 off = r_debug_reg_get (core->dbg, "pc");
	if (off == 0LL) {
		eprintf ("Cannot 'drn pc'\n");
		return R_FALSE;
	}
	if (r_bin_meta_get_line (core->bin, off, file, sizeof (file), &line)) {
		eprintf ("--> 0x%08"PFMT64x" %s : %d\n", off, file, line);
		eprintf ("--> %s\n", r_file_slurp_line (file, line, 0));
		find_meta = R_FALSE;
	} else {
		eprintf ("--> Stepping until dwarf line\n");
		find_meta = R_TRUE;
	}
	do {
		r_debug_step (core->dbg, 1);
		if (checkbpcallback (core)) {
			eprintf ("Interrupted by a breakpoint\n");
			break;
		}
		off = r_debug_reg_get (core->dbg, "pc");
		if (!r_bin_meta_get_line (core->bin, off, file2, sizeof (file2), &line2)) {
			if (find_meta)
				continue;
			eprintf ("Cannot retrieve dwarf info at 0x%08"PFMT64x"\n", off);
			return R_FALSE;
		}
	} while (!strcmp (file, file2) && line == line2);
	eprintf ("--> 0x%08"PFMT64x" %s : %d\n", off, file2, line2);
	eprintf ("--> %s\n", r_file_slurp_line (file2, line2, 0));
	return R_TRUE;
}

static void cmd_debug_pid(RCore *core, const char *input) {
	const char *ptr;
	int pid, sig;
	switch (input[1]) {
	case 'k':
		/* XXX: not for threads? signal is for a whole process!! */
		/* XXX: but we want fine-grained access to process resources */
		pid = atoi (input+2);
		ptr = strchr (input, ' ');
		if (ptr) sig = atoi (ptr+1);
		else sig = 0;
		if (pid > 0) {
			eprintf ("Sending signal '%d' to pid '%d'\n",
				sig, pid);
			r_debug_kill (core->dbg, R_FALSE, sig);
		} else eprintf ("Invalid arguments\n");
		break;
	case 'n':
		eprintf ("TODO: debug_fork: %d\n", r_debug_fork (core->dbg));
		break;
	case 't':
		if (input[2] == 'n') {
			eprintf ("TODO: debug_clone: %d\n", r_debug_clone (core->dbg));
		} else
		if (input[2]=='=' || input[2]==' ')
			r_debug_select (core->dbg, core->dbg->pid,
				(int) r_num_math (core->num, input+3));
		else r_debug_thread_list (core->dbg, core->dbg->pid);
		break;
	case '?':
		r_cons_printf ("Usage: dp[=][pid]\n"
			" dp      list current pid and childrens\n"
			" dp 748  list childs of pid\n"
			" dp*     list all attachable pids\n"
			" dpa 377 attach and select this pid\n"
			" dp=748  select this pid\n"
			" dpn     Create new process (fork)\n"
			" dpnt    Create new thread (clone)\n"
			" dpt     List threads of current pid\n"
			" dpt 74  List threads of given process\n"
			" dpt=64  Attach to thread\n"
			" dpk P S send signal S to P process id\n");
		break;
	case 'a':
		r_debug_attach (core->dbg,
			(int) r_num_math (core->num, input+2));
		r_debug_select (core->dbg, core->dbg->pid, core->dbg->tid);
		break;
	case 'f':
		r_debug_select (core->dbg, core->file->fd->fd, core->dbg->tid);
		break;
	case '=':
		r_debug_select (core->dbg,
			(int) r_num_math (core->num, input+2), core->dbg->tid);
		break;
	case '*':
		r_debug_pid_list (core->dbg, 0);
		break;
	case ' ':
		r_debug_pid_list (core->dbg,
			(int) r_num_math (core->num, input+2));
		break;
	default:
		r_debug_pid_list (core->dbg, core->dbg->pid);
		break;
	}
}

static int cmd_debug(void *data, const char *input) {
	RCore *core = (RCore *)data;
	struct r_anal_aop_t analop;
	int len, times, sig;
	ut64 addr;
	char *ptr;

	switch (input[0]) {
	case 'x': // XXX : only for testing
		r_debug_execute (core->dbg, (ut8*)
			"\xc7\xc0\x03\x00\x00\x00\x33\xdb\x33"
			"\xcc\xc7\xc2\x10\x00\x00\x00\xcd\x80", 18);
		break;
	case 't':
		// TODO: Add support to change the tag
		if (input[1]=='r') {
			r_debug_trace_free (core->dbg);
			core->dbg->trace = r_debug_trace_new ();
		} else r_debug_trace_list (core->dbg, -1);
		break;
	case 'd':
		eprintf ("TODO: dd: file descriptors\n");
		switch (input[1]) {
		case 0:
			// r_debug_desc_list()
			break;
		case '*':
			// r_debug_desc_list(1)
			break;
		case 's':
			// r_debug_desc_seek()
			break;
		case 'd':
			// r_debug_desc_dup()
			break;
		case 'r':
			// r_debug_desc_read()
			break;
		case 'w':
			// r_debug_desc_write()
			break;
		case '-':
			// close file
			break;
		case ' ':
			// open file
			break;
		}
		break;
	case 's':
		times = atoi (input+2);
		if (times<1) times = 1;
		switch (input[1]) {
		case '?':
			r_cons_printf ("Usage: ds[ol] [count]\n"
				" ds       step one instruction\n"
				" ds 4     step 4 instructions\n"
				" dso 3    step over 3 instructions\n"
				" dsu addr step until address\n"
				" dsl      step one source line\n"
				" dsl 40   step 40 source lines\n");
			break;
		case 'u':
			r_reg_arena_swap (core->dbg->reg, R_TRUE);
			step_until (core, r_num_math (core->num, input+2)); // XXX dupped by times
			break;
		case 'o':
			r_reg_arena_swap (core->dbg->reg, R_TRUE);
			r_debug_step_over (core->dbg, times);
			if (checkbpcallback (core)) {
				eprintf ("Interrupted by a breakpoint\n");
				break;
			}
			break;
		case 'l':
			r_reg_arena_swap (core->dbg->reg, R_TRUE);
			step_line (core, times);
			break;
		default:
			r_reg_arena_swap (core->dbg->reg, R_TRUE);
			r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE);
			r_debug_step (core->dbg, times);
			if (checkbpcallback (core)) {
				eprintf ("Interrupted by a breakpoint\n");
				break;
			}
		}
		break;
	case 'b':
		r_core_cmd_bp (core, input);
		break;
	case 'H':
		eprintf ("TODO: transplant process\n");
		break;
	case 'c':
		switch (input[1]) {
		case '?':
			eprintf("Usage: dc[?]  -- continue execution\n"
				" dc?              show this help\n"
				" dc               continue execution of all childs\n"
				" dcf              continue until fork (TODO)\n"
				" dct [len]        traptrace from curseek to len, no argument to list\n"
				" dcu [addr]       continue until address\n"
				" dco [num]        step over N instructions\n"
				" dcs [num]        continue until syscall\n"
				" dcc              continue until call (use step into)\n"
				" dcr              continue until ret (uses step over)\n"
				" dck [sig] [pid]  continue sending kill 9 to process\n"
				" dc [pid]         continue execution of pid\n"
				" dc[-pid]         stop execution of pid\n"
				"TODO: dcu/dcr needs dbg.untilover=true??\n"
				"TODO: same for only user/libs side, to avoid steping into libs\n"
				"TODO: support for threads?\n");
			break;
		case 'c':
			r_reg_arena_swap (core->dbg->reg, R_TRUE);
			r_debug_continue_until_optype (core->dbg, R_ANAL_OP_TYPE_CALL, 0);
			checkbpcallback (core);
			break;
		case 'r':
			r_reg_arena_swap (core->dbg->reg, R_TRUE);
			r_debug_continue_until_optype (core->dbg, R_ANAL_OP_TYPE_RET, 1);
			checkbpcallback (core);
			break;
		case 'k':
			// select pid and r_debug_continue_kill (core->dbg, 
			r_reg_arena_swap (core->dbg->reg, R_TRUE);
			ptr = strchr (input+3, ' ');
			if (ptr) {
				bypassbp (core);
				int old_pid = core->dbg->pid;
				int old_tid = core->dbg->tid;
				int pid = atoi (ptr+1);
				int tid = pid; // XXX
				*ptr = 0;
				r_debug_select (core->dbg, pid, tid);
				r_debug_continue_kill (core->dbg, atoi (input+2));
				r_debug_select (core->dbg, old_pid, old_tid);
			} else r_debug_continue_kill (core->dbg, atoi (input+2));
			checkbpcallback (core);
			break;
		case 's':
			sig = r_num_math (core->num, input+2);
			eprintf ("Continue until syscall %d\n", sig);
			r_reg_arena_swap (core->dbg->reg, R_TRUE);
			r_debug_continue_syscall (core->dbg, sig);
			checkbpcallback (core);
			/* TODO : use r_syscall here, to retrieve syscall info */
			break;
		case 'u':
			addr = r_num_math (core->num, input+2);
			if (addr) {
				eprintf ("Continue until 0x%08"PFMT64x"\n", addr);
				bypassbp (core);
				r_reg_arena_swap (core->dbg->reg, R_TRUE);
				r_bp_add_sw (core->dbg->bp, addr, 1, R_BP_PROT_EXEC);
				r_debug_continue (core->dbg);
				checkbpcallback (core);
				r_bp_del (core->dbg->bp, addr);
			} else eprintf ("Cannot continue until address 0\n");
			break;
		case ' ':
			{
				int old_pid = core->dbg->pid;
				int pid = atoi (input+2);
				bypassbp (core);
				r_reg_arena_swap (core->dbg->reg, R_TRUE);
				r_debug_select (core->dbg, pid, core->dbg->tid);
				r_debug_continue (core->dbg);
				r_debug_select (core->dbg, old_pid, core->dbg->tid);
				checkbpcallback (core);
			}
			break;
		case 't':
			len = r_num_math (core->num, input+2);
			if (len == 0) {
				r_bp_traptrace_list (core->dbg->bp);
			} else {
				ut64 oaddr = 0LL;
				eprintf ("Trap tracing 0x%08"PFMT64x"-0x%08"PFMT64x"\n", core->offset, core->offset+len);
				r_reg_arena_swap (core->dbg->reg, R_TRUE);
				r_bp_traptrace_reset (core->dbg->bp, R_TRUE);
				r_bp_traptrace_add (core->dbg->bp, core->offset, core->offset+len);
				r_bp_traptrace_enable (core->dbg->bp, R_TRUE);
				do {
					ut8 buf[32];
					r_debug_continue (core->dbg);
					if (checkbpcallback (core)) {
						eprintf ("Interrupted by breakpoint\n");
						break;
					}
					addr = r_debug_reg_get (core->dbg, "pc");
					if (addr == 0LL) {
						eprintf ("pc=0\n");
						break;
					}
					if (addr == oaddr) {
						eprintf ("pc=opc\n");
						break;
					}
					oaddr = addr;
					/* XXX Bottleneck..we need to reuse the bytes read by traptrace */
					// XXX Do asm.arch should define the max size of opcode?
					r_core_read_at (core, addr, buf, 32); // XXX longer opcodes?
					r_anal_aop (core->anal, &analop, addr, buf, sizeof (buf));
				} while (r_bp_traptrace_at (core->dbg->bp, addr, analop.length));
				r_bp_traptrace_enable (core->dbg->bp, R_FALSE);
			}
			break;
		default:
			bypassbp (core);
			r_reg_arena_swap (core->dbg->reg, R_TRUE);
			r_debug_continue (core->dbg);
			checkbpcallback (core);
		}
		break;
	case 'm':
		cmd_dm (core, input+1);
		break;
	case 'r':
		cmd_reg (core, input+1);
		//r_core_cmd (core, "|reg", 0);
		break;
	case 'p':
		cmd_debug_pid (core, input);
		break;
	case 'h':
		if (input[1]==' ')
			r_debug_use (core->dbg, input+2);
		else r_debug_plugin_list (core->dbg);
		break;
	default:
		r_cons_printf ("Usage: d[sbhcrbo] [arg]\n"
		" dh [handler]   list or set debugger handler\n"
		" dH [handler]   transplant process to a new handler\n"
		" dd             file descriptors (!fd in r1)\n"
		" ds[ol] N       step, over, source line\n"
		" dp[=*?t][pid]  list, attach to process or thread id\n"
		" dc[?]          continue execution. dc? for more\n"
		" dr[?]          cpu registers, dr? for extended help\n"
		" db[?]          breakpoints\n"
		" dbt            display backtrace\n"
		" dt[r] [tag]    display instruction traces (dtr=reset)\n"
		" dm             show memory maps\n");
		break;
	}
	return 0;
}

//TODO: Fix disasm loop is mandatory
R_API char *r_core_disassemble_instr(RCore *core, ut64 addr, int l) {
	char *cmd, *ret = NULL;
	cmd = r_str_dup_printf ("pd %i @ 0x%08"PFMT64x, l, addr);
	if (cmd) {
		ret = r_core_cmd_str (core, cmd);
		free (cmd);
	}
	return ret;
}

R_API char *r_core_disassemble_bytes(RCore *core, ut64 addr, int b) {
	char *cmd, *ret = NULL;
	cmd = r_str_dup_printf ("pD %i @ 0x%08"PFMT64x, b, addr);
	if (cmd) {
		ret = r_core_cmd_str (core, cmd);
		free (cmd);
	}
	return ret;
}

R_API int r_core_cmd_buffer(void *user, const char *buf) {
	char *ptr, *optr, *str = strdup (buf);
	optr = str;
	ptr = strchr (str, '\n');
	while (ptr) {
		ptr[0]='\0';
		r_core_cmd (user, optr, 0);
		optr = ptr+1;
		ptr = strchr (str, '\n');
	}
	r_core_cmd (user, optr, 0);
	free (str);
	return R_TRUE;
}

R_API int r_core_cmdf(void *user, const char *fmt, ...) {
	char string[1024];
	int ret;
	va_list ap;
	va_start (ap, fmt);
	vsnprintf (string, sizeof (string), fmt, ap);
	ret = r_core_cmd ((RCore *)user, string, 0);
	va_end(ap);
	return ret;
}

R_API int r_core_cmd0(void *user, const char *cmd) {
	return r_core_cmd ((RCore *)user, cmd, 0);
}

/* return: pointer to a buffer with the output of the command */
R_API char *r_core_cmd_str(RCore *core, const char *cmd) {
	char *retstr = NULL;
	r_cons_reset ();
	if (r_core_cmd (core, cmd, 0) == -1) {
		eprintf ("Invalid command: %s\n", cmd);
		retstr = strdup ("");
	} else {
		r_cons_filter ();
		const char *static_str = r_cons_get_buffer ();
		retstr = strdup (static_str?static_str:"");
		r_cons_reset ();
	}
	return retstr;
}

void r_core_cmd_init(RCore *core) {
	core->cmd = r_cmd_new ();
	core->cmd->macro.num = core->num;
	core->cmd->macro.user = core;
	core->cmd->macro.cmd = r_core_cmd0;
	r_cmd_set_data (core->cmd, core);
	r_cmd_add (core->cmd, "x",        "alias for px", &cmd_hexdump);
	r_cmd_add (core->cmd, "mount",    "mount filesystem", &cmd_mount);
	r_cmd_add (core->cmd, "analysis", "analysis", &cmd_anal);
	r_cmd_add (core->cmd, "flag",     "get/set flags", &cmd_flag);
	r_cmd_add (core->cmd, "debug",    "debugger operations", &cmd_debug);
	r_cmd_add (core->cmd, "info",     "get file info", &cmd_info);
	r_cmd_add (core->cmd, "cmp",      "compare memory", &cmd_cmp);
	r_cmd_add (core->cmd, "seek",     "seek to an offset", &cmd_seek);
	r_cmd_add (core->cmd, "zign",     "zignatures", &cmd_zign);
	r_cmd_add (core->cmd, "Section",  "setup section io information", &cmd_section);
	r_cmd_add (core->cmd, "bsize",    "change block size", &cmd_bsize);
	r_cmd_add (core->cmd, "eval",     "evaluate configuration variable", &cmd_eval);
	r_cmd_add (core->cmd, "print",    "print current block", &cmd_print);
	r_cmd_add (core->cmd, "write",    "write bytes", &cmd_write);
	r_cmd_add (core->cmd, "Code",     "code metadata", &cmd_meta);
	r_cmd_add (core->cmd, "Project",  "project", &cmd_project);
	r_cmd_add (core->cmd, "open",     "open or map file", &cmd_open);
	r_cmd_add (core->cmd, "yank",     "yank bytes", &cmd_yank);
	r_cmd_add (core->cmd, "resize",   "change file size", &cmd_resize);
	r_cmd_add (core->cmd, "Visual",   "enter visual mode", &cmd_visual);
	r_cmd_add (core->cmd, "!",        "run system command", &cmd_system);
	r_cmd_add (core->cmd, "=",        "io pipe", &cmd_rap); 
	r_cmd_add (core->cmd, "#",        "calculate hash", &cmd_hash);
	r_cmd_add (core->cmd, "?",        "help message", &cmd_help);
	r_cmd_add (core->cmd, ".",        "interpret", &cmd_interpret);
	r_cmd_add (core->cmd, "/",        "search kw, pattern aes", &cmd_search);
	r_cmd_add (core->cmd, "(",        "macro", &cmd_macro);
	r_cmd_add (core->cmd, "quit",     "exit program session", &cmd_quit);
}
