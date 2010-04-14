/* radare - LGPL - Copyright 2010 pancake<nopcode.org> */

#include <r_asm.h>
#include <r_cons.h>
#include <r_flags.h>
#include <r_anal.h>
#include <r_print.h>

#if 0
R_API void r_print_disasm(RPrint *p, ut64 addr, ut8 *buf, int len) {
	int ret, idx, i; 
	int middle = 0;
	char str[128];
	char *line;
	char *comment;
	char *opstr;
	char *osl = NULL; // old source line
	RAsmAop asmop;
	RAnalAop analop;
	RAnalRefline *reflines;
	RFlagItem *flag;

	//r_anal_set_pc(&core->anal, core->offset);
	r_asm_set_pc (&core->assembler, core->offset);

	reflines = r_anal_reflines_get (&core->anal, core->offset,
		buf, len, -1, linesout);
	for (i=idx=ret=0; idx < len && i<l; idx+=ret,i++) {
		ut64 addr = core->offset + idx;
		r_asm_set_pc (&core->assembler, addr);
		//r_anal_set_pc (&core->anal, core->anal.pc + ret);
		if (show_comments) {
			comment = r_meta_get_string (&core->meta, R_META_COMMENT, addr);
			if (comment) {
				r_cons_strcat (comment);
				free (comment);
			}
		}
		line = r_anal_reflines_str (&core->anal, reflines, addr, linesopts);
		ret = r_asm_disassemble (&core->assembler, &asmop, buf+idx, len-idx);
		if (ret<1) {
			ret = 1;
			eprintf ("** invalid opcode at 0x%08"PFMT64x" **\n", core->assembler.pc + ret);
			continue;
		}
		r_anal_aop (&core->anal, &analop, addr, buf+idx, (int)(len-idx));
	
		if (adistrick)
			middle = r_anal_reflines_middle (&core->anal,
					reflines, addr, analop.length);

		if (show_lines && line)
			r_cons_strcat (line);
		if (show_offset)
			r_cons_printf ("0x%08"PFMT64x"  ", core->offset + idx);
		flag = r_flag_get_i (&core->flags, core->offset+idx);
		if (flag || show_bytes) {
			char *str, *extra = " ";
			if (flag) str = strdup (flag->name);
			else {
				str = strdup (asmop.buf_hex);
				if (strlen (str) > nb) {
					str[nb] = '.';
					str[nb+1] = '\0';
					extra = "";
				}
			}
			if (flag) {
				if (show_color)
					r_cons_printf (Color_BWHITE"*[ %*s]  "Color_RESET, (nb)-4, str);
				else r_cons_printf ("*[ %*s]  ", (nb)-4, str);
			} else r_cons_printf ("%*s %s", nb, str, extra);
			free (str);
		} else r_cons_printf ("%*s  ", (nb), "");
		if (show_color) {
			switch (analop.type) {
			case R_ANAL_OP_TYPE_NOP:
				r_cons_printf (Color_BLUE);
				break;
			case R_ANAL_OP_TYPE_JMP:
			case R_ANAL_OP_TYPE_UJMP:
			case R_ANAL_OP_TYPE_CJMP:
				r_cons_printf (Color_GREEN);
				break;
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
		if (pseudo) {
			r_parse_parse (&core->parser, asmop.buf_asm, str);
			opstr = str;
		} else if (filter) {
			r_parse_filter (&core->parser, &core->flags, asmop.buf_asm, str);
			opstr = str;
		} else opstr = asmop.buf_asm;
		r_cons_strcat (opstr);
		if (show_color)
			r_cons_strcat (Color_RESET);
		if (show_dwarf) {
			char *sl = r_bin_meta_get_source_line (&core->bin, addr);
			int len = strlen (opstr);
			if (len<30)
				len = 30-len;
			if (sl)
			if (!osl || (osl && strcmp (sl, osl))) {
				while (len--)
					r_cons_strcat (" ");
				if (show_color)
					r_cons_printf (Color_TURQOISE"  ; %s"Color_RESET, sl);
				else r_cons_printf ("  ; %s\n", sl);
				free (osl);
				osl = sl;
			}
		}
		if (middle != 0) {
			ret = ret-middle;
			r_cons_printf (" ;  *middle* %d", ret);
		}
		r_cons_newline ();
		if (line) {
			if (show_lines && analop.type == R_ANAL_OP_TYPE_RET) {
				if (strchr (line, '>'))
					memset (line, ' ', strlen (line));
				r_cons_strcat (line);
				r_cons_strcat ("; ------------------------------------\n");
			}
			free (line);
		}
	}
	free (reflines);
	free (osl);
}
#endif
