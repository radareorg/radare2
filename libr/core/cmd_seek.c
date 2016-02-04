/* radare - LGPL - Copyright 2009-2016 - pancake */

#include "r_types.h"
#include "r_config.h"
#include "r_cons.h"
#include "r_core.h"
#include "r_debug.h"
#include "r_io.h"

static void __init_seek_line (RCore *core) {
	ut64 from, to;

	r_config_bump (core->config, "lines.to");
	from = r_config_get_i (core->config, "lines.from");
	to = r_config_get_i (core->config, "lines.to");
	if (r_core_lines_initcache (core, from, to) == -1) {
		eprintf ("ERROR: \"lines.from\" and \"lines.to\" must be set\n");
	}
}

static void __get_current_line (RCore *core) {
	if (core->print->lines_cache_sz > 0) {
		int curr = r_util_lines_getline (core->print->lines_cache, core->print->lines_cache_sz, core->offset);
		r_cons_printf ("%d\n", curr);
	}
}

static void __seek_line_absolute (RCore *core, int numline) {
	if (numline < 1 || numline > core->print->lines_cache_sz - 1) {
		eprintf ("ERROR: Line must be between 1 and %d\n", core->print->lines_cache_sz-1);
	} else {
		r_core_seek (core, core->print->lines_cache[numline-1], 1);
	}
}

static void __seek_line_relative (RCore *core, int numlines) {
	int curr = r_util_lines_getline (core->print->lines_cache, core->print->lines_cache_sz, core->offset);
	if (numlines > 0 && curr+numlines >= core->print->lines_cache_sz-1) {
		eprintf ("ERROR: Line must be < %d\n", core->print->lines_cache_sz-1);
	} else if (numlines < 0 && curr+numlines < 1) {
		eprintf ("ERROR: Line must be > 1\n");
	} else {
		r_core_seek (core, core->print->lines_cache[curr+numlines-1], 1);
	}
}

static void __clean_lines_cache (RCore *core) {
	core->print->lines_cache_sz = -1;
	R_FREE (core->print->lines_cache);
}

R_API int r_core_lines_currline (RCore *core) { // make priv8 again
	int imin = 0;
	int imax = core->print->lines_cache_sz;
	int imid = 0;

	while (imin <= imax) {
		imid = imin + ((imax - imin) / 2);
		if (core->print->lines_cache[imid] == core->offset) {
			return imid;
		}
		else if (core->print->lines_cache[imid] < core->offset)
			imin = imid + 1;
		else
			imax = imid - 1;
	}
	return imin;
}

R_API int r_core_lines_initcache (RCore *core, ut64 start_addr, ut64 end_addr) {
	int i, line_count;
	int bsz = core->blocksize;
	char *buf;
	ut64 off = start_addr;
	ut64 baddr; 
	if (start_addr == UT64_MAX || end_addr == UT64_MAX) {
		return -1;
	}

	free (core->print->lines_cache);
	core->print->lines_cache = R_NEWS0 (ut64, bsz);
	if (!core->print->lines_cache) {
		return -1;
	}

#if 0				//TODO: check this stuff
	{
		RIOSection *s = r_io_section_mget_in (core->io, core->offset);
		baddr = s ? s->addr : r_config_get_i (core->config, "bin.baddr");
	}
#endif
	baddr = r_config_get_i (core->config, "bin.baddr");

	line_count = start_addr ? 0 : 1;
	core->print->lines_cache[0] = start_addr ? 0 : baddr;
	buf = malloc (bsz);
	if (!buf) {
		return -1;
	}
	r_cons_break_push (NULL, NULL);
	while (off < end_addr) {
		if (r_cons_is_breaked ()) {
			break;
		}
		r_io_read_at (core->io, off, (ut8*)buf, bsz);
		for (i = 0; i < bsz; i++) {
			if (buf[i] == '\n') {
				core->print->lines_cache[line_count] = start_addr ? off+i+1 : off+i+1+baddr;
				line_count++;
				if (line_count % bsz == 0) {
					ut64 *tmp = realloc (core->print->lines_cache,
						(line_count+bsz)*sizeof(ut64));
					if (tmp) {
						core->print->lines_cache = tmp;
					} else {
						R_FREE (core->print->lines_cache);
						goto beach;
					}
				}
			}
		}
		off += bsz;
	}
	free (buf);
	r_cons_break_pop ();
	return line_count;
beach:
	free (buf);
	r_cons_break_pop ();
	return -1;
}

static int cmd_seek(void *data, const char *input) {
	RCore *core = (RCore *)data;
	char *cmd, *p;
	ut64 off;

	if (*input == 'r') {
		if (input[1] && input[2]) {
			if (core->io->debug) {
				off = r_debug_reg_get (core->dbg, input + 2);
				r_io_sundo_push (core->io, core->offset, r_print_get_cursor (core->print));
				r_core_seek (core, off, 1);
			} else {
				RReg *orig = core->dbg->reg;
				core->dbg->reg = core->anal->reg;
				off = r_debug_reg_get (core->dbg, input + 2);
				core->dbg->reg = orig;
				r_core_seek (core, off, 1);
			}
		} else eprintf ("|Usage| 'sr PC' seek to program counter register\n");
	}
	if (*input) {
		char* ptr;
		if ((ptr = strstr(input, "+.")) != NULL) {
			char* dup = strdup(input);
			dup[ptr - input] = '\x00';
			off = r_num_math (core->num, dup + 1);
			core->offset = off;
			free (dup);
		}
		const char *inputnum = strchr (input, ' ');
		int sign = 1;
		{
			const char *u_num = inputnum? inputnum + 1: input + 1;
			off = r_num_math (core->num, u_num);
			if (*u_num == '-') off = -off;
		}
#if 0
		if (input[0]!='/' && inputnum && isalpha (inputnum[0]) && off == 0) {
			if (!r_flag_get (core->flags, inputnum)) {
				eprintf ("Cannot find address for '%s'\n", inputnum);
				return false;
			}
		}
#endif
		if (input[0]==' ') {
			switch (input[1]) {
			case '-': sign=-1;
			case '+': input++; break;
			}
		}

		switch (*input) {
		case 'C':
			if (input[1]=='*') {
				r_core_cmd0 (core, "C*~^\"CC");
			} else
			if (input[1]==' ') {
				typedef struct {
					ut64 addr;
					char *str;
				} MetaCallback;
				int count = 0;
				MetaCallback cb = { 0, NULL };
				ut64 addr;
				char key[128];
				const char *val, *comma;
				char *list = sdb_get (core->anal->sdb_meta, "meta.C", 0);
				char *str, *next, *cur = list;
				if (list) {
					for (;;) {
						cur = sdb_anext (cur, &next);
						addr = sdb_atoi (cur);
						snprintf (key, sizeof (key)-1, "meta.C.0x%"PFMT64x, addr);
						val = sdb_const_get (core->anal->sdb_meta, key, 0);
						if (val) {
							comma = strchr (val, ',');
							if (comma) {
								str = (char *)sdb_decode (comma+1, 0);
								if (strstr (str, input+2)) {
									r_cons_printf ("0x%08"PFMT64x"  %s\n", addr, str);
									count++;
									cb.addr = addr;
									free (cb.str);
									cb.str = str;
								} else free (str);
							}
						} else eprintf ("sdb_const_get key not found '%s'\n", key);
						if (!next)
							break;
						cur = next;
					}
				}

				switch (count) {
				case 0:
					eprintf ("No matching comments\n");
					break;
				case 1:
					off = cb.addr;
					r_io_sundo_push (core->io, core->offset, r_print_get_cursor (core->print));
					r_core_seek (core, off, 1);
					r_core_block_read (core);
					break;
				default:
					eprintf ("Too many results\n");
					break;
				}
				free (cb.str);
			} else {
				const char *help_msg[] = {
					"Usage:", "sC", "Comment grep",
					"sC", "*", "List all comments",
					"sC", " str", "Seek to the first comment matching 'str'",
					NULL };
				r_core_cmd_help (core, help_msg);
			}
			break;
		case ' ':
			r_io_sundo_push (core->io, core->offset, r_print_get_cursor (core->print));
			r_core_seek (core, off * sign, 1);
			r_core_block_read (core);
			break;
		case '/':
			{
			const char *pfx = r_config_get (core->config, "search.prefix");
			ut64 from = r_config_get_i (core->config, "search.from");
//kwidx cfg var is ignored
			int kwidx = core->search->n_kws; //(int)r_config_get_i (core->config, "search.kwidx")-1;
			if (kwidx<0) kwidx = 0;
			switch (input[1]) {
			case ' ':
			case 'v':
			case 'V':
			case 'w':
			case 'W':
			case 'z':
			case 'm':
			case 'c':
			case 'A':
			case 'e':
			case 'E':
			case 'i':
			case 'R':
			case 'r':
			case '/':
			case 'x':
				r_config_set_i (core->config, "search.from", core->offset+1);
				r_config_set_i (core->config, "search.count", 1);
				r_core_cmdf (core, "s+1; %s; s-1; s %s%d_0; f-%s%d_0",
					input, pfx, kwidx, pfx, kwidx, pfx, kwidx);
				r_config_set_i (core->config, "search.from", from);
				r_config_set_i (core->config, "search.count", 0);
				break;
			case '?':
				eprintf ("Usage: s/.. arg.\n");
				r_cons_printf ("/?\n");
				break;
			default:
				eprintf ("unknown search method\n");
				break;
			}
			}
			break;
		case '.':
			for (input++;*input=='.';input++);
			r_core_seek_base (core, input);
			break;
		case '*':
		case '=':
		case 'j':
			r_io_sundo_list (core->io, input[0]);
			break;
		case '+':
			if (input[1]!='\0') {
				int delta = (input[1]=='+')? core->blocksize: off;
				r_io_sundo_push (core->io, core->offset, r_print_get_cursor (core->print));
				r_core_seek_delta (core, delta);
			} else {
				RIOUndos *undo = r_io_sundo_redo (core->io);
				if (undo != NULL)
					r_core_seek (core, undo->off, 0);
			}
			break;
		case '-':
			if (input[1]!='\0') {
				int delta = (input[1]=='-') ? -core->blocksize: -off;
				r_io_sundo_push (core->io, core->offset, r_print_get_cursor (core->print));
				r_core_seek_delta (core, delta);
			} else {
				RIOUndos *undo = r_io_sundo (core->io, core->offset);
				if (undo) {
					r_core_seek (core, undo->off, 0);
					r_core_block_read (core);
				}
			}
			break;
		case 'n':
			r_io_sundo_push (core->io, core->offset, r_print_get_cursor (core->print));
			r_core_seek_next (core, r_config_get (core->config, "scr.nkey"));
			break;
		case 'p':
			r_io_sundo_push (core->io, core->offset, r_print_get_cursor (core->print));
			r_core_seek_previous (core, r_config_get (core->config, "scr.nkey"));
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
				r_cmd_call (core->rcmd, cmd);
				free (cmd);
			}
			r_io_sundo_push (core->io, core->offset, r_print_get_cursor (core->print));
			r_core_seek_align (core, off, 0);
			break;
		case 'b':
			if (off == 0)
				off = core->offset;
			r_io_sundo_push (core->io, core->offset, r_print_get_cursor (core->print));
			r_core_anal_bb_seek (core, off);
			break;
		case 'f': // "sf"
			if (strlen(input) > 2 && input[1]==' ') {
				RAnalFunction *fcn = r_anal_fcn_find_name (core->anal, input+2);
				if (fcn) {
					r_core_seek (core, fcn->addr, 1);
				}
				break;
			}
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			if (fcn) {
				r_core_seek (core, fcn->addr + r_anal_fcn_size (fcn), 1);
			}
			break;
		case 'o': // "so"
			{
			RAnalOp op;
			int val=0, ret, i, n = r_num_math (core->num, input+1);
			if (n==0) n = 1;
			if (n<0) {
				int instr_len;
				ut64 addr = core->offset;
				int numinstr = n * -1;
				if (r_core_prevop_addr (core, core->offset, numinstr, &addr)) {
					ret = core->offset - addr;
				} else {
					ret = r_core_asm_bwdis_len (core, &instr_len, &addr, numinstr);
				}
				r_core_seek (core, addr, true);
				val += ret;
			} else {
				for (val=i=0; i<n; i++) {
					ret = r_anal_op (core->anal, &op,
							core->offset, core->block, core->blocksize);
					if (ret<1)
						ret = 1;
					r_core_seek_delta (core, ret);
					val += ret;
				}
			}
			core->num->value = val;
			}
			break;
		case 'g': // "sg"
			{
				SdbList *secs = r_io_section_vget_secs_at (core->io, core->offset);
				RIOSection *s = secs ? ls_pop (secs) : NULL;
				ls_free (secs);
				if (s) r_core_seek (core, s->vaddr, 1);
				else r_core_seek (core, 0, 1);
			}
			break;
		case 'G': // "sG"
			{
				if (!core->file) break;				//broken concept
				SdbList *secs = r_io_section_vget_secs_at (core->io, core->offset);
				RIOSection *s = secs ? ls_pop (secs) : NULL;
				ls_free (secs);
				// XXX: this +2 is a hack. must fix gap between sections
				if (s) r_core_seek (core, s->vaddr+s->size+2, 1);
				else r_core_seek (core, r_io_desc_size (core->file->desc), 1);
			}
			break;
		case 'l': // "sl"
			{
			int sl_arg = r_num_math (core->num, input+1);
			const char *help_msg[] = {
				"Usage:", "sl+ or sl- or slc", "",
				"sl", " [line]", "Seek to absolute line",
				"sl", "[+-][line]", "Seek to relative line",
				"slc", "", "Clear line cache",
				"sll", "", "Show total number of lines",
				NULL };
			switch (input[1]) {
			case 0:
				if (!core->print->lines_cache) {
					__init_seek_line (core);
				}
				__get_current_line (core);
				break;
			case ' ':
				if (!core->print->lines_cache) {
					__init_seek_line (core);
				}
				__seek_line_absolute (core, sl_arg);
				break;
			case '+':
			case '-':
				if (!core->print->lines_cache) {
					__init_seek_line (core);
				}
				__seek_line_relative (core, sl_arg);
				break;
			case 'c':
				__clean_lines_cache (core);
				break;
			case 'l':
				if (!core->print->lines_cache) {
					__init_seek_line (core);
				}
				eprintf ("%d lines\n", core->print->lines_cache_sz-1);
				break;
			case '?':
				r_core_cmd_help (core, help_msg);
				break;
			}
			}
			break;
		case '?': {
			const char * help_message[] = {
			"Usage: s", "", " # Seek commands",
			"s", "", "Print current address",
			"s", " addr", "Seek to address",
			"s-", "", "Undo seek",
			"s-", " n", "Seek n bytes backward",
			"s--", "", "Seek blocksize bytes backward",
			"s+", "", "Redo seek",
			"s+", " n", "Seek n bytes forward",
			"s++", "", "Seek blocksize bytes forward",
			"s[j*=]", "", "List undo seek history (JSON, =list, *r2)",
			"s/", " DATA", "Search for next occurrence of 'DATA'",
			"s/x", " 9091", "Search for next occurrence of \\x90\\x91",
			"s.", "hexoff", "Seek honoring a base from core->offset",
			"sa", " [[+-]a] [asz]", "Seek asz (or bsize) aligned to addr",
			"sb", "", "Seek aligned to bb start",
			"sC", "[?] string", "Seek to comment matching given string",
			"sf", "", "Seek to next function (f->addr+f->size)",
			"sf", " function", "Seek to address of specified function",
			"sg/sG", "", "Seek begin (sg) or end (sG) of section or file",
			"sl", "[?] [+-]line", "Seek to line",
			"sn/sp", "", "Seek next/prev scr.nkey",
			"so", " [N]", "Seek to N next opcode(s)",
			"sr", " pc", "Seek to register",
			//"sp [page]  seek page N (page = block)",
			NULL
			};
			r_core_cmd_help(core, help_message);
		}
			break;
		}
	} else r_cons_printf ("0x%"PFMT64x"\n", core->offset);
	return 0;
}
