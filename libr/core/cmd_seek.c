/* radare - LGPL - Copyright 2009-2014 - pancake */

// XXX DUP
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

static int cmd_seek(void *data, const char *input) {
	RCore *core = (RCore *)data;
	char *cmd, *p;
	ut64 off;

	if (*input=='r') {
		if (input[1] && input[2]) {
			if (core->io->debug) {
				off = r_debug_reg_get (core->dbg, input+2);
				r_io_sundo_push (core->io, core->offset);
				r_core_seek (core, off, 1);
			} else {
				RReg *orig = core->dbg->reg;
				core->dbg->reg = core->anal->reg;
				off = r_debug_reg_get (core->dbg, input+2);
				core->dbg->reg = orig;
				r_core_seek (core, off, 1);
			}
		} else eprintf ("|Usage| 'sr pc' seek to program counter register\n");
	} else
	if (*input) {
		const char *inputnum = strchr (input, ' ');
		int sign = 1;
		inputnum = inputnum? inputnum+1: input+1;
		off = r_num_math (core->num, inputnum);
		if (*inputnum== '-') off = -off;
#if 0
		if (input[0]!='/' && inputnum && isalpha (inputnum[0]) && off == 0) {
			if (!r_flag_get (core->flags, inputnum)) {
				eprintf ("Cannot find address for '%s'\n", inputnum);
				return R_FALSE;
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
					r_io_sundo_push (core->io, core->offset);
					r_core_seek (core, off, 1);
					r_core_block_read (core, 0);
					break;
				default:
					eprintf ("Too many results\n");
					break;
				}
				free (cb.str);
			} else eprintf ("Usage: sC[?*] comment-grep\n"
				"sC*        list all comments\n"
				"sC const   seek to comment matching 'const'\n");
			break;
		case ' ':
			r_io_sundo_push (core->io, core->offset);
			r_core_seek (core, off*sign, 1);
			r_core_block_read (core, 0);
			break;
		case '/':
			{
			const char *pfx = r_config_get (core->config, "search.prefix");
//kwidx cfg var is ignored
			int kwidx = core->search->n_kws; //(int)r_config_get_i (core->config, "search.kwidx")-1;
			if (kwidx<0) kwidx = 0;
			switch (input[1]) {
			case ' ':
			case 'x':
				r_config_set_i (core->config, "search.count", 1);
				r_core_cmdf (core, "s+1; p8 ; .%s;s-1;s %s%d_0;f-%s%d_0",
					input, pfx, kwidx, pfx, kwidx, pfx, kwidx);
				r_config_set_i (core->config, "search.count", 0);
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
			r_io_sundo_list (core->io);
			break;
		case '+':
			if (input[1]!='\0') {
				int delta = (input[1]=='+')? core->blocksize: off;
				r_io_sundo_push (core->io, core->offset);
				r_core_seek_delta (core, delta);
			} else {
				off = r_io_sundo_redo (core->io);
				if (off != UT64_MAX)
					r_core_seek (core, off, 0);
			}
			break;
		case '-':
			if (input[1]!='\0') {
				int delta = (input[1]=='-') ? -core->blocksize: -off;
				r_io_sundo_push (core->io, core->offset);
				r_core_seek_delta (core, delta);
			} else {
				off = r_io_sundo (core->io, core->offset);
				if (off != UT64_MAX)
					r_core_seek (core, off, 0);
			}
			r_core_block_read (core, 1);
			break;
		case 'n':
			r_io_sundo_push (core->io, core->offset);
			r_core_seek_next (core, r_config_get (core->config, "scr.nkey"));
			break;
		case 'p':
			r_io_sundo_push (core->io, core->offset);
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
			r_io_sundo_push (core->io, core->offset);
			r_core_seek_align (core, off, 0);
			break;
		case 'b':
			if (off == 0)
				off = core->offset;
			r_io_sundo_push (core->io, core->offset);
			r_core_anal_bb_seek (core, off);
			break;
		case 'f':
			if (strlen(input) > 2 && input[1]==' ') {
				RAnalFunction *fcn = r_anal_fcn_find_name (core->anal, input+2);
				if (fcn) {
					r_core_seek (core, fcn->addr, 1);
				}
				break;
			}
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			if (fcn) {
				r_core_seek (core, fcn->addr+fcn->size, 1);
			}
			break;
		case 'o':
			{
			RAnalOp op;
			int val=0, ret, i, n = r_num_math (core->num, input+1);
			if (n==0) n = 1;
			if (n<0) {
				int ret = prevopsz (core, n);
				ret = r_anal_op (core->anal, &op,
						core->offset, core->block, core->blocksize);
				if (ret<1) ret = 1;
				val += ret;
			} else
			for (val=i=0; i<n; i++) {
				ret = r_anal_op (core->anal, &op,
						core->offset, core->block, core->blocksize);
				if (ret<1)
					ret = 1;
				r_core_seek_delta (core, ret);
				val += ret;
			}
			core->num->value = val;
			}
			break;
		case 'g':
			{
			RIOSection *s = r_io_section_vget (core->io, core->offset);
			if (s) r_core_seek (core, s->vaddr, 1);
			else r_core_seek (core, 0, 1);
			}
			break;
		case 'G':
			{
			RIOSection *s = r_io_section_vget (core->io, core->offset);
			// XXX: this +2 is a hack. must fix gap between sections
			if (s) r_core_seek (core, s->vaddr+s->size+2, 1);
			else r_core_seek (core, r_io_desc_size (core->io, core->file->desc), 1);
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
			"s*", "", "List undo seek history",
			"s/", " DATA", "Search for next occurrence of 'DATA'",
			"s/x", " 9091", "Search for next occurrence of \\x90\\x91",
			"s.", "hexoff", "Seek honoring a base from core->offset",
			"sa", " [[+-]a] [asz]", "Seek asz (or bsize) aligned to addr",
			"sb", "", "Seek aligned to bb start",
			"sC", " string", "Seek to comment matching given string",
			"sf", "", "Seek to next function (f->addr+f->size)",
			"sf", " function", "Seek to address of specified function",
			"sg/sG", "", "Seek begin (sg) or end (sG) of section or file",
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
