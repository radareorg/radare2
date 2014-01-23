/* radare - LGPL - Copyright 2009-2013 - pancake */

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
			}// else eprintf ("cfg.debug is false\n");
		} else eprintf ("Usage: 'sr pc' ; seek to register\n");
	} else
	if (*input) {
		const char *inputnum = strchr (input+1, ' ');
		int sign = 1;
		inputnum = inputnum? inputnum+1: input+1;
		off = r_num_math (core->num, inputnum);
		if (*inputnum== '-') off = -off;
		if (input[0]!='/' && inputnum && isalpha (inputnum[0]) && off == 0) {
			if (!r_flag_get (core->flags, inputnum)) {
				eprintf ("Cannot find address for '%s'\n", inputnum);
				return R_FALSE;
			}
		}
		if (input[0]==' ') {
			switch (input[1]) {
			case '-': sign=-1;
			case '+': input++; break;
			}
		}

		switch (*input) {
		case 'C':
			if (input[1]=='*') {
				r_core_cmd0 (core, "C*~^CC");
			} else 
			if (input[1]==' ') {
				int n = 0;
				RListIter *iter;
				RAnalMetaItem *d, *item = NULL;
				/* seek to comment */
				r_list_foreach (core->anal->meta, iter, d) {
					if (d->type == R_META_TYPE_COMMENT) {
						if (strstr (d->str, input+2)) {
							if (n==1) {
								r_cons_printf ("0x%08"PFMT64x"  %s\n", item->from, item->str);
								r_cons_printf ("0x%08"PFMT64x"  %s\n", d->from, d->str);
							} else if (n>1) {
								r_cons_printf ("0x%08"PFMT64x"  %s\n", d->from, d->str);
							}
							item = d;
							n++;
						}
					}
				}
				switch (n) {
				case 0:
					eprintf ("No matching comments\n");
					break;
				case 1:
					r_cons_printf ("0x%08"PFMT64x"  %s\n", item->from, item->str);
					off = item->from;
					r_io_sundo_push (core->io, core->offset);
					r_core_seek (core, off, 1);
					r_core_block_read (core, 0);
					break;
				}

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
			{
			RAnalFunction *fcn = r_anal_fcn_find (core->anal, core->offset, 0);
			if (fcn)
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
				val += ret;
			} else
			for (val=i=0; i<n; i++) {
				ret = r_anal_op (core->anal, &op,
						core->offset, core->block, core->blocksize);
				if (ret<1) 
					break;
				r_core_seek_delta (core, ret);
				val += ret;
			}
			core->num->value = val;
			}
			break;
		case 'g':
			{
			RIOSection *s = r_io_section_get (core->io, 
				r_io_section_vaddr_to_offset (core->io,
				core->offset));
			if (s) r_core_seek (core, s->vaddr, 1);
			else r_core_seek (core, 0, 1);
			}
			break;
		case 'G':
			{
			RIOSection *s = r_io_section_get (core->io, 
				r_io_section_vaddr_to_offset (core->io,
				core->offset));
			// XXX: this +2 is a hack. must fix gap between sections
			if (s) r_core_seek (core, s->vaddr+s->size+2, 1);
			else r_core_seek (core, core->file->size, 1);
			}
			break;
		case '?':
			r_cons_printf (
			"Usage: s[+-] [addr]\n"
            " s                 print current address\n"
			" s 0x320           seek to this address\n"
			" s-                undo seek\n"
			" s+                redo seek\n"
			" s*                list undo seek history\n"
			" s++               seek blocksize bytes forward\n"
			" s--               seek blocksize bytes backward\n"
			" s+ 512            seek 512 bytes forward\n"
			" s- 512            seek 512 bytes backward\n"
			" sg/sG             seek begin (sg) or end (sG) of section or file\n"
			" s.hexoff          Seek honoring a base from core->offset\n"
			" sa [[+-]a] [asz]  seek asz (or bsize) aligned to addr\n"
			" sn/sp             seek next/prev scr.nkey\n"
			" s/ DATA           search for next occurrence of 'DATA'\n"
			" s/x 9091          search for next occurrence of \\x90\\x91\n"
			" sb                seek aligned to bb start\n"
			//" sp [page]  seek page N (page = block)\n"
			" so [num]          seek to N next opcode(s)\n"
			" sf                seek to next function (f->addr+f->size)\n"
			" sC str            seek to comment matching given string\n"
			" sr pc             seek to register\n");
			break;
		}
	} else r_cons_printf ("0x%"PFMT64x"\n", core->offset);
	return 0;
}
