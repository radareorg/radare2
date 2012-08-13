/* radare - LGPL - Copyright 2009-2012 // pancake<nopcode.org> */

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
	case '0': // 0xFF
		for (j=0; j<size; j++)
			if (bufz[j] == 0)
				ret++;
		break;
	case 'F': // 0xFF
		for (j=0; j<size; j++)
			if (bufz[j] == 0xff)
				ret++;
		break;
	case 'e': // entropy
		ret = (ut8) (r_hash_entropy_fraction (bufz, size)*255);
		break;
	case 'h': // head
	default:
		ret = *bufz;
	}
	return ret;
}

R_API void r_core_print_cmp(RCore *core, ut64 from, ut64 to) {
	long int delta = 0;
	int col = core->cons->columns>123;
	ut8 *b = malloc (core->blocksize);
	ut64 addr = core->offset;
	memset (b, 0xff, core->blocksize);
	delta = addr - from;
	r_core_read_at (core, to+delta, b, core->blocksize);
	r_print_hexdiff (core->print, core->offset, core->block, to+delta, b, core->blocksize, col);
	free (b);
}

static int cmd_print(void *data, const char *input) {
	RCore *core = (RCore *)data;
	int i, l, len = core->blocksize;
	ut32 tbs = core->blocksize;
	ut8 *ptr = core->block;

	/* TODO: Change also blocksize for 'pd'.. */
	l = len;
	if (input[0] && input[1]) {
		if (input[2]) {
			l = (int) r_num_math (core->num, input+(input[1]==' '?2:3));
			/* except disasm and memoryfmt (pd, pm) */
			if (input[0] != 'd' && input[0] != 'm') {
				if (l>0) len = l;
				if (l>tbs) r_core_block_size (core, l);
				l = len;
			}
		}// else l = 0;
	} else l = len;

	i = r_config_get_i (core->config, "io.maxblk");
	if (i && l > i) {
		eprintf ("This block size is too big. Did you mean 'p%c @ %s' instead?\n",
				*input, input+2);
		return R_FALSE;
	}

	if (input[0] && input[0]!='Z' && input[1] == 'f') {
		RAnalFunction *f = r_anal_fcn_find (core->anal, core->offset,
				R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
		if (f) len = f->size;
		else eprintf ("Cannot find function at 0x%08"PFMT64x"\n", core->offset);
	}
	core->num->value = len;
	switch (*input) {
	case '%':
		{
			ut64 off = core->io->off;
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
		switch (input[1]) {
		case '?': // entropy
			eprintf ("Usage: p=[bep?]\n");
			eprintf (" p=   print bytes of current block in bars\n");
			eprintf (" p=b  same as above\n");
			eprintf (" p=e  same as above but with entropy\n");
			eprintf (" p=p  print number of printable bytes for each filesize/blocksize\n");
			break;
		case 'e': // entropy
			{
			ut8 *p;
			int psz, i = 0;
			int fsz = core->file?core->file->size:0;
			psz = fsz/core->blocksize;
			ptr = malloc (core->blocksize);
			eprintf ("offset = num * %d\n", psz);
			p = malloc (psz);
			for (i=0; i<core->blocksize; i++) {
				r_core_read_at (core, i*psz, p, psz);
				ptr[i] = (ut8) (256 * r_hash_entropy_fraction (p, psz));
			}
			free (p);
			}
			break;
		case 'p': // printable chars
			{
			ut8 *p;
			int psz, i = 0, j, k;
			int fsz = core->file?core->file->size:0;
			psz = fsz/core->blocksize;
			ptr = malloc (core->blocksize);
			p = malloc (psz);
			for (i=0; i<core->blocksize; i++) {
				r_core_read_at (core, i*psz, p, psz);
				for (j=k=0; j<psz; j++) {
					if (IS_PRINTABLE (p[j]))
						k++;
				}
				ptr[i] = k;
			}
			free (p);
			}
			break;
		}
		r_print_fill (core->print, ptr, core->blocksize);
if (ptr != core->block)
free (ptr);
		/* TODO: Reimplement using API */ {
			char *out = r_sys_cmd_strf ("rahash2 -a entropy -b 512 '%s'", core->file->filename);
			if (out) {
				r_cons_strcat (out);
				free (out);
			}
		}
		break;
	case 'b': {
		const int size = len*8;
		char *buf = malloc (size+1);
		if (buf) {
			r_str_bits (buf, core->block, size, NULL);
			r_cons_printf ("%s\n", buf);
			free (buf);
		} else eprintf ("ERROR: Cannot malloc %d bytes\n", size);
		}
		break;
	case 'w':
		r_print_hexdump (core->print, core->offset, core->block, len, 32, 4);
		break;
	case 'q':
		r_print_hexdump (core->print, core->offset, core->block, len, 64, 8);
		break;
	case 'i': {
		RAsmOp asmop;
		int j, ret, err = 0;
		const ut8 *buf = core->block;
		int tbs = 0;
		int bs = core->blocksize;

		if (input[1]=='f') {
			RAnalFunction *f = r_anal_fcn_find (core->anal, core->offset,
					R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
			if (f) {
				len = bs = f->size;
				tbs = core->blocksize;
			}
		}
		if (bs>core->blocksize)
			r_core_block_size (core, tbs);

		if (l==0) l = len;
		for (i=j=0; i<bs && j<len; i+=ret,j++ ) {
			ret = r_asm_disassemble (core->assembler, &asmop, buf+i, core->blocksize-i);
			if (ret<1) {
				ret = err = 1;
				r_cons_printf ("???\n");
			} else r_cons_printf ("%s\n", asmop.buf_asm);
		}
		if (tbs) r_core_block_size (core, tbs);
		return err;
		}
	case 'D':
	case 'd':
		switch (input[1]) {
		case 'i': {// TODO
			RAsmOp asmop;
			int j, ret, err = 0;
			const ut8 *buf = core->block;
			if (l==0) l = len;
			for (i=j=0; i<core->blocksize && j<len; i+=ret,j++ ) {
				ret = r_asm_disassemble (core->assembler, &asmop, buf+i, core->blocksize-i);
				if (ret<1) {
					ret = err = 1;
					r_cons_printf ("0x%08"PFMT64x" %14s%02x  %s\n", core->offset+i, "", buf[i], "???");
				} else r_cons_printf ("0x%08"PFMT64x" %16s  %s\n",
					core->offset+i, asmop.buf_hex, asmop.buf_asm);
			}
			return err;
			}
			break;
		case 'a':
			{
				RAsmOp asmop;
				int j, ret, err = 0;
				const ut8 *buf = core->block;
				if (l==0) l = len;
				for (i=j=0; i<core->blocksize && j<len; i++,j++ ) {
					ret = r_asm_disassemble (core->assembler, &asmop, buf+i, core->blocksize-i);
					if (ret<1) {
						ret = err = 1;
						r_cons_printf ("???\n");
					} else r_cons_printf ("0x%08"PFMT64x" %16s  %s\n",
						core->offset+i, asmop.buf_hex, asmop.buf_asm);
				}
				return R_TRUE;
			}
			break;
		case 'b': {
			RAnalBlock *b = r_anal_bb_from_offset (core->anal, core->offset);
			if (b) {
				ut8 *block = malloc (b->size+1);
				if (block) {
					r_core_read_at (core, b->addr, block, b->size);
					core->num->value = r_core_print_disasm (core->print, core, b->addr, block, b->size, 9999, 0);
					free (block);
					return 0;
				}
			} else eprintf ("Cannot find function at 0x%08"PFMT64x"\n", core->offset);
			} break;
			break;
		case 'f': {
			RAnalFunction *f = r_anal_fcn_find (core->anal, core->offset,
					R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
			if (f) {
				ut8 *block = malloc (f->size+1);
				if (block) {
					r_core_read_at (core, f->addr, block, f->size);
					core->num->value = r_core_print_disasm (core->print, core, f->addr, block, f->size, 9999, 0);
					free (block);
					return 0;
				}
			} else eprintf ("Cannot find function at 0x%08"PFMT64x"\n", core->offset);
			} break;
		case 'l':
			{
			RAsmOp asmop;
			int j, ret;
			const ut8 *buf = core->block;
			if (l==0) l= len;
			for (i=j=0; i<core->blocksize && j<l; i+=ret,j++ ) {
				ret = r_asm_disassemble (core->assembler, &asmop, buf+i, len-i);
				printf ("%d\n", ret);
				if (ret<1) ret = 1;
			}
			return 0;
			}
			break;
		case '?':
			eprintf ("Usage: pd[f|i|l] [len] @ [addr]\n");
			//TODO: eprintf ("  pdr  : disassemble resume\n");
			eprintf ("  pda  : disassemble all possible opcodes (byte per byte)\n");
			eprintf ("  pdb  : disassemble basic block\n");
			eprintf ("  pdf  : disassemble function\n");
			eprintf ("  pdi  : like 'pi', with offset and bytes\n");
			eprintf ("  pdl  : show instruction sizes\n");
return 0;
			break;
		}
		//if (core->visual)
		//	l = core->cons->rows-core->cons->lines;
		if (l<0) {
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
						core->num->value = r_core_print_disasm (core->print,
							core, hit->addr, block, core->blocksize, l, 1);
						r_cons_printf ("------\n");
					}
					r_list_free (bwdhits);
				}
				free (block);
			}
		} else {
			core->num->value = r_core_print_disasm (
				core->print, core, core->offset,
				core->block, len, l, (*input=='d'));
		}
		break;
	case 's':
		if (input[1]=='p') {
			int mylen = core->block[0];
			// TODO: add support for 2-4 byte length pascal strings
			r_print_string (core->print, core->offset, core->block, mylen, 0, 1, 0); //, 78, 1);
			core->num->value = mylen;
		} else
		if (input[1]==' ') {
			len = r_num_math (core->num, input+2);
			r_print_string (core->print, core->offset, core->block, len, 0, 0, 0); //, 78, 1);
		} else r_print_string (core->print, core->offset, core->block, len, 0, 1, 0); //, 78, 1);
		break;
	case 'S':
		r_print_string (core->print, core->offset, core->block, len, 1, 1, 0); //, 78, 1);
		break;
	case 'm':
		if (input[1]=='?') {
			r_cons_printf ("Usage: pm [file|directory]\n"
				" r_magic will use given file/dir as reference\n"
				" output of those magic can contain expressions like:\n"
				"   foo@0x40   # use 'foo' magic file on address 0x40\n"
				"   @0x40      # use current magic file on address 0x40\n"
				"   \\n         # append newline\n"
				" e dir.magic  # defaults to "R_MAGIC_PATH"\n"
				);
		} else r_core_magic (core, input+1, R_TRUE);
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
		{
		ut64 from = r_config_get_i (core->config, "diff.from");
		ut64 to = r_config_get_i (core->config, "diff.to");
		if (from == to && from == 0) {
			r_print_hexdump (core->print, core->offset, core->block, len, 16, 1); //, 78, !(input[1]=='-'));
		} else {
			r_core_print_cmp (core, from, to);
		}
		}
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
				core->print->bigendian = !core->print->bigendian;
				for (l=0; l<len; l+=sizeof (ut64))
					r_print_date_w32 (core->print, core->block+l, sizeof (ut64));
				core->print->bigendian = !core->print->bigendian;
				break;
		case '?':
			r_cons_printf (
			"Usage: pt[dn?]\n"
			" pt      print unix time (32 bit cfg.bigendian)\n"
			" ptd     print dos time (32 bit cfg.bigendian)\n"
			" ptn     print ntfs time (64 bit !cfg.bigendian)\n"
			" pt?     show help message\n");
			break;
		}
		break;
	case 'z':
		{
		char *p, *s = malloc (core->blocksize+1);
		int i, j;
		if (s) {
			memset (s, 0, core->blocksize);
			// TODO: filter more chars?
			for (i=j=0;i<core->blocksize; i++) {
				char ch = (char)core->block[i];
				if (!ch) break;
				if (IS_PRINTABLE (ch))
					s[j++] = ch;
			}
			r_cons_printf ("%s\n", s);
			free (s);
		}
		}
		break;
	case 'Z':
		// TODO:0.9.2 zoom.byte changes does not take any effect
		if (input[1]=='?') {
			r_cons_printf (
			"Usage: pZ [len]\n"
			" print N bytes where each byte represents a block of filesize/N\n"
			"Configuration:\n"
			" zoom.maxsz : max size of block\n"
			" zoom.from  : start address\n"
			" zoom.to    : end address\n"
			" zoom.byte  : specify how to calculate each byte\n"
			"   p : number of printable chars\n"
			"   f : count of flags in block\n"
			"   s : strings in range\n"
			"   0 : number of bytes with value '0'\n"
			"   F : number of bytes with value 0xFF\n"
			"   e : calculate entropy and expand to 0-255 range\n"
			"   h : head (first byte value)\n"
			"WARNING: On big files, use 'zoom.byte=h' or restrict ranges\n");
		} else {
			char *oldzoom = NULL;
			ut64 maxsize = r_config_get_i (core->config, "zoom.maxsz");
			ut64 from, to;
			int oldva = core->io->va;

			from = 0;
			core->io->va = 0;
			to = r_io_size (core->io);
			from = r_config_get_i (core->config, "zoom.from");
			to = r_config_get_i (core->config, "zoom.to");
			if (input[1] && input[1] != ' ') {
				oldzoom = strdup (r_config_get (core->config, "zoom.byte"));
				if (!r_config_set (core->config, "zoom.byte", input+1)) {
					eprintf ("Invalid zoom.byte mode (%s)\n", input+1);
					free (oldzoom);
					return R_FALSE;
				}
			}
			r_print_zoom (core->print, core, printzoomcallback,
				from, to, core->blocksize, (int)maxsize);
			if (oldzoom) {
				r_config_set (core->config, "zoom.byte", oldzoom);
				free (oldzoom);
			}
			if (oldva)
				core->io->va = oldva;
		}
		break;
	default:
		r_cons_printf (
		"Usage: p[fmt] [len]\n"
		" p=           show entropy bars of full file\n"
		" p6[de] [len] base64 decode/encode\n"
		" p8 [len]     8bit hexpair list of bytes\n"
		" pb [len]     bitstream of N bytes\n"
		" pi[f] [len]  show opcodes of N bytes\n"
		" pd[lf] [l]   disassemble N opcodes (see pd?)\n"
		" pD [len]     disassemble N bytes\n"
		" p[w|q] [len] word (32), qword (64) value dump\n"
		" po [len]     octal dump of N bytes\n"
		" pc [len]     output C format\n"
		" pf [fmt]     print formatted data\n"
		" pm [magic]   print libmagic data (pm? for more information)\n"
		" ps [len]     print string\n"
		" psp          print pascal string\n"
		" pS [len]     print wide string\n"
		" pt [len]     print different timestamps\n"
		" pr [len]     print N raw bytes\n"
		" pu [len]     print N url encoded bytes\n"
		" pU [len]     print N wide url encoded bytes\n"
		" px [len]     hexdump of N bytes\n"
		" pz [len]     print zero terminated ascii string\n"
		" pZ [len]     print zoom view (see pZ? for help)\n");
		break;
	}
	if (tbs != core->blocksize)
		r_core_block_size (core, tbs);
	return 0;
}

static int cmd_hexdump(void *data, const char *input) {
	return cmd_print (data, input-1);
}
