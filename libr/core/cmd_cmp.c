/* radare - LGPL - Copyright 2009-2012 // pancake<nopcode.org> */
// move it out // r_diff maybe?
static int radare_compare(RCore *core, const ut8 *f, const ut8 *d, int len) {
	int i, eq = 0;
	for (i=0; i<len; i++) {
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
	case 'c':
		{ ut8 *b = malloc (core->blocksize);
		ut64 addr = r_num_math (core->num, input+2);
		if (!b) return 0;
		memset (b, 0xff, core->blocksize);
		r_core_read_at (core, addr, b, core->blocksize);
#if 0
		r_io_seek (core->io, addr, R_IO_SEEK_SET);
		r_io_read (core->io, b, core->blocksize);
#endif
		r_print_hexdiff (core->print, core->offset, core->block, addr, b, core->blocksize);
		free (b);
		}
		break;
	case 'g':
		{ // XXX: this is broken
			int diffops = 0;
		RCore *core2;
		char *file2 = NULL;
		if (input[1]=='o') {
			file2 = (char*)r_str_chop_ro (input+2);
			r_anal_diff_setup (core->anal, R_TRUE, -1, -1);
		} else
		if (input[1]==' ') {
			file2 = (char*)r_str_chop_ro (input+2);
			r_anal_diff_setup (core->anal, R_FALSE, -1, -1);
		} else {
			eprintf ("Usage: cg[o] [file]\n");
			eprintf (" cg  - byte-per-byte code graph diff\n");
			eprintf (" cgo - opcode-bytes code graph diff\n");
			return R_FALSE;
		}

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
		// TODO: must replicate on core1 too
		r_config_set_i (core2->config, "io.va", R_TRUE);
		r_config_set_i (core2->config, "anal.split", R_TRUE);
                r_anal_diff_setup (core->anal, diffops, -1, -1);
                r_anal_diff_setup (core2->anal, diffops, -1, -1);

		r_core_bin_load (core2, file2);
		r_core_gdiff (core, core2);
		r_core_diff_show (core, core2);
		r_core_free (core2);
		}
		break;
	case '?':
		r_cons_strcat (
		"Usage: c[?cdfx] [argument]\n"
		" c  [string]    Compares a plain with escaped chars string\n"
		" cc [at] [(at)] Compares in two hexdump columns of block size\n"
		//" cc [offset]   Code bindiff current block against offset\n"
		" cd [value]     Compare a doubleword from a math expression\n"
		//" cD [file]     Like above, but using radiff -b\n");
		" cq [value]     Compare a quadword from a math expression\n"
		" cx [hexpair]   Compare hexpair string\n"
		" cX [addr]      Like 'cc' but using hexdiff output\n"
		" cf [file]      Compare contents of file at current seek\n"
		" cg[o] [file]   Graphdiff current file and [file]\n");
		break;
	default:
		eprintf ("Usage: c[?cDdxf] [argument]\n");
	}

	return 0;
}

