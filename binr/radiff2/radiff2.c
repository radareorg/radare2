/* radare - LGPL - Copyright 2009-2014 - pancake */

#include <r_diff.h>
#include <r_core.h>

enum {
	MODE_DIFF,
	MODE_DIST,
	MODE_CODE,
	MODE_GRAPH,
	MODE_COLS
};

static ut32 count = 0;
static int showcount = 0;
static int useva = R_TRUE;
static int delta = 0;
static int showbare = R_FALSE;

static int cb(RDiff *d, void *user, RDiffOp *op) {
	int i, rad = (int)(size_t)user;
	if (showcount) {
		count++;
		return 1;
	}
	if (rad) {
		if (op->a_len == op->b_len) {
			printf ("wx ");
			for (i=0; i<op->b_len; i++)
				printf ("%02x", op->b_buf[i]);
			printf (" @ 0x%08"PFMT64x"\n", op->b_off);
		} else {
			if ((op->a_len)>0)
				printf ("r-%d @ 0x%08"PFMT64x"\n",
					op->a_len, op->a_off+delta);
			if (op->b_len> 0) {
				printf ("r+%d @ 0x%08"PFMT64x"\n",
					op->b_len, op->b_off+delta);
				printf ("wx ");
				for (i=0; i<op->b_len; i++)
					printf ("%02x", op->b_buf[i]);
				printf (" @ 0x%08"PFMT64x"\n", op->b_off+delta);
			}
			delta += (op->b_off - op->a_off);
		}
	} else {
		printf ("0x%08"PFMT64x" ", op->a_off);
		for (i = 0;i<op->a_len;i++)
			printf ("%02x", op->a_buf[i]);
		printf (" => ");
		for (i=0; i<op->b_len; i++)
			printf ("%02x", op->b_buf[i]);
		printf (" 0x%08"PFMT64x"\n", op->b_off);
	}
	return 1;
}

static RCore* opencore(const char *f) {
	const ut64 baddr = 0;
	RCore *c = r_core_new ();
	r_core_loadlibs (c, R_CORE_LOADLIBS_ALL, NULL);
	r_config_set_i (c->config, "io.va", useva);
	r_config_set_i (c->config, "anal.split", R_TRUE);
	if (r_core_file_open (c, f, 0, 0) == NULL) {
		r_core_free (c);
		return NULL;
	}
	r_core_bin_load (c, NULL, baddr);
	// TODO: must enable io.va here if wanted .. r_config_set_i (c->config, "io.va", va);
	return c;
}

static int show_help(int v) {
	printf ("Usage: radiff2 [-abcCdrspOv] [-g sym] [-t %%] [file] [file]\n");
	if (v) printf (
		"  -a [arch]  specify architecture plugin to use (x86, arm, ..)\n"
		"  -b [bits]  specify register size for arch (16 (thumb), 32, 64, ..)\n"
		"  -c         count of changes\n"
		"  -C         graphdiff code (columns: off-A, match-ratio, off-B)\n"
		"  -d         use delta diffing\n"
		"  -f         print bare addresses only (diff.bare=1)\n"
		"  -g [sym|off1,off2]   graph diff of given symbol, or between two offsets\n"
		"  -O         code diffing with opcode bytes only\n"
		"  -p         use physical addressing (io.va=0)\n"
		"  -r         output in radare commands\n"
		"  -s         compute text distance\n"
		"  -t [0-100] set threshold for code diff (default is 70%%)\n"
		"  -v         show version information\n");
	return 1;
}

static void dump_cols (ut8 *a, int as, ut8 *b, int bs, int w) {
	ut32 sz = R_MIN (as, bs);
	ut32 i, j;
	switch (w) {
	case 8:
		printf ("  offset     0 1 2 3 4 5 6 7 01234567    0 1 2 3 4 5 6 7 01234567\n");
		break;
	case 16:
		printf ("  offset     "
			"0 1 2 3 4 5 6 7 8 9 A B C D E F 0123456789ABCDEF    "
			"0 1 2 3 4 5 6 7 8 9 A B C D E F 0123456789ABCDEF\n");
		break;
	default:
		eprintf ("Invalid column width\n");
		return ;
	}
	for (i=0; i<sz; i+=w) {
		printf ("0x%08x%c ", i, (memcmp (a+i, b+i, 8))? ' ': '!');
		for (j=0; j<w; j++)
			printf ("%02x", a[i+j]);
		printf (" ");
		for (j=0; j<w; j++)
                	printf ("%c", IS_PRINTABLE (a[i+j])?a[i+j]:'.');
		printf ("   ");
		for (j=0; j<w; j++)
			printf ("%02x", b[i+j]);
		printf (" ");
		for (j=0; j<w; j++)
                	printf ("%c", IS_PRINTABLE (b[i+j])? b[i+j]:'.');
		printf ("\n");
	}
	if (as != bs)
		printf ("...\n");
}

int main(int argc, char **argv) {
	const char *addr = NULL;
	RCore *c, *c2;
	RDiff *d;
	const char *arch = NULL;
	int bits = 0;
	char *file, *file2;
	ut8 *bufa, *bufb;
	int o, sza, szb, rad = 0, delta = 0;
	int mode = MODE_DIFF;
	int diffops = 0;
	int threshold = -1;
	double sim;

	while ((o = getopt (argc, argv, "a:b:Cnpg:Orhcdsvxt:")) != -1) {
		switch (o) {
		case 'a':
			arch = optarg;
			break;
		case 'b':
			bits = atoi (optarg);
			break;
		case 'p':
			useva = R_FALSE;
			break;
		case 'r':
			rad = 1;
			break;
		case 'g':
			mode = MODE_GRAPH;
			addr = optarg;
			break;
		case 'c':
			showcount = 1;
			break;
		case 'C':
			mode = MODE_CODE;
			break;
		case 'n':
			showbare = R_TRUE;
			break;
		case 'O':
			diffops = 1;
			break;
		case 't':
			threshold = atoi (optarg);
			break;
		case 'd':
			delta = 1;
			break;
		case 'h':
			return show_help (1);
		case 's':
			mode = MODE_DIST;
			break;
		case 'x':
			mode = MODE_COLS;
			break;
		case 'v':
			printf ("radiff2 v"R2_VERSION"\n");
			return 0;
		default:
			return show_help (0);
		}
	}
	
	if (argc<3 || optind+2>argc)
		return show_help (0);

	file = argv[optind];
	file2 = argv[optind+1];

	switch (mode) {
	case MODE_GRAPH:
	case MODE_CODE:
		c = opencore (file);
		if (!c) eprintf ("Cannot open '%s'\n", file);
		c2 = opencore (file2);
		if (!c || !c2) {
			eprintf ("Cannot open '%s'\n", file2);
			return 1;
		}
		if (arch) {
			r_config_set (c->config, "asm.arch", arch);
			r_config_set (c2->config, "asm.arch", arch);
		}
		if (bits) {
			r_config_set_i (c->config, "asm.bits", bits);
			r_config_set_i (c2->config, "asm.bits", bits);
		}
		r_config_set_i (c->config, "diff.bare", showbare);
		r_config_set_i (c2->config, "diff.bare", showbare);
		r_anal_diff_setup_i (c->anal, diffops, threshold, threshold);
		r_anal_diff_setup_i (c2->anal, diffops, threshold, threshold);
		if (mode == MODE_GRAPH) {
			const char* second = strstr (addr, ",");
			if (!second) {
				r_core_gdiff (c, c2, R_TRUE);
				r_core_anal_graph (c, r_num_math (c->num, addr),
					R_CORE_ANAL_GRAPHBODY|R_CORE_ANAL_GRAPHDIFF);
			} else {
				const ut64 off = strtoull(addr, 0, 16);
				// define the same function at each offset
				r_core_anal_fcn (c, off, UT64_MAX, R_ANAL_REF_TYPE_NULL, 0);
				r_core_anal_fcn (c2, strtoull (second+1, 0, 16),
						UT64_MAX, R_ANAL_REF_TYPE_NULL, 0);
				r_core_gdiff (c, c2, R_FALSE); // compute the diff
				r_core_anal_graph (c, off, R_CORE_ANAL_GRAPHBODY|R_CORE_ANAL_GRAPHDIFF);
			}
		} else {
			r_core_gdiff (c, c2, R_TRUE);
			r_core_diff_show (c, c2);
		}
		return 0;
	}

	bufa = (ut8*)r_file_slurp (file, &sza);
	if (!bufa) {
		eprintf ("radiff2: Can not open %s\n", bufa);
		return 1;
	}
	bufb = (ut8*)r_file_slurp (file2, &szb);
	if (!bufb) {
		eprintf ("radiff2: Cannot open: %s\n", bufb);
		free (bufa);
		return 1;
	}

	switch (mode) {
	case MODE_COLS:
		{
			int cols = (r_cons_get_size (NULL)>112)?16:8;
			dump_cols (bufa, sza, bufb, szb, cols);
		}
		break;
	case MODE_DIFF:
		d = r_diff_new (0LL, 0LL);
		r_diff_set_delta (d, delta);
		r_diff_set_callback (d, &cb, (void *)(size_t)rad);
		r_diff_buffers (d, bufa, sza, bufb, szb);
		r_diff_free (d);
		break;
	case MODE_DIST:
		r_diff_buffers_distance (NULL, bufa, sza, bufb, szb, &count, &sim);
		printf ("similarity: %.2f\n", sim);
		printf ("distance: %d\n", count);
		break;
	}

	if (showcount)
		printf ("%d\n", count);
	free (bufa);
	free (bufb);

	return 0;
}
