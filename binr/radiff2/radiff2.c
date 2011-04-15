/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

#include <r_diff.h>
#include <r_core.h>

static ut32 count = 0;

static int cb(struct r_diff_t *d, void *user,
	struct r_diff_op_t *op)
{
	int i, rad = (int)(size_t)user;
	if (count) {
		count++;
		return 1;
	}
	if (rad) {
		// TODO
	} else {
		printf ("0x%08"PFMT64x" ", op->a_off);
		for (i = 0;i<op->a_len;i++)
			printf ("%02x", op->a_buf[i]);
		printf (" => ");
		for (i = 0;i<op->b_len;i++)
			printf ("%02x", op->b_buf[i]);
		printf (" 0x%08"PFMT64x"\n", op->b_off);
	}
	return 1;
}


static void diffrow(ut64 addr, const char *name, ut64 addr2, const char *name2, const char *match) {
	printf ("%30s  0x%"PFMT64x" |%8s  | 0x%"PFMT64x"  %s\n",
		name, addr, match, addr2, name2);
}

static RCore* opencore(const char *f) {
	RCore *c = r_core_new ();
	r_config_set_i (c->config, "io.va", R_TRUE);
	r_config_set_i (c->config, "anal.split", R_TRUE);
	if (r_core_file_open (c, f, 0, 0) == NULL) {
		r_core_free (c);
		return NULL;
	}
	r_core_bin_load (c, NULL);
	return c;
}

static void diff_graph(RCore *c, RCore *c2, const char *arg) {
	r_core_cmdf (c, "agd %s", arg);
}

static void diff_bins(RCore *c, RCore *c2) {
	const char *match;
	RList *fcns;
	RListIter *iter;
	RAnalFcn *f;

	fcns = r_anal_get_fcns (c->anal);
	r_list_foreach (fcns, iter, f) {
		switch (f->type) {
		case R_ANAL_FCN_TYPE_FCN:
		case R_ANAL_FCN_TYPE_SYM:
			switch (f->diff->type) {
			case R_ANAL_DIFF_TYPE_MATCH:
				match = "MATCH";
				break;
			case R_ANAL_DIFF_TYPE_UNMATCH:
				match = "UNMATCH";
				break;
			default:
				match = "NEW";
			}
			diffrow (f->addr, f->name, f->diff->addr, f->diff->name, match);
			break;
		}
	}
	fcns = r_anal_get_fcns (c2->anal);
	r_list_foreach (fcns, iter, f) {
		switch (f->type) {
		case R_ANAL_FCN_TYPE_FCN:
		case R_ANAL_FCN_TYPE_SYM:
			if (f->diff->type == R_ANAL_DIFF_TYPE_NULL)
				diffrow (f->addr, f->name, f->diff->addr, f->diff->name, "NEW");
		}
	}
}

static int show_help(int line) {
	printf ("Usage: radiff2 [-nsdl] [file] [file]\n");
	if (!line) printf (
//		"  -l     diff lines of text\n"
		"  -s     calculate text distance\n"
		"  -c     count of changes\n"
		"  -r     radare commands\n"
		"  -d     use delta diffing\n"
		"  -g     graph diff\n"
		"  -v     Use vaddr\n"
		"  -V     show version information\n");
	return 1;
}

enum {
	MODE_DIFF,
	MODE_DIST,
	MODE_LOCS,
	MODE_CODE,
	MODE_GRAPH,
};

int main(int argc, char **argv) {
	const char *addr = NULL;
	RCore *c, *c2;
	RDiff *d;
	int o, delta = 0;
	char *file, *file2;
	ut8 *bufa, *bufb;
	int sza, szb, rad = 0, va = 0;
	int mode = MODE_DIFF;
	int showcount = 0;
	double sim;

	while ((o = getopt (argc, argv, "Cvg:rhcdlsV")) != -1) {
		switch (o) {
		case 'v':
			va = 1;
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
		case 'd':
			delta = 1;
			break;
		case 'h':
			argc = 0;
			mode = MODE_DIST;
			break;
		case 's':
			mode = MODE_DIST;
			break;
//		case 'l':
//			mode = MODE_LOCS;
//			break;
		case 'V':
			printf ("radiff2 v"R2_VERSION"\n");
			return 0;
		default:
			return show_help (R_TRUE);
		}
	}
	
	if (argc<3 || optind+2<argc)
		return show_help (R_FALSE);

	file = argv[optind];
	file2 = argv[optind+1];

	switch (mode) {
	case MODE_GRAPH:
	case MODE_CODE:
		c = opencore (file);
		c2 = opencore (file2);
		if (c==NULL || c2==NULL) {
			eprintf ("Cannot open file\n");
			return 1;
		}
		r_core_gdiff (c, c2);
		if (mode == MODE_GRAPH)
			diff_graph (c, c2, addr);
		else diff_bins (c, c2);
		return 0;
	}

	bufa = (ut8*)r_file_slurp (file, &sza);
	bufb = (ut8*)r_file_slurp (file2, &szb);
	if (bufa == NULL || bufb == NULL) {
		eprintf ("Error slurping source files\n");
		return 1;
	}

	switch (mode) {
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
//	case MODE_LOCS:
//		count = r_diff_lines(file, (char*)bufa, sza, file2, (char*)bufb, szb);
//		break;
	/* TODO: DEPRECATE */
	case MODE_GRAPH:
		eprintf ("TODO: Use ragdiff2\n");
		break;
	}

	if (showcount)
		printf ("%d\n", count);

	return 0;
}
