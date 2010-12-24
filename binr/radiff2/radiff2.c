/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

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
	MODE_GRAPH,
};

int main(int argc, char **argv) {
	RDiff *d;
	int c, delta = 0;
	char *file, *file2;
	ut8 *bufa, *bufb;
	int sza, szb, rad = 0, va = 0;
	int mode = MODE_DIFF;
	int showcount = 0;
	double sim;

	while ((c = getopt (argc, argv, "vgrhcdlsV")) != -1) {
		switch(c) {
		case 'v':
			va = 1;
			break;
		case 'r':
			rad = 1;
			break;
		case 'g':
			mode = MODE_GRAPH;
			break;
		case 'c':
			showcount = 1;
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

	bufa = (ut8*)r_file_slurp (file, &sza);
	bufb = (ut8*)r_file_slurp (file2, &szb);
	if (bufa == NULL || bufb == NULL) {
		eprintf ("Error slurping source files\n");
		return 1;
	}

	switch(mode) {
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
