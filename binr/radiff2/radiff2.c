/* radare - LGPL - Copyright 2009-2016 - pancake */

#include <r_diff.h>
#include <r_core.h>
#include <r_hash.h>

#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"

enum {
	MODE_DIFF,
	MODE_DIST,
	MODE_CODE,
	MODE_GRAPH,
	MODE_COLS
};

static char *file = NULL;
static char *file2 = NULL;
static ut32 count = 0;
static int showcount = 0;
static int useva = true;
static int delta = 0;
static int showbare = false;
static int json_started = 0;
static int diffmode = 0; 
static bool disasm = false;
static RCore *core = NULL;
static const char *arch = NULL;
static int bits = 0;
static int anal_all = 0;

static RCore* opencore(const char *f) {
	const ut64 baddr = UT64_MAX;
	RCore *c = r_core_new ();
	r_core_loadlibs (c, R_CORE_LOADLIBS_ALL, NULL);
	r_config_set_i (c->config, "io.va", useva);
	r_config_set_i (c->config, "anal.split", true);
	if (f) {
		if (r_core_file_open (c, f, 0, 0) == NULL) {
			r_core_free (c);
			return NULL;
		}
		r_core_bin_load (c, NULL, baddr);
	}
	// TODO: must enable io.va here if wanted .. r_config_set_i (c->config, "io.va", va);
	if (anal_all) {
		const char *cmd = "aac";
		switch (anal_all) {
		case 1: cmd = "aaa"; break;
		case 2: cmd = "aaaa"; break;
		}
		r_core_cmd0 (c, cmd);
	}
	return c;
}

static int cb(RDiff *d, void *user, RDiffOp *op) {
	int i; //, diffmode = (int)(size_t)user;
	if (showcount) {
		count++;
		return 1;
	}
	switch (diffmode) {
	case 'r':
		if (disasm) {
			eprintf ("r2cmds (-r) + disasm (-D) not yet implemented\n");
		}
		if (op->a_len == op->b_len) {
			printf ("wx ");
			for (i = 0; i < op->b_len; i++)
				printf ("%02x", op->b_buf[i]);
			printf (" @ 0x%08"PFMT64x"\n", op->b_off);
		} else {
			if ((op->a_len) > 0)
				printf ("r-%d @ 0x%08"PFMT64x"\n",
					op->a_len, op->a_off + delta);
			if (op->b_len> 0) {
				printf ("r+%d @ 0x%08"PFMT64x"\n",
					op->b_len, op->b_off + delta);
				printf ("wx ");
				for (i = 0; i < op->b_len; i++)
					printf ("%02x", op->b_buf[i]);
				printf (" @ 0x%08"PFMT64x"\n", op->b_off+delta);
			}
			delta += (op->b_off - op->a_off);
		}
		return 1;
	case 'j':
		if (disasm) {
			eprintf ("JSON (-j) + disasm (-D) not yet implemented\n");
		}
		if (json_started)
			printf(",\n");
		json_started = 1;
		printf ("{\"offset\":%"PFMT64d",", op->a_off);
		printf("\"from\":\"");
		for (i = 0; i < op->a_len; i++)
			printf ("%02x", op->a_buf[i]);
		printf ("\", \"to\":\"");
		for (i = 0; i < op->b_len; i++)
			printf ("%02x", op->b_buf[i]);
		printf ("\"}"); //,\n");
		return 1;
	case 0:
	default:
		if (disasm) {
			printf ("--- 0x%08"PFMT64x"\n", op->a_off);
			if (!core) {
				core = opencore (file);
				if (arch) {
					r_config_set (core->config, "asm.arch", arch);
				}
				if (bits) {
					r_config_set_i (core->config, "asm.bits", bits);
				}
			}
			if (core) {
				RAsmCode *ac = r_asm_mdisassemble (core->assembler, op->a_buf, op->a_len);
				printf ("%s\n", ac->buf_asm);
				//r_asm_code_free (ac);
			}
		} else {
			printf ("0x%08"PFMT64x" ", op->a_off);
			for (i = 0; i < op->a_len; i++)
				printf ("%02x", op->a_buf[i]);
		}
		if (disasm) {
			printf ("+++ 0x%08"PFMT64x"\n", op->b_off);
			if (!core) {
				core = opencore (NULL);
			}
			if (core) {
				RAsmCode *ac = r_asm_mdisassemble (core->assembler, op->b_buf, op->b_len);
				printf ("%s\n", ac->buf_asm);
				//r_asm_code_free (ac);
			}
		} else {
			printf (" => ");
			for (i = 0; i < op->b_len; i++)
				printf ("%02x", op->b_buf[i]);
			printf (" 0x%08"PFMT64x"\n", op->b_off);
		}
		return 1;
	}
}

static int show_help(int v) {
	printf ("Usage: radiff2 [-abcCdjrspOxv] [-g sym] [-t %%] [file] [file]\n");
	if (v) printf (
		"  -a [arch]  specify architecture plugin to use (x86, arm, ..)\n"
		"  -A [-A]    run aaa or aaaa after loading each binary (see -C)\n"
		"  -b [bits]  specify register size for arch (16 (thumb), 32, 64, ..)\n"
		"  -c         count of changes\n"
		"  -C         graphdiff code (columns: off-A, match-ratio, off-B) (see -A)\n"
		"  -d         use delta diffing\n"
		"  -D         show disasm instead of hexpairs\n"
		"  -g [sym|off1,off2]   graph diff of given symbol, or between two offsets\n"
		"  -j         output in json format\n"
		"  -n         print bare addresses only (diff.bare=1)\n"
		"  -O         code diffing with opcode bytes only\n"
		"  -p         use physical addressing (io.va=0)\n"
		"  -r         output in radare commands\n"
		"  -s         compute text distance\n"
		"  -t [0-100] set threshold for code diff (default is 70%%)\n"
		"  -x         show two column hexdump diffing\n"
		"  -v         show version information\n");
	return 1;
}

#define DUMP_CONTEXT 2
static void dump_cols (ut8 *a, int as, ut8 *b, int bs, int w) {
	ut32 sz = R_MIN (as, bs);
	ut32 i, j;
	int ctx = DUMP_CONTEXT;
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
	for (i = 0; i < sz; i += w) {
		bool eq = !memcmp (a + i, b + i, w);
		if (eq) {
			ctx--;
			if (ctx == -1) {
				printf ("...\n");
				continue;
			}
			if (ctx < 0) {
				ctx = -1;
				continue;
			}
		} else {
			ctx = DUMP_CONTEXT;
		}
		printf (eq?Color_GREEN:Color_RED);
		printf ("0x%08x%c ", i, eq ? ' ' : '!');
		printf (Color_RESET);
		for (j = 0; j < w; j++) {
			bool eq2 = a[i+j] == b[i+j];
			if (!eq) printf (eq2?Color_GREEN:Color_RED);
			printf ("%02x", a[i + j]);
			if (!eq) printf (Color_RESET);
		}
		printf (" ");
		for (j = 0; j < w; j++) {
			bool eq2 = a[i+j] == b[i+j];
			if (!eq) printf (eq2?Color_GREEN:Color_RED);
			printf ("%c", IS_PRINTABLE (a[i + j]) ? a[i + j] : '.');
			if (!eq) printf (Color_RESET);
		}
		printf ("   ");
		for (j = 0; j < w; j++) {
			bool eq2 = a[i+j] == b[i+j];
			if (!eq) printf (eq2?Color_GREEN:Color_RED);
			printf ("%02x", b[i + j]);
			if (!eq) printf (Color_RESET);
		}
		printf (" ");
		for (j = 0; j < w; j++) {
			bool eq2 = a[i+j] == b[i+j];
			if (!eq) printf (eq2?Color_GREEN:Color_RED);
			printf ("%c", IS_PRINTABLE (b[i + j]) ? b[i + j] : '.');
			if (!eq) printf (Color_RESET);
		}
		printf ("\n");
	}
	if (as != bs)
		printf ("...\n");
}

static void handle_sha256 (const ut8 *block, int len) {
	int i = 0;
	RHash *ctx = r_hash_new (true, R_HASH_SHA256);
	const ut8 *c = r_hash_do_sha256 (ctx, block, len);
	for (i = 0; i < R_HASH_SIZE_SHA256; i++) printf ("%02x", c[i]);
	r_hash_free (ctx);
}

int main(int argc, char **argv) {
	const char *addr = NULL;
	RCore *c, *c2;
	RDiff *d;
	ut8 *bufa, *bufb;
	int o, sza, szb, /*diffmode = 0,*/ delta = 0;
	int mode = MODE_DIFF;
	int diffops = 0;
	int threshold = -1;
	double sim;

	while ((o = getopt (argc, argv, "Aa:b:CDnpg:Ojrhcdsvxt:")) != -1) {
		switch (o) {
		case 'a':
			arch = optarg;
			break;
		case 'A':
			anal_all++;
			break;
		case 'b':
			bits = atoi (optarg);
			break;
		case 'p':
			useva = false;
			break;
		case 'r':
			diffmode = 'r';
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
			showbare = true;
			break;
		case 'O':
			diffops = 1;
			break;
		case 't':
			threshold = atoi (optarg);
			printf ("%s\n", optarg);
			break;
		case 'd':
			delta = 1;
			break;
		case 'D':
			disasm = true;
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
		case 'j':
			diffmode = 'j';
			break;
		default:
			return show_help (0);
		}
	}
	
	if (argc < 3 || optind + 2 > argc)
		return show_help (0);

	if (optind < argc) {
		file = argv[optind];
	} else {
		file = NULL;
	}
	
	if (optind + 1 < argc) {
		file2 = argv[optind + 1];
	} else {
		file2 = NULL;
	}

	switch (mode) {
	case MODE_GRAPH:
	case MODE_CODE:
		c = opencore (file);
		if (!c) eprintf ("Cannot open '%s'\n", r_str_get (file));
		c2 = opencore (file2);
		if (!c || !c2) {
			eprintf ("Cannot open '%s'\n", r_str_get (file2));
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
			char *words = strdup (addr ? addr : "0");
			char *second = strstr (words, ",");
			if (second) {
				ut64 off;
				*second++ = 0;
				off = r_num_math (c->num, words);
				// define the same function at each offset
				r_core_anal_fcn (c, off, UT64_MAX, R_ANAL_REF_TYPE_NULL, 0);
				r_core_anal_fcn (c2, r_num_math (c2->num, second),
						UT64_MAX, R_ANAL_REF_TYPE_NULL, 0);
				r_core_gdiff (c, c2);
				r_core_anal_graph (c, off, R_CORE_ANAL_GRAPHBODY | R_CORE_ANAL_GRAPHDIFF);
			} else {
				r_core_anal_fcn (c, r_num_math (c->num, words),
						UT64_MAX, R_ANAL_REF_TYPE_NULL, 0);
				r_core_anal_fcn (c2, r_num_math (c2->num, words),
						UT64_MAX, R_ANAL_REF_TYPE_NULL, 0);
				r_core_gdiff (c, c2);
				r_core_anal_graph (c, r_num_math (c->num, addr),
					R_CORE_ANAL_GRAPHBODY | R_CORE_ANAL_GRAPHDIFF);
			}
			free (words);
		} else {
			r_core_gdiff (c, c2);
			r_core_diff_show (c, c2);
		}
		r_cons_flush ();
		r_core_free (c);
		r_core_free (c2);
		return 0;
	}

	bufa = (ut8*)r_file_slurp (file, &sza);
	if (!bufa) {
		eprintf ("radiff2: Cannot open %s\n", r_str_get (file));
		return 1;
	}
	bufb = (ut8*)r_file_slurp (file2, &szb);
	if (!bufb) {
		eprintf ("radiff2: Cannot open: %s\n", r_str_get (file2));
		free (bufa);
		return 1;
	}

	switch (mode) {
	case MODE_COLS:
		{
			int cols = (r_cons_get_size (NULL) > 112) ? 16 : 8;
			dump_cols (bufa, sza, bufb, szb, cols);
		}
		break;
	case MODE_DIFF:
		d = r_diff_new (0LL, 0LL);
		r_diff_set_delta (d, delta);
		if (diffmode == 'j') {
			printf("{\"files\":[{\"filename\":\"%s\", \"size\":%d, \"sha256\":\"", file, sza); 
			handle_sha256 (bufa, sza);
			printf("\"},\n{\"filename\":\"%s\", \"size\":%d, \"sha256\":\"", file2, szb);
			handle_sha256 (bufb, szb);
			printf("\"}],\n");
			printf("\"changes\":[");
		}
		r_diff_set_callback (d, &cb, 0);//(void *)(size_t)diffmode);
		r_diff_buffers (d, bufa, sza, bufb, szb);
		if (diffmode == 'j')
			printf("]\n");
		r_diff_free (d);
		break;
	case MODE_DIST:
		r_diff_buffers_distance (NULL, bufa, sza, bufb, szb, &count, &sim);
		printf ("similarity: %.2f\n", sim);
		printf ("distance: %d\n", count);
		break;
	}

	if (diffmode == 'j' && showcount)
		printf (",\"count\":%d}\n",count);
	else if (showcount && diffmode != 'j')
		printf ("%d\n", count);
	else if (!showcount && diffmode == 'j')
		printf ("}\n");
	free (bufa);
	free (bufb);

	return 0;
}
