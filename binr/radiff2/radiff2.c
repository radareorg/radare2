/* radare - LGPL - Copyright 2009-2017 - pancake */

#include <r_diff.h>
#include <r_core.h>
#include <r_hash.h>
#include <limits.h>
#include <getopt.c>
#ifdef _MSC_VER
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

#include "../blob/version.c"

enum {
	MODE_DIFF,
	MODE_DIFF_STRS,
	MODE_DIFF_IMPORTS,
	MODE_DIST,
	MODE_DIST_MYERS,
	MODE_DIST_LEVENSTEIN,
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
static bool pdc = false;
static bool quiet = false;
static RCore *core = NULL;
static const char *arch = NULL;
const char *runcmd = NULL;
static int bits = 0;
static int anal_all = 0;
static bool verbose = false;
static RList *evals = NULL;

static RCore *opencore(const char *f) {
	RListIter *iter;
	const ut64 baddr = UT64_MAX;
	const char *e;
	RCore *c = r_core_new ();
	if (!c) {
		return NULL;
	}
	r_core_loadlibs (c, R_CORE_LOADLIBS_ALL, NULL);
	r_config_set_i (c->config, "io.va", useva);
	r_config_set_i (c->config, "anal.split", true);
	r_config_set_i (c->config, "scr.interactive", false);
	r_list_foreach (evals, iter, e) {
		r_config_eval (c->config, e);
	}
	if (f) {
		if (!r_core_file_open (c, f, 0, 0)) {
			r_core_free (c);
			return NULL;
		}
		r_core_bin_load (c, NULL, baddr);
		(void) r_core_bin_update_arch_bits (c);

		if (anal_all) {
			const char *cmd = "aac";
			switch (anal_all) {
			case 1: cmd = "aaa"; break;
			case 2: cmd = "aaaa"; break;
			}
			r_core_cmd0 (c, cmd);
		}
		if (runcmd) {
			r_core_cmd0 (c, runcmd);
		}
	}
	// TODO: must enable io.va here if wanted .. r_config_set_i (c->config, "io.va", va);
	return c;
}

static void readstr(char *s, int sz, const ut8 *buf, int len) {
	*s = 0;
	int last = R_MIN (len, sz);
	if (last < 1) {
		return;
	}
	s[sz - 1] = 0;
	while (*s && *s == '\n') {
		s++;
	}
	strncpy (s, (char *) buf, last);
}

static int cb(RDiff *d, void *user, RDiffOp *op) {
	int i; // , diffmode = (int)(size_t)user;
	char s[256] = {0};
	if (showcount) {
		count++;
		return 1;
	}
	switch (diffmode) {
	case 'U': // 'U' in theory never handled here
	case 'u':
		if (op->a_len > 0) {
			readstr (s, sizeof (s), op->a_buf, op->a_len);
			if (*s) {
				if (!quiet) {
					printf (Color_RED);
				}
				if (r_mem_is_printable ((const ut8 *) s, R_MIN (strlen (s), 5))) {
					printf ("- %s\n", s);
				} else {
					printf ("-:");
					int len = op->a_len; // R_MIN (op->a_len, strlen (op->a_buf));
					for (i = 0; i < len; i++) {
						printf ("%02x", op->a_buf[i]);
					}
					printf (" \"%s\"\n", op->a_buf);
				}
				if (!quiet) {
					printf (Color_RESET);
				}
			}
		}
		if (op->b_len > 0) {
			readstr (s, sizeof (s), op->b_buf, op->b_len);
			if (*s) {
				if (!quiet) {
					printf (Color_GREEN);
				}
				if (r_mem_is_printable ((const ut8 *) s, R_MIN (strlen (s), 5))) {
					printf ("+ %s\n", s);
				} else {
					printf ("+:");
					for (i = 0; i < op->b_len; i++) {
						printf ("%02x", op->b_buf[i]);
					}
					printf (" \"%s\"\n", op->b_buf);
				}
				if (!quiet) {
					printf (Color_RESET);
				}
			}
		}
		break;
	case 'r':
		if (disasm) {
			eprintf ("r2cmds (-r) + disasm (-D) not yet implemented\n");
		}
		if (op->a_len == op->b_len) {
			printf ("wx ");
			for (i = 0; i < op->b_len; i++) {
				printf ("%02x", op->b_buf[i]);
			}
			printf (" @ 0x%08"PFMT64x "\n", op->b_off);
		} else {
			if (op->a_len > 0) {
				printf ("r-%d @ 0x%08"PFMT64x "\n",
					op->a_len, op->a_off + delta);
			}
			if (op->b_len > 0) {
				printf ("r+%d @ 0x%08"PFMT64x "\n",
					op->b_len, op->b_off + delta);
				printf ("wx ");
				for (i = 0; i < op->b_len; i++) {
					printf ("%02x", op->b_buf[i]);
				}
				printf (" @ 0x%08"PFMT64x "\n", op->b_off + delta);
			}
			delta += (op->b_off - op->a_off);
		}
		return 1;
	case 'j':
		if (disasm) {
			eprintf ("JSON (-j) + disasm (-D) not yet implemented\n");
		}
		if (json_started) {
			printf (",\n");
		}
		json_started = 1;
		printf ("{\"offset\":%"PFMT64d ",", op->a_off);
		printf ("\"from\":\"");
		for (i = 0; i < op->a_len; i++) {
			printf ("%02x", op->a_buf[i]);
		}
		printf ("\", \"to\":\"");
		for (i = 0; i < op->b_len; i++) {
			printf ("%02x", op->b_buf[i]);
		}
		printf ("\"}"); // ,\n");
		return 1;
	case 0:
	default:
		if (disasm) {
			int i;
			printf ("--- 0x%08"PFMT64x "  ", op->a_off);
			if (!core) {
				core = opencore (file);
				if (arch) {
					r_config_set (core->config, "asm.arch", arch);
				}
				if (bits) {
					r_config_set_i (core->config, "asm.bits", bits);
				}
			}
			for (i = 0; i < op->a_len; i++) {
				printf ("%02x", op->a_buf[i]);
			}
			printf ("\n");
			if (core) {
				int len = R_MAX (4, op->a_len);
				RAsmCode *ac = r_asm_mdisassemble (core->assembler, op->a_buf, len);
				if (quiet) {
					char *bufasm = r_str_prefix_all (strdup (ac->buf_asm), "- ");
					printf ("%s\n", bufasm);
					free (bufasm);
				} else {
					char *bufasm = r_str_prefix_all (strdup (ac->buf_asm), Color_RED"- ");
					printf ("%s"Color_RESET, bufasm);
					free (bufasm);
				}
				// r_asm_code_free (ac);
			}
		} else {
			printf ("0x%08"PFMT64x " ", op->a_off);
			for (i = 0; i < op->a_len; i++) {
				printf ("%02x", op->a_buf[i]);
			}
		}
		if (disasm) {
			int i;
			printf ("+++ 0x%08"PFMT64x "  ", op->b_off);
			if (!core) {
				core = opencore (NULL);
			}
			for (i = 0; i < op->b_len; i++) {
				printf ("%02x", op->b_buf[i]);
			}
			printf ("\n");
			if (core) {
				int len = R_MAX (4, op->b_len);
				RAsmCode *ac = r_asm_mdisassemble (core->assembler, op->b_buf, len);
				if (quiet) {
					char *bufasm = r_str_prefix_all (strdup (ac->buf_asm), "+ ");
					printf ("%s\n", bufasm);
					free (bufasm);
				} else {
					char *bufasm = r_str_prefix_all (strdup (ac->buf_asm), Color_GREEN"+ ");
					printf ("%s\n" Color_RESET, bufasm);
					free (bufasm);
				}
				// r_asm_code_free (ac);
			}
		} else {
			printf (" => ");
			for (i = 0; i < op->b_len; i++) {
				printf ("%02x", op->b_buf[i]);
			}
			printf (" 0x%08"PFMT64x "\n", op->b_off);
		}
		return 1;
	}
	return 0;
}

static ut64 gdiff_start = 0;

void print_bytes(const void *p, size_t len, bool big_endian) {
	size_t i;
	for (i = 0; i < len; ++i) {
		ut8 ch = ((ut8*) p)[big_endian ? (len - i - 1) : i];
		write (1, &ch, 1);
	}
}

static int bcb(RDiff *d, void *user, RDiffOp *op) {
	ut64 offset_diff = op->a_off - gdiff_start;
	unsigned char opcode;
	unsigned short USAddr = 0;
	int IAddr = 0;
	unsigned char UCLen = 0;
	unsigned short USLen = 0;
	int ILen = 0;
	
	// we copy from gdiff_start to a_off
	if (offset_diff > 0) {

		// size for the position
		if (gdiff_start <= USHRT_MAX) {
			opcode = 249;
			USAddr = (unsigned short) gdiff_start;
		} else if (gdiff_start <= INT_MAX) {
			opcode = 252;
			IAddr = (int) gdiff_start;
		} else {
			opcode = 255;
		}

		// size for the length
		if (opcode != 255 && offset_diff <= UCHAR_MAX) {
			UCLen = (unsigned char) offset_diff;
		} else if (opcode != 255 && offset_diff <= USHRT_MAX) {
			USLen = (unsigned short) offset_diff;
			opcode += 1;
		} else if (opcode != 255 && offset_diff <= INT_MAX) {
			ILen = (int) offset_diff;
			opcode += 2;
		} else if (offset_diff > INT_MAX) {
			int times = offset_diff / INT_MAX;
			int max = INT_MAX;
			size_t i;
			for (i = 0; i < times; i++) {
				print_bytes (&opcode, sizeof (opcode), true);
				// XXX this is overflowingly wrong
				// XXX print_bytes (&gdiff_start + i * max, sizeof (gdiff_start), true);
				print_bytes (&max, sizeof (max), true);
			}
		}

		// print opcode for COPY
		print_bytes (&opcode, sizeof (opcode), true);

		// print position for COPY
		if (opcode <= 251) {
			print_bytes (&USAddr, sizeof (USAddr), true);
		} else if (opcode < 255) {
			print_bytes (&IAddr, sizeof (IAddr), true);
		} else {
			print_bytes (&gdiff_start, sizeof (gdiff_start), true);
		}
		
		// print length for COPY
		switch (opcode) {
		case 249:
		case 252:
			print_bytes (&UCLen, sizeof (UCLen), true);
			break;
		case 250:
		case 253:
			print_bytes (&USLen, sizeof (USLen), true);
			break;
		case 251:
		case 254:
		case 255:
			print_bytes (&ILen, sizeof (ILen), true);
			break;
		}
	}
	
	// we append data
	if (op->b_len <= 246) {
		ut8 data = op->b_len;
		write (1, &data, 1);
	} else if (op->b_len <= USHRT_MAX) {
		USLen = (ut16) op->b_len;
		ut8 data = 247;
		write (1, &data, 1);
		print_bytes (&USLen, sizeof (USLen), true);
	} else if (op->b_len <= INT_MAX) {
		ut8 data = 248;
		write (1, &data, 1);
		ILen = (int) op->b_len;
		print_bytes (&ILen, sizeof (ILen), true);
	} else {
		// split into multiple DATA, because op->b_len is greater than INT_MAX
		int times = op->b_len / INT_MAX;
		int max = INT_MAX;
		size_t i;
		for(i = 0;i < times; i++) {
			ut8 data = 248;
			write (1, &data, 1);
			print_bytes (&max, sizeof (max), true);
			print_bytes (op->b_buf, max, false);
			op->b_buf += max;
		}
		op->b_len = op->b_len % max;

		// print the remaining size
		int remain_size = op->b_len;
		print_bytes(&remain_size, sizeof(remain_size), true);
	}
	print_bytes(op->b_buf, op->b_len, false);
	gdiff_start = op->b_off + op->b_len;
	return 0;
}

static int show_help(int v) {
	printf ("Usage: radiff2 [-abBcCdjrspOxuUvV] [-A[A]] [-g sym] [-t %%] [file] [file]\n");
	if (v) {
		printf (
			"  -a [arch]  specify architecture plugin to use (x86, arm, ..)\n"
			"  -A [-A]    run aaa or aaaa after loading each binary (see -C)\n"
			"  -b [bits]  specify register size for arch (16 (thumb), 32, 64, ..)\n"
			"  -B         output in binary diff (GDIFF)\n"
			"  -c         count of changes\n"
			"  -C         graphdiff code (columns: off-A, match-ratio, off-B) (see -A)\n"
			"  -d         use delta diffing\n"
			"  -D         show disasm instead of hexpairs\n"
			"  -e [k=v]   set eval config var value for all RCore instances\n"
			"  -g [sym|off1,off2]   graph diff of given symbol, or between two offsets\n"
			"  -G [cmd]   run an r2 command on every RCore instance created\n"
			"  -i         diff imports of target files (see -u, -U and -z)\n"
			"  -j         output in json format\n"
			"  -n         print bare addresses only (diff.bare=1)\n"
			"  -O         code diffing with opcode bytes only\n"
			"  -p         use physical addressing (io.va=0)\n"
			"  -q         quiet mode (disable colors, reduce output)\n"
			"  -r         output in radare commands\n"
			"  -s         compute edit distance (no substitution, Eugene W. Myers' O(ND) diff algorithm)\n"
			"  -ss        compute Levenshtein edit distance (substitution is allowed, O(N^2))\n"
			"  -S [name]  sort code diff (name, namelen, addr, size, type, dist) (only for -C or -g)\n"
			"  -t [0-100] set threshold for code diff (default is 70%%)\n"
			"  -x         show two column hexdump diffing\n"
			"  -u         unified output (---+++)\n"
			"  -U         unified output using system 'diff'\n"
			"  -v         show version information\n"
			"  -V         be verbose (current only for -s)\n"
			"  -z         diff on extracted strings\n");
	}
	return 1;
}

#define DUMP_CONTEXT 2
static void dump_cols(ut8 *a, int as, ut8 *b, int bs, int w) {
	ut32 sz = R_MIN (as, bs);
	ut32 i, j;
	int ctx = DUMP_CONTEXT;
	switch (w) {
	case 8:
		r_cons_printf ("  offset     0 1 2 3 4 5 6 7 01234567    0 1 2 3 4 5 6 7 01234567\n");
		break;
	case 16:
		r_cons_printf ("  offset     "
			"0 1 2 3 4 5 6 7 8 9 A B C D E F 0123456789ABCDEF    "
			"0 1 2 3 4 5 6 7 8 9 A B C D E F 0123456789ABCDEF\n");
		break;
	default:
		eprintf ("Invalid column width\n");
		return;
	}
	for (i = 0; i < sz; i += w) {
		bool eq = !memcmp (a + i, b + i, w);
		if (eq) {
			ctx--;
			if (ctx == -1) {
				r_cons_printf ("...\n");
				continue;
			}
			if (ctx < 0) {
				ctx = -1;
				continue;
			}
		} else {
			ctx = DUMP_CONTEXT;
		}
		r_cons_printf (eq? Color_GREEN: Color_RED);
		r_cons_printf ("0x%08x%c ", i, eq? ' ': '!');
		r_cons_printf (Color_RESET);
		for (j = 0; j < w; j++) {
			bool eq2 = a[i + j] == b[i + j];
			if (!eq) {
				r_cons_printf (eq2? Color_GREEN: Color_RED);
			}
			r_cons_printf ("%02x", a[i + j]);
			if (!eq) {
				r_cons_printf (Color_RESET);
			}
		}
		r_cons_printf (" ");
		for (j = 0; j < w; j++) {
			bool eq2 = a[i + j] == b[i + j];
			if (!eq) {
				r_cons_printf (eq2? Color_GREEN: Color_RED);
			}
			r_cons_printf ("%c", IS_PRINTABLE (a[i + j])? a[i + j]: '.');
			if (!eq) {
				r_cons_printf (Color_RESET);
			}
		}
		r_cons_printf ("   ");
		for (j = 0; j < w; j++) {
			bool eq2 = a[i + j] == b[i + j];
			if (!eq) {
				r_cons_printf (eq2? Color_GREEN: Color_RED);
			}
			r_cons_printf ("%02x", b[i + j]);
			if (!eq) {
				r_cons_printf (Color_RESET);
			}
		}
		r_cons_printf (" ");
		for (j = 0; j < w; j++) {
			bool eq2 = a[i + j] == b[i + j];
			if (!eq) {
				r_cons_printf (eq2? Color_GREEN: Color_RED);
			}
			r_cons_printf ("%c", IS_PRINTABLE (b[i + j])? b[i + j]: '.');
			if (!eq) {
				r_cons_printf (Color_RESET);
			}
		}
		r_cons_printf ("\n");
	}
	if (as != bs) {
		r_cons_printf ("...\n");
	}
	r_cons_flush ();
}

static void handle_sha256(const ut8 *block, int len) {
	int i = 0;
	RHash *ctx = r_hash_new (true, R_HASH_SHA256);
	const ut8 *c = r_hash_do_sha256 (ctx, block, len);
	if (!c) {
		r_hash_free (ctx);
		return;
	}
	for (i = 0; i < R_HASH_SIZE_SHA256; i++) {
		printf ("%02x", c[i]);
	}
	r_hash_free (ctx);
}

static ut8 *slurp(RCore **c, const char *file, int *sz) {
	RIODesc *d;
	RIO *io;
	if (c && file && strstr (file, "://")) {
		ut8 *data = NULL;
		ut64 size;
		if (!*c) {
			*c = opencore (NULL);
		}
		if (!*c) {
			eprintf ("opencore failed\n");
			return NULL;
		}
		io = (*c)->io;
		d = r_io_open (io, file, 0, 0);
		if (!d) {
			return NULL;
		}
		size = r_io_size (io);
		if (size > 0 && size < ST32_MAX) {
			data = calloc (1, size);
			if (r_io_read_at (io, 0, data, size)) {
				if (sz) {
					*sz = size;
				}
			} else {
				eprintf ("slurp: read error\n");
				R_FREE (data);
			}
		} else {
			eprintf ("slurp: Invalid file size\n");
		}
		r_io_desc_close (d);
		return data;
	}
	return (ut8 *) r_file_slurp (file, sz);
}

static int import_cmp(const RBinImport *a, const RBinImport *b) {
	return strcmp (a->name, b->name);
}

static ut8 *get_imports(RCore *c, int *len) {
	RListIter *iter;
	RBinImport *str, *old = NULL;
	ut8 *buf, *ptr;

	if (!c || !len) {
		return NULL;
	}

	RList *list = r_bin_get_imports (c->bin);
	r_list_sort (list, (RListComparator) import_cmp);

	*len = 0;

	r_list_foreach (list, iter, str) {
		if (!old || (old && import_cmp (old, str) != 0)) {
			*len += strlen (str->name) + 1;
			old = str;
		}
	}
	ptr = buf = malloc (*len + 1);
	if (!ptr) {
		return NULL;
	}

	old = NULL;

	r_list_foreach (list, iter, str) {
		if (old && !import_cmp (old, str)) {
			continue;
		}
		int namelen = strlen (str->name);
		memcpy (ptr, str->name, namelen);
		ptr += namelen;
		*ptr++ = '\n';
		old = str;
	}
	*ptr = 0;

	*len = strlen ((const char *) buf);
	return buf;
}

static int bs_cmp(const RBinString *a, const RBinString *b) {
	int diff = a->length - b->length;
	return diff == 0? strncmp (a->string, b->string, a->length): diff;
}

static ut8 *get_strings(RCore *c, int *len) {
	RList *list = r_bin_get_strings (c->bin);
	RListIter *iter;
	RBinString *str, *old = NULL;
	ut8 *buf, *ptr;

	r_list_sort (list, (RListComparator) bs_cmp);

	*len = 0;

	r_list_foreach (list, iter, str) {
		if (!old || (old && bs_cmp (old, str) != 0)) {
			*len += str->length + 1;
			old = str;
		}
	}

	ptr = buf = malloc (*len + 1);
	if (!ptr) {
		return NULL;
	}

	old = NULL;

	r_list_foreach (list, iter, str) {
		if (old && bs_cmp (old, str) == 0) {
			continue;
		}
		memcpy (ptr, str->string, str->length);
		ptr += str->length;
		*ptr++ = '\n';
		old = str;
	}
	*ptr = 0;

	*len = strlen ((const char *) buf);
	return buf;
}

int main(int argc, char **argv) {
	const char *columnSort = NULL;
	const char *addr = NULL;
	RCore *c = NULL, *c2 = NULL;
	RDiff *d;
	ut8 *bufa, *bufb;
	int o, sza, szb, /*diffmode = 0,*/ delta = 0;
	int mode = MODE_DIFF;
	int diffops = 0;
	int threshold = -1;
	double sim = 0.0;

	evals = r_list_newf (NULL);

	while ((o = getopt (argc, argv, "Aa:b:BCDe:npg:G:OijrhcdsS:uUvVxt:zq")) != -1) {
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
		case 'B':
			diffmode = 'B';
			break;
		case 'e':
			r_list_append (evals, optarg);
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
		case 'G':
			runcmd = optarg;
			break;
		case 'c':
			showcount = 1;
			break;
		case 'C':
			mode = MODE_CODE;
			break;
		case 'i':
			mode = MODE_DIFF_IMPORTS;
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
			if (disasm) {
				pdc = true;
				disasm = false;
				mode = MODE_CODE;
			} else {
				disasm = true;
			}
			break;
		case 'h':
			return show_help (1);
		case 's':
			if (mode == MODE_DIST) {
				mode = MODE_DIST_LEVENSTEIN;
			} else if (mode == MODE_DIST_LEVENSTEIN) {
				mode = MODE_DIST_MYERS;
			} else {
				mode = MODE_DIST;
			}
			break;
		case 'S':
			columnSort = optarg;
			break;
		case 'x':
			mode = MODE_COLS;
			break;
		case 'u':
			diffmode = 'u';
			break;
		case 'U':
			diffmode = 'U';
			break;
		case 'v':
			return blob_version ("radiff2");
			return 0;
		case 'q':
			quiet = true;
			break;
		case 'V':
			verbose = true;
			break;
		case 'j':
			diffmode = 'j';
			break;
		case 'z':
			mode = MODE_DIFF_STRS;
			break;
		default:
			return show_help (0);
		}
	}

	if (argc < 3 || optind + 2 > argc) {
		return show_help (0);
	}
	file = (optind < argc)? argv[optind]: NULL;
	file2 = (optind + 1 < argc)? argv[optind + 1]: NULL;

	switch (mode) {
	case MODE_GRAPH:
	case MODE_CODE:
	case MODE_DIFF_STRS:
	case MODE_DIFF_IMPORTS:
		c = opencore (file);
		if (!c) {
			eprintf ("Cannot open '%s'\n", r_str_get (file));
		}
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
		if (columnSort) {
			r_config_set (c->config, "diff.sort", columnSort);
			r_config_set (c2->config, "diff.sort", columnSort);
		}
		r_config_set_i (c->config, "diff.bare", showbare);
		r_config_set_i (c2->config, "diff.bare", showbare);
		r_anal_diff_setup_i (c->anal, diffops, threshold, threshold);
		r_anal_diff_setup_i (c2->anal, diffops, threshold, threshold);
		if (pdc) {
			if (!addr) {
				//addr = "entry0";
				addr = "main";
			}
			/* should be in mode not in bool pdc */
			r_config_set_i (c->config, "scr.color", COLOR_MODE_DISABLED);
			r_config_set_i (c2->config, "scr.color", COLOR_MODE_DISABLED);

			ut64 addra = r_num_math (c->num, addr);
			bufa = (ut8 *) r_core_cmd_strf (c, "af;pdc @ 0x%08"PFMT64x, addra);
			sza = strlen ((const char *) bufa);

			ut64 addrb = r_num_math (c2->num, addr);
			bufb = (ut8 *) r_core_cmd_strf (c2, "af;pdc @ 0x%08"PFMT64x, addrb);
			szb = strlen ((const char *) bufb);
			mode = MODE_DIFF;
		} else if (mode == MODE_GRAPH) {
			char *words = strdup (addr? addr: "0");
			char *second = strstr (words, ",");
			if (second) {
				*second++ = 0;
				ut64 off = r_num_math (c->num, words);
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
		} else if (mode == MODE_CODE) {
			r_core_gdiff (c, c2);
			r_core_diff_show (c, c2);
		} else if (mode == MODE_DIFF_IMPORTS) {
			bufa = get_imports (c, &sza);
			bufb = get_imports (c2, &szb);
		} else if (mode == MODE_DIFF_STRS) {
			bufa = get_strings (c, &sza);
			bufb = get_strings (c2, &szb);
		}
		if (mode == MODE_CODE || mode == MODE_GRAPH) {
			r_cons_flush ();
		}
		r_core_free (c);
		r_core_free (c2);

		if (mode == MODE_CODE || mode == MODE_GRAPH) {
			return 0;
		}
		break;
	default:
		bufa = slurp (&c, file, &sza);
		if (!bufa) {
			eprintf ("radiff2: Cannot open %s\n", r_str_get (file));
			return 1;
		}
		bufb = slurp (&c, file2, &szb);
		if (!bufb) {
			eprintf ("radiff2: Cannot open: %s\n", r_str_get (file2));
			free (bufa);
			return 1;
		}
		if (sza != szb) {
			eprintf ("File size differs %d vs %d\n", sza, szb);
		}
		break;
	}

	switch (mode) {
	case MODE_COLS:
		if (!c && !r_list_empty (evals)) {
			c = opencore (NULL);
		}
		dump_cols (bufa, sza, bufb, szb, (r_cons_get_size (NULL) > 112)? 16: 8);
		break;
	case MODE_DIFF:
	case MODE_DIFF_STRS:
	case MODE_DIFF_IMPORTS:
		d = r_diff_new ();
		r_diff_set_delta (d, delta);
		if (diffmode == 'j') {
			printf ("{\"files\":[{\"filename\":\"%s\", \"size\":%d, \"sha256\":\"", file, sza);
			handle_sha256 (bufa, sza);
			printf ("\"},\n{\"filename\":\"%s\", \"size\":%d, \"sha256\":\"", file2, szb);
			handle_sha256 (bufb, szb);
			printf ("\"}],\n");
			printf ("\"changes\":[");
		}
		if (diffmode == 'B') {
			write (1, "\xd1\xff\xd1\xff", 4);
			write (1, "\x04", 1);
		}
		if (diffmode == 'U') {
			r_diff_buffers_unified (d, bufa, sza, bufb, szb);
		} else if (diffmode == 'B') {
			r_diff_set_callback (d, &bcb, 0);
			r_diff_buffers (d, bufa, sza, bufb, szb);
			write (1, "\x00", 1);
		} else {
			r_diff_set_callback (d, &cb, 0); // (void *)(size_t)diffmode);
			r_diff_buffers (d, bufa, sza, bufb, szb);
		}
		if (diffmode == 'j') {
			printf ("]\n");
		}
		r_diff_free (d);
		break;
	case MODE_DIST:
	case MODE_DIST_MYERS:
	case MODE_DIST_LEVENSTEIN:
		{
			RDiff *d = r_diff_new ();
			if (d) {
				d->verbose = verbose;
				if (mode == MODE_DIST_LEVENSTEIN) {
					d->type = 'l';
				} else if (mode == MODE_DIST_MYERS) {
					d->type = 'm';
				} else {
					d->type = 0;
				}
				r_diff_buffers_distance (d, bufa, sza, bufb, szb, &count, &sim);
				r_diff_free (d);
			}
		}
		printf ("similarity: %.3f\n", sim);
		printf ("distance: %d\n", count);
		break;
	}

	if (diffmode == 'j' && showcount) {
		printf (",\"count\":%d}\n", count);
	} else if (showcount && diffmode != 'j') {
		printf ("%d\n", count);
	} else if (!showcount && diffmode == 'j') {
		printf ("}\n");
	}
	free (bufa);
	free (bufb);

	return 0;
}
