/* radare - LGPL - Copyright 2009-2025 - pancake */

#define R_LOG_ORIGIN "radiff2"

#include <r_core.h>
#include <r_main.h>

typedef enum {
	ROF_HEXDUMP, // MODE_COLS
	ROF_HEXII, // MODE_COLSII
} RadiffOutputFormat;

enum {
	MODE_DIFF,
	MODE_DIFF_STRS,
	MODE_DIFF_IMPORTS,
	MODE_DIFF_SYMBOLS,
	MODE_DIFF_SECTIONS,
	MODE_DIFF_CLASSES,
	MODE_DIFF_METHODS,
	MODE_DIFF_FIELDS,
	MODE_DIST_MYERS,
	MODE_DIST_LEVENSHTEIN,
	MODE_CODE,
	MODE_GRAPH,
	MODE_COLS,
	MODE_COLSII,
	MODE_XPATCH,
};

enum {
	GRAPH_DEFAULT_MODE,
	GRAPH_SDB_MODE,
	GRAPH_JSON_MODE,
	GRAPH_JSON_DIS_MODE,
	GRAPH_TINY_MODE,
	GRAPH_INTERACTIVE_MODE,
	GRAPH_DOT_MODE,
	GRAPH_MERMAID_MODE,
	GRAPH_STAR_MODE,
	GRAPH_GML_MODE
};

typedef struct {
	ut64 gdiff_start;
	bool zignatures;
	const char *file;
	const char *file2;
	ut32 count;
	bool showcount;
	bool useva;
	int delta;
	bool json_started;
	int diffmode;
	bool diffops;
	int mode;
	int gmode;
	bool disasm;
	bool pdc;
	bool quiet;
	RCore *core;
	const char *arch;
	RList *runcmd;
	int bits;
	int analysis_level;
	int threshold;
	bool verbose;
	RList *evals;
	PJ *pj;
	ut64 baddr;
	bool thready;
	RCons *cons;
} RadiffOptions;

static RCore *opencore(RadiffOptions *ro, const char *f) {
	RListIter *iter;
	const ut64 baddr = UT64_MAX;
	const char *e;
	RCore *c = r_core_new ();
	if (!c) {
		return NULL;
	}
	r_core_loadlibs (c, R_CORE_LOADLIBS_ALL, NULL);
	r_config_set_b (c->config, "io.va", ro->useva);
	r_config_set_b (c->config, "scr.interactive", false);
	r_list_foreach (ro->evals, iter, e) {
		char *res = r_config_eval (c->config, e, false, NULL);
		r_kons_println (c->cons, res);
		free (res);
	}
	if (f) {
		RIODesc *rfile = NULL;
#if R2__WINDOWS__
		char *winf = r_acp_to_utf8 (f);
		rfile = r_core_file_open (c, winf, 0, 0);
		free (winf);
#else
		rfile = r_core_file_open (c, f, 0, 0);
#endif

		if (!rfile) {
			r_core_free (c);
			return NULL;
		}
		(void) r_core_bin_load (c, NULL, baddr);
		(void) r_core_bin_update_arch_bits (c);

		// force PA mode when working with raw bins
		if (r_list_empty (r_bin_get_sections (c->bin))) {
			r_config_set_i (c->config, "io.va", false);
		}
		if (ro->analysis_level) {
			const char *cmd = "aac";
			switch (ro->analysis_level) {
			case 1: cmd = "aa"; break;
			case 2: cmd = "aaa"; break;
			case 3: cmd = "aaaa"; break;
			case 4: cmd = "aaaaa"; break;
			}
			r_core_cmd0 (c, cmd);
		}
		if (ro->runcmd) {
			const char *cmd;
			RListIter *iter;
			r_list_foreach (ro->runcmd, iter, cmd) {
				r_core_cmd0 (c, cmd);
			}
		}
		// generate zignaturez?
		if (ro->zignatures) {
			r_core_cmd0 (c, "zg");
		}
		r_cons_flush (c->cons);
	}
	// TODO: must enable io.va here if wanted .. r_config_set_i (c->config, "io.va", va);
	return c;
}

static void readstr(char *s, int sz, const ut8 *buf, int len) {
	*s = 0;
	const int last = R_MIN (len, sz);
	if (last > 0) {
		s[sz - 1] = 0;
		while (*s == '\n') {
			s++;
		}
		r_str_ncpy (s, (char *) buf, last);
	}
}

static int cb_xpatch(RDiff *d, void *user, RDiffOp *op) {
	int i;
	RadiffOptions *ro = (RadiffOptions*)user;
	r_kons_printf (ro->cons, "@@ u8,u8,%%2x -0x%08"PFMT64x",%d, +0x%08"PFMT64x",%d @@\n",
			op->a_off + ro->baddr, op->a_len,
			op->b_off + ro->baddr, op->b_len);
	r_kons_printf (ro->cons, "- ");
	for (i = 0; i < op->a_len; i++) {
		r_kons_printf (ro->cons, "%02x", op->a_buf[i]);
	}
	r_kons_printf (ro->cons, "\n+ ");
	for (i = 0; i < op->b_len; i++) {
		r_kons_printf (ro->cons, "%02x", op->b_buf[i]);
	}
	r_cons_newline (ro->cons);
	return 0;
}

static int cb(RDiff *d, void *user, RDiffOp *op) {
	int i;
	RadiffOptions *ro = (RadiffOptions*)user;
	char s[256] = {0};
	if (ro->showcount) {
		ro->count++;
		return 1;
	}
	switch (ro->diffmode) {
	case 'U': // 'U' in theory never handled here
	case 'u':
		if (op->a_len > 0) {
			readstr (s, sizeof (s), op->a_buf, op->a_len);
			if (*s) {
				if (!ro->quiet) {
					printf (Color_RED);
				}
				printf ("-0x%08"PFMT64x":", op->a_off + ro->baddr);
				int len = op->a_len; // R_MIN (op->a_len, strlen (op->a_buf));
				for (i = 0; i < len; i++) {
					printf ("%02x ", op->a_buf[i]);
				}
				if (!ro->quiet) {
					char *p = r_str_escape ((const char*)op->a_buf);
					printf (" \"%s\"", p);
					free (p);
					printf (Color_RESET);
				}
				printf ("\n");
			}
		}
		if (op->b_len > 0) {
			readstr (s, sizeof (s), op->b_buf, op->b_len);
			if (*s) {
				if (!ro->quiet) {
					printf (Color_GREEN);
				}
				printf ("+0x%08"PFMT64x":", op->b_off + ro->baddr);
				for (i = 0; i < op->b_len; i++) {
					printf ("%02x ", op->b_buf[i]);
				}
				if (!ro->quiet) {
					char *p = r_str_escape ((const char*)op->b_buf);
					printf (" \"%s\"", p);
					free (p);
					printf (Color_RESET);
				}
				printf ("\n");
			}
		}
		break;
	case 'r':
		if (ro->disasm) {
			R_LOG_WARN ("r2cmds (-r) + disasm (-D) is not yet implemented");
		}
		if (op->a_len == op->b_len) {
			printf ("wx ");
			for (i = 0; i < op->b_len; i++) {
				printf ("%02x", op->b_buf[i]);
			}
			printf (" @ 0x%08"PFMT64x "\n", op->b_off + ro->baddr);
		} else {
			if (op->a_len > 0) {
				printf ("r-%d @ 0x%08"PFMT64x "\n",
					op->a_len, op->a_off + ro->delta + ro->baddr);
			}
			if (op->b_len > 0) {
				printf ("r+%d @ 0x%08"PFMT64x "\n",
					op->b_len, op->b_off + ro->delta + ro->baddr);
				printf ("wx ");
				for (i = 0; i < op->b_len; i++) {
					printf ("%02x", op->b_buf[i]);
				}
				printf (" @ 0x%08"PFMT64x "\n", op->b_off + ro->delta + ro->baddr);
			}
			ro->delta += (op->b_off - op->a_off);
		}
		return 1;
	case 'j':
		// TODO PJ
		if (ro->disasm) {
			R_LOG_WARN ("JSON (-j) + disasm (-D) not yet implemented");
		}
		{
			PJ *pj = ro->pj;
			pj_o (pj);
			pj_kn (pj, "addr", op->a_off + ro->baddr);
			char *hex_from = r_hex_bin2strdup (op->a_buf, op->a_len);
			pj_ks (pj, "from", hex_from);
			char *hex_to = r_hex_bin2strdup (op->b_buf, op->b_len);
			pj_ks (pj, "to", hex_to);
			pj_end (pj);
		}
		return 1;
	case 0:
	default:
		if (ro->disasm) {
			int i;
			printf ("--- 0x%08"PFMT64x "  ", op->a_off + ro->baddr);
			if (!ro->core) {
				ro->core = opencore (ro, ro->file);
				if (ro->arch) {
					r_config_set (ro->core->config, "asm.arch", ro->arch);
				}
				if (ro->bits) {
					r_config_set_i (ro->core->config, "asm.bits", ro->bits);
				}
			}
			for (i = 0; i < op->a_len; i++) {
				printf ("%02x", op->a_buf[i]);
			}
			printf ("\n");
			if (ro->core) {
				int len = R_MAX (4, op->a_len);
				RAsmCode *ac = r_asm_mdisassemble (ro->core->rasm, op->a_buf, len);
				char *acbufasm = strdup (ac->assembly);
				if (ro->quiet) {
					char *bufasm = r_str_prefix_all (acbufasm, "- ");
					printf ("%s\n", bufasm);
					free (bufasm);
				} else {
					char *bufasm = r_str_prefix_all (acbufasm, Color_RED"- ");
					printf ("%s"Color_RESET, bufasm);
					free (bufasm);
				}
				free (acbufasm);
				r_asm_code_free (ac);
			}
		} else {
			printf ("0x%08"PFMT64x " ", op->a_off + ro->baddr);
			for (i = 0; i < op->a_len; i++) {
				printf ("%02x", op->a_buf[i]);
			}
		}
		if (ro->disasm) {
			int i;
			printf ("+++ 0x%08"PFMT64x "  ", op->b_off + ro->baddr);
			if (!ro->core) {
				ro->core = opencore (ro, NULL);
			}
			for (i = 0; i < op->b_len; i++) {
				printf ("%02x", op->b_buf[i]);
			}
			printf ("\n");
			if (ro->core) {
				int len = R_MAX (4, op->b_len);
				RAsmCode *ac = r_asm_mdisassemble (ro->core->rasm, op->b_buf, len);
				char *acbufasm = strdup (ac->assembly);
				if (ro->quiet) {
					char *bufasm = r_str_prefix_all (acbufasm, "+ ");
					printf ("%s\n", bufasm);
					free (bufasm);
					free (acbufasm);
				} else {
					char *bufasm = r_str_prefix_all (acbufasm, Color_GREEN"+ ");
					printf ("%s\n" Color_RESET, bufasm);
					free (bufasm);
					free (acbufasm);
				}
				// r_asm_code_free (ac);
			}
		} else {
			printf (" => ");
			for (i = 0; i < op->b_len; i++) {
				printf ("%02x", op->b_buf[i]);
			}
			printf (" 0x%08"PFMT64x "\n", op->b_off + ro->baddr);
		}
		return 1;
	}
	return 0;
}

void print_bytes(const void *p, size_t len, bool big_endian) {
	size_t i;
	for (i = 0; i < len; i++) {
		ut8 ch = ((ut8*) p)[big_endian ? (len - i - 1) : i];
		if (write (1, &ch, 1) != 1) {
			break;
		}
	}
}

static int bcb(RDiff *d, void *user, RDiffOp *op) {
	RadiffOptions *ro = user;
	ut64 offset_diff = op->a_off - ro->gdiff_start;
	ut8 opcode;
	ut16 USAddr = 0;
	int IAddr = 0;
	ut8 UCLen = 0;
	ut16 USLen = 0;
	int ILen = 0;

	// we copy from gdiff_start to a_off
	if (offset_diff > 0) {

		// size for the position
		if (ro->gdiff_start <= USHRT_MAX) {
			opcode = 249;
			USAddr = (unsigned short) ro->gdiff_start;
		} else if (ro->gdiff_start <= INT_MAX) {
			opcode = 252;
			IAddr = (int) ro->gdiff_start;
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
			print_bytes (&ro->gdiff_start, sizeof (ro->gdiff_start), true);
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
		R_UNUSED_RESULT (write (1, &data, 1));
	} else if (op->b_len <= USHRT_MAX) {
		USLen = (ut16) op->b_len;
		ut8 data = 247;
		R_UNUSED_RESULT (write (1, &data, 1));
		print_bytes (&USLen, sizeof (USLen), true);
	} else if (op->b_len <= INT_MAX) {
		ut8 data = 248;
		R_UNUSED_RESULT (write (1, &data, 1));
		ILen = (int) op->b_len;
		print_bytes (&ILen, sizeof (ILen), true);
	} else {
		// split into multiple DATA, because op->b_len is greater than INT_MAX
		int times = op->b_len / INT_MAX;
		int max = INT_MAX;
		size_t i;
		for (i = 0; i < times; i++) {
			ut8 data = 248;
			if (write (1, &data, 1) != 1) {
				break;
			}
			print_bytes (&max, sizeof (max), true);
			print_bytes (op->b_buf, max, false);
			op->b_buf += max;
		}
		op->b_len = op->b_len % max;

		// print the remaining size
		int remain_size = op->b_len;
		print_bytes (&remain_size, sizeof (remain_size), true);
	}
	print_bytes (op->b_buf, op->b_len, false);
	ro->gdiff_start = op->b_off + op->b_len;
	return 0;
}

static int show_help(int v) {
	printf ("Usage: radiff2 [-options] [-A[A]] [-B #] [-g sym] [-m graph_mode][-t %%] [file] [file]\n");
	if (v) {
		printf (
			"  -a [arch]  specify architecture plugin to use (x86, arm, ..)\n"
			"  -A [-A]    run aaa or aaaa after loading each binary (see -C)\n"
			"  -b [bits]  specify register size for arch (16 (thumb), 32, 64, ..)\n"
			"  -B [baddr] define the base address to add the offsets when listing\n"
			"  -c [cmd]   run given command on every RCore instance\n"
			"  -C         graphdiff code (columns: off-A, match-ratio, off-B) (see -A)\n"
			"  -d         use delta diffing\n"
			"  -D         show disasm instead of hexpairs\n"
			"  -e [k=v]   set eval config var value for all RCore instances\n"
			"  -f [help]  select output format (see '-f help' for details)\n"
			"  -g [arg]   graph diff of [sym] or functions in [off1,off2]\n"
			"  -i [help]  compare bin information (symbols, strings, classes, ..)\n"
			"  -j         output in json format (see -f json)\n"
			"  -m [mode]  choose the graph output mode (aditsjJ)\n"
			"  -n         count of changes\n"
			"  -O         code diffing with opcode bytes only\n"
			"  -p         use physical addressing (io.va=false) (only for radiff2 -AC)\n"
			"  -q         quiet mode (disable colors, reduce output)\n"
			"  -r         output in radare commands\n"
			"  -s         compute edit distance (no substitution, Eugene W. Myers O(ND) diff algorithm)\n"
			"  -ss        compute Levenshtein edit distance (substitution is allowed, O(N^2))\n"
			"  -S [name]  sort code diff (name, namelen, addr, size, type, dist) (only for -C or -g)\n"
			"  -t [0-100] set threshold for code diff (default is 70%%)\n"
			"  -T         analyze files in threads (EXPERIMENTAL, 30%% faster and crashy)\n"
			"  -x         show two column hexdump diffing\n"
			"  -X         use xpatch format for the diffing output\n"
			"  -u         unified output (---+++)\n"
			"  -U         unified output using system 'diff'\n"
			"  -v         show version information\n"
			"  -V         be verbose (current only for -s)\n"
			);
	}
	return 1;
}

#define DUMP_CONTEXT 2
static void dump_cols(RadiffOptions *ro, ut8 *a, int as, ut8 *b, int bs, int w) {
	ut32 sz = R_MIN (as, bs);
	ut32 i, j;
	int ctx = DUMP_CONTEXT;
	int pad = 0;
	if (!a || !b || as < 0 || bs < 0) {
		return;
	}
	switch (w) {
	case 8:
		r_kons_printf (ro->cons, "  offset     0 1 2 3 4 5 6 7 01234567    0 1 2 3 4 5 6 7 01234567\n");
		break;
	case 16:
		r_kons_printf (ro->cons, "  offset     "
			"0 1 2 3 4 5 6 7 8 9 A B C D E F 0123456789ABCDEF    "
			"0 1 2 3 4 5 6 7 8 9 A B C D E F 0123456789ABCDEF\n");
		break;
	default:
		R_LOG_ERROR ("Invalid column width");
		return;
	}
	r_kons_break_push (ro->cons, NULL, NULL);
	for (i = 0; i < sz; i += w) {
		if (r_kons_is_breaked (ro->cons)) {
			break;
		}
		if (i + w >= sz) {
			pad = w - sz + i;
			w = sz - i;
		}
		bool eq = !memcmp (a + i, b + i, w);
		if (eq) {
			ctx--;
			if (ctx == -1) {
				r_kons_printf (ro->cons, "...\n");
				continue;
			}
			if (ctx < 0) {
				ctx = -1;
				continue;
			}
		} else {
			ctx = DUMP_CONTEXT;
		}
		r_kons_printf (ro->cons, eq? Color_GREEN: Color_RED);
		r_kons_printf (ro->cons, "0x%08x%c ", i, eq? ' ': '!');
		r_kons_printf (ro->cons, Color_RESET);
		for (j = 0; j < w; j++) {
			bool eq2 = a[i + j] == b[i + j];
			if (!eq) {
				r_kons_printf (ro->cons, eq2? Color_GREEN: Color_RED);
			}
			r_kons_printf (ro->cons, "%02x", a[i + j]);
			if (!eq) {
				r_kons_printf (ro->cons, Color_RESET);
			}
		}
		for (j = 0; j < pad; j++) {
			r_kons_printf (ro->cons, "  ");
		}
		r_kons_printf (ro->cons, " ");
		for (j = 0; j < w; j++) {
			bool eq2 = a[i + j] == b[i + j];
			if (!eq) {
				r_kons_printf (ro->cons, eq2? Color_GREEN: Color_RED);
			}
			r_kons_printf (ro->cons, "%c", IS_PRINTABLE (a[i + j])? a[i + j]: '.');
			if (!eq) {
				r_kons_printf (ro->cons, Color_RESET);
			}
		}
		for (j = 0; j < pad; j++) {
			r_kons_printf (ro->cons, " ");
		}
		r_kons_printf (ro->cons, "   ");
		for (j = 0; j < w; j++) {
			bool eq2 = a[i + j] == b[i + j];
			if (!eq) {
				r_kons_printf (ro->cons, eq2? Color_GREEN: Color_RED);
			}
			r_kons_printf (ro->cons, "%02x", b[i + j]);
			if (!eq) {
				r_kons_printf (ro->cons, Color_RESET);
			}
		}
		for (j = 0; j < pad; j++) {
			r_kons_printf (ro->cons, "  ");
		}
		r_kons_printf (ro->cons, " ");
		for (j = 0; j < w; j++) {
			bool eq2 = a[i + j] == b[i + j];
			if (!eq) {
				r_kons_printf (ro->cons, eq2? Color_GREEN: Color_RED);
			}
			r_kons_printf (ro->cons, "%c", IS_PRINTABLE (b[i + j])? b[i + j]: '.');
			if (!eq) {
				r_kons_printf (ro->cons, Color_RESET);
			}
		}
		r_kons_printf (ro->cons, "\n");
		r_cons_flush (ro->cons);
	}
	r_kons_break_end (ro->cons);
	r_kons_printf (ro->cons, "\n"Color_RESET);
	r_cons_flush (ro->cons);
	if (as != bs) {
		r_kons_printf (ro->cons, "...\n");
	}
}

static void dump_cols_hexii(RadiffOptions *ro, ut8 *a, int as, ut8 *b, int bs, int w) {
	bool spacy = false;
	ut32 sz = R_MIN (as, bs);
	ut32 i, j;
	int ctx = DUMP_CONTEXT;
	int pad = 0;
	if (!a || !b || as < 0 || bs < 0) {
		return;
	}
	r_kons_break_push (ro->cons, NULL, NULL);
	for (i = 0; i < sz; i += w) {
		if (r_kons_is_breaked (ro->cons)) {
			break;
		}
		if (i + w >= sz) {
			pad = w - sz + i;
			w = sz - i;
		}
		bool eq = !memcmp (a + i, b + i, w);
		if (eq) {
			ctx--;
			if (ctx == -1) {
				r_kons_printf (ro->cons, "...\n");
				continue;
			}
			if (ctx < 0) {
				ctx = -1;
				continue;
			}
		} else {
			ctx = DUMP_CONTEXT;
		}
		r_kons_printf (ro->cons, eq? Color_GREEN: Color_RED);
		r_kons_printf (ro->cons, "0x%08x%c ", i, eq? ' ': '!');
		r_kons_printf (ro->cons, Color_RESET);
		for (j = 0; j < w; j++) {
			bool eq2 = a[i + j] == b[i + j];
			if (!eq) {
				r_kons_printf (ro->cons, eq2? Color_GREEN: Color_RED);
			}
			ut8 ch = a[i + j];
			if (spacy) {
				r_kons_print (ro->cons, " ");
			}
			if (ch == 0x00) {
				r_kons_print (ro->cons, "  ");
			} else if (ch == 0xff) {
				r_kons_print (ro->cons, "##");
			} else if (IS_PRINTABLE (ch)) {
				r_kons_printf (ro->cons, ".%c", ch);
			} else {
				r_kons_printf (ro->cons, "%02x", ch);
			}
			if (!eq) {
				r_kons_printf (ro->cons, Color_RESET);
			}
		}
		for (j = 0; j < pad; j++) {
			r_kons_printf (ro->cons, "  ");
		}
		for (j = 0; j < pad; j++) {
			r_kons_printf (ro->cons, " ");
		}
		r_kons_printf (ro->cons, "   ");
		for (j = 0; j < w; j++) {
			bool eq2 = a[i + j] == b[i + j];
			if (!eq) {
				r_kons_printf (ro->cons, eq2? Color_GREEN: Color_RED);
			}
			ut8 ch = b[i + j];
			if (spacy) {
				r_kons_print (ro->cons, " ");
			}
			if (ch == 0x00) {
				r_kons_print (ro->cons, "  ");
			} else if (ch == 0xff) {
				r_kons_print (ro->cons, "##");
			} else if (IS_PRINTABLE (ch)) {
				r_kons_printf (ro->cons, ".%c", ch);
			} else {
				r_kons_printf (ro->cons, "%02x", ch);
			}
			if (!eq) {
				r_kons_printf (ro->cons, Color_RESET);
			}
		}
		for (j = 0; j < pad; j++) {
			r_kons_printf (ro->cons, "  ");
		}
		r_kons_printf (ro->cons, "\n");
		r_cons_flush (ro->cons);
	}
	r_kons_break_end (ro->cons);
	r_kons_printf (ro->cons, "\n"Color_RESET);
	r_cons_flush (ro->cons);
	if (as != bs) {
		r_kons_printf (ro->cons, "...\n");
	}
}

static char *handle_sha256(const ut8 *block, int len) {
	int i = 0;
	char *p = malloc (128);
	RHash *ctx = r_hash_new (true, R_HASH_SHA256);
	const ut8 *c = r_hash_do_sha256 (ctx, block, len);
	if (!c) {
		r_hash_free (ctx);
		free (p);
		return NULL;
	}
	char *r = p;
	for (i = 0; i < R_HASH_SIZE_SHA256; i++) {
		snprintf (r + (i * 2), 3, "%02x", c[i]);
	}
	r_hash_free (ctx);
	return p;
}

static ut8 *slurp(RadiffOptions *ro, RCore **c, const char *file, size_t *sz) {
	int fd;
	RIO *io;
	if (c && file && strstr (file, "://")) {
		ut8 *data = NULL;
		ut64 size;
		if (!*c) {
			*c = opencore (ro, NULL);
		}
		if (!*c) {
			R_LOG_ERROR ("opencore failed");
			return NULL;
		}
		io = (*c)->io;
		fd = r_io_fd_open (io, file, R_PERM_R, 0);
		if (fd < 1) {
			return NULL;
		}
		size = r_io_fd_size (io, fd);
		if (size > 0 && size < ST32_MAX) {
			data = calloc (1, size);
			if (r_io_fd_read_at (io, fd, 0, data, size)) {
				if (sz) {
					*sz = size;
				}
			} else {
				R_LOG_ERROR ("slurp: read error");
				R_FREE (data);
			}
		} else {
			R_LOG_ERROR ("slurp: Invalid file size");
		}
		r_io_fd_close (io, fd);
		return data;
	}
	return (ut8 *) r_file_slurp (file, sz);
}

static int import_cmp(const RBinImport *a, const RBinImport *b) {
	const char *aname = r_bin_name_tostring (a->name);
	const char *bname = r_bin_name_tostring (b->name);
	return strcmp (aname, bname);
}

static ut8 *get_sections(RCore *c, int *len) {
	RListIter *iter;

	if (!c || !len) {
		return NULL;
	}

	RBinSection *sec;
	const RList *list = r_bin_get_sections (c->bin);
	RList *reslist = r_list_newf (free);
	r_list_foreach (list, iter, sec) {
		r_list_append (reslist, strdup (sec->name));
	}
	r_list_sort (reslist, (RListComparator)strcmp);
	char *buf = r_str_list_join (reslist, "\n");
	*len = strlen (buf);
	r_list_free (reslist);
	return (ut8*)buf;
}

static ut8 *get_classes(RCore *c, int *len) {
	RListIter *iter;

	if (!c || !len) {
		return NULL;
	}

	RBinClass *klass;
	const RList *list = r_bin_get_classes (c->bin);
	RList *reslist = r_list_newf (free);
	r_list_foreach (list, iter, klass) {
		const char *kname = r_bin_name_tostring (klass->name);
		r_list_append (reslist, strdup (kname));
	}
	r_list_sort (reslist, (RListComparator)strcmp);
	char *buf = r_str_list_join (reslist, "\n");
	*len = strlen (buf);
	r_list_free (reslist);
	return (ut8*)buf;
}

static ut8 *get_fields(RCore *c, int *len) {
	R_RETURN_VAL_IF_FAIL (c, NULL);
	const int pref = r_config_get_b (c->config, "asm.demangle")? 'd': 0;

	if (!len) {
		// uh?
		return NULL;
	}

	RBinClass *klass;
	const RList *list = r_bin_get_classes (c->bin);
	RList *reslist = r_list_newf (free);
	RListIter *iter, *iter2;
	r_list_foreach (list, iter, klass) {
		const char *kname = r_bin_name_tostring (klass->name);
		RBinField *field;
		r_list_foreach (klass->fields, iter2, field) {
			const char *fname = r_bin_name_tostring2 (field->name, pref);
			r_list_append (reslist, r_str_newf ("%s.%s", kname, fname));
		}
	}
	r_list_sort (reslist, (RListComparator)strcmp);
	char *buf = r_str_list_join (reslist, "\n");
	*len = strlen (buf);
	r_list_free (reslist);
	return (ut8*)buf;
}

static ut8 *get_methods(RCore *c, int *len) {
	RListIter *iter, *iter2;

	if (!c || !len) {
		return NULL;
	}

	RBinClass *klass;
	RBinSymbol *sym;
	const RList *list = r_bin_get_classes (c->bin);
	RList *reslist = r_list_newf (free);
	r_list_foreach (list, iter, klass) {
		const char *kname = r_bin_name_tostring (klass->name);
		r_list_foreach (klass->methods, iter2, sym) {
			const char *name = r_bin_name_tostring (sym->name);
			r_list_append (reslist, r_str_newf ("%s.%s", kname, name));
		}
	}
	r_list_sort (reslist, (RListComparator)strcmp);
	char *buf = r_str_list_join (reslist, "\n");
	*len = strlen (buf);
	r_list_free (reslist);
	return (ut8*)buf;
}

static ut8 *get_symbols(RCore *c, int *len) {
	RListIter *iter;

	if (!c || !len) {
		return NULL;
	}

	RBinSymbol *sym;
	const RList *list = r_bin_get_symbols (c->bin);
	RList *reslist = r_list_newf (free);
	r_list_foreach (list, iter, sym) {
		const char *name = r_bin_name_tostring (sym->name);
		r_list_append (reslist, strdup (name));
	}
	char *buf = r_str_list_join (reslist, "\n");
	*len = strlen (buf);
	r_list_free (reslist);
	return (ut8*)buf;
}

static ut8 *get_imports(RCore *c, int *len) {
	RListIter *iter;
	RBinImport *str, *old = NULL;

	if (!c || !len) {
		return NULL;
	}

	const RList *list = r_bin_get_imports (c->bin);
	// XXX we probably dont want to sort an unowned list
	r_list_sort ((RList *)list, (RListComparator) import_cmp);

	*len = 0;

	RStrBuf *sb = r_strbuf_new ("");
	r_list_foreach (list, iter, str) {
		if (old && !import_cmp (old, str)) {
			continue;
		}
		const char *symname = r_bin_name_tostring (str->name);
		r_strbuf_appendf (sb, "%s\n", symname);
		old = str;
	}

	*len = r_strbuf_length (sb);
	return (ut8*)r_strbuf_drain (sb);
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

static char *get_graph_commands(RCore *c, ut64 off) {
	RConsContext *ctx = c->cons->context;
	bool tmp_html = ctx->is_html;
	ctx->is_html = false;
	r_kons_push (c->cons);
	r_core_anal_graph (c, off, R_CORE_ANAL_GRAPHBODY | R_CORE_ANAL_GRAPHDIFF |  R_CORE_ANAL_STAR);
	const char *static_str = r_kons_get_buffer (c->cons, NULL);
	char *retstr = strdup (r_str_get (static_str));
	r_kons_pop (c->cons);
	r_kons_echo (c->cons, NULL);
	ctx->is_html = tmp_html;
	return retstr;
}

static void __generate_graph(RCore *c, ut64 off) {
	R_RETURN_IF_FAIL (c);
	char *ptr = get_graph_commands (c, off);
	char *str = ptr;
	r_kons_break_push (c->cons, NULL, NULL);
	if (str) {
		for (;;) {
			if (r_kons_is_breaked (c->cons)) {
				break;
			}
			char *eol = strchr (ptr, '\n');
			if (eol) {
				*eol = '\0';
			}
			if (*ptr) {
				char *p = strdup (ptr);
				if (!p) {
					free (str);
					return;
				}
				r_core_cmd0 (c, p);
				free (p);
			}
			if (!eol) {
				break;
			}
			ptr = eol + 1;
		}
		free (str);
	}
	r_kons_break_pop (c->cons);
}

static void __print_diff_graph(RCore *c, ut64 off, int gmode) {
	int opts = R_CORE_ANAL_GRAPHBODY | R_CORE_ANAL_GRAPHDIFF;
	int use_utf8 = r_config_get_i (c->config, "scr.utf8");
	r_agraph_reset (c->graph);
	switch (gmode) {
	case GRAPH_DOT_MODE:
		r_core_anal_graph (c, off, opts);
		break;
	case GRAPH_MERMAID_MODE:
		r_core_agraph_print (c, use_utf8, "m");
		break;
	case GRAPH_STAR_MODE:
		r_core_anal_graph (c, off, opts | R_CORE_ANAL_STAR);
		break;
	case GRAPH_TINY_MODE:
		__generate_graph (c, off);
		r_core_agraph_print (c, use_utf8, "t");
		break;
	case GRAPH_INTERACTIVE_MODE:
		__generate_graph (c, off);
		r_core_agraph_print (c, use_utf8, "v");
		r_kons_reset_colors (c->cons);
		break;
	case GRAPH_SDB_MODE:
		__generate_graph (c, off);
		r_core_agraph_print (c, use_utf8, "k");
		break;
	case GRAPH_GML_MODE:
		__generate_graph (c, off);
		r_core_agraph_print (c, use_utf8, "g");
		break;
	case GRAPH_JSON_MODE:
		r_core_anal_graph (c, off, opts | R_CORE_ANAL_JSON);
		break;
	case GRAPH_JSON_DIS_MODE:
		r_core_anal_graph (c, off, opts | R_CORE_ANAL_JSON | R_CORE_ANAL_JSON_FORMAT_DISASM);
		break;
	case GRAPH_DEFAULT_MODE:
	default:
		__generate_graph (c, off);
		r_core_agraph_print (c, use_utf8, "");
		r_kons_reset_colors (c->cons);
		break;
	}
}

static void radiff_options_init(RadiffOptions *ro) {
	memset (ro, 0, sizeof (RadiffOptions));
	ro->threshold = -1;
	ro->useva = true;
	ro->evals = r_list_newf (NULL);
	ro->mode = MODE_DIFF;
	ro->gmode = GRAPH_DEFAULT_MODE;
	ro->cons = r_cons_singleton ();
	if (!ro->cons) {
		ro->cons = r_cons_new ();
	}
}

static void radiff_options_fini(RadiffOptions *ro) {
	r_list_free (ro->runcmd);
	r_list_free (ro->evals);
	r_core_free (ro->core);
	r_kons_free (ro->cons);
}

static void fileobj(RadiffOptions *ro, const char *ro_file, const ut8 *buf, size_t sz) {
	PJ *pj = ro->pj;
	pj_o (pj);
	pj_ks (pj, "filename", ro_file);
	pj_kn (pj, "size", sz);
	char *hasha = handle_sha256 (buf, (int)sz);
	pj_ks (pj, "sha256", hasha);
	free (hasha);
	pj_end (pj);
}

static inline bool singlechar(const char *arg) {
	return (arg[0] && !arg[1]);
}

static const char idhelp[] = \
	"Usage: radiff2 -i [what]\n"
	"Available whats:\n"
	" c code\n"
	" d data\n"
	"Binary Information:\n"
	" c classes\n"
	" f fields\n"
	" i imports\n"
	" m methods\n"
	" s symbols\n"
	" S sections\n"
	" z strings\n"
	" Z zignatures\n"
;

static bool select_input_data(RadiffOptions *ro, const char *arg) {
	char ch0 = *arg;
	if (!singlechar (arg)) {
		if (!strcmp (arg, "symbols")) {
			ch0 = 's';
		} else if (!strcmp (arg, "imports")) {
			ch0 = 'i';
		} else if (!strcmp (arg, "classes")) {
			ch0 = 'c';
		} else if (!strcmp (arg, "fields")) {
			ch0 = 'f';
		} else if (!strcmp (arg, "methods")) {
			ch0 = 'm';
		} else if (!strcmp (arg, "code")) {
			ch0 = 'k';
		} else if (!strcmp (arg, "data")) {
			ch0 = 'd';
		} else if (!strcmp (arg, "strings")) {
			ch0 = 'z';
		} else if (!strcmp (arg, "sections")) {
			ch0 = 'S';
		} else if (!strcmp (arg, "help")) {
			ch0 = 'h';
		} else if (!strcmp (arg, "zignatures")) {
			ch0 = 'Z';
		} else {
			return false;
		}
	}
	switch (ch0) {
	case '?':
	case 'h':
		printf ("%s\n", idhelp);
		return false;
	case 'c':
		ro->mode = MODE_DIFF_CLASSES;
		break;
	case 'd':
		// diff code instead of bin
	//	ro->mode = MODE_CODE;
	//	ro->diffmode = 'U';
		break;
	case 'f':
		ro->mode = MODE_DIFF_FIELDS;
		break;
	case 'k':
		// diff code instead of bin
		ro->mode = MODE_CODE;
		ro->diffmode = 'U';
		break;
	case 'i':
		ro->mode = MODE_DIFF_IMPORTS;
		break;
	case 's':
		ro->mode = MODE_DIFF_SYMBOLS;
		break;
	case 'S':
		ro->mode = MODE_DIFF_SECTIONS;
		break;
	case 'm':
		ro->mode = MODE_DIFF_METHODS;
		break;
	case 'z':
		ro->mode = MODE_DIFF_STRS;
		break;
	case 'Z':
		ro->zignatures = true;
		break;
	default:
		return false;
	}
	return true;
}

static const char gfhelp[] = \
	"Usage: radiff2 -m [graphtype]\n"
	"Available types:\n"
	"  <blank/a>  ascii art\n"
	"  s          r2 commands\n"
	"  d          graphviz dot\n"
	"  g          graph Modelling Language (gml)\n"
	"  j          json\n"
	"  J          json with disasm\n"
	"  k          sdb key-value\n"
	"  t          tiny ascii art\n"
	"  i          interactive ascii art\n"
;

static bool select_graph_type(RadiffOptions *ro, const char *arg) {
	char ch0 = *arg;
	if (!singlechar (arg)) {
		if (!strcmp (arg, "sdb")) {
			ch0 = 'k';
		} else if (!strcmp (arg, "tui")) {
			ch0 = 'i';
		} else if (!strcmp (arg, "json")) {
			ch0 = 'j';
		} else if (!strcmp (arg, "r2")) {
			ch0 = 'r';
		} else if (!strcmp (arg, "dot")) {
			ch0 = 'd';
		} else if (!strcmp (arg, "tiny")) {
			ch0 = 't';
		} else if (!strcmp (arg, "jsondis")) {
			ch0 = 'J';
		} else if (!strcmp (arg, "mermaid")) {
			ch0 = 'm';
		} else if (!strcmp (arg, "gml")) {
			ch0 = 'g';
		} else if (!strcmp (arg, "help")) {
			ch0 = '?';
		} else {
			return false;
		}
	}
	switch (ch0) {
	case '?':
	case 'h':
		printf ("%s\n", gfhelp);
		return false;
	case 'i': ro->gmode = GRAPH_INTERACTIVE_MODE; break;
	case 'k': ro->gmode = GRAPH_SDB_MODE; break;
	case 'j': ro->gmode = GRAPH_JSON_MODE; break;
	case 'J': ro->gmode = GRAPH_JSON_DIS_MODE; break;
	case 't': ro->gmode = GRAPH_TINY_MODE; break;
	case 'd': ro->gmode = GRAPH_DOT_MODE; break;
	case 'r': ro->gmode = GRAPH_STAR_MODE; break;
	case 'm': ro->gmode = GRAPH_MERMAID_MODE; break;
	case 'g': ro->gmode = GRAPH_GML_MODE; break;
	case 'a':ro->gmode = GRAPH_DEFAULT_MODE; break;
	default:
		 return false;
	}
	return true;
}
static const char ofhelp[] = \
	"Usage: radiff2 -f [format]\n"
	"Available formats:\n"
	" 1 bdiff        generic binary diff format\n"
	" j json         json format\n"
	" r radare       output as radare2 script\n"
	" u unified      unified diffing format\n"
	" U gdiff        use system's diff program instead\n"
	" x hex          two column hexdump-style\n"
	" X hexii        simplified hexdump (hexII format)\n"
;

static bool select_output_format(RadiffOptions *ro, const char *arg) {
	char ch0 = *arg;
	if (!singlechar (arg)) {
		if (!strcmp (arg, "hexii")) {
			ch0 = 'X';
		} else if (r_str_startswith (arg, "hex")) {
			ch0 = 'x';
		} else if (!strcmp (arg, "r2") || !strcmp (arg, "radare")) {
			ch0 = 'r';
		} else if (!strcmp (arg, "unified")) {
			ch0 = 'u';
		} else if (!strcmp (arg, "json")) {
			ch0 = 'j';
		} else if (!strcmp (arg, "gdiff")) {
			ch0 = 'U';
		} else if (!strcmp (arg, "bdiff")) {
			ch0 = '1';
		} else if (!strcmp (arg, "help")) {
			ch0 = '?';
		} else {
			return false;
		}
	}
	switch (ch0) {
	case '?':
	case 'h':
		printf ("%s\n", ofhelp);
		return false;
	case 'j':
		ro->diffmode = 'j';
		ro->pj = pj_new ();
		break;
	case 'u':
		ro->diffmode = 'u';
		break;
	case 'U':
		ro->diffmode = 'U';
		break;
	case 'x':
		ro->mode = MODE_COLS;
		break;
	case 'r':
		ro->diffmode = 'r';
		break;
	case '1':
		ro->diffmode = 'B';
		break;
	case 'X':
		ro->mode = MODE_COLSII;
		break;
	default:
		return false;
	}
	return true;
}

typedef struct {
	RCore **core;
	const char *file;
	RadiffOptions *ro;
} ThreadData;

static RThreadFunctionRet thready_core(RThread *th) {
	ThreadData *td = (ThreadData*)th->user;
	*td->core = NULL;
	*td->core = opencore (td->ro, td->file);
	return false;
}

R_API int r_main_radiff2(int argc, const char **argv) {
	RadiffOptions ro;
	const char *columnSort = NULL;
	const char *addr = NULL;
	RCore *c = NULL, *c2 = NULL;
	ut8 *bufa = NULL, *bufb = NULL;
	int o, delta = 0;
	ut64 sza = 0, szb = 0;
	double sim = 0.0;
	RDiff *d;
	RGetopt opt;

	radiff_options_init (&ro);

	r_getopt_init (&opt, argc, argv, "Aa:b:B:c:CdDe:f:g:hi:jm:nOprst:TXxuUqvV");
	while ((o = r_getopt_next (&opt)) != -1) {
		switch (o) {
		case 'a':
			ro.arch = opt.arg;
			break;
		case 'A':
			ro.analysis_level++;
			break;
		case 'b':
			ro.bits = atoi (opt.arg);
			break;
		case 'B':
			ro.baddr = r_num_math (NULL, opt.arg);
			break;
		case 'c':
			if (!ro.runcmd) {
				ro.runcmd = r_list_newf (NULL);
			}
			r_list_append (ro.runcmd, (void*)opt.arg);
			break;
		case 'C':
			ro.mode = MODE_CODE;
			ro.diffmode = 'U';
			break;
		case 'd':
			delta = 1;
			break;
		case 'D':
			if (ro.disasm) {
				ro.pdc = true;
				ro.disasm = true;
				ro.mode = MODE_CODE;
			} else {
				ro.disasm = true;
			}
			break;
		case 'e':
			r_list_append (ro.evals, (void*)opt.arg);
			break;
		case 'f':
			if (!select_output_format (&ro, opt.arg)) {
				R_LOG_ERROR ("Invalid output format selected");
				return 1;
			}
			break;
		case 'g':
			ro.mode = MODE_GRAPH;
			// ro.pdc = true;
			addr = opt.arg;
			break;
		case 'h':
			return show_help (1);
		case 'i':
			if (!select_input_data (&ro, opt.arg)) {
				R_LOG_ERROR ("Invalid input data selected (see -i help)");
				return 1;
			}
			break;
		case 'j':
			ro.diffmode = 'j';
			ro.pj = pj_new ();
			break;
		case 'm':
			if (!select_graph_type (&ro, opt.arg)) {
				R_LOG_ERROR ("Invalid input data selected (see -i help)");
				return 1;
			}
			break;
		case 'n':
			ro.showcount = true;
			break;
		case 'O': // move to options
			ro.diffops = true;
			break;
		case 'p':
			ro.useva = false;
			break;
		case 'r':
			ro.diffmode = 'r';
			break;
		case 's':
			// TODO: maybe use -a to select algorithm?
			ro.mode = (ro.mode == MODE_DIST_MYERS)
				? MODE_DIST_LEVENSHTEIN
				: MODE_DIST_MYERS;
			break;
		case 'S':
			columnSort = opt.arg;
			break;
		case 't':
			ro.threshold = atoi (opt.arg);
			// printf ("%s\n", opt.arg);
			break;
		case 'T': // imho `t <=> T`
			R_LOG_WARN ("Threading support is experimental and known to be crashy");
			ro.thready = true;
			// printf ("%s\n", opt.arg);
			break;
		case 'x':
			ro.mode = MODE_COLS;
			break;
		case 'X':
			ro.mode = MODE_XPATCH;
			break;
		case 'u':
			ro.diffmode = 'u';
			break;
		case 'U':
			ro.diffmode = 'U';
			break;
		case 'q':
			ro.quiet = true;
			break;
		case 'v':
			return r_main_version_print ("radiff2", 0);
		case 'V':
			ro.verbose = true;
			break;
		default:
			return show_help (0);
		}
	}

	if (argc < 3 || opt.ind + 2 > argc) {
		return show_help (0);
	}
	ro.file = (opt.ind < argc)? argv[opt.ind]: NULL;
	ro.file2 = (opt.ind + 1 < argc)? argv[opt.ind + 1]: NULL;

	if (R_STR_ISEMPTY (ro.file) || R_STR_ISEMPTY (ro.file2)) {
		R_LOG_ERROR ("Cannot open empty path");
		return 1;
	}

	switch (ro.mode) {
	case MODE_GRAPH:
	case MODE_CODE:
	case MODE_DIFF_STRS:
	case MODE_DIFF_METHODS:
	case MODE_DIFF_CLASSES:
	case MODE_DIFF_FIELDS:
	case MODE_DIFF_SYMBOLS:
	case MODE_DIFF_IMPORTS:
		if (ro.thready) {
			// spawn 1st thread
			ThreadData t0d = { .core = &c, .file = ro.file, .ro = &ro };
			RThread *t0 = r_th_new (thready_core, &t0d, false);
			r_th_start (t0);
			// spawn 2nd thread
			ThreadData t1d = { .core = &c2, .file = ro.file2, .ro = &ro };
			RThread *t1 = r_th_new (thready_core, &t1d, false);
			r_th_start (t1);
			// sync
			r_th_wait (t0);
			r_th_wait (t1);
		} else {
			c = opencore (&ro, ro.file);
			if (!c) {
				R_LOG_ERROR ("Cannot open '%s'", r_str_getf (ro.file));
				return 1;
			}
			c2 = opencore (&ro, ro.file2);
			if (!c2) {
				R_LOG_ERROR ("Cannot open '%s'", r_str_getf (ro.file2));
				return 1;
			}
		}
		if (!c || !c2) {
			return 1;
		}
		c->c2 = c2;
		c2->c2 = c;
		r_core_parse_radare2rc (c);
		if (ro.arch) {
			r_config_set (c->config, "asm.arch", ro.arch);
			r_config_set (c2->config, "asm.arch", ro.arch);
		}
		if (ro.bits) {
			r_config_set_i (c->config, "asm.bits", ro.bits);
			r_config_set_i (c2->config, "asm.bits", ro.bits);
		}
		if (columnSort) {
			r_config_set (c->config, "diff.sort", columnSort);
			r_config_set (c2->config, "diff.sort", columnSort);
		}
		r_anal_diff_setup_i (c->anal, ro.diffops, ro.threshold, ro.threshold);
		r_anal_diff_setup_i (c2->anal, ro.diffops, ro.threshold, ro.threshold);
		if (addr) {
			bool err = false;
			if (r_num_math (c->num, addr) == 0) {
				err = true;
			} else if (r_num_math (c2->num, addr) == 0) {
				err = true;
			}
			if (err) {
				R_LOG_ERROR ("Unknown symbol name '%s'", addr);
				return -1;
			}
		} else {
			if (r_num_math (c->num, "main")) {
				addr = "main";
			} else if (r_num_math (c->num, "entry0")) {
				addr = "entry0";
			} else {
				R_LOG_WARN ("Cannot find entrypoint");
			}
		}
		if (ro.pdc) {
			const char *r2cmd = "pdc";
			/* should be in mode not in bool pdc */
			r_config_set_i (c->config, "scr.color", 0);
			r_config_set_i (c2->config, "scr.color", 0);

			ut64 addra = r_num_math (c->num, addr);
			bufa = (ut8 *) r_core_cmd_strf (c, "af;%s @ 0x%08"PFMT64x, r2cmd, addra);
			sza = (ut64)strlen ((const char *) bufa);

			ut64 addrb = r_num_math (c2->num, addr);
			bufb = (ut8 *) r_core_cmd_strf (c2, "af;%s @ 0x%08"PFMT64x, r2cmd, addrb);
			szb = (ut64)strlen ((const char *) bufb);
			ro.mode = MODE_DIFF;
		} else if (ro.mode == MODE_GRAPH) {
			int depth = r_config_get_i (c->config, "anal.depth");
			if (depth < 1) {
				depth = 64;
			}
			char *words = strdup (r_str_get_fail (addr, "0"));
			char *second = strchr (words, ',');
			if (second) {
				*second++ = 0;
				ut64 off = r_num_math (c->num, words);
				// define the same function at each offset
				r_core_anal_fcn (c, off, UT64_MAX, R_ANAL_REF_TYPE_NULL, depth);
				r_core_anal_fcn (c2, r_num_math (c2->num, second),
					UT64_MAX, R_ANAL_REF_TYPE_NULL, depth);
				r_core_gdiff (c, c2);
				__print_diff_graph (c, off, ro.gmode);
			} else {
				r_core_anal_fcn (c, r_num_math (c->num, words),
					UT64_MAX, R_ANAL_REF_TYPE_NULL, depth);
				r_core_anal_fcn (c2, r_num_math (c2->num, words),
					UT64_MAX, R_ANAL_REF_TYPE_NULL, depth);
				r_core_gdiff (c, c2);
				__print_diff_graph (c, r_num_math (c->num, addr), ro.gmode);
			}
			free (words);
		} else if (ro.mode == MODE_CODE) {
			if (ro.zignatures) {
				r_core_cmd0 (c, "z~?");
				r_core_cmd0 (c2, "z~?");
				r_core_zdiff (c, c2);
			} else {
				r_core_gdiff (c, c2);
				if (ro.diffmode == 'j') {
					r_core_diff_show_json (c, c2);
				} else {
					r_core_diff_show (c, c2);
				}
			}
		} else if (ro.mode == MODE_DIFF_FIELDS) {
			int sz;
			bufa = get_fields (c, &sz);
			sza = sz;
			bufb = get_fields (c2, &sz);
			szb = sz;
		} else if (ro.mode == MODE_DIFF_METHODS) {
			int sz;
			bufa = get_methods (c, &sz);
			sza = sz;
			bufb = get_methods (c2, &sz);
			szb = sz;
		} else if (ro.mode == MODE_DIFF_CLASSES) {
			int sz;
			bufa = get_classes (c, &sz);
			sza = sz;
			bufb = get_classes (c2, &sz);
			szb = sz;
		} else if (ro.mode == MODE_DIFF_SECTIONS) {
			int sz;
			bufa = get_sections (c, &sz);
			sza = sz;
			bufb = get_sections (c2, &sz);
			szb = sz;
		} else if (ro.mode == MODE_DIFF_SYMBOLS) {
			int sz;
			bufa = get_symbols (c, &sz);
			sza = sz;
			bufb = get_symbols (c2, &sz);
			szb = sz;
		} else if (ro.mode == MODE_DIFF_IMPORTS) {
			int sz;
			bufa = get_imports (c, &sz);
			sza = sz;
			bufb = get_imports (c2, &sz);
			szb = sz;
		} else if (ro.mode == MODE_DIFF_STRS) {
			int sz;
			bufa = get_strings (c, &sz);
			sza = sz;
			bufb = get_strings (c2, &sz);
			szb = sz;
		}
// r_kons_printf (c2->cons, "PENE\n");
		if (ro.mode == MODE_CODE || ro.mode == MODE_GRAPH) {
			r_cons_flush (c->cons);
			r_cons_flush (c2->cons);
			r_cons_flush (ro.cons);
		}
		r_core_free (c);
		r_core_free (c2);
		if (ro.mode == MODE_CODE || ro.mode == MODE_GRAPH) {
			return 0;
		}
		break;
	default: {
		size_t fsz = 0;
		bufa = slurp (&ro, &c, ro.file, &fsz);
		sza = fsz;
		if (!bufa) {
			R_LOG_ERROR ("Cannot open %s", r_str_getf (ro.file));
			return 1;
		}
		bufb = slurp (&ro, &c, ro.file2, &fsz);
		szb = fsz;
		if (!bufb) {
			R_LOG_ERROR ("Cannot open: %s", r_str_getf (ro.file2));
			free (bufa);
			return 1;
		}
		if (sza != szb) {
			R_LOG_INFO ("File size differs %"PFMT64u" vs %"PFMT64u, (ut64)sza, (ut64)szb);
		}
		break;
	}
	}

	switch (ro.mode) {
	case MODE_XPATCH:
		d = r_diff_new ();
		r_diff_set_delta (d, delta);
		r_kons_printf (ro.cons, "--- %s\n", ro.file);
		r_kons_printf (ro.cons, "+++ %s\n", ro.file2);
		r_diff_set_callback (d, &cb_xpatch, &ro);
		r_diff_buffers (d, bufa, (ut32)sza, bufb, (ut32)szb);
		r_cons_flush (ro.cons);
		break;
	case MODE_COLSII:
		if (!c && !r_list_empty (ro.evals)) {
			c = opencore (&ro, NULL);
		}
		dump_cols_hexii (&ro, bufa, (int)sza, bufb, (int)szb, (r_cons_get_size (ro.cons, NULL) > 112)? 16: 8);
		break;
	case MODE_COLS:
		if (!c && !r_list_empty (ro.evals)) {
			c = opencore (&ro, NULL);
		}
		dump_cols (&ro, bufa, (int)sza, bufb, (int)szb, (r_cons_get_size (ro.cons, NULL) > 112)? 16: 8);
		break;
	case MODE_DIFF:
	case MODE_DIFF_STRS:
	case MODE_DIFF_FIELDS:
	case MODE_DIFF_SYMBOLS:
	case MODE_DIFF_METHODS:
	case MODE_DIFF_CLASSES:
	case MODE_DIFF_IMPORTS:
		d = r_diff_new ();
		r_diff_set_delta (d, delta);
		if (ro.diffmode == 'j') {
			pj_o (ro.pj);
			pj_ka (ro.pj, "files");
			fileobj (&ro, ro.file, bufa, sza);
			fileobj (&ro, ro.file2, bufb, szb);
			pj_end (ro.pj);
			pj_ka (ro.pj, "changes");
		}
		if (ro.diffmode == 'B') {
			R_UNUSED_RESULT (write (1, "\xd1\xff\xd1\xff\x04", 5));
		}
		if (ro.diffmode == 'U') {
			char *res = r_diff_buffers_unified (d, bufa, (int)sza, bufb, (int)szb);
			if (res) {
				printf ("%s", res);
				free (res);
			}
		} else if (ro.diffmode == 'B') {
			r_diff_set_callback (d, &bcb, &ro);
			r_diff_buffers (d, bufa, (ut32)sza, bufb, (ut32)szb);
			R_UNUSED_RESULT (write (1, "\x00", 1));
		} else {
			r_diff_set_callback (d, &cb, &ro);
			// r_diff_buffers (d, bufa, (ut32)sza, bufb, (ut32)szb);
			if (ro.pdc) {
				char *res = r_diff_buffers_unified (d, bufa, (ut32)sza, bufb, (ut32)szb);
				r_kons_printf (ro.cons, "%s\n", res);
				free (res);
			} else {
				r_diff_buffers (d, bufa, (ut32)sza, bufb, (ut32)szb);
				// r_diff_buffers_delta (d, bufa, (ut32)sza, bufb, (ut32)szb);
			}
		}
		if (ro.diffmode == 'j') {
			pj_end (ro.pj);
		}
		r_diff_free (d);
		break;
	case MODE_DIST_MYERS:
	case MODE_DIST_LEVENSHTEIN:
		{
			RDiff *d = r_diff_new ();
			if (d) {
				d->verbose = ro.verbose;
				if (ro.mode == MODE_DIST_MYERS) {
					d->type = 'm';
				} else {
					d->type = 'l';
				}
				r_diff_buffers_distance (d, bufa, (ut32)sza, bufb, (ut32)szb, &ro.count, &sim);
				r_diff_free (d);
			}
		}
		printf ("similarity: %.3f\n", sim);
		printf ("distance: %d\n", ro.count);
		break;
	}

	if (ro.diffmode == 'j' && ro.showcount) {
		pj_kd (ro.pj, "count", ro.count);
	} else if (ro.showcount && ro.diffmode != 'j') {
		printf ("%d\n", ro.count);
	}
	if (ro.pj) {
		pj_end (ro.pj);
		char *s = pj_drain (ro.pj);
		printf ("%s\n", s);
		free (s);
		ro.pj = NULL;
	}
	free (bufa);
	free (bufb);
	radiff_options_fini (&ro);

	return 0;
}
