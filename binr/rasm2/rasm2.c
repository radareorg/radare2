/* radare - LGPL - Copyright 2009-2017 - pancake, nibble, maijin */

#include "../blob/version.c"
#include <getopt.c> /* getopt.h is not portable :D */
#include <r_anal.h>
#include <r_asm.h>
#include <r_lib.h>
#include <r_types.h>
#include <r_util.h>
#include <stdio.h>
#include <string.h>

static RLib *l = NULL;
static RAsm *a = NULL;
static RAnal *anal = NULL;
static int coutput = false;
static bool json = false;
static bool quiet = false;

static int showanal(RAnal *lanal, RAnalOp *op, ut64 offset, ut8 *buf, int len, bool json);

// TODO: add israw/len
static int show_analinfo(const char *arg, ut64 offset) {
	ut8 *buf = (ut8 *)strdup ((const char *)arg);
	int ret, len;
	len = r_hex_str2bin ((char *)buf, buf);
	RAnalOp aop = { 0 };
	if (json) {
		printf ("[");
	}
	for (ret = 0; ret < len;) {
		aop.size = 0;
		if (r_anal_op (anal, &aop, offset, buf + ret, len - ret) > 0) {
			//printf ("%s\n", R_STRBUF_SAFEGET (&aop.esil));
		}
		if (aop.size < 1) {
			if (json) {
				printf ("{\"bytes\": \"%s\",", r_hex_bin2strdup (buf, ret));
				printf ("\"type\": \"Invalid\"}");
			} else {
				eprintf ("Invalid\n");
			}
			break;
		}
		showanal (anal, &aop, offset, buf + ret, len - ret, json);
		if (json && ret + 1 != len) {
			printf (",");
		}
		ret += aop.size;
		r_anal_op_fini (&aop);
	}
	if (json) {
		printf ("]");
	}
	free (buf);
	return ret;
}

static const char *has_esil(RAnal *lanal, const char *name) {
	RListIter *iter;
	RAnalPlugin *h;
	r_list_foreach (anal->plugins, iter, h) {
		if (!strcmp (name, h->name)) {
			if (h->esil) {
				return "Ae";
			}
			return "A_";
		}
	}
	return "__";
}

static void rasm2_list(RAsm *la, const char *arch) {
	int i;
	char bits[32];
	const char *feat2, *feat;
	RAsmPlugin *h;
	RListIter *iter;
	if (json) {
		printf ("{");
	}
	r_list_foreach (a->plugins, iter, h) {
		if (arch) {
			if (h->cpus && !strcmp (arch, h->name)) {
				char *c = strdup (h->cpus);
				int n = r_str_split (c, ',');
				for (i = 0; i < n; i++)
					printf ("%s\n", r_str_word_get0 (c, i));
				free (c);
				break;
			}
		} else {
			bits[0] = 0;
			if (h->bits == 27) {
				strcat (bits, "27");
			} else {
				if (h->bits & 8) strcat (bits, "8 ");
				if (h->bits & 16) strcat (bits, "16 ");
				if (h->bits & 32) strcat (bits, "32 ");
				if (h->bits & 64) strcat (bits, "64 ");
			}
			feat = "__";
			if (h->assemble && h->disassemble) feat = "ad";
			if (h->assemble && !h->disassemble) feat = "a_";
			if (!h->assemble && h->disassemble) feat = "_d";
			feat2 = has_esil (anal, h->name);
			if (quiet) {
				printf ("%s\n", h->name);
			} else if (json) {
				const char *str_bits = "32, 64";
				const char *license = "GPL";
				printf ("\"%s\":{\"bits\":[%s],\"license\":\"%s\",\"description\":\"%s\",\"features\":\"%s\"}%s",
					h->name, str_bits, license, h->desc, feat, iter->n? ",": "");
			} else {
				printf ("%s%s  %-9s  %-11s %-7s %s",
					feat, feat2, bits, h->name,
					h->license? h->license: "unknown", h->desc);
				if (h->author) {
					printf (" (by %s)", h->author);
				}
				if (h->version) {
					printf (" v%s", h->version);
				}
				printf ("\n");
			}
		}
	}
	if (json) {
		printf ("}\n");
	}
}
// TODO: move into libr/anal/stack.c ?

static char *stackop2str(int type) {
	switch (type) {
	case R_ANAL_STACK_NULL: return strdup ("null");
	case R_ANAL_STACK_NOP:
		return strdup ("nop");
	//case R_ANAL_STACK_INCSTACK: return strdup ("incstack");
	case R_ANAL_STACK_GET: return strdup ("get");
	case R_ANAL_STACK_SET: return strdup ("set");
	}
	return strdup ("unknown");
}

static int showanal(RAnal *lanal, RAnalOp *op, ut64 offset, ut8 *buf, int len, bool json) {
	const char *optype = NULL;
	char *bytes, *stackop = NULL;
	int ret;

	ret = r_anal_op (anal, op, offset, buf, len);
	if (ret) {
		stackop = stackop2str (op->stackop);
		optype = r_anal_optype_to_string (op->type);
		bytes = r_hex_bin2strdup (buf, ret);
		if (json) {
			printf ("{\"opcode\": \"0x%08" PFMT64x "\",", offset);
			printf ("\"bytes\": \"%s\",", bytes);
			printf ("\"type\": \"%s\",", optype);
			if (op->jump != -1LL)
				printf ("{\"jump\": \"0x%08" PFMT64x ",", op->jump);
			if (op->fail != -1LL)
				printf ("{\"fail\": \"0x%08" PFMT64x ",", op->fail);
			if (op->val != -1LL)
				printf ("{\"value\": \"0x%08" PFMT64x ",", op->val);
			printf ("\"stackop\": \"%s\",", stackop);
			printf ("\"esil\": \"%s\",", r_strbuf_get (&op->esil));
			printf ("\"stackptr\": \"0x%08" PFMT64x "\"", op->stackptr);
			printf ("}");
		} else {
			printf ("offset:   0x%08" PFMT64x "\n", offset);
			printf ("bytes:    %s\n", bytes);
			printf ("type:     %s\n", optype);
			if (op->jump != -1LL)
				printf ("jump:     0x%08" PFMT64x "\n", op->jump);
			if (op->fail != -1LL)
				printf ("fail:     0x%08" PFMT64x "\n", op->fail);
			//if (op->ref != -1LL)
			//      printf ("ref:      0x%08"PFMT64x"\n", op->ref);
			if (op->val != -1LL)
				printf ("value:    0x%08" PFMT64x "\n", op->val);
			printf ("stackop:  %s\n", stackop);
			printf ("esil:     %s\n", r_strbuf_get (&op->esil));
			printf ("stackptr: %" PFMT64d "\n", op->stackptr);
			// produces (null) printf ("decode str: %s\n", r_anal_op_to_string (anal, op));
			printf ("\n");
		}
		free (stackop);
		free (bytes);
	}
	return ret;
}

static int rasm_show_help(int v) {
	if (v < 2) {
		printf ("Usage: rasm2 [-ACdDehLBvw] [-a arch] [-b bits] [-o addr] [-s syntax]\n"
			"             [-f file] [-F fil:ter] [-i skip] [-l len] 'code'|hex|-\n");
	}
	if (v != 1) {
		printf (" -a [arch]    Set architecture to assemble/disassemble (see -L)\n"
			" -A           Show Analysis information from given hexpairs\n"
			" -b [bits]    Set cpu register size (8, 16, 32, 64) (RASM2_BITS)\n"
			" -B           Binary input/output (-l is mandatory for binary input)\n"
			" -c [cpu]     Select specific CPU (depends on arch)\n"
			" -C           Output in C format\n"
			" -d, -D       Disassemble from hexpair bytes (-D show hexpairs)\n"
			" -e           Use big endian instead of little endian\n"
			" -E           Display ESIL expression (same input as in -d)\n"
			" -f [file]    Read data from file\n"
			" -F [in:out]  Specify input and/or output filters (att2intel, x86.pseudo, ...)\n"
			" -h, -hh      Show this help, -hh for long\n"
			" -i [len]     ignore/skip N bytes of the input buffer\n"
			" -j           output in json format\n"
			" -k [kernel]  Select operating system (linux, windows, darwin, ..)\n"
			" -l [len]     Input/Output length\n"
			" -L           List Asm plugins: (a=asm, d=disasm, A=analyze, e=ESIL)\n"
			" -o [offset]  Set start address for code (default 0)\n"
			" -O [file]    Output file name (rasm2 -Bf a.asm -O a)\n"
			" -p           Run SPP over input for assembly\n"
			" -q           quiet mode\n"
			" -r           output in radare commands\n"
			" -s [syntax]  Select syntax (intel, att)\n"
			" -v           Show version information\n"
			" -w           What's this instruction for? describe opcode\n"
			" If '-l' value is greater than output length, output is padded with nops\n"
			" If the last argument is '-' reads from stdin\n");
		printf ("Environment:\n"
			" RASM2_NOPLUGINS  do not load shared plugins (speedup loading)\n"
			" R_DEBUG          if defined, show error messages and crash signal\n"
			"");
	}
	if (v == 2) {
		printf ("Supported Assembler directives:\n");
		r_asm_list_directives ();
	}
	return 0;
}

static bool oneliner = false;
static int rasm_disasm(char *buf, ut64 offset, int len, int bits, int ascii, int bin, int hex) {
	RAsmCode *acode;
	ut8 *data = NULL;
	int ret = 0;
	ut64 clen = 0;
	if (bits == 1) {
		len /= 8;
	}
	if (bin) {
		if (len < 0) {
			return false;
		}
		clen = len; // XXX
		data = (ut8 *)buf;
	} else if (ascii) {
		clen = strlen (buf);
		data = (ut8 *)buf;
	} else {
		clen = r_hex_str2bin (buf, NULL);
		if ((int)clen < 1 || !(data = malloc (clen))) {
			ret = 0;
			goto beach;
		}
		r_hex_str2bin (buf, data);
	}

	if (!len || clen <= len) {
		len = clen;
	}

	if (hex == 2) {
		RAnalOp aop = { 0 };
		while (ret < len) {
			aop.size = 0;
			if (r_anal_op (anal, &aop, offset, data + ret, len - ret) > 0) {
				printf ("%s\n", R_STRBUF_SAFEGET (&aop.esil));
			}
			if (aop.size < 1) {
				eprintf ("Invalid\n");
				break;
			}
			ret += aop.size;
			r_anal_op_fini (&aop);
		}
	} else if (hex) {
		RAsmOp op;
		r_asm_set_pc (a, offset);
		while ((len - ret) > 0) {
			int dr = r_asm_disassemble (a, &op, data + ret, len - ret);
			if (dr == -1 || op.size < 1) {
				op.size = 1;
				strcpy (op.buf_asm, "invalid");
				sprintf (op.buf_hex, "%02x", data[ret]);
			}
			printf ("0x%08" PFMT64x "  %2d %24s  %s\n",
				a->pc, op.size, op.buf_hex, op.buf_asm);
			ret += op.size;
			r_asm_set_pc (a, offset + ret);
		}
	} else {
		r_asm_set_pc (a, offset);
		if (!(acode = r_asm_mdisassemble (a, data, len))) {
			goto beach;
		}
		if (oneliner) {
			r_str_replace_char (acode->buf_asm, '\n', ';');
			printf ("%s\"\n", acode->buf_asm);
		} else {
			printf ("%s", acode->buf_asm);
		}
		ret = acode->len;
		r_asm_code_free (acode);
	}
beach:
	if (data && data != (ut8 *)buf) {
		free (data);
	}
	return ret;
}

static void print_buf(char *str) {
	int i;
	if (coutput) {
		printf ("\"");
		for (i = 1; *str; str += 2, i += 2) {
			if (!(i % 41)) {
				printf ("\" \\\n\"");
				i = 1;
			}
			printf ("\\x%c%c", *str, str[1]);
		}
		printf ("\"\n");
	} else printf ("%s\n", str);
}

static bool print_label(void *user, const char *k, void *v) {
	printf ("f label.%s = %s\n", k, (const char *)v);
	return true;
}

static int rasm_asm(const char *buf, ut64 offset, ut64 len, int bits, int bin, bool use_spp) {
	RAsmCode *acode;
	int i, j, ret = 0;
	r_asm_set_pc (a, offset);
	if (!(acode = r_asm_rasm_assemble (a, buf, use_spp))) {
		return 0;
	}
	if (acode->len) {
		ret = acode->len;
		if (bin) {
			write (1, acode->buf, acode->len);
		} else {
			int b = acode->len;
			if (bits == 1) {
				int bytes = (b / 8) + 1;
				for (i = 0; i < bytes; i++) {
					for (j = 0; j < 8 && b--; j++) {
						printf ("%c", (acode->buf[i] & (1 << j))? '1': '0');
					}
				}
				printf ("\n");
			} else {
				print_buf (acode->buf_hex);
			}
		}
	}
	r_asm_code_free (acode);
	return (ret > 0);
}

/* asm callback */
static int __lib_asm_cb(RLibPlugin *pl, void *user, void *data) {
	RAsmPlugin *hand = (RAsmPlugin *)data;
	r_asm_add (a, hand);
	return true;
}

static int __lib_asm_dt(RLibPlugin *pl, void *p, void *u) {
	return true;
}

/* anal callback */
static int __lib_anal_cb(RLibPlugin *pl, void *user, void *data) {
	RAnalPlugin *hand = (RAnalPlugin *)data;
	r_anal_add (anal, hand);
	return true;
}

static int __lib_anal_dt(RLibPlugin *pl, void *p, void *u) {
	return true;
}

static int print_assembly_output(const char *buf, ut64 offset, ut64 len, int bits,
                                 int bin, bool use_spp, bool rad, char *arch) {
	int ret = 0;
	if (rad) {
		printf ("e asm.arch=%s\n", arch? arch: R_SYS_ARCH);
		printf ("e asm.bits=%d\n", bits);
		if (offset) {
			printf ("s 0x%"PFMT64x"\n", offset);
		}
		printf ("wx ");
	}
	ret = rasm_asm ((char *)buf, offset, len, a->bits, bin, use_spp);
	if (rad) {
		printf ("f entry = $$\n");
		printf ("f label.main = $$ + 1\n");
		ht_foreach (a->flags, print_label, NULL);
	}
	return ret;
}

int main (int argc, char *argv[]) {
	const char *path;
	const char *env_arch = r_sys_getenv ("RASM2_ARCH");
	const char *env_bits = r_sys_getenv ("RASM2_BITS");
	unsigned char buf[R_ASM_BUFSIZE];
	char *arch = NULL, *file = NULL, *filters = NULL, *kernel = NULL, *cpu = NULL, *tmp;
	bool isbig = false;
	bool rad = false;
	bool use_spp = false;
	ut64 offset = 0;
	int fd = -1, dis = 0, ascii = 0, bin = 0, ret = 0, bits = 32, c, whatsop = 0;
	int help = 0;
	ut64 len = 0, idx = 0, skip = 0;
	bool analinfo = false;

	if (argc < 2) {
		return rasm_show_help (1);
	}
	a = r_asm_new ();
	anal = r_anal_new ();

	if ((tmp = r_sys_getenv ("RASM2_NOPLUGINS"))) {
		free (tmp);
	} else {
		l = r_lib_new ("radare_plugin");
		r_lib_add_handler (l, R_LIB_TYPE_ASM, "(dis)assembly plugins",
				&__lib_asm_cb, &__lib_asm_dt, NULL);
		r_lib_add_handler (l, R_LIB_TYPE_ANAL, "analysis/emulation plugins",
				&__lib_anal_cb, &__lib_anal_dt, NULL);

		path = r_sys_getenv (R_LIB_ENV);
		if (path && *path)
			r_lib_opendir (l, path);

		if (1) {
			char *homeplugindir = r_str_home (R2_HOMEDIR "/plugins");
			// eprintf ("OPENDIR (%s)\n", homeplugindir);
			r_lib_opendir (l, homeplugindir);
			free (homeplugindir);
		}
		if (1) { //where & R_CORE_LOADLIBS_SYSTEM) {
			r_lib_opendir (l, R2_LIBDIR "/radare2/" R2_VERSION);
			r_lib_opendir (l, R2_LIBDIR "/radare2-extras/" R2_VERSION);
			r_lib_opendir (l, R2_LIBDIR "/radare2-bindings/" R2_VERSION);
		}
		free (tmp);
	}

	r_asm_use (a, R_SYS_ARCH);
	r_anal_use (anal, R_SYS_ARCH);
	{
		int sysbits = (R_SYS_BITS & R_SYS_BITS_64)? 64: 32;
		r_asm_set_bits (a, sysbits);
		r_anal_set_bits (anal, sysbits);
	}
	// TODO set addrbytes
	char *r2arch = r_sys_getenv ("R2_ARCH");
	if (r2arch) {
		arch = r2arch;
	}
	char *r2bits = r_sys_getenv ("R2_BITS");
	if (r2bits) {
		bits = r_num_math (NULL, r2bits);
		free (r2bits);
	}
	while ((c = getopt (argc, argv, "a:Ab:Bc:CdDeEf:F:hi:jk:l:Lo:O:pqrs:vw")) != -1) {
		switch (c) {
		case 'a':
			arch = optarg;
			break;
		case 'A':
			analinfo = true;
			break;
		case 'b':
			bits = r_num_math (NULL, optarg);
			break;
		case 'B':
			bin = 1;
			break;
		case 'c':
			cpu = optarg;
			break;
		case 'C':
			coutput = true;
			break;
		case 'd':
			dis = 1;
			break;
		case 'D':
			dis = 2;
			break;
		case 'e':
			isbig = true;
			break;
		case 'E':
			dis = 3;
			break;
		case 'f':
			file = optarg;
			break;
		case 'F':
			filters = optarg;
			break;
		case 'h':
			help++;
		case 'i':
			skip = r_num_math (NULL, optarg);
			break;
		case 'j':
			json = true;
			break;
		case 'k':
			kernel = optarg;
			break;
		case 'l':
			len = r_num_math (NULL, optarg);
			break;
		case 'L':
			rasm2_list (a, argv[optind]);
			ret = 1;
			goto beach;
		case 'o':
			offset = r_num_math (NULL, optarg);
			break;
		case 'O':
			fd = open (optarg, O_TRUNC | O_RDWR | O_CREAT, 0644);
			if (fd != -1) dup2 (fd, 1);
			break;
		case 'p':
			use_spp = true;
			break;
		case 'q':
			quiet = true;
			break;
		case 'r':
			rad = true;
			break;
		case 's':
			if (*optarg == '?') {
				printf ("att\nintel\nmasm\njz\nregnum\n");
				return 0;
			} else {
				int syntax = r_asm_syntax_from_string (optarg);
				if (syntax == -1) {
					return 1;
				}
				r_asm_set_syntax (a, syntax);
			}
			break;
		case 'v':
			if (quiet) {
				printf ("%s\n", R2_VERSION);
			} else {
				ret = blob_version ("rasm2");
			}
			goto beach;
		case 'w':
			whatsop = true;
			break;
		default:
			ret = rasm_show_help (0);
			goto beach;
		}
	}

	if (help > 0) {
		ret = rasm_show_help (help > 1? 2: 0);
		goto beach;
	}

	if (arch) {
		if (!r_asm_use (a, arch)) {
			eprintf ("rasm2: Unknown asm plugin '%s'\n", arch);
			ret = 0;
			goto beach;
		}
		r_anal_use (anal, arch);
		if (!strcmp (arch, "bf"))
			ascii = 1;
	} else if (env_arch) {
		if (!r_asm_use (a, env_arch)) {
			eprintf ("rasm2: Unknown asm plugin '%s'\n", env_arch);
			ret = 0;
			goto beach;
		}
	} else if (!r_asm_use (a, "x86")) {
		eprintf ("rasm2: Cannot find asm.x86 plugin\n");
		ret = 0;
		goto beach;
	}
	r_asm_set_cpu (a, cpu);
	r_asm_set_bits (a, (env_bits && *env_bits)? atoi (env_bits): bits);
	r_anal_set_bits (anal, (env_bits && *env_bits)? atoi (env_bits): bits);
	a->syscall = r_syscall_new ();
	r_syscall_setup (a->syscall, arch, kernel, bits);
	{
		bool canbebig = r_asm_set_big_endian (a, isbig);
		if (isbig && !canbebig) {
			eprintf ("Warning: This architecture can't swap to big endian.\n");
		}
		r_anal_set_big_endian (anal, canbebig);
	}
	if (whatsop) {
		const char *s = r_asm_describe (a, argv[optind]);
		ret = 1;
		if (s) {
			printf ("%s\n", s);
			ret = 0;
		}
		goto beach;
	}
	if (filters) {
		char *p = strchr (filters, ':');
		if (p) {
			*p = 0;
			if (*filters) {
				r_asm_filter_input (a, filters);
			}
			if (p[1]) {
				r_asm_filter_output (a, p + 1);
			}
			*p = ':';
		} else {
			if (dis) {
				r_asm_filter_output (a, filters);
			} else {
				r_asm_filter_input (a, filters);
			}
		}
	}

	if (file) {
		char *content;
		int length = 0;
		if (!strcmp (file, "-")) {
			ret = read (0, buf, sizeof (buf) - 1);
			if (ret == R_ASM_BUFSIZE) {
				eprintf ("rasm2: Cannot slurp all stdin data\n");
			}
			if (ret >= 0) { // only for text
				buf[ret] = '\0';
			}
			len = ret;
			if (dis) {
				if (skip && length > skip) {
					if (bin) {
						memmove (buf, buf + skip, length - skip);
						length -= skip;
					}
				}
				ret = rasm_disasm ((char *)buf, offset, len,
						a->bits, ascii, bin, dis - 1);
			} else if (analinfo) {
				ret = show_analinfo ((const char *)buf, offset);
			} else {
				ret = print_assembly_output ((char *)buf, offset, len,
								a->bits, bin, use_spp, rad, arch);
			}
		} else {
			content = r_file_slurp (file, &length);

			if (content) {
				if (len && len > 0 && len < length)
					length = len;
				content[length] = '\0';
				if (skip && length > skip) {
					if (bin) {
						memmove (content, content + skip, length - skip);
						length -= skip;
					}
				}
				if (dis) {
					ret = rasm_disasm (content, offset,
							length, a->bits, ascii, bin, dis - 1);
				} else if (analinfo) {
					ret = show_analinfo ((const char *)buf, offset);
				} else {
					ret = print_assembly_output (content, offset, length,
									a->bits, bin, use_spp, rad, arch);
				}
				ret = !ret;
				free (content);
			} else {
				eprintf ("rasm2: Cannot open file %s\n", file);
				ret = 1;
			}
		}
	} else if (argv[optind]) {
		if (!strcmp (argv[optind], "-")) {
			int length;
			do {
				length = read (0, buf, sizeof (buf) - 1);
				if (length < 1) break;
				if (len > 0 && len < length) {
					length = len;
				}
				buf[length] = 0;
				if ((!bin || !dis) && feof (stdin)) {
					break;
				}
				if (skip && length > skip) {
					if (bin) {
						memmove (buf, buf + skip, length - skip + 1);
						length -= skip;
					}
				}
				if (!bin || !dis) {
					int buflen = strlen ((const char *)buf);
					if (buf[buflen] == '\n')
						buf[buflen - 1] = '\0';
				}
				if (dis) {
					ret = rasm_disasm ((char *)buf, offset, length, a->bits, ascii, bin, dis - 1);
				} else if (analinfo) {
					ret = show_analinfo ((const char *)buf, offset);
				} else {
					ret = rasm_asm ((const char *)buf, offset, length, a->bits, bin, use_spp);
				}
				idx += ret;
				offset += ret;
				if (!ret) {
					goto beach;
				}
			} while (!len || idx < length);
			ret = idx;
			goto beach;
		}
		if (dis) {
			char *buf = argv[optind];
			len = strlen (buf);
			if (skip && len > skip) {
				skip *= 2;
				//eprintf ("SKIP (%s) (%lld)\n", buf, skip);
				memmove (buf, buf + skip, len - skip);
				len -= skip;
				buf[len] = 0;
			}
			if (!strncmp (buf, "0x", 2)) {
				buf += 2;
			}
			if (rad) {
				oneliner = true;
				printf ("e asm.arch=%s\n", arch? arch: R_SYS_ARCH);
				printf ("e asm.bits=%d\n", bits);
				printf ("\"wa ");
			}
			ret = rasm_disasm ((char *)buf, offset, len,
					a->bits, ascii, bin, dis - 1);
		} else if (analinfo) {
			ret = show_analinfo ((const char *)argv[optind], offset);
		} else {
			ret = print_assembly_output (argv[optind], offset, len, a->bits,
							bin, use_spp, rad, arch);
		}
		if (!ret) {
			eprintf ("invalid\n");
		}
		ret = !ret;
	}
beach:
	r_asm_free (a);
	r_lib_free (l);
	if (fd != -1) {
		close (fd);
	}
	return ret;
}
