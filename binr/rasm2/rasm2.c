/* radare - LGPL - Copyright 2009-2014 - pancake, nibble */

#include <stdio.h>
#include <string.h>
#include <getopt.c> /* getopt.h is not portable :D */
#include <r_types.h>
#include <r_asm.h>
#include <r_anal.h>
#include <r_util.h>
#include <r_lib.h>
#include "../blob/version.c"

static RLib *l = NULL;
static RAsm *a = NULL;
static RAnal *anal = NULL;
static int coutput = R_FALSE;

static const char *has_esil(RAnal *a, const char *name) {
	RListIter *iter;
	RAnalPlugin *h;
	r_list_foreach (a->plugins, iter, h) {
		if (!strcmp (name, h->name)) {
			if (h->esil)
				return "Ae";
			return "A_";
		}
	}
	return "__";
}
static void rasm2_list(RAsm *a, const char *arch) {
	int i;
	char bits[32];
	const char *feat2, *feat;
	RAsmPlugin *h;
	RListIter *iter;
	r_list_foreach (a->plugins, iter, h) {
		if (arch) {
			if (h->cpus && !strcmp (arch, h->name)) {
				char *c = strdup (h->cpus);
				int n = r_str_split (c, ',');
				for (i=0;i<n;i++)
					printf ("%s\n", r_str_word_get0 (c, i));
				free (c);
				break;
			}
		} else {
			bits[0] = 0;
			if (h->bits&8) strcat (bits, "8 ");
			if (h->bits&16) strcat (bits, "16 ");
			if (h->bits&32) strcat (bits, "32 ");
			if (h->bits&64) strcat (bits, "64 ");
			feat = "__";
			if (h->assemble && h->disassemble)  feat = "ad";
			if (h->assemble && !h->disassemble) feat = "a_";
			if (!h->assemble && h->disassemble) feat = "_d";
			feat2 = has_esil (anal, h->name);
			printf ("%s%s  %-9s  %-11s %-7s %s\n",
				feat, feat2, bits, h->name,
				h->license?h->license:"unknown", h->desc);
		}
	}
}

static int rasm_show_help(int v) {
	printf ("Usage: rasm2 [-CdDehLBvw] [-a arch] [-b bits] [-o addr] [-s syntax]\n"
		"             [-f file] [-F fil:ter] [-i skip] [-l len] 'code'|hex|-\n");
	if (v)
	printf (" -a [arch]    Set architecture to assemble/disassemble (see -L)\n"
		" -b [bits]    Set cpu register size (8, 16, 32, 64) (RASM2_BITS)\n"
		" -c [cpu]     Select specific CPU (depends on arch)\n"
		" -C           Output in C format\n"
		" -d, -D       Disassemble from hexpair bytes (-D show hexpairs)\n"
		" -e           Use big endian instead of little endian\n"
		" -f [file]    Read data from file\n"
		" -F [in:out]  Specify input and/or output filters (att2intel, x86.pseudo, ...)\n"
		" -h           Show this help\n"
		" -i [len]     ignore/skip N bytes of the input buffer\n"
		" -k [kernel]  Select operating system (linux, windows, darwin, ..)\n"
		" -l [len]     Input/Output length\n"
		" -L           List supported asm plugins + features:\n"
		"               a___ asm, _d__ disasm, __A_ analyzer, ___e ESIL\n"
		" -o [offset]  Set start address for code (default 0)\n"
		" -O [file]    Output file name (rasm2 -Bf a.asm -O a)\n"
		" -s [syntax]  Select syntax (intel, att)\n"
		" -B           Binary input/output (-l is mandatory for binary input)\n"
		" -v           Show version information\n"
		" -w           What's this instruction for? describe opcode\n"
		" If '-l' value is greater than output length, output is padded with nops\n"
		" If the last argument is '-' reads from stdin\n");
	return 0;
}

static int rasm_disasm(char *buf, ut64 offset, int len, int bits, int ascii, int bin, int hex) {
	RAsmCode *acode;
	ut8 *data = NULL;
	char *ptr = buf;
	int ret = 0;
	ut64 word = 0, clen = 0; 
	if (bits == 1)
		len /= 8;

	if (bin) {
		if (len<0) return R_FALSE;
		clen = len; // XXX
		data = (ut8*)buf;
	} else if (ascii) {
		clen = strlen (buf);
		data = (ut8*)buf;
	} else {
		for (; *ptr; ptr++)
			if (*ptr!=' ' && *ptr!='\n' && *ptr!='\r')
				if (!(++word%2)) clen++;
		data = malloc (clen+1);
		if (r_hex_str2bin (buf, data)==-1)
			goto beach;
	}

	if (!len || clen <= len)
		len = clen;

	if (hex) {
		RAsmOp op;
		r_asm_set_pc (a, offset);
		while (len-ret > 0) {
			int dr = r_asm_disassemble (a, &op, data+ret, len-ret);
			if (dr == -1 || op.size<1) {
				op.size = 1;
				strcpy (op.buf_asm, "invalid");
				sprintf (op.buf_hex, "%02x", data[ret]);
			}
			printf ("0x%08"PFMT64x"  %2d %24s  %s\n", 
				a->pc, op.size, op.buf_hex, op.buf_asm);
			ret += op.size;
			r_asm_set_pc (a, offset+ret);
		}
	} else {
		r_asm_set_pc (a, offset);
		if (!(acode = r_asm_mdisassemble (a, data, len)))
			goto beach;
		printf ("%s", acode->buf_asm);
		ret = acode->len;
		r_asm_code_free (acode);
	}
beach:
	if (data && data != (ut8*)buf) free (data);
	return ret;
}

static void print_buf(char *str) {
	int i;
	if (coutput) {
		printf ("\"");
		for (i=1; *str; str+=2, i+=2) {
			if (!(i%41)) {
				printf ("\" \\\n\"");
				i=1;
			}
			printf ("\\x%c%c", *str, str[1]);
		}
		printf ("\"\n");
	} else printf ("%s\n", str);
}

static int rasm_asm(char *buf, ut64 offset, ut64 len, int bits, int bin) {
	RAsmCode *acode;
	int i, j, ret = 0;

	r_asm_set_pc (a, offset);
	if (!(acode = r_asm_massemble (a, buf)))
		return 0;
	if (acode->len) {
		ret = acode->len;
		if (bin) {
			write (1, acode->buf, acode->len);
		} else {
			int b = acode->len;
			if (bits==1) {
				int bytes = (b/8)+1;
				for (i=0; i<bytes; i++)
					for (j=0; j<8 && b--; j++)
						printf ("%c", (acode->buf[i] & (1<<j))?'1':'0');
				printf ("\n");
			} else print_buf (acode->buf_hex);
		}
	}
	r_asm_code_free (acode);
	return ret > 0;
}

/* asm callback */
static int __lib_asm_cb(struct r_lib_plugin_t *pl, void *user, void *data) {
	RAsmPlugin *hand = (struct r_asm_plugin_t *)data;
	r_asm_add (a, hand);
	return R_TRUE;
}
static int __lib_asm_dt(struct r_lib_plugin_t *pl, void *p, void *u) { return R_TRUE; }

int main(int argc, char *argv[]) {
	const char *path;
	const char *env_arch = r_sys_getenv ("RASM2_ARCH");
	const char *env_bits = r_sys_getenv ("RASM2_BITS");
	char buf[R_ASM_BUFSIZE];
	char *arch = NULL, *file = NULL, *filters = NULL, *kernel = NULL, *cpu = NULL;
	ut64 offset = 0;
	int fd =-1, dis = 0, ascii = 0, bin = 0, ret = 0, bits = 32, c, whatsop = 0;
	ut64 len = 0, idx = 0, skip = 0;

	if (argc<2)
		return rasm_show_help (0);

	a = r_asm_new ();
	anal = r_anal_new ();
	l = r_lib_new ("radare_plugin");
	r_lib_add_handler (l, R_LIB_TYPE_ASM, "(dis)assembly plugins",
		&__lib_asm_cb, &__lib_asm_dt, NULL);
	path = r_sys_getenv ("LIBR_PLUGINS");
	if (!path || !*path)
		path = R2_PREFIX"/lib/radare2/"R2_VERSION;
	r_lib_opendir (l, path);


	r_asm_use (a, R_SYS_ARCH);
	r_asm_set_big_endian (a, R_FALSE);
	while ((c = getopt (argc, argv, "i:k:DCc:eva:b:s:do:Bl:hLf:F:wO:")) != -1) {
		switch (c) {
		case 'k':
			kernel = optarg;
			break;
		case 'D':
			dis = 2;
			break;
		case 'f':
			file = optarg;
			break;
		case 'F':
			filters = optarg;
			break;
		case 'c':
			cpu = optarg;
			break;
		case 'C':
			coutput = R_TRUE;
			break;
		case 'a':
			arch = optarg;
			break;
		case 'b':
			bits = r_num_math (NULL, optarg);
			break;
		case 's':
			if (!strcmp (optarg, "att"))
				r_asm_set_syntax (a, R_ASM_SYNTAX_ATT);
			else r_asm_set_syntax (a, R_ASM_SYNTAX_INTEL);
			break;
		case 'd':
			dis = 1;
			break;
		case 'o':
			offset = r_num_math (NULL, optarg);
			break;
		case 'O':
			fd = open (optarg, O_TRUNC|O_RDWR|O_CREAT, 0644);
			if (fd != -1)
				dup2 (fd, 1);
			break;
		case 'B':
			bin = 1;
			break;
		case 'i':
			skip = r_num_math (NULL, optarg);
			break;
		case 'l':
			len = r_num_math (NULL, optarg);
			break;
		case 'L':
			rasm2_list (a, argv[optind]);
			ret = 1;
			goto beach;
		case 'e':
			r_asm_set_big_endian (a, !!!a->big_endian);
			break;
		case 'v':
			ret = blob_version ("rasm2");
			goto beach;
		case 'h':
			ret = rasm_show_help (1);
			goto beach;
		case 'w':
			whatsop = R_TRUE;
			break;
		}
	}

	if (arch) {
		if (!r_asm_use (a, arch)) {
			eprintf ("rasm2: Unknown asm plugin '%s'\n", arch);
			ret = 0;
			goto beach;
		}
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
	a->syscall = r_syscall_new ();
	r_syscall_setup (a->syscall, arch, kernel, bits);

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
			if (*filters) r_asm_filter_input (a, filters);
			if (p[1]) r_asm_filter_output (a, p+1);
			*p = ':';
		} else {
			if (dis) r_asm_filter_output (a, filters);
			else r_asm_filter_input (a, filters);
		}
	}

	if (file) {
		char *content;
		int length = 0;
		if (!strcmp (file, "-")) {
			ret = read (0, buf, sizeof (buf)-1);
			if (ret == R_ASM_BUFSIZE)
				eprintf ("rasm2: Cannot slurp all stdin data\n");
			if (ret>=0) // only for text
				buf[ret] = '\0';
			len = ret;
			if (dis) {
				if (skip && length>skip) {
					if (bin) {
						memmove (buf, buf+skip, length-skip);
						length -= skip;
					}
				}
				ret = rasm_disasm (buf, offset, len,
					a->bits, ascii, bin, dis-1);
			} else ret = rasm_asm (buf, offset, len, a->bits, bin);
		} else {
			content = r_file_slurp (file, &length);
			if (content) {
				if (len && len>0 && len<length)
					length = len;
				content[length] = '\0';
				if (dis) ret = rasm_disasm (content, offset,
					length, a->bits, ascii, bin, dis-1);
				else ret = rasm_asm (content, offset, length, a->bits, bin);
				ret = !!! ret;
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
				length = read (0, buf, sizeof (buf)-1);
				if (length<1) break;
				if (len>0 && len < length)
					length = len;
				buf[length] = 0;
				if ((!bin || !dis) && feof (stdin))
					break;
				if (skip && length>skip) {
					if (bin) {
						memmove (buf, buf+skip, length-skip+1);
						length -= skip;
					}
				}
				if (!bin || !dis) {
					int buflen = strlen (buf);
					if (buf[buflen]=='\n')
						buf[buflen-1]='\0';
				}
				if (dis) ret = rasm_disasm (buf, offset,
					length, a->bits, ascii, bin, dis-1);
				else ret = rasm_asm (buf, offset, length, a->bits, bin);
				idx += ret;
				offset += ret;
				if (!ret) goto beach;
			} while (!len || idx<length);
			ret = idx;
			goto beach;
		}
		if (dis) {
			char *buf = argv[optind];
			len = strlen (buf);
			if (skip && len>skip) {
				skip *= 2;
				//eprintf ("SKIP (%s) (%lld)\n", buf, skip);
				memmove (buf, buf+skip, len-skip);
				len -= skip;
				buf[len] = 0;
			}
			if (!strncmp (buf, "0x", 2))
				buf += 2;
			ret = rasm_disasm (buf, offset, len,
				a->bits, ascii, bin, dis-1);
		} else ret = rasm_asm (argv[optind], offset, len, a->bits, bin);
		if (!ret) eprintf ("invalid\n");
		ret = !!!ret;
	}
beach:
	if (a)
		r_asm_free (a);
	if (l)
		r_lib_free (l);
	if (fd != -1)
		close (fd);
	return ret;
}
