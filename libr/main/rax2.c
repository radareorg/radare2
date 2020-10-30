/* radare - LGPL - Copyright 2007-2020 - pancake */

#include <r_main.h>
#include <r_util.h>
#include <r_util/r_print.h>

// don't use fixed sized buffers
#define STDIN_BUFFER_SIZE 354096
static int rax(RNum *num, char *str, int len, int last, ut64 *flags, int *fm);

static int use_stdin(RNum *num, ut64 *flags, int *fm) {
	if (!flags) {
		return 0;
	}
	char *buf = calloc (1, STDIN_BUFFER_SIZE + 1);
	int l;
	if (!buf) {
		return 0;
	}
	if (!(*flags & (1<<14))) {
		for (l = 0; l >= 0 && l < STDIN_BUFFER_SIZE; l++) {
			// make sure we don't read beyond boundaries
			int n = read (0, buf + l, STDIN_BUFFER_SIZE - l);
			if (n < 1) {
				break;
			}
			l += n;
			if (buf[l - 1] == 0) {
				l--;
				continue;
			}
			buf[n] = 0;
			// if (sflag && strlen (buf) < STDIN_BUFFER_SIZE) // -S
			buf[STDIN_BUFFER_SIZE] = '\0';
			if (!rax (num, buf, l, 0, flags, fm)) {
				break;
			}
			l = -1;
		}
	} else {
		l = 1;
	}
	if (l > 0) {
		rax (num, buf, l, 0, flags, fm);
	}
	free (buf);
	return 0;
}

static int format_output(RNum *num, char mode, const char *s, int force_mode, ut64 flags) {
	ut64 n = r_num_math (num, s);
	char strbits[65];
	if (force_mode) {
		mode = force_mode;
	}
	if (flags & 2) {
		ut64 n2 = n;
		r_mem_swapendian ((ut8 *) &n, (ut8 *) &n2, (n >> 32)? 8: 4);
	}
	switch (mode) {
	case 'I':
		printf ("%" PFMT64d "\n", n);
		break;
	case '0':
		printf ("0x%" PFMT64x "\n", n);
		break;
	case 'F': {
		float *f = (float *) &n;
		printf ("%ff\n", *f);
	} break;
	case 'f': printf ("%.01lf\n", num->fvalue); break;
	case 'l':
		R_STATIC_ASSERT (sizeof (float) == 4);
		float f = (float) num->fvalue;
		ut8 *p = (ut8 *) &f;
		printf ("Fx%02x%02x%02x%02x\n", p[3], p[2], p[1], p[0]);
		break;
	case 'O': printf ("0%" PFMT64o "\n", n); break;
	case 'B':
		if (n) {
			r_num_to_bits (strbits, n);
			printf ("%sb\n", strbits);
		} else {
			printf ("0b\n");
		}
		break;
	case 'T':
		if (n) {
			r_num_to_trits (strbits, n);
			printf ("%st\n", strbits);
		} else {
			printf ("0t\n");
		}
		break;
	default:
		eprintf ("Unknown output mode %d\n", mode);
		break;
	}
	return true;
}

static void print_ascii_table(void) {
	printf ("%s", ret_ascii_table());
}

static int help(void) {
	printf (
		"  =[base]                      ;  rax2 =10 0x46 -> output in base 10\n"
		"  int     ->  hex              ;  rax2 10\n"
		"  hex     ->  int              ;  rax2 0xa\n"
		"  -int    ->  hex              ;  rax2 -77\n"
		"  -hex    ->  int              ;  rax2 0xffffffb3\n"
		"  int     ->  bin              ;  rax2 b30\n"
		"  int     ->  ternary          ;  rax2 t42\n"
		"  bin     ->  int              ;  rax2 1010d\n"
		"  ternary ->  int              ;  rax2 1010dt\n"
		"  float   ->  hex              ;  rax2 3.33f\n"
		"  hex     ->  float            ;  rax2 Fx40551ed8\n"
		"  oct     ->  hex              ;  rax2 35o\n"
		"  hex     ->  oct              ;  rax2 Ox12 (O is a letter)\n"
		"  bin     ->  hex              ;  rax2 1100011b\n"
		"  hex     ->  bin              ;  rax2 Bx63\n"
		"  ternary ->  hex              ;  rax2 212t\n"
		"  hex     ->  ternary          ;  rax2 Tx23\n"
		"  raw     ->  hex              ;  rax2 -S < /binfile\n"
		"  hex     ->  raw              ;  rax2 -s 414141\n"
		"  -l                           ;  append newline to output (for -E/-D/-r/..\n"
		"  -a      show ascii table     ;  rax2 -a\n"
		"  -b      bin -> str           ;  rax2 -b 01000101 01110110\n"
		"  -B      str -> bin           ;  rax2 -B hello\n"
		"  -d      force integer        ;  rax2 -d 3 -> 3 instead of 0x3\n"
		"  -e      swap endianness      ;  rax2 -e 0x33\n"
		"  -D      base64 decode        ;\n"
		"  -E      base64 encode        ;\n"
		"  -f      floating point       ;  rax2 -f 6.3+2.1\n"
		"  -F      stdin slurp code hex ;  rax2 -F < shellcode.[c/py/js]\n"
		"  -h      help                 ;  rax2 -h\n"
		"  -i      dump as C byte array ;  rax2 -i < bytes\n"
		"  -k      keep base            ;  rax2 -k 33+3 -> 36\n"
		"  -K      randomart            ;  rax2 -K 0x34 1020304050\n"
		"  -L      bin -> hex(bignum)   ;  rax2 -L 111111111 # 0x1ff\n"
		"  -n      binary number        ;  rax2 -n 0x1234 # 34120000\n"
		"  -o      octalstr -> raw      ;  rax2 -o \\162 \\62 # r2\n"
		"  -N      binary number        ;  rax2 -N 0x1234 # \\x34\\x12\\x00\\x00\n"
		"  -r      r2 style output      ;  rax2 -r 0x1234\n"
		"  -s      hexstr -> raw        ;  rax2 -s 43 4a 50\n"
		"  -S      raw -> hexstr        ;  rax2 -S < /bin/ls > ls.hex\n"
		"  -t      tstamp -> str        ;  rax2 -t 1234567890\n"
		"  -x      hash string          ;  rax2 -x linux osx\n"
		"  -u      units                ;  rax2 -u 389289238 # 317.0M\n"
		"  -w      signed word          ;  rax2 -w 16 0xffff\n"
		"  -v      version              ;  rax2 -v\n");
	return true;
}

static int rax(RNum *num, char *str, int len, int last, ut64 *_flags, int *fm) {
	ut64 flags = *_flags;
	const char *nl = "";
	ut8 *buf;
	char *p, out_mode = (flags & 128)? 'I': '0';
	int i;
	if (!(flags & 4) || !len) {
		len = strlen (str);
	}
	if ((flags & 4)) {
		goto dotherax;
	}
	if (*str == '=') {
		int force_mode = 0;
		switch (atoi (str + 1)) {
		case 2: force_mode = 'B'; break;
		case 3: force_mode = 'T'; break;
		case 8: force_mode = 'O'; break;
		case 10: force_mode = 'I'; break;
		case 16: force_mode = '0'; break;
		case 0: force_mode = str[1]; break;
		}
		*fm = force_mode;
		return true;
	}
	if (*str == '-') {
		while (str[1] && str[1] != ' ') {
			switch (str[1]) {
			case 'l': nl = "\n"; break;
			case 'a': print_ascii_table (); return 0;
			case 's': flags ^= 1 << 0; break;
			case 'e': flags ^= 1 << 1; break;
			case 'S': flags ^= 1 << 2; break;
			case 'b': flags ^= 1 << 3; break;
			case 'B': flags ^= 1 << 17; break;
			case 'x': flags ^= 1 << 4; break;
			case 'k': flags ^= 1 << 5; break;
			case 'f': flags ^= 1 << 6; break;
			case 'd': flags ^= 1 << 7; break;
			case 'K': flags ^= 1 << 8; break;
			case 'n': flags ^= 1 << 9; break;
			case 'u': flags ^= 1 << 10; break;
			case 't': flags ^= 1 << 11; break;
			case 'E': flags ^= 1 << 12; break;
			case 'D': flags ^= 1 << 13; break;
			case 'F': flags ^= 1 << 14; break;
			case 'N': flags ^= 1 << 15; break;
			case 'w': flags ^= 1 << 16; break;
			case 'r': flags ^= 1 << 18; break;
			case 'L': flags ^= 1 << 19; break;
			case 'i': flags ^= 1 << 21; break;
			case 'o': flags ^= 1 << 22; break;
			case 'v': return r_main_version_print ("rax2");
			case '\0':
				*_flags = flags;
				return !use_stdin (num, _flags, fm);
			default:
				/* not as complete as for positive numbers */
				out_mode = (flags ^ 32)? '0': 'I';
				if (str[1] >= '0' && str[1] <= '9') {
					if (str[2] == 'x') {
						out_mode = 'I';
					} else if (r_str_endswith (str, "f")) {
						out_mode = 'l';
					}
					return format_output (num, out_mode, str, *fm, flags);
				}
				printf ("Usage: rax2 [options] [expr ...]\n");
				return help ();
			}
			str++;
		}
		*_flags = flags;
		if (last) {
			return !use_stdin (num, _flags, fm);
		}
		return true;
	}
	*_flags = flags;
	if (!flags && r_str_nlen (str, 2) == 1) {
		if (*str == 'q') {
			return false;
		}
		if (*str == 'h' || *str == '?') {
			help ();
			return false;
		}
	}
dotherax:
	if (flags & 1) { // -s
		int n = ((strlen (str)) >> 1) + 1;
		buf = malloc (n);
		if (buf) {
			memset (buf, '\0', n);
			n = r_hex_str2bin (str, (ut8 *) buf);
			if (n > 0) {
				fwrite (buf, n, 1, stdout);
			}
#if __EMSCRIPTEN__
			puts ("");
#else
			if (nl && *nl) {
				puts ("");
			}
#endif
			fflush (stdout);
			free (buf);
		}
		return true;
	}
	if (flags & (1 << 2)) { // -S
		for (i = 0; i < len; i++) {
			printf ("%02x", (ut8) str[i]);
		}
		printf ("\n");
		return true;
	} else if (flags & (1 << 3)) { // -b
		int i;
		ut8 buf[4096];
		const int n = r_str_binstr2bin (str, buf, sizeof (buf));
		for (i = 0; i < n; i++) {
			printf ("%c", buf[i]);
		}
		return true;
	} else if (flags & (1 << 4)) { // -x
		int h = r_str_hash (str);
		printf ("0x%x\n", h);
		return true;
	} else if (flags & (1 << 5)) { // -k
		out_mode = 'I';
	} else if (flags & (1 << 6)) { // -f
		out_mode = 'f';
	} else if (flags & (1 << 8)) { // -K
		int n = ((strlen (str)) >> 1) + 1;
		char *s = NULL;
		buf = (ut8 *) malloc (n);
		if (!buf) {
			return false;
		}
		ut32 *m = (ut32 *) buf;
		memset (buf, '\0', n);
		n = r_hex_str2bin (str, (ut8 *) buf);
		if (n < 1 || !memcmp (str, "0x", 2)) {
			ut64 q = r_num_math (num, str);
			s = r_print_randomart ((ut8 *) &q, sizeof (q), q);
			printf ("%s\n", s);
			free (s);
		} else {
			s = r_print_randomart ((ut8 *) buf, n, *m);
			printf ("%s\n", s);
			free (s);
		}
		free (m);
		return true;
	} else if (flags & (1 << 9)) { // -n
		ut64 n = r_num_math (num, str);
		if (n >> 32) {
			/* is 64 bit value */
			ut8 *np = (ut8 *) &n;
			if (flags & 1) {
				fwrite (&n, sizeof (n), 1, stdout);
			} else {
				printf ("%02x%02x%02x%02x"
					"%02x%02x%02x%02x\n",
					np[0], np[1], np[2], np[3],
					np[4], np[5], np[6], np[7]);
			}
		} else {
			/* is 32 bit value */
			ut32 n32 = (ut32) (n & UT32_MAX);
			ut8 *np = (ut8 *) &n32;
			if (flags & 1) {
				fwrite (&n32, sizeof (n32), 1, stdout);
			} else {
				printf ("%02x%02x%02x%02x\n",
					np[0], np[1], np[2], np[3]);
			}
		}
		fflush (stdout);
		return true;
	} else if (flags & (1 << 17)) { // -B (bin -> str)
		int i = 0;
		// TODO: move to r_util
		for (i = 0; i < strlen (str); i++) {
			ut8 ch = str[i];
			printf ("%d%d%d%d"
				"%d%d%d%d",
				ch & 128? 1: 0,
				ch & 64? 1: 0,
				ch & 32? 1: 0,
				ch & 16? 1: 0,
				ch & 8? 1: 0,
				ch & 4? 1: 0,
				ch & 2? 1: 0,
				ch & 1? 1: 0);
		}
		return true;
	} else if (flags & (1 << 16)) { // -w
		ut64 n = r_num_math (num, str);
		if (n >> 31) {
			// is >32bit
			n = (st64) (st32) n;
		} else if (n >> 14) {
			n = (st64) (st16) n;
		} else if (n >> 7) {
			n = (st64) (st8) n;
		}
		printf ("%" PFMT64d "\n", n);
		fflush (stdout);
		return true;
	} else if (flags & (1 << 15)) { // -N
		ut64 n = r_num_math (num, str);
		if (n >> 32) {
			/* is 64 bit value */
			ut8 *np = (ut8 *) &n;
			if (flags & 1) {
				fwrite (&n, sizeof (n), 1, stdout);
			} else {
				printf ("\\x%02x\\x%02x\\x%02x\\x%02x"
					"\\x%02x\\x%02x\\x%02x\\x%02x\n",
					np[0], np[1], np[2], np[3],
					np[4], np[5], np[6], np[7]);
			}
		} else {
			/* is 32 bit value */
			ut32 n32 = (ut32) (n & UT32_MAX);
			ut8 *np = (ut8 *) &n32;
			if (flags & 1) {
				fwrite (&n32, sizeof (n32), 1, stdout);
			} else {
				printf ("\\x%02x\\x%02x\\x%02x\\x%02x\n",
					np[0], np[1], np[2], np[3]);
			}
		}
		fflush (stdout);
		return true;
	} else if (flags & (1 << 10)) { // -u
		char buf[8];
		r_num_units (buf, sizeof (buf), r_num_math (NULL, str));
		printf ("%s\n", buf);
		return true;
	} else if (flags & (1 << 11)) { // -t
		RList *split = r_str_split_list (str, "GMT", 0);
		char *ts = r_list_head (split)->data;
		const char *gmt = NULL;
		if (r_list_length (split) >= 2 && strlen (r_list_head (split)->n->data) > 2) {
			gmt = (const char*) r_list_head (split)->n->data + 2;
		}
		ut32 n = r_num_math (num, ts);
		RPrint *p = r_print_new ();
		if (gmt) {
			p->datezone = r_num_math (num, gmt);
		}
		r_print_date_unix (p, (const ut8 *) &n, sizeof (ut32));
		r_print_free (p);
		r_list_free (split);
		return true;
	} else if (flags & (1 << 12)) { // -E
		const int n = strlen (str);
		/* http://stackoverflow.com/questions/4715415/base64-what-is-the-worst-possible-increase-in-space-usage */
		char *out = calloc (1, (n + 2) / 3 * 4 + 1); // ceil(n/3)*4 plus 1 for NUL
		if (out) {
			r_base64_encode (out, (const ut8 *) str, n);
			printf ("%s%s", out, nl);
			fflush (stdout);
			free (out);
		}
		return true;
	} else if (flags & (1 << 13)) { // -D
		const int n = strlen (str);
		ut8 *out = calloc (1, n / 4 * 3 + 1);
		if (out) {
			r_base64_decode (out, str, n);
			printf ("%s%s", out, nl);
			fflush (stdout);
			free (out);
		}
		return true;
	} else if (flags & 1 << 14) { // -F
		char *s = r_stdin_slurp (NULL);
		if (s) {
			char *res = r_hex_from_code (s);
			if (res) {
				printf ("%s\n", res);
				fflush (stdout);
				free (res);
			} else {
				eprintf ("Invalid input.\n");
			}
			free (s);
		}
		return false;
	} else if (flags & (1 << 18)) { // -r
		char *asnum, unit[8];
		char out[128];
		ut32 n32, s, a;
		double d;
		float f;
		ut64 n = r_num_math (num, str);

		if (num->dbz) {
			eprintf ("RNum ERROR: Division by Zero\n");
			return false;
		}
		n32 = (ut32) (n & UT32_MAX);
		asnum = r_num_as_string (NULL, n, false);
		memcpy (&f, &n32, sizeof (f));
		memcpy (&d, &n, sizeof (d));

		/* decimal, hexa, octal */
		s = n >> 16 << 12;
		a = n & 0x0fff;
		r_num_units (unit, sizeof (unit), n);
#if 0
		eprintf ("%" PFMT64d " 0x%" PFMT64x " 0%" PFMT64o
			" %s %04x:%04x ",
			n, n, n, unit, s, a);

		if (n >> 32) {
			eprintf ("%" PFMT64d " ", (st64) n);
		} else {
			eprintf ("%d ", (st32) n);
		}
		if (asnum) {
			eprintf ("\"%s\" ", asnum);
			free (asnum);
		}
		/* binary and floating point */
		r_str_bits (out, (const ut8 *) &n, sizeof (n), NULL);
		eprintf ("%s %.01lf %ff %lf\n",
			out, num->fvalue, f, d);
#endif
				printf ("hex     0x%"PFMT64x"\n", n);
				printf ("octal   0%"PFMT64o"\n", n);
				printf ("unit    %s\n", unit);
				printf ("segment %04x:%04x\n", s, a);
				if (n >> 32) {
					printf ("int64   %"PFMT64d"\n", (st64)n);
				} else {
					printf ("int32   %d\n", (st32)n);
				}
				if (asnum) {
					printf ("string  \"%s\"\n", asnum);
					free (asnum);
				}
				/* binary and floating point */
				r_str_bits64 (out, n);
				memcpy (&f, &n, sizeof (f));
				memcpy (&d, &n, sizeof (d));
				printf ("binary  0b%s\n", out);
				printf ("float:  %ff\n", f);
				printf ("double: %lf\n", d);

				/* ternary */
				r_num_to_trits (out, n);
				printf ("trits   0t%s\n", out);

		return true;
	} else if (flags & (1 << 19)) { // -L
		r_print_hex_from_bin (NULL, str);
		return true;
	} else if (flags & (1 << 21)) { // -i
		static const char start[] = "unsigned char buf[] = {";
		printf (start);
		/* reasonable amount of bytes per line */
		const int byte_per_col = 12;
		for (i = 0; i < len-1; i++) {
			/* wrapping every N bytes */
			if (i % byte_per_col == 0) {
				printf ("\n  ");
			}
			printf ("0x%02x, ", (ut8) str[i]);
		}
		/* some care for the last element */
		if (i % byte_per_col == 0) {
			printf("\n  ");
		}
		printf ("0x%02x\n", (ut8) str[len-1]);
		printf ("};\n");
		printf ("unsigned int buf_len = %d;\n", len);
		return true;
	} else if (flags & (1 << 22)) { // -o
		// check -r
		// flags & (1 << 18)
		char *asnum, *modified_str;

		// To distinguish octal values.
		if (*str != '0') {
			modified_str = r_str_newf ("0%s", str);
		} else {
			modified_str = r_str_new (str);
		}

		ut64 n = r_num_math (num, modified_str);
		free (modified_str);
		if (num->dbz) {
			eprintf ("RNum ERROR: Division by Zero\n");
			return false;
		}

		asnum = r_num_as_string (NULL, n, false);
		if (asnum) {
			printf ("%s", asnum);
			free (asnum);
		} else {
			printf("No String Possible");
		}
		return true;
	}

	if  (str[0] == '0' && (tolower (str[1]) == 'x')) {
		out_mode = (flags & 32)? '0': 'I';
	} else if (r_str_startswith (str, "b")) {
		out_mode = 'B';
		str++;
	} else if (r_str_startswith (str, "t")) {
		out_mode = 'T';
		str++;
	} else if (r_str_startswith (str, "Fx")) {
		out_mode = 'F';
		*str = '0';
	} else if (r_str_startswith (str, "Bx")) {
		out_mode = 'B';
		*str = '0';
	} else if (r_str_startswith (str, "Tx")) {
		out_mode = 'T';
		*str = '0';
	} else if (r_str_startswith (str, "Ox")) {
		out_mode = 'O';
		*str = '0';
	} else if (r_str_endswith (str, "d")) {
		out_mode = 'I';
		str[strlen (str) - 1] = 'b';
		// TODO: Move print into format_output
	} else if (r_str_endswith (str, "f")) {
		out_mode = 'l';
	} else if (r_str_endswith (str, "dt")) {
		out_mode = 'I';
		str[strlen (str) - 2] = 't';
		str[strlen (str) - 1] = '\0';
	}
	while ((p = strchr (str, ' '))) {
		*p = 0;
		format_output (num, out_mode, str, *fm, flags);
		str = p + 1;
	}
	if (*str) {
		format_output (num, out_mode, str, *fm, flags);
	}
	return true;
}

R_API int r_main_rax2(int argc, const char **argv) {
	int i, fm = 0;
	RNum *num = r_num_new (NULL, NULL, NULL);
	if (argc == 1) {
		use_stdin (num, 0, &fm);
	} else {
		ut64 flags = 0;
		for (i = 1; i < argc; i++) {
			char *argv_i = strdup (argv[i]);
			r_str_unescape (argv_i);
			rax (num, argv_i, 0, i == argc - 1, &flags, &fm);
		}
	}
	r_num_free (num);
	num = NULL;
	return 0;
}
