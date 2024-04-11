/* radare2 - LGPL - Copyright 2007-2024 - pancake */

#define R_LOG_ORIGIN "rax2"

// R2R db/tools/rax2
// R2R db/tools/radiff2
// R2R db/tools/rahash2

#include <r_main.h>
#include <r_util/pj.h>
#include <r_util/r_print.h>
#include <r_util/r_str.h>

typedef struct {
	bool hexstr2raw;	// -s
	bool swapendian;	// -e
	bool raw2hexstr;	// -S
	bool binstr2raw;	// -b
	bool hashstr;		// -X
	bool keepbase;		// -k
	bool floating;		// -f
	bool decimal;		// -d
	bool randomart;		// -K
	bool binarynum;		// -x
	bool showunits;		// -u
	bool timestamp;		// -t
	bool b64encode;		// -E
	bool b64decode;		// -D
	bool slurphex;		// -F
	bool binaryraw;		// -c
	bool signedword;	// -w
	bool str2hexstr;	// -B
	bool manybases;		// -r
	bool binstr2hex;	// -L
	bool dumpcstr;		// -i
	bool octal2raw;		// -o
	bool ipaddr2num;	// -I
	bool newline;		// -n
	bool jsonbases;		// -j
} RaxActions;

static bool rax(RNum *num, char *str, int len, int last, RaxActions *flags, int *fm, PJ **pj);

static int use_stdin(RNum *num, RaxActions *flags, int *fm, PJ **pj) {
	r_return_val_if_fail (num && flags, -1);
	int rc = 0;
	if (flags->slurphex) {
		char buf[1]= {0};
		if (!rax (num, buf, 1, 0, flags, fm, pj)) {
			rc = 1;
		}
	} else {
		int l = 0;
		for (;;) {
			char *buf = r_stdin_readline (&l);
			if (!buf) {
				break;
			}
			if (!rax (num, buf, l, 0, flags, fm, pj)) {
				rc = 1;
			}
			free (buf);
		}
	}
	return rc;
}

static void rax2_newline(RaxActions flags) {
#if __EMSCRIPTEN__
	puts ("");
#else
	if (flags.newline) {
		puts ("");
	}
#endif
	fflush (stdout);
}

static bool format_output(RNum *num, char mode, const char *s, int force_mode, RaxActions flags) {
	const char *errstr = NULL;
	ut64 n = r_num_calc (num, s, &errstr);
	if (errstr) {
		R_LOG_ERROR (errstr);
		return false;
	}
	char strbits[65];
	if (force_mode) {
		mode = force_mode;
	}
	if (flags.swapendian) {
		ut64 n2 = n;
		r_mem_swapendian ((ut8 *) &n, (ut8 *) &n2, 8);
		if (!(int) n) {
			n >>= 32;
		}
	}
	switch (mode) {
	case 'I':
		printf ("%" PFMT64d "\n", n);
		break;
	case '0':
		printf ("0x%" PFMT64x "\n", n);
		break;
	case 'F': {
		int n2 = (int) n;
		float *f = (float *) &n2;
		printf ("%ff\n", *f);
		}
		break;
	case 'f':
		printf ("%.01lf\n", num->fvalue);
		break;
	case 'l':
		{
			R_STATIC_ASSERT (sizeof (float) == 4);
			float f = (float) num->fvalue;
			ut32 *p = (ut32 *) &f;
			printf ("Fx%08x\n", *p);
		}
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
			r_num_to_ternary (strbits, n);
			printf ("%st\n", strbits);
		} else {
			printf ("0t\n");
		}
		break;
	default:
		R_LOG_ERROR ("Unknown output mode %d", mode);
		return false;
	}
	return true;
}

static void help_usage(void) {
	printf ("Usage: rax2 [-h|...] [- | expr ...] # convert between numeric bases\n");
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
		"  -a      show ascii table     ;  rax2 -a\n"
		"  -b      bin -> str           ;  rax2 -b 01000101 01110110\n"
		"  -B      str -> bin           ;  rax2 -B hello\n"
		"  -c      output in C string   ;  rax2 -c 0x1234 # \\x34\\x12\\x00\\x00\n"
		"  -d      force integer        ;  rax2 -d 3 -> 3 instead of 0x3\n"
		"  -e      swap endianness      ;  rax2 -e 0x33\n"
		"  -D      base64 decode        ;  rax2 -D \"aGVsbG8=\"\n"
		"  -E      base64 encode        ;  rax2 -E \"hello\"\n"
		"  -f      floating point       ;  rax2 -f 6.3+2.1\n"
		"  -F      stdin slurp code hex ;  rax2 -F < shellcode.[c/py/js]\n"
		"  -h      help                 ;  rax2 -h\n"
		"  -i      dump as C byte array ;  rax2 -i < bytes\n"
		"  -I      IP address <-> LONG  ;  rax2 -I 3530468537\n"
		"  -j      json format output   ;  rax2 -j 0x1234 # same as r2 -c '?j 0x1234'\n"
		"  -k      keep base            ;  rax2 -k 33+3 -> 36\n"
		"  -K      randomart            ;  rax2 -K 0x34 1020304050\n"
		"  -L      bin -> hex(bignum)   ;  rax2 -L 111111111 # 0x1ff\n"
		"  -n      newline              ;  append newline to output (for -E/-D/-r/..)\n"
		"  -o      octalstr -> raw      ;  rax2 -o \\162 \\62 # r2\n"
		"  -r      r2 style output      ;  rax2 -r 0x1234 # same as r2 -c '? 0x1234'\n"
		"  -s      hexstr -> raw        ;  rax2 -s 43 4a 50\n"
		"  -S      raw -> hexstr        ;  rax2 -S < /bin/ls > ls.hex\n"
		"  -rS     raw -> hex.r2        ;  rax2 -rS < /bin/ls > ls.r2\n"
		"  -t      tstamp -> str        ;  rax2 -t 1234567890\n"
		"  -u      units                ;  rax2 -u 389289238 # 317.0M\n"
		"  -v      version              ;  rax2 -v\n"
		"  -w      signed word          ;  rax2 -w 16 0xffff\n"
		"  -x      output in hexpairs   ;  rax2 -x 0x1234 # 34120000\n"
		"  -X      hash string          ;  rax2 -X linux osx\n"
	);
	return true;
}

static bool invalid_length(RaxActions flags) {
	if (flags.raw2hexstr) {
		return false;
	}
	if (flags.b64decode) {
		return false;
	}
	if (flags.b64encode) {
		return false;
	}
	return true;
}

static bool rax(RNum *num, char *str, int len, int last, RaxActions *flags, int *fm, PJ **pj) {
	const char *errstr = NULL;
	ut8 *buf;
	char *p, out_mode = (flags->decimal)? 'I': '0';
	int i;
	if (len == 0 || invalid_length (*flags)) {
		len = strlen (str);
	}
	// For -S and -E we do not compute the length again since it may contain null byte.
	if (flags->raw2hexstr) {
		goto dotherax;
	}
	if (*str == '=') {
		int force_mode = 0;
		switch (atoi (str + 1)) {
		case 0: force_mode = str[1]; break;
		case 2: force_mode = 'B'; break;
		case 3: force_mode = 'T'; break;
		case 8: force_mode = 'O'; break;
		case 10: force_mode = 'I'; break;
		case 16: force_mode = '0'; break;
		}
		*fm = force_mode;
		return true;
	}
	bool usedflags = false;
	if (*str == '-') {
		while (str[1] && str[1] != ' ') {
			switch (str[1]) {
			case 'n': flags->newline = true; break;
			case 'a': printf ("%s", r_str_asciitable ()); return 0;
			case 's': flags->hexstr2raw = !flags->hexstr2raw; break;
			case 'e': flags->swapendian = !flags->swapendian; break;
			case 'S': flags->raw2hexstr = !flags->raw2hexstr; break;
			case 'b': flags->binstr2raw = !flags->binstr2raw; break;
			case 'X': flags->hashstr = !flags->hashstr; break;
			case 'k': flags->keepbase = !flags->keepbase; break;
			case 'f': flags->floating = !flags->floating; break;
			case 'd': flags->decimal = !flags->decimal; break;
			case 'K': flags->randomart = !flags->randomart; break;
			case 'x': flags->binarynum = !flags->binarynum; break;
			case 'u': flags->showunits = !flags->showunits; break;
			case 't': flags->timestamp = !flags->timestamp; break;
			case 'E': flags->b64encode = !flags->b64encode; break;
			case 'D': flags->b64decode = !flags->b64decode; break;
			case 'F': flags->slurphex = !flags->slurphex; break;
			case 'c': flags->binaryraw = !flags->binaryraw; break;
			case 'w': flags->signedword = !flags->signedword; break;
			case 'B': flags->str2hexstr = !flags->str2hexstr; break;
			case 'r': flags->manybases = !flags->manybases; break;
			case 'L': flags->binstr2hex = !flags->binstr2hex; break;
			case 'i': flags->dumpcstr = !flags->dumpcstr; break;
			case 'o': flags->octal2raw = !flags->octal2raw; break;
			case 'I': flags->ipaddr2num = !flags->ipaddr2num; break;
			case 'j': flags->jsonbases = !flags->jsonbases; break;
			case 'v': return r_main_version_print ("rax2", 0);
			case '\0': return !use_stdin (num, flags, fm, pj);
			default:
				/* not as complete as for positive numbers */
				out_mode = !flags->keepbase? '0': 'I';
				if (str[1] >= '0' && str[1] <= '9') {
					if (str[2] == 'x') {
						out_mode = 'I';
					} else if (r_str_endswith (str, "f")) {
						out_mode = 'l';
					}
					return format_output (num, out_mode, str, *fm, *flags);
				}
				help_usage ();
				return help ();
			}
			str++;
		}
		usedflags = true;
		if (last) {
			return !use_stdin (num, flags, fm, pj);
		}
		return true;
	}
	if (!usedflags && r_str_nlen (str, 2) == 1) {
		if (*str == 'q') {
			return false;
		}
		if (*str == 'h' || *str == '?') {
			help ();
			return false;
		}
	}

dotherax:
	if (flags->hexstr2raw) { // -s
		int n = ((strlen (str)) >> 1) + 1;
		buf = calloc (1, n);
		if (buf) {
			n = r_hex_str2bin (str, (ut8 *) buf);
			if (n > 0) {
				fwrite (buf, n, 1, stdout);
			}
			rax2_newline (*flags);
			free (buf);
		}
		return true;
	}
	if (flags->raw2hexstr) { // -S
		if (flags->str2hexstr) {
			int j;
			printf ("s+0\n");
			for (i = 0; i < len;) {
				printf ("wx+");
				for (j = 0; j < 80 && i < len; j++, i++) {
					printf ("%02x", (ut8) str[i]);
				}
				printf ("\n");
			}
			printf ("s-\n");
			printf ("\n");
		} else {
			for (i = 0; i < len; i++) {
				printf ("%02x", (ut8) str[i]);
			}
			printf ("\n");
		}
		return true;
	}
	if (flags->binstr2raw) { // -b
		ut8 out[256] = {0};
		if (r_mem_from_binstring (str, out, sizeof (out) - 1)) {
			printf ("%s\n", out); // TODO accept non null terminated strings
		} else {
			R_LOG_ERROR ("Invalid binary input string");
		}
		return true;
	}
	if (flags->hashstr) { // -X
		int h = r_str_hash (str);
		printf ("0x%x\n", h);
		return true;
	}
	if (flags->keepbase) { // -k
		out_mode = 'I';
	} else if (flags->floating) { // -f
		out_mode = 'f';
	}
	if (flags->randomart) { // -K
		int n = ((strlen (str)) >> 1) + 1;
		char *s = NULL;
		buf = (ut8 *) calloc (1, n);
		if (!buf) {
			return false;
		}
		ut32 *m = (ut32 *) buf;
		n = r_hex_str2bin (str, (ut8 *) buf);
		if (n < 1 || r_str_startswith (str, "0x")) {
			ut64 q = r_num_calc (num, str, &errstr);
			if (errstr) {
				R_LOG_ERROR (errstr);
				free (buf);
				return false;
			}
			s = r_print_randomart ((ut8 *) &q, sizeof (q), q);
		} else {
			s = r_print_randomart ((ut8 *) buf, n, *m);
		}
		printf ("%s\n", s);
		free (s);
		free (m);
		return true;
	}
	if (flags->binarynum) { // -x
		ut64 n = r_num_calc (num, str, &errstr);
		if (errstr) {
			R_LOG_ERROR (errstr);
			return false;
		}
		if (n >> 32) {
			/* is 64 bit value */
			if (flags->hexstr2raw) {
				fwrite (&n, sizeof (n), 1, stdout);
			} else {
				int i;
				for (i = 0; i < 8; i++) {
					printf ("%02x", (int) (n & 0xff));
					n >>= 8;
				}
				printf ("\n");
			}
		} else {
			/* is 32 bit value */
			ut32 n32 = (ut32) n;
			if (flags->hexstr2raw) {
				fwrite (&n32, sizeof (n32), 1, stdout);
			} else {
				int i;
				for (i = 0; i < 4; i++) {
					printf ("%02x", n32 & 0xff);
					n32 >>= 8;
				}
				printf ("\n");
			}
		}
		return true;
	} else if (flags->str2hexstr) { // -B (bin -> str)
		char *newstr = r_mem_to_binstring((const ut8*)str, strlen (str));
		printf ("%s\n", newstr);
		free (newstr);
		return true;
	} else if (flags->signedword) { // -w
		ut64 n = r_num_calc (num, str, &errstr);
		if (errstr) {
			R_LOG_ERROR (errstr);
			return false;
		}
		if (n >> 31) {
			// is >32bit
			n = (st64) (st32) n;
		} else if (n >> 14) {
			n = (st64) (st16) n;
		} else if (n >> 7) {
			n = (st64) (st8) n;
		}
		printf ("%" PFMT64d "\n", n);
		return true;
	} else if (flags->binaryraw) { // -c
		ut64 n = r_num_calc (num, str, &errstr);
		if (errstr) {
			R_LOG_ERROR (errstr);
			return false;
		}
		if (n >> 32) {
			/* is 64 bit value */
			if (flags->hexstr2raw) {
				fwrite (&n, sizeof (n), 1, stdout);
			} else {
				int i;
				for (i = 0; i < 8; i++) {
					printf ("\\x%02x", (int) (n & 0xff));
					n >>= 8;
				}
				printf ("\n");
			}
		} else {
			/* is 32 bit value */
			ut32 n32 = (ut32) n;
			if (flags->hexstr2raw) {
				fwrite (&n32, sizeof (n32), 1, stdout);
			} else {
				int i;
				for (i = 0; i < 4; i++) {
					printf ("\\x%02x", n32 & 0xff);
					n32 >>= 8;
				}
				printf ("\n");
			}
		}
		return true;
	} else if (flags->showunits) { // -u
		char buf[8] = {0};
		r_num_units (buf, sizeof (buf), r_num_calc (NULL, str, &errstr));
		if (errstr) {
			R_LOG_ERROR (errstr);
			return false;
		}
		printf ("%s\n", buf);
		return true;
	} else if (flags->timestamp) { // -t
		RList *split = r_str_split_list (str, "GMT", 0);
		char *ts = r_list_head (split)->data;
		const char *gmt = NULL;
		if (r_list_length (split) >= 2 && strlen (r_list_head (split)->n->data) > 2) {
			gmt = (const char*) r_list_head (split)->n->data + 2;
		}
		ut32 n = r_num_calc (num, ts, &errstr);
		if (errstr) {
			R_LOG_ERROR (errstr);
			return false;
		}
		RPrint *p = r_print_new ();
		if (gmt) {
			p->datezone = r_num_calc (num, gmt, &errstr);
			if (errstr) {
				R_LOG_ERROR (errstr);
				return false;
			}
		}
		r_print_date_unix (p, (const ut8 *) &n, sizeof (ut32));
		r_print_free (p);
		r_list_free (split);
		return true;
	} else if (flags->b64encode) { // -E
		// TODO: use the dynamic b64 encoder so we dont have to manually calloc here
		/* http://stackoverflow.com/questions/4715415/base64-what-is-the-worst-possible-increase-in-space-usage */
		char *out = calloc (1, (len + 2) / 3 * 4 + 1); // ceil(n/3)*4 plus 1 for NUL
		if (out) {
			int olen = r_base64_encode (out, (const ut8 *)str, len);
			if (olen > 0) {
				printf ("%s", out);
				rax2_newline (*flags);
			}
			free (out);
		}
		return true;
	} else if (flags->b64decode) { // -D
		int n = strlen (str);
		ut8 *out = calloc (1, (n / 4 * 3) + 1);
		if (out) {
			n = r_base64_decode (out, str, n);
			if (n > 0) {
				fwrite (out, n, 1, stdout);
				rax2_newline (*flags);
			} else {
				R_LOG_ERROR ("Cannot decode");
			}
			free (out);
		}
		return true;
	} else if (flags->slurphex) { // -F
		char *s = r_stdin_slurp (NULL);
		if (s) {
			char *res = r_hex_from_code (s);
			if (res) {
				printf ("%s\n", res);
				fflush (stdout);
				free (res);
			} else {
				R_LOG_ERROR ("Invalid input");
			}
			free (s);
		}
		return false;
	} else if (flags->manybases) { // -r -B wtf should be -r aka 19 wtf but it was is 18
		char *asnum, unit[8];
		char out[128];
		ut32 n32, s, a;
		double d;
		float f;
		const char *errstr = NULL;
		ut64 n = r_num_calc (num, str, &errstr);
		if (errstr) {
			R_LOG_ERROR (errstr);
			return false;
		}
		if (num->dbz) { // XXX should be done in errstr already
			R_LOG_ERROR ("division by zero");
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
		if (n >> 32) {
			printf ("int64   %"PFMT64d"\n", (st64)n);
			printf ("uint64  %"PFMT64u"\n", (ut64)n);
		} else {
			printf ("int32   %d\n", (st32)n);
			printf ("uint32  %u\n", (ut32)n);
		}
		printf ("hex     0x%"PFMT64x"\n", n);
		printf ("octal   0%"PFMT64o"\n", n);
		printf ("unit    %s\n", unit);
		printf ("segment %04x:%04x\n", s, a);
		if (asnum) {
			printf ("string  \"%s\"\n", asnum);
			free (asnum);
		}
		/* binary and floating point */
		r_str_bits64 (out, n);
		memcpy (&f, &n, sizeof (f));
		memcpy (&d, &n, sizeof (d));
		printf ("float   %ff\n", f);
		printf ("double  %lf\n", d);
		printf ("binary  0b%s\n", out);

		// base36
		char b36str[16];
		b36_fromnum (b36str, n);
		printf ("base36  %s\n", b36str);

		/* ternary */
		r_num_to_ternary (out, n);
		printf ("ternary 0t%s\n", out);

		return true;
	} else if (flags->jsonbases) {
		r_strf_buffer (256);
		char unit[8];
		char out[128];
		ut32 n32, s, a;
		double d;
		float f;
		const char *errstr = NULL;
		ut64 n = r_num_calc (num, str, &errstr);
		if (errstr) {
			R_LOG_ERROR (errstr);
			return false;
		}
		if (num->dbz) { // XXX should be done in errstr already
			R_LOG_ERROR ("division by zero");
			return false;
		}
		n32 = (ut32) (n & UT32_MAX);

		if (!*pj) {
			*pj = pj_new ();
			pj_o (*pj);
		}

		pj_ks (*pj, "int32", r_strf ("%d", (st32)(n & UT32_MAX)));
		pj_ks (*pj, "uint32", r_strf ("%u", (ut32)n));
		pj_ks (*pj, "int64", r_strf ("%"PFMT64d, (st64)n));
		pj_ks (*pj, "uint64", r_strf ("%"PFMT64u, (ut64)n));
		pj_ks (*pj, "hex", r_strf ("0x%08"PFMT64x, n));
		pj_ks (*pj, "octal", r_strf ("0%"PFMT64o, n));

		/* decimal, hexa, octal */
		s = n >> 16 << 12;
		a = n & 0x0fff;
		r_num_units (unit, sizeof (unit), n);

		pj_ks (*pj, "unit", unit);
		pj_ks (*pj, "segment", r_strf ("%04x:%04x", s, a));

		/* binary and floating point */
		r_str_bits64 (out, n);
		memcpy (&f, &n32, sizeof (f));
		memcpy (&d, &n, sizeof (d));

		pj_ks (*pj, "fvalue", r_strf ("%.1lf", num->fvalue));
		pj_ks (*pj, "float", r_strf ("%ff", f));
		pj_ks (*pj, "double", r_strf ("%lf", d));
		pj_ks (*pj, "binary", r_strf ("0b%s", out));
		char b36str[16];
		b36_fromnum (b36str, n);
		pj_ks (*pj, "base36", b36str);
		r_num_to_ternary (out, n);
		pj_ks (*pj, "ternary", r_strf ("0t%s", out));

		if (last) {
			pj_end (*pj);
		}
		return true;
	}
	if (flags->binstr2hex) { // -L
		r_print_hex_from_bin (NULL, str);
		return true;
	}
	if (flags->dumpcstr) { // -i
		RStrBuf *sb = r_strbuf_new ("unsigned char buf[] = {");
		const int byte_per_col = 12;
		for (i = 0; i < len - 1; i++) {
			// wrapping every N bytes
			if (i % byte_per_col == 0) {
				r_strbuf_append (sb, "\n  ");
			}
			r_strbuf_appendf (sb, "0x%02x, ", (ut8) str[i]);
		}
		// some care for the last element
		if (i % byte_per_col == 0) {
			r_strbuf_append (sb, "\n  ");
		}
		r_strbuf_appendf (sb, "0x%02x\n", (ut8) str[len - 1]);
		r_strbuf_append (sb, "};\n");
		r_strbuf_appendf (sb, "unsigned int buf_len = %d;\n", len);
		char *s = r_strbuf_drain (sb);
		if (s) {
			printf ("%s", s);
			free (s);
		}
		return true;
	}
	if (flags->octal2raw) { // -o
		char *modified_str = (*str == '0')
			? r_str_new (str)
			: r_str_newf ("0%s", str);
		const char *errstr = NULL;
		ut64 n = r_num_calc (num, modified_str, &errstr);
		free (modified_str);
		if (errstr) {
			R_LOG_ERROR ("%s", errstr);
			return false;
		}
		if (num->dbz) {
			R_LOG_ERROR ("Division by Zero");
			return false;
		}
		char *asnum = r_num_as_string (NULL, n, false);
		if (asnum) {
			printf ("%s", asnum);
			free (asnum);
		} else {
			R_LOG_ERROR ("Not a string");
			return false;
		}
		return true;
	}
	if (flags->ipaddr2num) { // -I
		if (strchr (str, '.')) {
			ut8 ip[4];
			sscanf (str, "%hhd.%hhd.%hhd.%hhd", ip, ip + 1, ip + 2, ip + 3);
			ut32 ip32 = ip[0] | (ip[1] << 8) | (ip[2] << 16) | (ip[3] << 24);
			printf ("0x%08x\n", ip32);
		} else {
			const char *errstr = NULL;
			ut32 ip32 = (ut32)r_num_calc (NULL, str, &errstr);
			if (errstr) {
				R_LOG_ERROR (errstr);
				return false;
			}
			ut8 ip[4] = { ip32 & 0xff, (ip32 >> 8) & 0xff, (ip32 >> 16) & 0xff, ip32 >> 24 };
			printf ("%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
		}
		return true;
	}
	// no flags passed

	if  (str[0] == '0' && (tolower ((ut8)str[1]) == 'x')) {
		out_mode = (flags->keepbase)? '0': 'I';
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
		if (!format_output (num, out_mode, str, *fm, *flags)) {
			return false;
		}
		str = p + 1;
	}
	return *str? format_output (num, out_mode, str, *fm, *flags): true;
}

R_API int r_main_rax2(int argc, const char **argv) {
	int i, fm = 0;
	int rc = 0;
	int len = 0;

	if (argc < 2) {
		help_usage ();
		// use_stdin (num, NULL, &fm);
	} else {
		RNum *num = r_num_new (NULL, NULL, NULL);
		RaxActions flags = {0};
		PJ *pj = NULL;
		for (i = 1; i < argc; i++) {
			char *argv_i = strdup (argv[i]);
			if (argv_i) {
				len = r_str_unescape (argv_i);
				if (!rax (num, argv_i, len, i == argc - 1, &flags, &fm, &pj)) {
					rc = 1;
				}
				free (argv_i);
			}
		}
		if (pj) {
			printf ("%s\n", pj_string (pj));
			pj_free (pj);
		}
		r_num_free (num);
	}
	return rc;
}
