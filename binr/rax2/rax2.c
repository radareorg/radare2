/* radare - LGPL - Copyright 2007-2015 - pancake */

#include <r_util.h>
#include <r_print.h>
#include "../blob/version.c"

#define STDIN_BUFFER_SIZE 354096

static RNum *num;
static int help ();
static ut64 flags = 0;
static int use_stdin ();
static int force_mode = 0;
static int rax (char *str, int len, int last);

enum {
	Flag_hexstr_to_raw = 1 << 0,
	Flag_swap_endian   = 1 << 1,
	Flag_raw_to_hexstr = 1 << 2,
	Flag_binstr_to_bin = 1 << 3,
	Flag_hash_string   = 1 << 4,
	Flag_keep_base     = 1 << 5,
	Flag_float         = 1 << 6,
	Flag_force_int     = 1 << 7,
	Flag_randomart     = 1 << 8,
	Flag_convert_endian= 1 << 9,
	Flag_convert_units = 1 <<10,
	Flag_timestamp_str = 1 <<11,
	Flag_to_base64     = 1 <<12,
	Flag_from_base64   = 1 <<13,
	Flag_stdin_slurp   = 1 <<14,
	Flag_to_escape_seq = 1 <<15,
} flags_t;

static int format_output (char mode, const char *s) {
	ut64 n = r_num_math (num, s);
	const char *str = (char*) &n;
	char strbits[65];

	if (force_mode)
		mode = force_mode;

	if (flags & Flag_swap_endian) {
		/* swap endian */
		ut32 n2 = (n>>32)? 8:4;
		r_mem_copyendian ((ut8*) str, (ut8*) str, n2, 0);
	}
	switch (mode) {
	case 'I': printf ("%"PFMT64d"\n", n); break;
	case '0': printf ("0x%"PFMT64x"\n", n); break;
	case 'F': printf ("%ff\n", (float)(ut32)n); break;
	case 'f': printf ("%.01lf\n", num->fvalue); break;
	case 'O': printf ("%"PFMT64o"\n", n); break;
	case 'B':
		if (n) {
			r_num_to_bits (strbits, n);
			printf ("%sb\n", strbits);
		} else printf ("0b\n");
		break;
	case 'T':
		if (n) {
			r_num_to_trits (strbits, n);
			printf ("%st\n", strbits);
		} else	printf ("0t\n");
		break;
	default:
		eprintf ("Unknown output mode %d\n", mode);
		break;
	}
	return R_TRUE;
}

static int help () {
	printf (
		"  =[base]                 ;  rax2 =10 0x46 -> output in base 10\n"
		"  int   ->  hex           ;  rax2 10\n"
		"  hex   ->  int           ;  rax2 0xa\n"
		"  -int  ->  hex           ;  rax2 -77\n"
		"  -hex  ->  int           ;  rax2 0xffffffb3\n"
		"  int   ->  bin           ;  rax2 b30\n"
		"  int   ->  ternary       ;  rax2 t42\n"
		"  bin   ->  int           ;  rax2 1010d\n"
		"  float ->  hex           ;  rax2 3.33f\n"
		"  hex   ->  float         ;  rax2 Fx40551ed8\n"
		"  oct   ->  hex           ;  rax2 35o\n"
		"  hex   ->  oct           ;  rax2 Ox12 (O is a letter)\n"
		"  bin   ->  hex           ;  rax2 1100011b\n"
		"  hex   ->  bin           ;  rax2 Bx63\n"
		"  hex   ->  ternary       ;  rax2 Tx23\n"
		"  raw   ->  hex           ;  rax2 -S < /binfile\n"
		"  hex   ->  raw           ;  rax2 -s 414141\n"
		"  -b    binstr -> bin     ;  rax2 -b 01000101 01110110\n"
		"  -B    keep base         ;  rax2 -B 33+3 -> 36\n"
		"  -d    force integer     ;  rax2 -d 3 -> 3 instead of 0x3\n"
		"  -D    from Base64       ;  rax2 -D aGVsbG8= # hello"
		"  -e    swap endianness   ;  rax2 -e 0x33\n"
		"  -E    to Base64         ;  rax2 -E 0x11223344 # MHgxMTIyMzM0NA==\n"
		"  -f    floating point    ;  rax2 -f 6.3+2.1\n"
		"  -F    stdin slurp C hex ;  rax2 -F < shellcode.c\n"
		"  -h    help              ;  rax2 -h\n"
		"  -k    randomart         ;  rax2 -k 0x34 1020304050\n"
		"  -n    binary number     ;  rax2 -n 0x1234 # 34120000\n"
		"  -N    binary number     ;  rax2 -N 0x1234 # \\x34\\x12\\x00\\x00\n"
		"  -s    hexstr -> raw     ;  rax2 -s 43 4a 50\n"
		"  -S    raw -> hexstr     ;  rax2 -S < /bin/ls > ls.hex\n"
		"  -t    tstamp -> str     ;  rax2 -t 1234567890\n"
		"  -x    hash string       ;  rax2 -x linux osx\n"
		"  -u    units             ;  rax2 -u 389289238 # 317.0M\n"
		"  -v    rax2 version      ;  rax2 -v\n"
		);
	return R_TRUE;
}

static int rax (char *str, int len, int last) {
	float f;
	ut8 *buf;
	char *p, out_mode = (flags & Flag_force_int)? 'I': '0';
	int i;
	if (!(flags & Flag_raw_to_hexstr) || !len)
		len = strlen (str);
	if ((flags & Flag_raw_to_hexstr))
		goto dotherax;
	if (*str=='=') {
		switch (atoi (str+1)) {
		case 2: force_mode = 'B'; break;
		case 3: force_mode = 'T'; break;
		case 8: force_mode = 'O'; break;
		case 10: force_mode = 'I'; break;
		case 16: force_mode = '0'; break;
		case 0: force_mode = str[1]; break;
		}
		return R_TRUE;
	}
	if (*str=='-') {
		while (str[1] && str[1]!=' ') {
			switch (str[1]) {
			case 's': flags ^= Flag_hexstr_to_raw; break;
			case 'e': flags ^= Flag_swap_endian; break;
			case 'S': flags ^= Flag_raw_to_hexstr; break;
			case 'b': flags ^= Flag_binstr_to_bin; break;
			case 'x': flags ^= Flag_hash_string; break;
			case 'B': flags ^= Flag_keep_base; break;
			case 'f': flags ^= Flag_float; break;
			case 'd': flags ^= Flag_force_int; break;
			case 'k': flags ^= Flag_randomart; break;
			case 'n': flags ^= Flag_convert_endian; break;
			case 'u': flags ^= Flag_convert_units; break;
			case 't': flags ^= Flag_timestamp_str; break;
			case 'E': flags ^= Flag_to_base64; break;
			case 'D': flags ^= Flag_from_base64; break;
			case 'F': flags ^= Flag_stdin_slurp; break;
			case 'N': flags ^= Flag_to_escape_seq; break;
			case 'v': blob_version ("rax2"); return 0;
			case '\0': return !use_stdin ();
			default:
				out_mode = (flags ^ Flag_keep_base)? '0': 'I';
				if (str[1]>='0' && str[1]<='9') {
					if (str[2]=='x') out_mode = 'I';
					return format_output (out_mode, str);
				}
				printf ("Usage: rax2 [options] [expr ...]\n");
				return help ();
			}
			str++;
		}
		if (last)
			return !use_stdin ();
		return R_TRUE;
	}
	if (!flags) {
		if (*str=='q')
			return R_FALSE;
		if (*str=='h' || *str=='?')
			return help ();
	}
	dotherax:
	
	if (flags & Flag_hexstr_to_raw) { // -s
		int n = ((strlen (str))>>1)+1;
		buf = malloc (n);
		if (buf) {
			memset (buf, '\0', n);
			n = r_hex_str2bin (str, (ut8*)buf);
			if (n>0) fwrite (buf, n, 1, stdout);
#if __EMSCRIPTEN__
			puts ("");
#endif
			fflush (stdout);
			free (buf);
		}
		return R_TRUE;
	}
	if (flags & Flag_raw_to_hexstr) { // -S
		for (i=0; i<len; i++)
			printf ("%02x", (ut8)str[i]);
		printf ("\n");
		return R_TRUE;
	} else if (flags & Flag_binstr_to_bin) {
		int i, len;
		ut8 buf[4096];
		len = r_str_binstr2bin (str, buf, sizeof (buf));
		for (i=0; i<len; i++)
			printf ("%c", buf[i]);
		return R_TRUE;
	} else if (flags & Flag_hash_string) {
		int h = r_str_hash (str);
		printf ("0x%x\n", h);
		return R_TRUE;
	} else if (flags & Flag_keep_base) {
		out_mode = 'I';
	} else if (flags & Flag_float) {
		out_mode = 'f';
	} else if (flags & Flag_randomart) { // -k
		int n = ((strlen (str))>>1)+1;
		char *s = NULL;
		ut32 *m;
		buf = (ut8*) malloc (n);
		if (!buf) {
			return R_FALSE;
		}
		m = (ut32 *) buf;
		memset (buf, '\0', n);
		n = r_hex_str2bin (str, (ut8*)buf);
		if (n < 1 || !memcmp (str, "0x", 2)) {
			ut64 q = r_num_math (num, str);
			s = r_print_randomart ((ut8*)&q, sizeof (q), q);
			printf ("%s\n", s);
			free (s);
		} else {
			s = r_print_randomart ((ut8*)buf, n, *m);
			printf ("%s\n", s);
			free (s);
		}
		free (m);
		return R_TRUE;
	} else if (flags & Flag_convert_endian) { // -n
		ut64 n = r_num_math (num, str);
		if (n>>32) {
			/* is 64 bit value */
			ut8 *np = (ut8*)&n;
			if (flags & Flag_hexstr_to_raw) fwrite (&n, sizeof (n), 1, stdout);
			else printf ("%02x%02x%02x%02x" "%02x%02x%02x%02x\n",
				np[0], np[1], np[2], np[3],
				np[4], np[5], np[6], np[7]);
		} else {
			/* is 32 bit value */
			ut32 n32 = (ut32)(n&UT32_MAX);
			ut8 *np = (ut8*)&n32;
			if (flags & Flag_hexstr_to_raw) fwrite (&n32, sizeof (n32), 1, stdout);
			else printf ("%02x%02x%02x%02x\n",
					np[0], np[1], np[2], np[3]);
		}
		fflush (stdout);
		return R_TRUE;
	} else if (flags & Flag_to_escape_seq) { // -N
		ut64 n = r_num_math (num, str);
		if (n>>32) {
			/* is 64 bit value */
			ut8 *np = (ut8*)&n;
			if (flags & Flag_hexstr_to_raw) fwrite (&n, sizeof (n), 1, stdout);
			else printf ("\\x%02x\\x%02x\\x%02x\\x%02x"
				"\\x%02x\\x%02x\\x%02x\\x%02x\n",
				np[0], np[1], np[2], np[3],
				np[4], np[5], np[6], np[7]);
		} else {
			/* is 32 bit value */
			ut32 n32 = (ut32)(n&UT32_MAX);
			ut8 *np = (ut8*)&n32;
			if (flags & Flag_hexstr_to_raw) fwrite (&n32, sizeof (n32), 1, stdout);
			else printf ("\\x%02x\\x%02x\\x%02x\\x%02x\n",
				np[0], np[1], np[2], np[3]);
		}
		fflush (stdout);
		return R_TRUE;
	} else if (flags & Flag_convert_units) { // -u
		char buf[80];
		r_num_units (buf, r_num_math (NULL, str));
		printf ("%s\n", buf);
		return R_TRUE;
	} else if (flags & Flag_timestamp_str) { // -t
		ut32 n = r_num_math (num, str);
		RPrint *p = r_print_new ();
		r_mem_copyendian ((ut8*) &n, (ut8*) &n, 4, !(flags & Flag_swap_endian));
		r_print_date_unix (p, (const ut8*)&n, sizeof (ut32));
		r_print_free (p);
		return R_TRUE;
	} else if (flags & Flag_to_base64) { // -E
		const int len = strlen (str);
		char * out = calloc (sizeof(ut8), ((len+1)*4)/3);
		if (out) {
			r_base64_encode (out, (const ut8*)str, len);
			printf ("%s\n", out);
			fflush (stdout);
			free (out);
		}
		return R_TRUE;
	} else if (flags & Flag_from_base64) { // -D
		const int len = strlen (str);
		ut8* out = calloc (sizeof(ut8), ((len+1)/4)*3);
		if (out) {
			r_base64_decode (out, str, len);
			printf ("%s\n", out);
			fflush (stdout);
			free (out);
		}
		return R_TRUE;
	} else if (flags & Flag_stdin_slurp) { // -F
		char *str = r_stdin_slurp (NULL);
		if (str) {
			char *res = r_hex_from_c (str);
			if (res) {
				printf ("%s\n", res);
				fflush (stdout);
				free (res);
			} else {
				eprintf ("Invalid input.\n");
			}
			free (str);
		}
		return R_FALSE;
	}

	if (str[0]=='0' && str[1]=='x') {
		out_mode = (flags & Flag_keep_base)? '0': 'I';
	} else if (str[0]=='b') {
		out_mode = 'B';
		str++;
	} else if (str[0]=='t') {
		out_mode = 'T';
		str++;
	} else if (str[0]=='F' && str[1]=='x') {
		out_mode = 'F';
		*str = '0';
	} else if (str[0]=='B' && str[1]=='x') {
		out_mode = 'B';
		*str = '0';
	} else if (str[0]=='T' && str[1]=='x') {
		out_mode = 'T';
		*str = '0';
	} else if (str[0]=='O' && str[1]=='x') {
		out_mode = 'O';
		*str = '0';
	} else if (str[strlen (str)-1]=='d') {
		out_mode = 'I';
		str[strlen (str)-1] = 'b';
	//TODO: Move print into format_output
	} else if (str[strlen(str)-1]=='f') {
		ut8 *p = (ut8*)&f;
		sscanf (str, "%f", &f);
		printf ("Fx%02x%02x%02x%02x\n", p[0], p[1], p[2], p[3]);
		return R_TRUE;
	}
	while ((p = strchr (str, ' '))) {
		*p = 0;
		format_output (out_mode, str);
		str = p+1;
	}
	if (*str)
		format_output (out_mode, str);
	return R_TRUE;
}

static int use_stdin () {
	static char buf[STDIN_BUFFER_SIZE];
	int l, sflag = (flags & Flag_keep_base);
	if (! (flags & Flag_stdin_slurp)) {
		for (l=0; l>=0; l++) {
			int n = read (0, buf+l, sizeof (buf)-l-1);
			if (n<1) break;
			l+= n;
			if (buf[l-1]==0) {
				l--;
				continue;
			}
			buf[n] = 0;
			if (sflag && strlen (buf) < sizeof (buf)) // -S
				buf[strlen (buf)] = '\0';
			else buf[strlen (buf)-1] = '\0';
			if (!rax (buf, l, 0)) break;
			l = -1;
		}
	} else {
		l = 1;
	}
	if (l>0)
		rax (buf, l, 0);
	return 0;
}

int main (int argc, char **argv) {
	int i;
	num = r_num_new (NULL, NULL);
	if (argc == 1) {
		use_stdin ();
	} else {
		for (i=1; i<argc; i++) {
			rax (argv[i], 0, i==argc-1);
		}
	}
	r_num_free (num);
	return 0;
}
