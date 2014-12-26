/* radare - LGPL - Copyright 2007-2014 - pancake */

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

static int format_output (char mode, const char *s) {
	ut64 n = r_num_math (num, s);
	const char *str = (char*) &n;
	char strbits[65];

	if (force_mode)
		mode = force_mode;

	if (flags & 2) {
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
		"  -e    swap endianness   ;  rax2 -e 0x33\n"
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
		"  -v    version           ;  rax2 -V\n"
		);
	return R_TRUE;
}

static int rax (char *str, int len, int last) {
	float f;
	ut8 *buf;
	char *p, out_mode = (flags&128)? 'I': '0';
	int i;
	if (!(flags & 4) || !len)
		len = strlen (str);
	if ((flags & 4))
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
			case 's': flags ^= 1; break;
			case 'e': flags ^= 1<<1; break;
			case 'S': flags ^= 1<<2; break;
			case 'b': flags ^= 1<<3; break;
			case 'x': flags ^= 1<<4; break;
			case 'B': flags ^= 1<<5; break;
			case 'f': flags ^= 1<<6; break;
			case 'd': flags ^= 1<<7; break;
			case 'k': flags ^= 1<<8; break;
			case 'n': flags ^= 1<<9; break;
			case 'u': flags ^=1<<10; break;
			case 't': flags ^=1<<11; break;
			case 'E': flags ^=1<<12; break;
			case 'D': flags ^=1<<13; break;
			case 'F': flags ^=1<<14; break;
			case 'N': flags ^=1<<15; break;
			case 'v': blob_version ("rax2"); return 0;
			case '\0': return !use_stdin ();
			default:
				out_mode = (flags^32)? '0': 'I';
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
	
	if (flags & 1) { // -s
		ut64 n = ((strlen (str))>>1)+1;
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
	if (flags & 4) { // -S
		for (i=0; i<len; i++)
			printf ("%02x", (ut8)str[i]);
		printf ("\n");
		return R_TRUE;
	} else if (flags & 8) {
		int i, len;
		ut8 buf[4096];
		len = r_str_binstr2bin (str, buf, sizeof (buf));
		for (i=0; i<len; i++)
			printf ("%c", buf[i]);
		return R_TRUE;
	} else if (flags & 16) {
		int h = r_str_hash (str);
		printf ("0x%x\n", h);
		return R_TRUE;
	} else if (flags & 32) {
		out_mode = 'I';
	} else if (flags & 64) {
		out_mode = 'f';
	} else if (flags & 256) { // -k
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
	} else if (flags & (1<<9)) { // -n
		ut64 n = r_num_math (num, str);
		if (n>>32) {
			/* is 64 bit value */
			ut8 *np = (ut8*)&n;
			if (flags & 1) fwrite (&n, sizeof (n), 1, stdout);
			else printf ("%02x%02x%02x%02x" "%02x%02x%02x%02x\n",
				np[0], np[1], np[2], np[3],
				np[4], np[5], np[6], np[7]);
		} else {
			/* is 32 bit value */
			ut32 n32 = (ut32)(n&UT32_MAX);
			ut8 *np = (ut8*)&n32;
			if (flags & 1) fwrite (&n32, sizeof (n32), 1, stdout);
			else printf ("%02x%02x%02x%02x\n",
					np[0], np[1], np[2], np[3]);
		}
		fflush (stdout);
		return R_TRUE;
	} else if (flags & (1<<15)) { // -N
		ut64 n = r_num_math (num, str);
		if (n>>32) {
			/* is 64 bit value */
			ut8 *np = (ut8*)&n;
			if (flags & 1) fwrite (&n, sizeof (n), 1, stdout);
			else printf ("\\x%02x\\x%02x\\x%02x\\x%02x"
				"\\x%02x\\x%02x\\x%02x\\x%02x\n",
				np[0], np[1], np[2], np[3],
				np[4], np[5], np[6], np[7]);
		} else {
			/* is 32 bit value */
			ut32 n32 = (ut32)(n&UT32_MAX);
			ut8 *np = (ut8*)&n32;
			if (flags & 1) fwrite (&n32, sizeof (n32), 1, stdout);
			else printf ("\\x%02x\\x%02x\\x%02x\\x%02x\n",
				np[0], np[1], np[2], np[3]);
		}
		fflush (stdout);
		return R_TRUE;
	} else if (flags & 1024) { // -u
		char buf[80];
		r_num_units (buf, r_num_math (NULL, str));
		printf ("%s\n", buf);
		return R_TRUE;
	} else if (flags & 2048) { // -t
		ut32 n = r_num_math (num, str);
		RPrint *p = r_print_new ();
		p->big_endian = 0; // TODO: honor endian here
		r_mem_copyendian ((ut8*) &n, (ut8*) &n, 8, 0); // fix endian here
		r_print_date_unix (p, (const ut8*)&n, sizeof (ut64));
		r_print_free (p);
		return R_TRUE;
	} else if (flags & 4096) { // -E
		const int len = strlen (str);
		ut8* out = calloc (sizeof(ut8), ((len+1)*4)/3);
		if (out) {
			r_base64_encode (out, (const ut8*)str, len);
			printf ("%s\n", out);
			fflush (stdout);
			free (out);
		}
		return R_TRUE;
	} else if (flags & 8192) { // -D
		const int len = strlen (str);
		ut8* out = calloc (sizeof(ut8), ((len+1)/4)*3);
		if (out) {
			r_base64_decode (out, str, len);
			printf ("%s\n", out);
			fflush (stdout);
			free (out);
		}
		return R_TRUE;
	} else if (flags & 16384) { // -F
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
		out_mode = (flags&32)? '0': 'I';
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
	int l, sflag = (flags & 5);
	if (! (flags & 16384)) {
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
		r_num_free (num);
		return use_stdin ();
	}
	for (i=1; i<argc; i++)
		rax (argv[i], 0, (i+1)==argc);
	r_num_free (num);
	return 0;
}
