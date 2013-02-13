/* radare - LGPL - Copyright 2007-2013 - pancake */

#include <r_util.h>
#include <r_print.h>

static ut64 flags = 0;

static RNum *num;
static int help ();
static int rax (char *str, int len, int last);
static int use_stdin ();

static int format_output (char mode, const char *s) {
	ut64 n;
	char *str = (char*) &n;
	char strbits[65];
	n = r_num_math (num, s);

	if (flags & 2)
		r_mem_copyendian ((ut8*) str, (ut8*) str, 4, 0);
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
	}
	return R_TRUE;
}

static int help () {
	printf (
		"  int   ->  hex           ;  rax2 10\n"
		"  hex   ->  int           ;  rax2 0xa\n"
		"  -int  ->  hex           ;  rax2 -77\n"
		"  -hex  ->  int           ;  rax2 0xffffffb3\n"
		"  int   ->  bin           ;  rax2 b30\n"
		"  bin   ->  int           ;  rax2 1010d\n"
		"  float ->  hex           ;  rax2 3.33f\n"
		"  hex   ->  float         ;  rax2 Fx40551ed8\n"
		"  oct   ->  hex           ;  rax2 35o\n"
		"  hex   ->  oct           ;  rax2 Ox12 (O is a letter)\n"
		"  bin   ->  hex           ;  rax2 1100011b\n"
		"  hex   ->  bin           ;  rax2 Bx63\n"
		"  raw   ->  hex           ;  rax2 -S < /binfile\n"
		"  hex   ->  raw           ;  rax2 -s 414141\n"
		"  -e    swap endianness   ;  rax2 -e 0x33\n"
		"  -d    force integer     ;  rax2 -d 3 -> 3 instead of 0x3\n"
		"  -f    floating point    ;  rax2 -f 6.3+2.1\n"
		"  -b    binstr -> bin     ;  rax2 -b 01000101 01110110\n"
		"  -s    hexstr -> raw     ;  rax2 -s 43 4a 50\n"
		"  -S    raw -> hexstr     ;  rax2 -S C  J  P\n"
		"  -v    version           ;  rax2 -V\n"
		"  -x    hash string       ;  rax2 -x linux osx\n"
		"  -k    randomart         ;  rax2 -k 0x34 1020304050\n"
		"  -B    keep base         ;  rax2 -B 33+3 -> 36\n"
		"  -h    help              ;  rax2 -h\n");
	return R_TRUE;
}

static int rax (char *str, int len, int last) {
	float f;
	ut8 *buf;
	char *p, out_mode = (flags&128)?'I':'0';
	int i;
	if (!len)
		len = strlen (str);

	if ((flags & 4))
		goto dotherax;
	if (*str=='-') {
		while (str[1] && str[1]!=' ') {
			switch (str[1]) {
			case 's': flags ^= 1; break;
			case 'e': flags ^= 2; break;
			case 'S': flags ^= 4; break;
			case 'b': flags ^= 8; break;
			case 'x': flags ^= 16; break;
			case 'B': flags ^= 32; break;
			case 'f': flags ^= 64; break;
			case 'd': flags ^=128; break;
			case 'k': flags ^=256; break;
			case 'v': printf ("rax2 v"R2_VERSION"\n"); break;
			case '\0': return use_stdin ();
			default:
				if (str[1]>='0' && str[1]<='9')
					return format_output (out_mode, str);
				printf ("Usage: rax2 [options] [expression]\n");
				return help ();
			}
			str++;
		}
		if (last)
			return use_stdin ();
		return R_TRUE;
	} else if (*str=='q')
		return R_FALSE;
	else if (*str=='h' || *str=='?')
		return help ();

	dotherax:
	if (flags & 256) { // -k
		int n = ((strlen (str))>>1)+1;
		char *s;
		ut32 *m;
		buf = (ut8*) malloc (n);
		m = (ut32 *) buf;
		memset (buf, '\0', n);
		n = r_hex_str2bin (str, (ut8*)buf);
		if (n<1 || !memcmp (str, "0x", 2)) {
			ut64 q = r_num_math (num, str);
			s = r_print_randomart ((ut8*)&q, sizeof (q), q);
			printf ("%s\n", s);
			free (s);
		} else {
			s = r_print_randomart ((ut8*)buf, n, *m);
			printf ("%s\n", s);
			free (s);
		}
		return R_TRUE;
	}
	if (flags & 1) { // -s
		ut64 n = ((strlen (str))>>1)+1;
		buf = malloc (n);
		memset (buf, '\0', n);
		n = r_hex_str2bin (str, (ut8*)buf);
		write (1, buf, n);
		free (buf);
		return R_TRUE;
	}
	if (flags & 4) { // -S
		for (i=0; i<len; i++)
			printf ("%02x", (ut8)str[i]);
		printf ("\n");
		return R_TRUE;
	}
	if (flags & 8) {
		int i, len;
		ut8 buf[4096];
		len = r_str_binstr2bin (str, buf, sizeof (buf));
		if (len>0)
			for (i=0; i<len; i++)
				printf ("%c", buf[i]);
		return R_TRUE;
	}
	if (flags & 16) {
		int h = r_str_hash (str);
		printf ("0x%x\n", h);
		return R_TRUE;
	}

#define KB (flags&32)
	if (flags & 64) { out_mode = 'f';
	} else if (KB) out_mode = 'I';
	if (str[0]=='0' && str[1]=='x') {
		out_mode = (KB)? '0': 'I';
	} else if (str[0]=='b') {
		out_mode = 'B';
		str++;
	} else if (str[0]=='F' && str[1]=='x') {
		out_mode = 'F';
		*str = '0';
	} else if (str[0]=='B' && str[1]=='x') {
		out_mode = 'B';
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
		format_output (out_mode, str); //r_num_math (NULL, str));
		str = p+1;
	}
	if (*str)
		format_output (out_mode, str); //r_num_math (NULL, str));
	return R_TRUE;
}

static char buf[354096]; // TODO: remove this limit

static int use_stdin () {
	while (!feof (stdin)) {
		int n = read (0, buf, sizeof (buf));
		if (n<1) break;
		buf[n] = 0;
		if (feof (stdin)) break;
		if ((flags & 4) && strlen (buf) < sizeof (buf)) // -S
			buf[strlen (buf)] = '\0';
		else buf[strlen (buf)-1] = '\0';
		if (!rax (buf, n, 0)) break;
	}
	return 0;
}

int main (int argc, char **argv) {
	int i;
	num = r_num_new (NULL, NULL);
	if (argc == 1)
		return use_stdin ();
	for (i=1; i<argc; i++)
		rax (argv[i], 0, (i+1)==argc);
	return 0;
}
