/* radare - LGPL - Copyright 2007-2017 - pancake */

#include "../blob/version.c"
#include <r_print.h>

#define STDIN_BUFFER_SIZE 354096
#define R_STATIC_ASSERT(x)\
	switch (0) {\
	case 0:\
	case (x):;\
	}

static RNum *num;
static int help();
static ut64 flags = 0;
static int use_stdin();
static int force_mode = 0;
static int rax(char *str, int len, int last);
static const char *nl = "";

static int format_output(char mode, const char *s) {
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
	case '0': {
		int len = strlen (s);
		if (len > 0 && s[len - 1] == 'f') {
			R_STATIC_ASSERT (sizeof (float) == 4)
			float f = (float) num->fvalue;
			ut8 *p = (ut8 *) &f;
			printf ("Fx%02x%02x%02x%02x\n", p[3], p[2], p[1], p[0]);
		} else {
			printf ("0x%" PFMT64x "\n", n);
		}
	} break;
	case 'F': {
		float *f = (float *) &n;
		printf ("%ff\n", *f);
	} break;
	case 'f': printf ("%.01lf\n", num->fvalue); break;
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

static void show_ascii_table() {
	printf(
		"The following table contains the 128 ASCII characters.\n"
		"\n"
		"Oct   Dec   Hex   Char                        Oct   Dec   Hex   Char\n"
		"────────────────────────────────────────────────────────────────────────\n"
		"000   0     00    NUL '\\0' (null character)   100   64    40    @\n"
		"001   1     01    SOH (start of heading)      101   65    41    A\n"
		"002   2     02    STX (start of text)         102   66    42    B\n"
		"003   3     03    ETX (end of text)           103   67    43    C\n"
		"004   4     04    EOT (end of transmission)   104   68    44    D\n"
		"005   5     05    ENQ (enquiry)               105   69    45    E\n"
		"006   6     06    ACK (acknowledge)           106   70    46    F\n"
		"007   7     07    BEL '\\a' (bell)             107   71    47    G\n"
		"010   8     08    BS  '\\b' (backspace)        110   72    48    H\n"
		"011   9     09    HT  '\\t' (horizontal tab)   111   73    49    I\n"
		"012   10    0A    LF  '\\n' (new line)         112   74    4A    J\n"
		"013   11    0B    VT  '\\v' (vertical tab)     113   75    4B    K\n"
		"014   12    0C    FF  '\\f' (form feed)        114   76    4C    L\n"
		"015   13    0D    CR  '\\r' (carriage ret)     115   77    4D    M\n"
		"016   14    0E    SO  (shift out)             116   78    4E    N\n"
		"017   15    0F    SI  (shift in)              117   79    4F    O\n"
		"020   16    10    DLE (data link escape)      120   80    50    P\n"
		"021   17    11    DC1 (device control 1)      121   81    51    Q\n"
		"022   18    12    DC2 (device control 2)      122   82    52    R\n"
		"023   19    13    DC3 (device control 3)      123   83    53    S\n"
		"024   20    14    DC4 (device control 4)      124   84    54    T\n"
		"025   21    15    NAK (negative ack.)         125   85    55    U\n"
		"026   22    16    SYN (synchronous idle)      126   86    56    V\n"
		"027   23    17    ETB (end of trans. blk)     127   87    57    W\n"
		"030   24    18    CAN (cancel)                130   88    58    X\n"
		"031   25    19    EM  (end of medium)         131   89    59    Y\n"
		"032   26    1A    SUB (substitute)            132   90    5A    Z\n"
		"033   27    1B    ESC (escape)                133   91    5B    [\n"
		"034   28    1C    FS  (file separator)        134   92    5C    \\  '\\\\'\n"
		"035   29    1D    GS  (group separator)       135   93    5D    ]\n"
		"036   30    1E    RS  (record separator)      136   94    5E    ^\n"
		"037   31    1F    US  (unit separator)        137   95    5F    _\n"
		"040   32    20    SPACE                       140   96    60    `\n"
		"041   33    21    !                           141   97    61    a\n"
		"042   34    22    \"                           142   98    62    b\n"
		"043   35    23    #                           143   99    63    c\n"
		"044   36    24    $                           144   100   64    d\n"
		"045   37    25    %%                           145   101   65    e\n"
		"046   38    26    &                           146   102   66    f\n"
		"047   39    27    '                           147   103   67    g\n"
		"050   40    28    (                           150   104   68    h\n"
		"051   41    29    )                           151   105   69    i\n"
		"052   42    2A    *                           152   106   6A    j\n"
		"053   43    2B    +                           153   107   6B    k\n"
		"054   44    2C    ,                           154   108   6C    l\n"
		"055   45    2D    -                           155   109   6D    m\n"
		"056   46    2E    .                           156   110   6E    n\n"
		"057   47    2F    /                           157   111   6F    o\n"
		"060   48    30    0                           160   112   70    p\n"
		"061   49    31    1                           161   113   71    q\n"
		"062   50    32    2                           162   114   72    r\n"
		"063   51    33    3                           163   115   73    s\n"
		"064   52    34    4                           164   116   74    t\n"
		"065   53    35    5                           165   117   75    u\n"
		"066   54    36    6                           166   118   76    v\n"
		"067   55    37    7                           167   119   77    w\n"
		"070   56    38    8                           170   120   78    x\n"
		"071   57    39    9                           171   121   79    y\n"
		"072   58    3A    :                           172   122   7A    z\n"
		"073   59    3B    ;                           173   123   7B    {\n"
		"074   60    3C    <                           174   124   7C    |\n"
		"075   61    3D    =                           175   125   7D    }\n"
		"076   62    3E    >                           176   126   7E    ~\n"
		"077   63    3F    ?                           177   127   7F    DEL\n"
	);
}

static int help() {
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
		"  -F      stdin slurp code hex ;  rax2 -F < shellcode.c\n"
		"  -h      help                 ;  rax2 -h\n"
		"  -k      keep base            ;  rax2 -k 33+3 -> 36\n"
		"  -K      randomart            ;  rax2 -K 0x34 1020304050\n"
		"  -L      bin -> hex(bignum)   ;  rax2 -L 111111111 # 0x1ff\n"
		"  -n      binary number        ;  rax2 -n 0x1234 # 34120000\n"
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

static int rax(char *str, int len, int last) {
	float f;
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
		switch (atoi (str + 1)) {
		case 2: force_mode = 'B'; break;
		case 3: force_mode = 'T'; break;
		case 8: force_mode = 'O'; break;
		case 10: force_mode = 'I'; break;
		case 16: force_mode = '0'; break;
		case 0: force_mode = str[1]; break;
		}
		return true;
	}
	if (*str == '-') {
		while (str[1] && str[1] != ' ') {
			switch (str[1]) {
			case 'l': nl = "\n"; break;
			case 'a': show_ascii_table (); return 0;
			case 's': flags ^= 1; break;
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
			case 'v': blob_version ("rax2"); return 0;
			case '\0': return !use_stdin ();
			default:
				out_mode = (flags ^ 32)? '0': 'I';
				if (str[1] >= '0' && str[1] <= '9') {
					if (str[2] == 'x') {
						out_mode = 'I';
					}
					return format_output (out_mode, str);
				}
				printf ("Usage: rax2 [options] [expr ...]\n");
				return help ();
			}
			str++;
		}
		if (last) {
			return !use_stdin ();
		}
		return true;
	}
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
		int i, len;
		ut8 buf[4096];
		len = r_str_binstr2bin (str, buf, sizeof (buf));
		for (i = 0; i < len; i++) {
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
		ut32 *m;
		buf = (ut8 *) malloc (n);
		if (!buf) {
			return false;
		}
		m = (ut32 *) buf;
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
		char buf[80];
		r_num_units (buf, r_num_math (NULL, str));
		printf ("%s\n", buf);
		return true;
	} else if (flags & (1 << 11)) { // -t
		ut32 n = r_num_math (num, str);
		RPrint *p = r_print_new ();
		r_print_date_unix (p, (const ut8 *) &n, sizeof (ut32));
		r_print_free (p);
		return true;
	} else if (flags & (1 << 12)) { // -E
		const int len = strlen (str);
		/* http://stackoverflow.com/questions/4715415/base64-what-is-the-worst-possible-increase-in-space-usage */
		char *out = calloc (sizeof (char), (len + 2) / 3 * 4 + 1); // ceil(len/3)*4 plus 1 for NUL
		if (out) {
			r_base64_encode (out, (const ut8 *) str, len);
			printf ("%s%s", out, nl);
			fflush (stdout);
			free (out);
		}
		return true;
	} else if (flags & (1 << 13)) { // -D
		const int len = strlen (str);
		ut8 *out = calloc (sizeof (ut8), len / 4 * 3 + 1);
		if (out) {
			r_base64_decode (out, str, len);
			printf ("%s%s", out, nl);
			fflush (stdout);
			free (out);
		}
		return true;
	} else if (flags & 1 << 14) { // -F
		char *str = r_stdin_slurp (NULL);
		if (str) {
			char *res = r_hex_from_code (str);
			if (res) {
				printf ("%s\n", res);
				fflush (stdout);
				free (res);
			} else {
				eprintf ("Invalid input.\n");
			}
			free (str);
		}
		return false;
	} else if (flags & (1 << 18)) { // -r
		char *asnum, unit[32];
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
		r_num_units (unit, n);
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

		return true;
	} else if (flags & (1 << 19)) { // -L
		r_print_hex_from_bin (NULL, str);
		return true;
	} else if (flags & (1 << 20)) { // -P
		char *str = r_stdin_slurp (NULL);
		if (str) {
			char *res = r_hex_from_py (str);
			if (res) {
				printf ("%s\n", res);
				fflush (stdout);
				free (res);
			} else {
				eprintf ("Invalid input.\n");
			}
			free (str);
		}
		return false;
	}

	if (r_str_startswith (str, "0x")) {
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
		ut8 *p = (ut8 *) &f;
		sscanf (str, "%f", &f);
		printf ("Fx%02x%02x%02x%02x\n", p[3], p[2], p[1], p[0]);
		return true;
	} else if (r_str_endswith (str, "dt")) {
		out_mode = 'I';
		str[strlen (str) - 2] = 't';
		str[strlen (str) - 1] = '\0';
	}
	while ((p = strchr (str, ' '))) {
		*p = 0;
		format_output (out_mode, str);
		str = p + 1;
	}
	if (*str) {
		format_output (out_mode, str);
	}
	return true;
}

static int use_stdin() {
	char *buf = calloc (1, STDIN_BUFFER_SIZE + 1);
	int l; // , sflag = (flags & 5);
	if (!buf) {
		return 0;
	}
	if (!(flags & 16384)) {
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
			if (!rax (buf, l, 0)) {
				break;
			}
			l = -1;
		}
	} else {
		l = 1;
	}
	if (l > 0) {
		rax (buf, l, 0);
	}
	free (buf);
	return 0;
}

int main(int argc, char **argv) {
	int i;
	num = r_num_new (NULL, NULL, NULL);
	if (argc == 1) {
		use_stdin ();
	} else {
		for (i = 1; i < argc; i++) {
			rax (argv[i], 0, i == argc - 1);
		}
	}
	r_num_free (num);
	return 0;
}
