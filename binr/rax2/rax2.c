/* radare - LGPL - Copyright 2007-2010 pancake<nopcode.org> */

#include <r_util.h>

int flags = 0;

int format_output (char mode, ut64 n) {
	char *str = (char*) &n;

	if (flags & 2) r_mem_copyendian ((ut8*) str, (ut8*) str, 4, 0);
	switch (mode){
	case 'I':
		printf ("%"PFMT64d"\n", n);
		break;
	case '0':
		printf ("0x%"PFMT64x"\n", n);
		break;
	case 'F':
		printf ("%ff\n", (float)(ut32)n);
		break;
	case 'B':
		if (!n)
			printf ("0b\n");
		else {
			str = malloc (sizeof(ut64));
			r_num_to_bits (str, n);
			printf ("%sb\n", str);
			free (str);
		}
		break;
	case 'O':
		printf ("%"PFMT64o"\n", n);
		break;
	}
	return R_TRUE;
}

static int rax (char *str) {
	ut64 n;
	float f;
	char *buf, out_mode = '0';

	if (flags & 1) {
		n = (strlen (str)) >> 4;
		buf = malloc (sizeof (char) * n);
		memset (buf, '\0', n);
		n = r_hex_str2bin (str, (ut8*)buf);
		printf ("%s\n", buf);
		free (buf);
		return R_TRUE;
	}
	if (!strcmp (str, "-e")) {
		flags ^= 2;
		return R_TRUE;
	}
	if (*str=='q') return R_FALSE;
	else if (*str=='h' || *str=='?') {
		printf(
		" int   ->  hex           ;  rax 10\n"
		" hex   ->  int           ;  rax 0xa\n"
		" -int  ->  hex           ;  rax -77\n"
		" -hex  ->  int           ;  rax 0xffffffb3\n"
		" float ->  hex           ;  rax 3.33f\n"
		" hex   ->  float         ;  rax Fx40551ed8\n"
		" oct   ->  hex           ;  rax 35o\n"
		" hex   ->  oct           ;  rax Ox12 (O is a letter)\n"
		" bin   ->  hex           ;  rax 1100011b\n"
		" hex   ->  bin           ;  rax Bx63\n"
		" -e    swap endianness   ;  rax -e 0x33\n"
		" -s    swap hex to bin   ;  rax -s 43 4a 50\n"
		" -     read data from stdin until eof\n");
		return R_TRUE;
	} else if (str[0]=='0' && str[1]=='x') {
		out_mode='I';
	} else if (str[0]=='F' && str[1]=='x') {
		out_mode = 'F';
		str[0] = '0';
	} else if (str[0]=='B' && str[1]=='x') {
		out_mode = 'B';
		str[0] = '0';
	} else if (str[0]=='O' && str[1]=='x') {
		out_mode = 'O';
		str[0] = '0';
	//TODO: Move print into format_output
	} else if (str[strlen(str)-1]=='f') {
		unsigned char *p = (unsigned char *)&f;
		sscanf(str, "%f", &f);
		printf("Fx%02x%02x%02x%02x\n", p[0], p[1], p[2], p[3]);
		return R_TRUE;
	}
	n = r_num_math (NULL, str);
	return format_output (out_mode, n);
}

int use_stdin () {
	char buf[1024];

	while (!feof (stdin)) {
		fgets (buf, sizeof (buf)-1, stdin);
		if (feof (stdin)) break;
		buf[strlen (buf)-1] = '\0';
		if (!rax (buf)) break;
	}
	return 0;
}

int main (int argc, char **argv) {
	int i=1;

	if (argc == 1)
		return use_stdin ();

	//XXX: Use a better way to parse. Maybe getopt??
	for (i=1;i<argc;i++) {
		if (argv[i][0]=='-') {
			if (argv[i][1]=='\0') {
				if (i==argc-1) return use_stdin ();
				else break;
			}
			switch (argv[i][1]) {
			case 's':
				flags |= 1;
				break;
			case 'e':
				flags |= 2;
				break;
			case 'h':
				printf ("Usage: rax2 [-hV] [expression]\n");
				return 0;
			case 'V':
				printf ("rax2 v"R2_VERSION"\n");
				return 0;
			}
		} else break;
	}

	for (;i<argc; i++)
		rax (argv[i]);
	return 0;
}
