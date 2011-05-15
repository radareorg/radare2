/* stupid source file cipher -- pancake */
/* this is necessary in order to avoid antiviruses detect shellcodes are malware */

#include <stdio.h>
#include <string.h>

static int unshift = 0;

static char shiftchar (char c) {
	if (c>='0'&&c<='9') c=c-'0';
	else if (c>='a'&&c<='f') c=c-'a'+10;
	else if (c>='A'&&c<='F') c=c-'A'+10;
	else return c;
	if (unshift) c = (c==0xf)?0:c+1;
	else c = c?c-1:0xf;
	//if (unshift) c = ((c<<1)&0xf) | ((c&0x80)>>7);
	//else c = (c>>1) | ((c&1)<<7);
	return (c<=9)? c+'0': (c-10)+'a';
}

static int ishexa(char c) {
	if (c>='0'&&c<='9') return 1;
	if (c>='a'&&c<='f') return 1;
	if (c>='A'&&c<='F') return 1;
	return 0;
}

static void parsestr (char *b) {
	char o = 0;
	for (b++; *b; b++) {
		if (o=='\\' && *b=='x')
			for (b++; *b && ishexa (*b); b++)
				*b = shiftchar (*b);
		o = *b;
	}
}

static void parseint (char *b) {
	char o = 0;
	for (b++; *b; b++) {
		if (o=='0' && *b=='x')
			for (b++; *b && ishexa (*b); b++)
				*b = shiftchar (*b);
		o = *b;
	}
}

int main(int argc, char **argv) {
	char buf[2048];
	unshift = argc-1;
	for (;;) {
		fgets (buf, sizeof (buf), stdin);
		if (feof (stdin))
			return 0;
		if (buf[0]=='\t') {
			if (!memcmp (buf+1, "\"\\x", 3))
				parsestr (buf);
			else
			if (!memcmp (buf+1, "0x", 2))
				parseint (buf);
		}
		printf ("%s", buf);
	}
}
