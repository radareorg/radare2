#include <stdio.h>
#include "disasm.c"

int main() {
	int i, len;
	unsigned char buf[32];
	char str[1024];
	for (i=0; i<255; i++) {
		buf[0] = i;
		len = Disassemble (0, buf, str, sizeof (str));
		printf ("%d  %02x%02x%02x --> %s\n", len, buf[0], buf[1], buf[2], str);
	}
	return 0;
}
