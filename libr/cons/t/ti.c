#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <curses.h>

static char buf[1024];

static void strcatch (char *b, char c) {
	char *e = b + strlen (b);
	*e++ = c;
	*e = 0;
}

static const char *str (char* p) {
	buf[0] = 0;
	if (p) {
		while (*p) {
			char c = *p++;
			switch (c) {
			case 0x1b:
				strcat (buf, "\\e");
				break;
			case '\t':
				strcat (buf, "\\t");
				break;
			case '\n':
				strcat (buf, "\\n");
				break;
			default:
				strcatch (buf, c);
			}
		}
	}
	return buf;
}

int main() {
	system ("echo \"TERM  = $TERM\"");
	setupterm (NULL, 1, NULL);
	printf ("cup   = %s\n", str (tigetstr ("cup")));
	printf ("smcup = %s\n", str (tigetstr ("smcup")));
	printf ("rmcup = %s\n", str (tigetstr ("rmcup")));
	return 0;
}
