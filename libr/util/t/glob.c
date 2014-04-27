#include <r_util.h>

void chk(const char *s, const char *g, int o) {
	int r = r_str_glob (s, g);
	printf ("%d %d   %s (%s)\n", r, o, s, g);
}

main () {
	chk ("foo.c", "*.c", 1);
	chk ("foo.c", "*.d", 0);
	chk ("foo.c", "foo*", 1);
	chk ("foo.c", "*oo*", 1);
	chk ("foo.c", "*uu*", 0);
	chk ("foo.c", "f*c", 1);
	chk ("foo.c", "f*d", 0);
}
