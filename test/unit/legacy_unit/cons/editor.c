#include <r_cons.h>

int main(int argc, char **argv) {
	r_cons_editor (r_cons_singleton (), argc > 1? argv[1]: NULL, NULL, NULL);
	return 0;
}
