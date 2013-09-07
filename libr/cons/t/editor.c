#include <r_cons.h>

int main(int argc, char **argv) {
	r_cons_editor (argc>1?argv[1]:NULL);
	return 0;
}
