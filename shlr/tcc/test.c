#include "libr_tcc.h"

int main(int argc, char **argv) {
	TCCState *T = tcc_new ();
	//T->nostdlib = 1;
//	tcc_set_output_type(T, TCC_OUTPUT_MEMORY); //PREPROCESS);
	//tcc_output_file (T, "test.cpp");
	const char *file = argc>1? argv[1]: "test.cparse";
	if (tcc_add_file (T, file) == -1) {
		printf ("Cannot parse file\n");
		return 1;
	}

	tcc_compile_string (T,
		"int foo = 3;"
		"int bar = 10;");
	tcc_delete (T);
}
