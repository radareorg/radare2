/* radare - LGPL - Copyright 2012-2021 - pancake */

#include <r_main.h>
#include <r_util.h>

int main(int argc, const char **argv) {
	int rc = 1;
	const char *prog_name = r_file_basename (argv[0]);
	RMain *m = r_main_new (prog_name);
	if (m) {
		rc = r_main_run (m, argc, argv);
		r_main_free (m);
	} else {
		eprintf ("Error: r2blob must be renamed or accesed from a symlink:\n"
		" ln -fs r2blob r2       ; ./r2 -h\n"
		" ln -fs r2blob rasm2    ; ./rasm2 -h\n"
		" ln -fs r2blob rabin2   ; ./rabin2 -h\n");
	}
	return rc;
}
