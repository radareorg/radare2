/* radare - LGPL - Copyright 2012-2020 - pancake */

#include <r_main.h>
#include <r_util.h>

int main(int argc, char **argv) {
	int rc = 1;
	const char *prog_name = r_file_basename (argv[0]);
	RMain *m = r_main_new (prog_name);
	if (m) {
		rc = r_main_run (m, argc, argv);
		r_main_free (m);
	}
	return rc;
}
