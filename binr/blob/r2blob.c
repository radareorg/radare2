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
#if __WINDOWS__
		eprintf ("Error: %s must be renamed to act as the desired radare2 program.\n"
		" targets: r2 r2pm rax2 radiff2 rafind2 rarun2 rasm2 ragg2 rabin2 radare2 rabin2\n"
		" cmd> copy %s radare2.exe\n", prog_name);
#else
		eprintf ("Error: %s must be renamed or symlinked to act as the desired command\n"
		" targets: r2 r2pm rax2 radiff2 rafind2 rarun2 rasm2 ragg2 rabin2 radare2 rabin2\n"
		" ln -fs r2blob r2       ; ./r2 -h\n"
		" ln -fs r2blob rasm2    ; ./rasm2 -h\n"
		" ln -fs r2blob rabin2   ; ./rabin2 -h\n", prog_name);
#endif
	}
	return rc;
}
