/* radare - LGPL - Copyright 2024 - pancake */

#define R_LOG_ORIGIN "rapatch2"

#include <r_core.h>
#include <r_main.h>

static int show_help(int v) {
	printf ("Usage: rapatch2 [-p N] [-sv] [-R] [origfile] ([patchfile])\n");
	if (v) {
		printf (
			"  -p N       patch level, skip N directories\n"
			"  -R         reverse patch\n"
			"  -s         be silent\n"
			"  -v         show version\n"
		       );
	}
	return 1;
}

R_API int r_main_rapatch2(int argc, const char **argv) {
	RGetopt opt;
	int o;

	bool reverse = false;
	bool silent = false;
	int patchlevel = 0;

	r_getopt_init (&opt, argc, argv, "hRvsp:");
	while ((o = r_getopt_next (&opt)) != -1) {
		switch (o) {
		case 'h':
			return show_help (1);
		case 's':
			silent = true;
			break;
		case 'p':
			patchlevel = atoi (opt.arg);
			break;
		case 'R':
			reverse = true;
			break;
		case 'v':
			return r_main_version_print ("rapatch2", 0);
		default:
			return show_help (0);
		}
	}

	if (argc < 3 || opt.ind + 2 > argc) {
		return show_help (0);
	}
	const char *file = (opt.ind < argc)? argv[opt.ind]: NULL;
	const char *patchfile = (opt.ind + 1 < argc)? argv[opt.ind + 1]: NULL;

	if (R_STR_ISEMPTY (file) || R_STR_ISEMPTY (patchfile)) {
		R_LOG_ERROR ("Cannot open empty path");
		return 1;
	}
	if (reverse) {
		R_LOG_TODO ("reverse patch not yet supported");
	}
	if (silent) {
		R_LOG_TODO ("silent not yet supported");
	}
	if (patchlevel) {
		R_LOG_TODO ("patchlevel not yet supported");
	}
	const char *r2argv[5] = {
		"radare2",
		"-qwP",
		patchfile,
		file,
		NULL
	};
	r_main_radare2 (5, r2argv);

	return 0;
}
