/* radare - LGPL - Copyright 2009-2020 - pancake */
#include <stdio.h>
#include <string.h>
#include <r_getopt.h>
#include <r_main.h>
#include <r_sign.h>
#include <r_core.h>

#include "r_userconf.h"

static int rasign_show_help() {
	printf ("Usage: rasign2 [options] [file]\n"
		" -a [-a]          add extra 'a' to analysis command\n"
		" -o sigs.sdb      add signatures to file, create if it does not exist\n"
		" -r               show output in radare commands\n"
		"Examples:\n"
		"  rasign2 -o libc.sdb libc.so.6\n");
	return 0;
}

static RCore *opencore(const char *fname) {
	RCore *c = r_core_new ();
	if (!c) {
		eprintf ("Count not get core\n");
		return NULL;
	}
	r_core_loadlibs (c, R_CORE_LOADLIBS_ALL, NULL);
	r_config_set_i (c->config, "scr.interactive", false);
	if (fname) {
#if __WINDOWS__
		fname = r_acp_to_utf8 (fname);
#endif
		if (!r_core_file_open (c, fname, 0, 0)) {
			eprintf ("Could not open file %s\n", fname);
			r_core_free (c);
			return NULL;
		}
		(void)r_core_bin_load (c, NULL, UT64_MAX);
		(void)r_core_bin_update_arch_bits (c);
		r_cons_flush ();
	}
	return c;
}

static int find_functions(RCore *core, size_t count) {
	const char *cmd = NULL;
	switch (count) {
	case 0: cmd = "aa"; break;
	case 1: cmd = "aaa"; break;
	case 2: cmd = "aaaa"; break;
	default:
		eprintf ("Invalid analysis (too many -a's?)\n");
		rasign_show_help ();
		return -1;
	}
	r_core_cmd0 (core, cmd);
	return 0;
}

R_API int r_main_rasign2(int argc, const char **argv) {
	const char *ofile = NULL;
	int c;
	size_t a_cnt = 0;
	bool rad = false;
	RGetopt opt;

	r_getopt_init (&opt, argc, argv, "ao:rvh");
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'a':
			a_cnt++;
			break;
		case 'o':
			ofile = opt.arg;
			break;
		case 'r':
			rad = true;
			break;
		case 'v':
			return r_main_version_print ("rasign2");
		default:
			return rasign_show_help ();
		}
	}

	const char *ifile = NULL;
	if ( opt.ind >= argc ) {
		eprintf("must provide a file\n");
		return rasign_show_help ();
	}
	ifile = argv[opt.ind];

	// get the core
	RCore *core = opencore (ifile);
	if (!core) {
	  return -1;
	}

	// run analysis to find functions
	if (find_functions (core, a_cnt)) {
		r_core_free (core);
		return -1;
	}

	// create zignatures
	r_core_cmd0 (core, "zg");

	// write sigs to file
	if (ofile) {
		r_core_cmdf (core, "\"zos %s\"", ofile);
	}

	if (rad) {
		r_core_flush (core, "z*");
	}

	r_core_free (core);
	return 0;
}
