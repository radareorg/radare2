/* radare - LGPL - Copyright 2009-2020 - pancake */
#include <r_main.h>
#include <r_core.h>

static void rasign_show_help(void) {
	printf ("Usage: rasign2 [options] [file]\n"
		" -a [-a]          add extra 'a' to analysis command\n"
		" -f               interpret the file as a FLIRT .sig file and dump signatures\n"
		" -h               help menu\n"
		" -j               show signatures in json\n"
		" -o sigs.sdb      add signatures to file, create if it does not exist\n"
		" -q               quiet mode\n"
		" -r               show output in radare commands\n"
		" -s signspace     save all signatures under this signspace\n"
		" -v               show version information\n"
		"Examples:\n"
		"  rasign2 -o libc.sdb libc.so.6\n");
}

static RCore *opencore(const char *fname) {
	RIODesc * rfile = NULL;
	RCore *c = r_core_new ();
	if (!c) {
		eprintf ("Count not get core\n");
		return NULL;
	}
	r_core_loadlibs (c, R_CORE_LOADLIBS_ALL, NULL);
	r_config_set_i (c->config, "scr.interactive", false);
	if (fname) {
#if __WINDOWS__
		char *winf = r_acp_to_utf8 (fname);
		rfile = r_core_file_open (c, winf, 0, 0);
		free (winf);
#else
		rfile = r_core_file_open (c, fname, 0, 0);
#endif

		if (!rfile) {
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

static void find_functions(RCore *core, size_t count) {
	const char *cmd = NULL;
	switch (count) {
	case 0: cmd = "aa"; break;
	case 1: cmd = "aaa"; break;
	case 2: cmd = "aaaa"; break;
	}
	r_core_cmd0 (core, cmd);
}

R_API int r_main_rasign2(int argc, const char **argv) {
	const char *ofile = NULL;
	const char *space = NULL;
	int c;
	size_t a_cnt = 0;
	bool rad = false;
	bool quiet = false;
	bool json = false;
	bool flirt = false;
	RGetopt opt;

	r_getopt_init (&opt, argc, argv, "afhjo:qrs:v");
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'a':
			a_cnt++;
			break;
		case 'o':
			ofile = opt.arg;
			break;
		case 's':
			space = opt.arg;
			break;
		case 'r':
			rad = true;
			break;
		case 'j':
			json = true;
			break;
		case 'q':
			quiet = true;
			break;
		case 'f':
			flirt = true;
			break;
		case 'v':
			return r_main_version_print ("rasign2");
		case 'h':
			rasign_show_help ();
			return 0;
		default:
			rasign_show_help ();
			return -1;
		}
	}

	if (a_cnt > 2) {
		eprintf ("Invalid analysis (too many -a's?)\n");
		rasign_show_help ();
		return -1;
	}

	const char *ifile = NULL;
	if (opt.ind >= argc) {
		eprintf ("must provide a file\n");
		rasign_show_help ();
		return -1;
	}
	ifile = argv[opt.ind];

	RCore *core = NULL;
	if (flirt) {
		if (rad || ofile || json) {
			eprintf ("Only FLIRT output is supported for FLIRT files\n");
			return -1;
		}
		core = opencore (NULL);
		r_sign_flirt_dump (core->anal, ifile);
		r_cons_flush ();
		r_core_free (core);
		return 0;
	} else {
		core = opencore (ifile);
	}

	if (!core) {
		eprintf ("Could not get core\n");
		return -1;
	}

	// quiet mode
	if (quiet) {
		r_config_set (core->config, "scr.interactive", "false");
		r_config_set (core->config, "scr.prompt", "false");
		r_config_set_i (core->config, "scr.color", COLOR_MODE_DISABLED);
	}

	if (space) {
		r_spaces_set (&core->anal->zign_spaces, space);
	}

	// run analysis to find functions
	find_functions (core, a_cnt);

	// create zignatures
	r_core_cmd0 (core, "zg");

	// write sigs to file
	if (ofile) {
		r_core_cmdf (core, "\"zos %s\"", ofile);
	}

	if (rad) {
		r_core_flush (core, "z*");
	}

	if (json) {
		r_core_flush (core, "zj");
	}

	r_core_free (core);
	return 0;
}
