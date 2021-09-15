/* radare - LGPL - Copyright 2009-2020 - pancake */
#include <r_main.h>
#include <r_core.h>

struct rasignconf {
	const char *ofile, *space;
	size_t a_cnt;
	bool ar, rad, quiet, json, flirt, collision;
};

static void rasign_show_help(void) {
	printf ("Usage: rasign2 [options] [file]\n"
		" -a [-a]          add extra 'a' to analysis command\n"
		" -A               make signatures from all .o files in the provided .a file\n"
		" -f               interpret the file as a FLIRT .sig file and dump signatures\n"
		" -h               help menu\n"
		" -j               show signatures in json\n"
		" -o sigs.sdb      add signatures to file, create if it does not exist\n"
		" -q               quiet mode\n"
		" -r               show output in radare commands\n"
		" -s signspace     save all signatures under this signspace\n"
		" -c               add collision signatures before writing file\n"
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

static int signs_from_file(const char *fname, struct rasignconf *conf) {
	RCore *core = opencore (fname);
	if (!core) {
		eprintf ("Could not get core\n");
		return -1;
	}

	// quiet mode
	if (conf->quiet) {
		r_config_set (core->config, "scr.prompt", "false");
		r_config_set_i (core->config, "scr.color", COLOR_MODE_DISABLED);
	}

	if (conf->space) {
		r_spaces_set (&core->anal->zign_spaces, conf->space);
	}

	// run analysis to find functions
	find_functions (core, conf->a_cnt);

	// create zignatures
	r_sign_all_functions (core->anal);

	if (conf->collision) {
		r_sign_resolve_collisions (core->anal);
	}

	if (conf->rad) {
		r_sign_list (core->anal, '*');
	}

	if (conf->json) {
		r_sign_list (core->anal, 'j');
	}

	// write sigs to file
	if (conf->ofile && !r_sign_save (core->anal, conf->ofile)) {
		eprintf ("Failed to write file\n");
	}

	r_cons_flush ();
	r_core_free (core);
	return 0;
}

static RList *get_ar_file_uris(const char *fname) {
	r_return_val_if_fail (fname, NULL);
	RIO *io = r_io_new ();
	// core is only used to to list uri's in archive, then it's free'd
	if (!io) {
		eprintf ("Failed to alloc io\n");
		return NULL;
	}

	char *allfiles = r_str_newf ("arall://%s", fname);
	if (!allfiles) {
		eprintf ("Failed to alloc\n");
		r_io_free (io);
		return NULL;
	}
	RList *uris = r_list_newf (free);
	RList *list_fds = r_io_open_many (io, allfiles, 0, 0444);
	free (allfiles);

	bool fail = false;
	if (list_fds && uris) {
		RIODesc *fd;
		RListIter *iter;
		r_list_foreach (list_fds, iter, fd) {
			char *u = strdup (fd->uri);
			if (!u) {
				fail = true;
				break;
			}
			r_list_append (uris, u);
		}
	}
	r_list_free (list_fds);
	r_io_free (io);
	if (fail) {
		r_list_free (uris);
		uris = NULL;
	}
	return uris;
}

static int dump_flirt(const char *ifile) {
	RCore *core = opencore (NULL);
	r_sign_flirt_dump (core->anal, ifile);
	r_cons_flush ();
	r_core_free (core);
	return 0;
}

static int handle_archive_files(const char *fname, struct rasignconf *conf) {
	RList *uris = get_ar_file_uris (fname);
	if (!uris) {
		return -1;
	}

	bool collision = false;
	if (conf->collision && conf->ofile) {
		collision = true;
	}
	conf->collision = false;

	RListIter *iter;
	char *u;
	int ret = 0;
	r_list_foreach (uris, iter, u) {
		if (r_str_endswith (u, ".o")) {
			eprintf ("\nProcessing %s...\n", u);
			int err = signs_from_file (u, conf);
			if (err) {
				ret = err;
			}
		} else {
			eprintf ("[!!] skipping %s because it is not a .o file\n", u);
		}
	}
	r_list_free (uris);

	if (collision) {
		eprintf ("Computing collisions on sdb file\n");
		RAnal *anal = r_anal_new ();
		if (anal) {
			r_sign_load (anal, conf->ofile);
			r_sign_resolve_collisions (anal);
			int tmpret = r_sign_save (anal, conf->ofile);
			r_anal_free (anal);
			if (!ret && tmpret) {
				ret = tmpret;
			}
		}
	}

	return ret;
}

R_API int r_main_rasign2(int argc, const char **argv) {
	int c;
	RGetopt opt;
	struct rasignconf conf;
	memset (&conf, 0, sizeof (struct rasignconf));

	r_getopt_init (&opt, argc, argv, "Aafhjo:qrs:cv");
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'A':
			conf.ar = true;
			break;
		case 'a':
			conf.a_cnt++;
			break;
		case 'o':
			conf.ofile = opt.arg;
			break;
		case 'c':
			conf.collision = true;
			break;
		case 's':
			conf.space = opt.arg;
			break;
		case 'r':
			conf.rad = true;
			break;
		case 'j':
			conf.json = true;
			break;
		case 'q':
			conf.quiet = true;
			break;
		case 'f':
			conf.flirt = true;
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

	if (conf.a_cnt > 2) {
		eprintf ("Invalid analysis (too many -a's?)\n");
		rasign_show_help ();
		return -1;
	}

	if (opt.ind >= argc) {
		eprintf ("must provide a file\n");
		rasign_show_help ();
		return -1;
	}

	const char *ifile = argv[opt.ind];
	if (conf.flirt) {
		if (conf.rad || conf.ofile || conf.json) {
			eprintf ("Only FLIRT output is supported for FLIRT files\n");
			return -1;
		}
		return dump_flirt (ifile);
	} else if (conf.ar) {
		if (conf.json) {
			eprintf ("JSON does not work with .a files currently\n");
			return -1;
		} else if (conf.collision && conf.rad) {
			eprintf ("Rasign2 can not currently handle .a files with -c and -r\n");
			return -1;
		} else {
			return handle_archive_files (ifile, &conf);
		}
	} else {
		return signs_from_file (ifile, &conf);
	}
}
