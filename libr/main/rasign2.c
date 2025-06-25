/* radare - LGPL - Copyright 2009-2025 - pancake, DennisGoodlett */

#define R_LOG_ORIGIN "rasign2"

#include <r_main.h>
#include <r_core.h>

typedef struct {
	const char *ofile;
	const char *space;
	const char *script;
	size_t a_cnt;
	bool merge, sdb, ar, rad, quiet, json, flirt, collision, show_version;
} RasignOptions;

static void rasign_show_help(void) {
	printf ("Usage: rasign2 [options] [file]\n"
		" -a               make signatures from all .o files in the provided .a file\n"
		" -A[AAA]          same as r2 -A, the more 'A's the more analysis is performed\n"
		" -f               interpret the file as a FLIRT .sig file and dump signatures\n"
		" -h               help menu\n"
		" -j               show signatures in json\n"
		" -i script.r2     execute this script in the \n"
		" -o sigs.sdb      add signatures to file, create if it does not exist\n"
		" -q               quiet mode\n"
		" -r               show output in radare commands\n"
		" -S               perform operation on sdb signature file ('-o -' to save to same file)\n"
		" -s signspace     save all signatures under this signspace\n"
		" -c               add collision signatures before writing file\n"
		" -v               show version information\n"
		" -m               merge/overwrite signatures with same name\n"
		"Examples:\n"
		"  rasign2 -o libc.sdb libc.so.6\n");
}

static RCore *opencore(const char *fname) {
	RIODesc * rfile = NULL;
	RCore *c = r_core_new ();
	if (!c) {
		R_LOG_ERROR ("Count not get core");
		return NULL;
	}
	r_core_loadlibs (c, R_CORE_LOADLIBS_ALL, NULL);
	r_config_set_b (c->config, "scr.interactive", false);
	if (fname) {
#if R2__WINDOWS__
		char *winf = r_acp_to_utf8 (fname);
		rfile = r_core_file_open (c, winf, 0, 0);
		free (winf);
#else
		rfile = r_core_file_open (c, fname, 0, 0);
#endif

		if (!rfile) {
			R_LOG_ERROR ("Could not open file %s", fname);
			r_core_free (c);
			return NULL;
		}
		(void)r_core_bin_load (c, NULL, UT64_MAX);
		(void)r_core_bin_update_arch_bits (c);
		r_cons_flush (c->cons);
	}
	return c;
}

static void find_functions(RCore *core, size_t count) {
	const char *cmd = NULL;
	switch (count) {
	case 0: cmd = "aa"; break;
	case 1: cmd = "aaa"; break;
	case 2: cmd = "aaaa"; break;
	case 3: cmd = "aaaaa"; break;
	}
	r_core_cmd0 (core, cmd);
}

static int inline output(RCore *core, RasignOptions *conf) {
	RAnal *anal = core->anal;
	if (conf->collision) {
		r_sign_resolve_collisions (anal);
	}
	ut64 oaddr = core->addr; // R2_600 - r_sign_list should take addr as arg
	core->addr = UT64_MAX;
	if (conf->rad) {
		r_sign_list (anal, '*');
	}
	if (conf->json) {
		r_sign_list (anal, 'j');
	}
	core->addr = oaddr;
	// write sigs to file
	if (conf->ofile && !r_sign_save (anal, conf->ofile)) {
		R_LOG_ERROR ("Failed to write file");
		return -1;
	}
	r_cons_flush (core->cons);
	return 0;
}

static int handle_sdb(const char *fname, RasignOptions *conf) {
	int ret = -1;
	// can't use RAnal here because JSON output requires core, in a sneaky way
	RCore *core = r_core_new ();
	if (!core) {
		return -1;
	}
	r_config_set_b (core->config, "scr.interactive", false);
	if (conf->ofile && r_file_exists (conf->ofile)) {
		r_sign_load (core->anal, conf->ofile, true);
	}
	if (r_sign_load (core->anal, fname, conf->merge)) {
		if (conf->collision) {
			r_sign_resolve_collisions (core->anal);
		}
		ret = output (core, conf);
	}
	r_core_free (core);
	return ret;
}

static int signs_from_file(const char *fname, RasignOptions *conf) {
	RCore *core = opencore (fname);
	if (!core) {
		R_LOG_ERROR ("Could not get core");
		return -1;
	}
	if (conf->quiet) {
		r_config_set_b (core->config, "scr.prompt", false);
		r_config_set_i (core->config, "scr.color", COLOR_MODE_DISABLED);
	}
	if (conf->space) {
		r_spaces_set (&core->anal->zign_spaces, conf->space);
	}
	if (conf->ofile) {
		if (r_file_exists (conf->ofile)) {
			r_sign_load (core->anal, conf->ofile, true);
		} else {
			R_LOG_ERROR ("Cannot load signature file %s", conf->ofile);
		}
	}
	if (conf->script) {
		r_core_run_script (core, conf->script);
	}
	// run analysis to find functions
	find_functions (core, conf->a_cnt);
	// create zignatures
	r_sign_all_functions (core->anal, conf->merge);

	int ret = output (core, conf);
	r_core_free (core);
	return ret;
}

static RList *get_ar_file_uris(const char *fname) {
	R_RETURN_VAL_IF_FAIL (fname, NULL);
	RIO *io = r_io_new ();
	// core is only used to to list uri's in archive, then it's free'd
	if (!io) {
		R_LOG_ERROR ("Failed to alloc io");
		return NULL;
	}

	char *allfiles = r_str_newf ("arall://%s", fname);
	if (!allfiles) {
		R_LOG_ERROR ("Failed to alloc");
		r_io_free (io);
		return NULL;
	}
	RList *uris = r_list_newf (free);
	RList *list_fds = r_io_open_many (io, allfiles, 0, 0);
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
	r_cons_flush (core->cons);
	r_core_free (core);
	return 0;
}

static int handle_archive_files(const char *fname, RasignOptions *conf) {
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
			R_LOG_WARN ("[!!] skipping %s because it is not a .o file", u);
		}
	}
	r_list_free (uris);

	if (collision) {
		R_LOG_INFO ("Computing collisions on sdb file");
		RAnal *anal = r_anal_new ();
		if (anal) {
			r_sign_load (anal, conf->ofile, true);
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
	RasignOptions conf = {0};

	r_getopt_init (&opt, argc, argv, "Aafhjmo:qrSs:cvi:");
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'a':
			conf.ar = true;
			break;
		case 'i':
			conf.script = opt.arg;
			break;
		case 'A':
			conf.a_cnt++;
			break;
		case 'o':
			conf.ofile = opt.arg;
			break;
		case 'c':
			conf.collision = true;
			break;
		case 'S':
			conf.sdb = true;
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
		case 'm':
			conf.merge = true;
			break;
		case 'q':
			conf.quiet = true;
			break;
		case 'f':
			conf.flirt = true;
			break;
		case 'v':
			conf.show_version = true;
			break;
		case 'h':
			rasign_show_help ();
			return 0;
		default:
			rasign_show_help ();
			return -1;
		}
	}
	if (conf.show_version) {
		int mode = conf.quiet? 'q': 0;
		return r_main_version_print ("rasign2", mode);
	}

	if (conf.a_cnt > 2) {
		R_LOG_ERROR ("Invalid analysis (too many -a's?)");
		rasign_show_help ();
		return -1;
	}

	if (opt.ind >= argc) {
		R_LOG_ERROR ("You must provide a file");
		rasign_show_help ();
		return -1;
	}

	const char *ifile = argv[opt.ind];
	if (conf.flirt) {
		if (conf.rad || conf.ofile || conf.json) {
			R_LOG_ERROR ("Only FLIRT output is supported for FLIRT files");
			return -1;
		}
		if (conf.sdb) {
			R_LOG_ERROR ("Can't use -S with -f");
			return -1;
		}
		return dump_flirt (ifile);
	} else if (conf.ar) {
		if (conf.json) {
			R_LOG_ERROR ("JSON does not work with .a files currently");
			return -1;
		}
		if (conf.collision && conf.rad) {
			R_LOG_ERROR ("Rasign2 can not currently handle .a files with -c and -r");
			return -1;
		}
		if (conf.sdb) {
			R_LOG_ERROR ("Can't use -S with -A");
			return -1;
		}
		return handle_archive_files (ifile, &conf);
	} else if (conf.sdb) {
		if (conf.a_cnt > 0) {
			R_LOG_ERROR ("Option -a invalid with -S");
			return -1;
		}
		if (conf.ofile && !strcmp (conf.ofile, "-")) {
			if (!conf.collision) {
				R_LOG_ERROR ("Option '-So -' is only useful with '-c'");
				return -1;
			}
			conf.ofile = ifile;
		}
		return handle_sdb (ifile, &conf);
	} else {
		return signs_from_file (ifile, &conf);
	}
}
