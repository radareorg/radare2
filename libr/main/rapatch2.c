/* radare - LGPL - Copyright 2024-2025 - pancake */

#define R_LOG_ORIGIN "rapatch2"

#include <r_core.h>
#include <r_main.h>

static int show_help(int v) {
	printf ("Usage: rapatch2 [-p N] [-sv] [-R] [patchfile] ([targetfile])\n");
	if (v) {
		printf (
			"  -p N       patch level, skip N directories\n"
			"  -R         reverse patch\n"
			"  -s         sandbox mode, disable scripts and r2 command execution\n"
			"  -q         be quiet\n"
			"  -v         show version\n"
		       );
	}
	return 1;
}

typedef struct {
	bool sandbox;
	bool quiet;
	bool reverse;
	int level;
	RCore *core;
} RapatchOptions;

static int rapatch_directory(RapatchOptions *ro, const char *patch) {
	char *patchdata = r_file_slurp (patch, NULL);
	if (!patchdata) {
		R_LOG_ERROR ("Cannot open patch file %s", patch);
		return 1;
	}
	if (!r_str_startswith (patchdata, "--- ")) {
		R_LOG_ERROR ("This is not an unified radiff2 patch file");
		return 1;
	}

	bool res = r_core_patch_unified (ro->core, patchdata, ro->level, ro->reverse);
	if (!res) {
		R_LOG_ERROR ("Patch failed");
	}
	free (patchdata);
	return res? 0: 1;
}

static int rapatch_file(RapatchOptions *ro, const char *patch, const char *file) {
	R_LOG_INFO ("Using the old rapatch file format, be careful");
	RIODesc *fd = r_core_file_open (ro->core, file, R_PERM_W, 0);
	if (!fd) {
		R_LOG_ERROR ("Cannot open %s for writing", file);
		return 1;
	}
	ut64 size = r_io_desc_size (fd);
	r_io_map_add (ro->core->io, fd->fd, R_PERM_RW, 0, 0, size);
	if (ro->sandbox) {
		r_config_set_b (ro->core->config, "cfg.sandbox", true);
	}
	if (ro->reverse) {
		R_LOG_TODO ("reverse patch not yet supported");
	}
	if (ro->quiet) {
		R_LOG_TODO ("quiet mode not yet supported");
	}
	if (ro->level) {
		R_LOG_TODO ("patchlevel is ignored when patching files");
	}
	if (!r_core_patch_file (ro->core, patch)) {
		R_LOG_ERROR ("Couldnt patch the file");
	}
	r_core_cmd0 (ro->core, "o");
	R_LOG_INFO ("File %s patched", file);
	r_cons_flush ();
	return 0;
}

R_API int r_main_rapatch2(int argc, const char **argv) {
	RGetopt opt;
	int o;
	RapatchOptions ro = {0};

	r_getopt_init (&opt, argc, argv, "hRvsp:");
	while ((o = r_getopt_next (&opt)) != -1) {
		switch (o) {
		case 'h':
			return show_help (1);
		case 's':
			ro.sandbox = true;
			break;
		case 'p':
			ro.level = atoi (opt.arg);
			if (ro.level < 0) {
				R_LOG_ERROR ("-p only accepts positive values");
				return 1;
			}
			break;
		case 'R':
			ro.reverse = true;
			break;
		case 'v':
			return r_main_version_print ("rapatch2", 0);
		default:
			return show_help (0);
		}
	}

	if (argc < 2 || opt.ind + 1 > argc) {
		return show_help (0);
	}
	const char *patchfile = (opt.ind < argc)? argv[opt.ind]: NULL;
	const char *target = (opt.ind + 1 < argc)? argv[opt.ind + 1]: NULL;

	if (R_STR_ISEMPTY (patchfile)) {
		R_LOG_ERROR ("Missing patchfile");
		return 1;
	}
	ro.core = r_core_new ();
	int rc = 0;
	if (R_STR_ISNOTEMPTY (target)) {
		rc = rapatch_file (&ro, patchfile, target);
	} else {
		rc = rapatch_directory (&ro, patchfile);
	}
	r_core_free (ro.core);
	return rc;
}
