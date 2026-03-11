#include <r_core.h>
#include <r_getopt.h>

static const char *opt_forcebin = NULL;

static void usage() {
	printf (
		"Usage: fuzz_bin <libFuzzer flags> <corpora> -- <flags>\n"
		"\n"
		"libFuzzer flags: show with -help=1\n"
		"\n"
		"Target Flags\n"
		" -F [binfmt]     force to use that bin plugin (ignore header check)\n");
	exit (1);
}

int LLVMFuzzerInitialize(int *lf_argc, char ***lf_argv) {
	r_sys_clearenv ();
	r_sandbox_enable (true);
	r_sandbox_grain (R_SANDBOX_GRAIN_NONE);
	r_log_set_quiet (true);

	int argc = *lf_argc;
	const char **argv = (const char **)(*lf_argv);
	bool has_args = false;
	int i;
	int c;
	for (i = 1; i < argc; i++) {
		argv++;
		if (!strcmp ((*lf_argv)[i], "--")) {
			has_args = true;
			break;
		}
	}
	if (has_args) {
		*lf_argc = i;
		argc -= i;

		RGetopt opt;
		r_getopt_init (&opt, argc, argv, "F:");
		while ((c = r_getopt_next (&opt)) != -1) {
			switch (c) {
			case 'F':
				opt_forcebin = opt.arg;
				break;
			default:
				usage ();
				break;
			}
		}
		if (opt.ind < argc) {
			usage ();
		}
	}
	return 0;
}

int LLVMFuzzerTestOneInput(const ut8 *data, size_t len) {
	if (!len) {
		return 0;
	}
	RCore *core = r_core_new ();
	if (!core) {
		return 0;
	}
	r_core_cmd0 (core, "e cfg.sandbox=true");
	r_core_cmd0 (core, "e scr.interactive=false");
	r_core_cmd0 (core, "e scr.color=0");
	r_core_cmdf (core, "o malloc://%" PFMT64d, (ut64)len);
	r_io_write_at (core->io, 0, data, len);
	if (opt_forcebin) {
		r_core_cmdf (core, "e bin.force=%s", opt_forcebin);
	}
	r_core_cmd0 (core, "oob");
	r_core_cmd0 (core, "iI");
	r_core_cmd0 (core, "iIj");
	r_core_cmd0 (core, "ie");
	r_core_cmd0 (core, "iEj");
	r_core_cmd0 (core, "iS");
	r_core_cmd0 (core, "iSj");
	r_core_cmd0 (core, "ii");
	r_core_cmd0 (core, "iij");
	r_core_cmd0 (core, "is");
	r_core_cmd0 (core, "isj");
	r_core_cmd0 (core, "iz");
	r_core_cmd0 (core, "izj");
	r_core_cmd0 (core, "ir");
	r_core_cmd0 (core, "irj");
	r_core_cmd0 (core, "ic");
	r_core_cmd0 (core, "icj");
	r_core_free (core);
	return 0;
}
