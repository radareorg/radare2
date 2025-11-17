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
	" -F [binfmt]     force to use that bin plugin (ignore header check)\n"
	);
	exit (1);
}

int LLVMFuzzerInitialize(int *lf_argc, char ***lf_argv) {
	r_sys_clearenv ();
	// r_sandbox_enable (true);
	// r_sandbox_grain (R_SANDBOX_GRAIN_NONE);
	r_log_set_quiet (true);

	int argc = *lf_argc;
	const char **argv = (const char **)(*lf_argv);
	bool has_args = false;
	int i, c;
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
				usage();
				break;
			}
		}

		if (opt.ind < argc) {
			usage();
		}
	}

	return 0;
}

int LLVMFuzzerTestOneInput(const ut8 *data, size_t len) {
	RCore *core = r_core_new ();
	if (len == 0) {
		eprintf ("Empty input. Doing nothing\n");
		return 1;
	}
	r_core_cmdf (core, "-e log.level=0");
	r_core_cmdf (core, "o malloc://%"PFMT64d, (ut64)len);
	r_io_write_at (core->io, 0, data, len);
	r_core_cmd0 (core, "oob");
	char *archs = r_core_cmd_str (core, "-a?");
	RList *larchs = r_str_split_list (archs, "\n", -1);
	RListIter *iter;
	char *arch;
	r_list_foreach (larchs, iter, arch) {
		r_core_cmdf (core, "-a %s", arch);
		r_core_cmd0 (core, "af-*");
		r_core_cmd0 (core, "aa");
	}
	r_list_free (larchs);
	// setup a random arch+bits
	// run analysis
	r_core_free (core);
	return 0;
}
