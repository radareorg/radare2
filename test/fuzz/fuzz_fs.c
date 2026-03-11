#include <r_core.h>
#include <r_getopt.h>

#include "fuzz_common.h"

static const char *opt_forcebin = NULL;
static const char *fs_plugins[] = {
	"zip", "cpio", "tar", "fat", "ext2", "iso9660", "squashfs", "udf"
};

static void usage() {
	printf (
		"Usage: fuzz_bin <libFuzzer flags> <corpora> -- <flags>\n"
		"\n"
		"libFuzzer flags: show with -help=1\n");
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
	RFuzzInput input;
	ut8 selector;
	const char *plugin;
	if (!len) {
		return 0;
	}
	rfuzz_input_init (&input, data, len);
	selector = rfuzz_consume_u8 (&input);
	plugin = fs_plugins[selector % (sizeof (fs_plugins) / sizeof (fs_plugins[0]))];

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
	r_core_cmd0 (core, "s 0");
	r_core_cmd0 (core, "mL");
	r_core_cmdf (core, "m /mnt %s 0", plugin);
	r_core_cmd0 (core, "md /mnt");
	r_core_cmd0 (core, "mdd /mnt");
	r_core_cmd0 (core, "mn /mnt");
	r_core_cmd0 (core, "m-/mnt");
	r_core_cmd0 (core, "m /auto");
	r_core_cmd0 (core, "md /auto");
	r_core_cmd0 (core, "mn /auto");
	r_core_cmd0 (core, "m-/auto");
	r_core_free (core);
	return 0;
}
