#include <r_core.h>
#include <r_getopt.h>

#include "fuzz_common.h"

static const char *opt_forcebin = NULL;
static const char *analysis_arches[] = {
	"x86", "arm", "mips", "ppc", "riscv", "sparc", "sh"
};
static const int analysis_bits[] = { 16, 32, 64 };

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
	RFuzzInput input;
	size_t i;
	if (!len) {
		return 0;
	}
	rfuzz_input_init (&input, data, len);

	RCore *core = r_core_new ();
	if (!core) {
		return 0;
	}
	r_core_cmd0 (core, "e cfg.sandbox=true");
	r_core_cmd0 (core, "e scr.interactive=false");
	r_core_cmd0 (core, "e scr.color=0");
	r_core_cmd0 (core, "e anal.jmptbl=false");
	r_core_cmdf (core, "o malloc://%" PFMT64d, (ut64)len);
	r_io_write_at (core->io, 0, data, len);
	r_core_cmd0 (core, "oob");
	if (opt_forcebin) {
		r_core_cmdf (core, "e bin.force=%s", opt_forcebin);
	}
	for (i = 0; i < 3; i++) {
		const char *arch = analysis_arches[(rfuzz_consume_u8 (&input) + i)
			% (sizeof (analysis_arches) / sizeof (analysis_arches[0]))];
		int bits = analysis_bits[(rfuzz_consume_u8 (&input) + i)
			% (sizeof (analysis_bits) / sizeof (analysis_bits[0]))];
		r_core_cmdf (core, "-a %s", arch);
		r_core_cmdf (core, "-b %d", bits);
		r_core_cmdf (core, "e cfg.bigendian=%d", rfuzz_consume_bool (&input)? 1: 0);
		r_core_cmd0 (core, "af-*");
		r_core_cmd0 (core, "s 0");
		r_core_cmd0 (core, "ao 32");
		r_core_cmd0 (core, "pd 16");
		r_core_cmd0 (core, "aa");
		r_core_cmd0 (core, "af");
	}
	r_core_free (core);
	return 0;
}
