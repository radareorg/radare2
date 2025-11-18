#include <r_bin.h>
#include <r_getopt.h>
#include <r_io.h>
#include <r_types.h>
#include <r_util/r_buf.h>
#include <r_util/r_log.h>
#include <r_util/r_sys.h>
#include <r_util/r_sandbox.h>

// static int demangle_type = R_BIN_LANG_CXX;
// static int demangle_type = R_BIN_LANG_JAVA;
static int demangle_type = R_BIN_LANG_SWIFT;

static void usage() {
	printf (
		"Usage: fuzz_bin_demangle <libFuzzer flags> <corpora> -- <flags>\n"
		"\n"
		"libFuzzer flags: show with -help=1\n"
		"\n"
		"Target Flags\n"
		" -l [lang]     set demangle lang\n");
	exit (1);
}

int LLVMFuzzerInitialize(int *lf_argc, char ***lf_argv) {
	r_sys_clearenv ();
	r_sandbox_enable (true);
	r_sandbox_grain (R_SANDBOX_GRAIN_NONE);
	r_log_set_quiet (true);

	int argc = *lf_argc;
	const char **argv = (const char **) (*lf_argv);
	bool has_args = false;
	int i, c;
	for (i = 1; i < argc; i++) {
		++argv;
		if (strcmp ((*lf_argv)[i], "--") == 0) {
			has_args = true;
			break;
		}
	}

	if (has_args) {
		*lf_argc = i;
		argc = argc - i;

		RGetopt opt;
		r_getopt_init (&opt, argc, argv, "l:");
		while ((c = r_getopt_next (&opt)) != -1) {
			switch (c) {
			case 'l':
				demangle_type = r_bin_demangle_type (opt.arg);
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
	char *str = malloc (len + 1);
	memcpy (str, data, len);
	str[len] = 0;

	ut64 vaddr = 0x10000000;
	char *demangled = NULL;
	// TODO: replace with r_bin_demangle
	switch (demangle_type) {
	case R_BIN_LANG_JAVA: demangled = r_bin_demangle_java (str); break;
	case R_BIN_LANG_RUST: demangled = r_bin_demangle_rust (NULL, str, vaddr); break;
	case R_BIN_LANG_OBJC: demangled = r_bin_demangle_objc (NULL, str); break;
	case R_BIN_LANG_SWIFT: demangled = r_bin_demangle_swift (str, false, false); break;
	case R_BIN_LANG_CXX: demangled = r_bin_demangle_cxx (NULL, str, vaddr); break;
	case R_BIN_LANG_MSVC: demangled = r_bin_demangle_msvc (str); break;
	default:
		abort ();
	}

	free (str);
	free (demangled);

	if (demangle_type == R_BIN_LANG_MSVC) {
		// Flush out globals
		free (r_bin_demangle_msvc ("."));
	}

	return 0;
}
