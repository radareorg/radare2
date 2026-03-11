#include <r_bin.h>
#include <r_getopt.h>
#include <r_io.h>
#include <r_types.h>
#include <r_util/r_buf.h>
#include <r_util/r_log.h>
#include <r_util/r_sys.h>
#include <r_util/r_sandbox.h>

#include "fuzz_common.h"

// static int demangle_type = R_BIN_LANG_CXX;
// static int demangle_type = R_BIN_LANG_JAVA;
static int demangle_type = R_BIN_LANG_ANY;

static const int default_demanglers[] = {
	R_BIN_LANG_JAVA,
	R_BIN_LANG_RUST,
	R_BIN_LANG_OBJC,
	R_BIN_LANG_SWIFT,
	R_BIN_LANG_CXX,
	R_BIN_LANG_MSVC,
	R_BIN_LANG_PASCAL,
};

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

static const char *demangle_lang_name(int type) {
	switch (type) {
	case R_BIN_LANG_JAVA:
		return "java";
	case R_BIN_LANG_RUST:
		return "rust";
	case R_BIN_LANG_OBJC:
		return "objc";
	case R_BIN_LANG_SWIFT:
		return "swift";
	case R_BIN_LANG_CXX:
		return "cxx";
	case R_BIN_LANG_MSVC:
		return "msvc";
	case R_BIN_LANG_PASCAL:
		return "pascal";
	default:
		break;
	}
	return NULL;
}

static void demangle_one(const char *symbol, ut64 vaddr, int type) {
	char *demangled = NULL;
	switch (type) {
	case R_BIN_LANG_JAVA:
		demangled = r_bin_demangle_java (symbol);
		break;
	case R_BIN_LANG_RUST:
		demangled = r_bin_demangle_rust (NULL, symbol, vaddr);
		break;
	case R_BIN_LANG_OBJC:
		demangled = r_bin_demangle_objc (NULL, symbol);
		break;
	case R_BIN_LANG_SWIFT:
		demangled = r_bin_demangle_swift (symbol, false, false);
		break;
	case R_BIN_LANG_CXX:
		demangled = r_bin_demangle_cxx (NULL, symbol, vaddr);
		break;
	case R_BIN_LANG_MSVC:
		demangled = r_bin_demangle_msvc (symbol);
		break;
	case R_BIN_LANG_PASCAL:
		demangled = r_bin_demangle_freepascal (symbol);
		break;
	default:
		return;
	}
	free (demangled);
}

int LLVMFuzzerTestOneInput(const ut8 *data, size_t len) {
	RFuzzInput input;
	rfuzz_input_init (&input, data, len);

	ut64 vaddr = 0x10000000ULL | rfuzz_consume_u8 (&input);
	size_t sym_len = 0;
	const ut8 *symbol_data = rfuzz_consume_tail (&input, &sym_len);
	if (!symbol_data) {
		symbol_data = data;
		sym_len = len;
	}
	char *symbol = rfuzz_strndup (symbol_data, sym_len);
	if (!symbol) {
		return 0;
	}
	rfuzz_normalize_text (symbol, sym_len, '_');

	char *autodetected = r_bin_demangle (NULL, NULL, symbol, vaddr, false);
	free (autodetected);

	if (demangle_type != R_BIN_LANG_ANY) {
		const char *lang = demangle_lang_name (demangle_type);
		demangle_one (symbol, vaddr, demangle_type);
		if (lang) {
			char *generic = r_bin_demangle (NULL, lang, symbol, vaddr, false);
			free (generic);
		}
	} else {
		size_t i;
		for (i = 0; i < sizeof (default_demanglers) / sizeof (default_demanglers[0]); i++) {
			const char *lang = demangle_lang_name (default_demanglers[i]);
			demangle_one (symbol, vaddr, default_demanglers[i]);
			if (lang) {
				char *generic = r_bin_demangle (NULL, lang, symbol, vaddr, false);
				free (generic);
			}
		}
	}
	free (r_bin_demangle_msvc ("."));
	free (symbol);

	return 0;
}
