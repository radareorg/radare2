#include <r_bin.h>
#include <r_getopt.h>
#include <r_io.h>
#include <r_types.h>
#include <r_util/pj.h>
#include <r_util/r_buf.h>
#include <r_util/r_log.h>
#include <r_util/r_sys.h>
#include <r_util/r_sandbox.h>

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
	RBuffer *buf = r_buf_new_with_bytes (data, len);
	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	if (!buf || !bin || !io) {
		r_bin_free (bin);
		r_io_free (io);
		r_unref (buf);
		return 0;
	}
	r_io_bind (io, &bin->iob);
	if (opt_forcebin) {
		r_bin_force_plugin (bin, opt_forcebin);
	}

	RIODesc *desc = r_io_open_buffer (io, buf, R_PERM_R, 0);
	if (desc) {
		RBinFileOptions bo;
		r_bin_file_options_init (&bo, desc->fd, 0x10000000, 0, 0);
		bo.sz = len;
		bo.filename = "fuzz-bin";
		if (r_bin_open_io (bin, &bo)) {
			PJ *pj = pj_new ();
			char *types = r_bin_get_types (bin);
			RList *hashes = r_bin_file_compute_hashes (bin, len? len: 1);
			(void)r_bin_get_info (bin);
			(void)r_bin_get_size (bin);
			(void)r_bin_get_entries (bin);
			(void)r_bin_get_imports (bin);
			(void)r_bin_get_imports_vec (bin);
			(void)r_bin_get_libs (bin);
			(void)r_bin_get_relocs (bin);
			(void)r_bin_get_sections (bin);
			(void)r_bin_get_classes (bin);
			(void)r_bin_get_strings (bin);
			(void)r_bin_get_symbols_vec (bin);
			if (pj) {
				r_bin_list (bin, pj, R_MODE_JSON);
				free (pj_drain (pj));
			}
			free (types);
			r_list_free (hashes);
		}
	}
	r_bin_free (bin);
	r_io_free (io);
	r_unref (buf);
	return 0;
}
