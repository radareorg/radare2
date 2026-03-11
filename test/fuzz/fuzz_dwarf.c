#include <r_bin.h>
#include <r_getopt.h>
#include <r_io.h>
#include <r_types.h>
#include <r_util/r_buf.h>
#include <r_util/r_log.h>
#include <r_util/r_sys.h>
#include <r_util/r_sandbox.h>

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
		r_getopt_init (&opt, argc, argv, "");
		while ((c = r_getopt_next (&opt)) != -1) {
			switch (c) {
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
	int mode;
	int addr_size;
	if (!buf || !bin || !io) {
		r_bin_free (bin);
		r_io_free (io);
		r_unref (buf);
		return 0;
	}
	r_io_bind (io, &bin->iob);

	RBinFileOptions bo;
	r_bin_file_options_init (&bo, -1, 0x10000000, 0, 0);
	bo.filename = "fuzz-dwarf";
	r_bin_open_buf (bin, buf, &bo);

	mode = (len && (data[0] & 1))? R_MODE_JSON: R_MODE_PRINT;
	addr_size = (len && (data[0] & 2))? 8: 4;
	RBinFile *bf = r_bin_cur (bin);
	if (bf) {
		RVecDwarfAbbrevDecl *abbrev = r_bin_dwarf_parse_abbrev (bf, mode);
		RBinDwarfDebugInfo *info = abbrev? r_bin_dwarf_parse_info (bf, abbrev, mode): NULL;
		HtUP /*<offset, RBinDwarfLocList*>*/ *loc_table = r_bin_dwarf_parse_loc (bf, addr_size);
		RList *lines = r_bin_dwarf_parse_line (bf, mode);
		r_bin_dwarf_parse_aranges (bf, mode);
		if (loc_table) {
			char *text = r_bin_dwarf_print_loc (loc_table, addr_size);
			free (text);
			r_bin_dwarf_free_loc (loc_table);
		}
		r_list_free (lines);
		r_bin_dwarf_free_debug_info (info);
		r_bin_dwarf_free_debug_abbrev (abbrev);
	}
	r_bin_free (bin);
	r_io_free (io);
	r_unref (buf);
	return 0;
}
