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
	const char **argv = (const char **) (*lf_argv);
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
	r_io_bind (io, &bin->iob);

	RBinFileOptions bo;
	r_bin_file_options_init (&bo, /*fd*/ -1, /*baseaddr*/ 0x10000000, /*loadaddr*/ 0, /*rawstr*/ 0);
	bo.filename = strdup ("test");
	r_bin_open_buf (bin, buf, &bo);

	int mode = 0;
	{
		// TODO: complete and speed-up support for dwarf
		RVecDwarfAbbrevDecl *da = r_bin_dwarf_parse_abbrev (bin, mode);
		if (!da) {
			exit (1);
			return false;
		}
		RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (bin, da, mode);
		HtUP /*<offset, List *<LocListEntry>*/ *loc_table = r_bin_dwarf_parse_loc (bin, 8);
		// I suppose there is no reason the parse it for a printing purposes
#if 0
		if (info && mode != R_MODE_PRINT) {
			/* Should we do this by default? */
			RAnalDwarfContext ctx = {
				.info = info,
				.loc = loc_table
			};
			r_anal_dwarf_process_info (core->anal, &ctx);
		}
#endif
		if (loc_table) {
			r_bin_dwarf_print_loc (loc_table, 8);
			r_bin_dwarf_free_loc (loc_table);
		}
		r_bin_dwarf_free_debug_info (info);
		r_bin_dwarf_parse_aranges (bin, mode);
		r_list_free (r_bin_dwarf_parse_line (bin, mode));
		r_bin_dwarf_free_debug_abbrev (da);
	}

	r_bin_free (bin);
	R_FREE (bo.filename);
	r_io_free (io);
	r_buf_free (buf);
	return 0;
}
