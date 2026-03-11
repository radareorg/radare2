#include <stdarg.h>
#include <r_anal.h>
#include <r_bin.h>
#include <r_types.h>
#include <r_util/pj.h>
#include <r_util/r_log.h>

int LLVMFuzzerInitialize(int *lf_argc, char ***lf_argv) {
	r_log_set_quiet (true);
	return 0;
}

static int null_printf(const char *fmt, ...) {
	return 0;
}

int LLVMFuzzerTestOneInput(const ut8 *data, size_t len) {
	RBuffer *buf = r_buf_new_with_bytes (data, len);
	if (!buf) {
		return 0;
	}

	RBinPdb pdb = { 0 };
	pdb.cb_printf = null_printf;
	if (r_bin_pdb_parser_with_buf (&pdb, buf)) {
		if (pdb.pdb_parse && pdb.pdb_parse (&pdb)) {
			RAnal *anal = r_anal_new ();
			if (anal) {
				r_parse_pdb_types (anal, &pdb);
				r_anal_free (anal);
			}
			if (pdb.print_types) {
				PJ *pj = pj_new ();
				if (pj) {
					pdb.print_types (&pdb, pj, 'j');
					free (pj_drain (pj));
				}
				pdb.print_types (&pdb, NULL, '*');
			}
			if (pdb.print_gvars) {
				PJ *pj = pj_new ();
				if (pj) {
					pdb.print_gvars (&pdb, 0x10000000, pj, 'j');
					free (pj_drain (pj));
				}
				pdb.print_gvars (&pdb, 0x10000000, NULL, '*');
			}
		}
		if (pdb.finish_pdb_parse) {
			pdb.finish_pdb_parse (&pdb);
		}
	} else {
		r_unref (buf);
	}

	return 0;
}
