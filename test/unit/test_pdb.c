#include <r_util.h>
#include "minunit.h"
#include <r_bin.h>
#include <r_core.h>
#include <r_bin_dwarf.h>
#include "../../libr/bin/pdb/types.h"

#define MODE 2

// copy from cbin.c modified to get pdb back
int pdb_info(const char *file, R_PDB *pdb) {
	pdb->cb_printf = r_cons_printf;
	if (!init_pdb_parser (pdb, file)) {
		return false;
	}
	if (!pdb->pdb_parse (pdb)) {
		eprintf ("pdb was not parsed\n");
		pdb->finish_pdb_parse (pdb);
		return false;
	}
	return true;
}

bool test_pdb_tpi(void) {
	R_PDB pdb = R_EMPTY;
	mu_assert_true (pdb_info ("/home/hound/Projects/radare2/test/bins/pe/types.pdb", &pdb), "pdb parsing failed");

	RList *plist = pdb.pdb_streams;
	mu_assert_notnull (plist, "PDB streams is NULL");

	mu_assert_eq (pdb.root_stream->num_streams, 58, "Incorrect number of streams");

	STpiStream *tpi_stream = r_list_get_n (plist, ePDB_STREAM_TPI);
	mu_assert_notnull (tpi_stream, "TPIs stream not found in current PDB");
	mu_assert_eq (tpi_stream->header.hdr_size + tpi_stream->header.follow_size, 158056, "Wrong TPI size");
	pdb.finish_pdb_parse (&pdb);
	mu_end;
}

bool all_tests() {
	mu_run_test (test_pdb_tpi);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}