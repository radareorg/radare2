/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#include "r2r.h"

static int help(bool verbose) {
	printf ("Usage: r2r [test]\n");
	if (verbose) {
		printf (" TODO: verbose help\n");
	}
	return 1;
}

int main(int argc, char **argv) {
	int c;
	while ((c = r_getopt (argc, argv, "h")) != -1) {
		switch (c) {
		case 'h':
			return help (true);
		default:
			return help (false);
		}
	}

	if (!r2r_subprocess_init ()) {
		eprintf ("Subprocess init failed\n");
		return 1;
	}
	atexit (r2r_subprocess_fini);

	R2RRunConfig config = { "radare2", "rasm2" };
	R2RTestDatabase *db = r2r_test_database_new ();
	if (!db) {
		return 1;
	}

	if (optind < argc) {
		// Manually specified path(s)
		int i;
		for (i = optind; i < argc; i++) {
			if (!r2r_test_database_load (db, argv[i])) {
				eprintf ("Failed to load tests from \"%s\"\n", argv[i]);
				r2r_test_database_free (db);
				return 1;
			}
		}
	} else {
		// Default db path
		if (!r2r_test_database_load (db, "db")) {
			eprintf ("Failed to load tests from ./db\n");
			r2r_test_database_free (db);
			return 1;
		}
	}

	void **it;
	r_pvector_foreach (&db->tests, it) {
		R2RTest *test = *it;
		R2RTestResultInfo *result = r2r_run_test (&config, test);
		char *name = r2r_test_name (test);
		printf ("%s: ", name ? name : "");
		switch (result->result) {
		case R2R_TEST_RESULT_OK:
			printf ("OK\n");
			break;
		case R2R_TEST_RESULT_FAILED:
			printf ("XX\n");
			break;
		case R2R_TEST_RESULT_BROKEN:
			printf ("BR\n");
			break;
		case R2R_TEST_RESULT_FIXED:
			printf ("FX\n");
			break;
		}
		r2r_test_result_info_free (result);
		free (name);
	}

	r2r_test_database_free (db);
	return 0;
}
