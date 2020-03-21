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

	if (optind == argc) {
		eprintf ("No file specified. TODO: automatically detect tests\n");
		return help (true);
	}

	if (!r2r_subprocess_init ()) {
		eprintf ("Subprocess init failed\n");
		return 1;
	}
	atexit (r2r_subprocess_fini);

	R2RRunConfig config = { "radare2" };

	int i;
	for (i = optind; i < argc; i++) {
		printf ("%s\n", argv[i]);
		RPVector *tests = r2r_load_cmd_test_file (argv[i]);
		if (!tests) {
			eprintf ("FAILED!!!!\n");
			continue;
		}
		void **it;
		r_pvector_foreach (tests, it) {
			R2RCmdTest *test = *it;
			if (!test->name.value) {
				eprintf ("horse with no name\n");
			}
			R2RTestOutput *out = r2r_run_cmd_test (&config, test);
			R2RTestResult result = r2r_test_output_check (out, test);
			printf ("%s: ", test->name.value ? test->name.value : "<unnamed>");
			switch (result) {
			case R2R_TEST_RESULT_OK:
				printf ("OK\n");
				break;
			case R2R_TEST_RESULT_FAILED:
				printf ("XX\n");
				printf("%s\n", out->out);
				printf("%s\n", out->err);
				break;
			case R2R_TEST_RESULT_BROKEN:
				printf ("BR\n");
				break;
			case R2R_TEST_RESULT_FIXED:
				printf ("FX\n");
				break;
			}
			r2r_test_output_free (out);
		}
		r_pvector_free (tests);
	}

	return 0;
}
