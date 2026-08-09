#include <r_core.h>
#include <r_util.h>
#include <unistd.h>
#include "minunit.h"

static bool test_project_notes_file_allows_regular_notes(void) {
	int retval = MU_PASSED;
	RCore *core = NULL;
	char template[] = "/tmp/r2-project-notes-XXXXXX";
	char *root = NULL;
	char *projects_dir = NULL;
	char *project_dir = NULL;
	char *notes_path = NULL;
	char *notes = NULL;
	char *data = NULL;

	if (!mkdtemp (template)) {
		mu_cleanup_sysfail (cleanup, "mkdtemp");
	}
	root = strdup (template);
	if (!root) {
		mu_cleanup_fail (cleanup, "strdup root");
	}
	projects_dir = r_str_newf ("%s/projects", root);
	project_dir = r_str_newf ("%s/ok", projects_dir);
	notes_path = r_str_newf ("%s/notes.txt", project_dir);
	if (!projects_dir || !project_dir || !notes_path) {
		mu_cleanup_fail (cleanup, "allocate paths");
	}
	if (!r_sys_mkdirp (project_dir)) {
		mu_cleanup_fail (cleanup, "create project directory");
	}
	if (!r_file_dump (notes_path, (const ut8 *)"SAFE_NOTE\n", sizeof ("SAFE_NOTE\n") - 1, false)) {
		mu_cleanup_fail (cleanup, "write project notes");
	}

	core = r_core_new ();
	mu_assert_notnull (core, "Should create core");
	r_config_set (core->config, "dir.projects", projects_dir);

	notes = r_core_project_notes_file (core, "ok");
	mu_assert_notnull (notes, "Regular project notes path should resolve");
	data = r_file_slurp (notes, NULL);
	mu_assert_notnull (data, "Regular project notes should be readable");
	mu_assert_streq (data, "SAFE_NOTE\n", "Regular project notes should keep content");

cleanup:
	free (data);
	free (notes);
	if (core) {
		r_core_free (core);
	}
	if (root) {
		r_file_rm_rf (root);
	}
	free (notes_path);
	free (project_dir);
	free (projects_dir);
	free (root);
	mu_cleanup_end;
}

static bool test_project_notes_file_rejects_symlinked_project_directory(void) {
	int retval = MU_PASSED;
	RCore *core = NULL;
	char template[] = "/tmp/r2-project-notes-XXXXXX";
	char *root = NULL;
	char *projects_dir = NULL;
	char *outside_dir = NULL;
	char *outside_notes = NULL;
	char *outside_rc = NULL;
	char *evil_link = NULL;
	char *notes = NULL;

	if (!mkdtemp (template)) {
		mu_cleanup_sysfail (cleanup, "mkdtemp");
	}
	root = strdup (template);
	if (!root) {
		mu_cleanup_fail (cleanup, "strdup root");
	}
	projects_dir = r_str_newf ("%s/projects", root);
	outside_dir = r_str_newf ("%s/outside", root);
	outside_notes = r_str_newf ("%s/notes.txt", outside_dir);
	outside_rc = r_str_newf ("%s/rc.r2", outside_dir);
	evil_link = r_str_newf ("%s/evil", projects_dir);
	if (!projects_dir || !outside_dir || !outside_notes || !outside_rc || !evil_link) {
		mu_cleanup_fail (cleanup, "allocate paths");
	}
	if (!r_sys_mkdirp (projects_dir)) {
		mu_cleanup_fail (cleanup, "create projects directory");
	}
	if (!r_sys_mkdirp (outside_dir)) {
		mu_cleanup_fail (cleanup, "create outside directory");
	}
	if (!r_file_dump (outside_rc, (const ut8 *)"# r2 rdb project file\n", sizeof ("# r2 rdb project file\n") - 1, false)) {
		mu_cleanup_fail (cleanup, "write project rc");
	}
	if (!r_file_dump (outside_notes, (const ut8 *)"DIR_SYMLINK_NOTE\n", sizeof ("DIR_SYMLINK_NOTE\n") - 1, false)) {
		mu_cleanup_fail (cleanup, "write outside notes");
	}
	if (symlink (outside_dir, evil_link) != 0) {
		mu_cleanup_sysfail (cleanup, "symlink");
	}

	core = r_core_new ();
	mu_assert_notnull (core, "Should create core");
	r_config_set (core->config, "dir.projects", projects_dir);

	notes = r_core_project_notes_file (core, "evil");
	mu_assert_null (notes, "Symlinked project directory notes path should be rejected");

cleanup:
	free (notes);
	if (core) {
		r_core_free (core);
	}
	if (root) {
		r_file_rm_rf (root);
	}
	free (evil_link);
	free (outside_rc);
	free (outside_notes);
	free (outside_dir);
	free (projects_dir);
	free (root);
	mu_cleanup_end;
}

int all_tests(void) {
	mu_run_test (test_project_notes_file_allows_regular_notes);
	mu_run_test (test_project_notes_file_rejects_symlinked_project_directory);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
