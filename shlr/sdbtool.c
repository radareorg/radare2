#include <r_util.h>

static bool dothething(const char *basedir, const char *file_txt) {
	char *file_sdb = r_str_ndup (file_txt, strlen (file_txt) - 4);
	char *file_c = strdup (file_sdb);
	strcpy (file_c + strlen (file_c) - 3, "c");

	if (!r_file_exists (file_c) || r_file_is_newer (file_txt, file_c)) {
		R_LOG_INFO ("newer %s", file_c);
	}
	if (!r_file_exists (file_sdb) || r_file_is_newer (file_txt, file_sdb)) {
		R_LOG_INFO ("newer %s", file_sdb);
	}

	// R_LOG_INFO ("%s (%s) (%s)", file_txt, file_sdb, file_c);
	free (file_c);
	free (file_sdb);
	return true;
}

int main(int argc, char **argv) {
	if (argc < 2) {
		R_LOG_ERROR ("Usage: sdbtool [path]");
		return 1;
	}
	char *file;
	RListIter *iter;
	const char *basedir = argv[1];
	RList *files = r_sys_dir (basedir);
	if (!files) {
		R_LOG_ERROR ("Invalid directory: %s", basedir);
		return 1;
	}
	if (!r_sys_chdir (basedir)) {
		R_LOG_ERROR ("Cannot chdir to %s", basedir);
		return 1;
	}
	r_list_foreach (files, iter, file) {
		if (r_str_endswith (file, ".sdb.txt")) {
			dothething (basedir, file);
		}
	}
	// take path as argument
	return 0;
}
