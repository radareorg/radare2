#include <r_util.h>

static bool dothec(const char *file_txt, const char *file_c) {
	// TODO: there's no api in sdb to do that yet, its all hardcoded in sdb.c
	// Sdb *db = sdb_new (NULL, file_c, 0);
	// sdb_free (db);
}

static bool dothesdb(const char *file_txt, const char *file_sdb) {
	Sdb *db = sdb_new (NULL, file_sdb, 0);
	if (sdb_text_load (db, file_txt)) {
		eprintf ("maked %s\n", file_sdb);
		sdb_sync (db);
	} else {
		eprintf ("Failed to parse %s\n", file_txt);
	}
	sdb_free (db);
}

static bool dothething(const char *basedir, const char *file_txt) {
	char *file_sdb = r_str_ndup (file_txt, strlen (file_txt) - 4);
	char *file_c = strdup (file_sdb);
	strcpy (file_c + strlen (file_c) - 3, "c");

	if (!r_file_exists (file_c) || r_file_is_newer (file_txt, file_c)) {
		R_LOG_INFO ("newer %s", file_c);
		dothec (file_txt, file_c);
	}
	if (!r_file_exists (file_sdb) || r_file_is_newer (file_txt, file_sdb)) {
		R_LOG_INFO ("newer %s", file_sdb);
		dothesdb (file_txt, file_sdb);
	}
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
