/* radare2 - LGPL - Copyright 2009-2024 - pancake, condret */

#include <r_core.h>

static char *getFortuneFile(RCore *core, const char *type) {
	if (!r_sandbox_check (R_SANDBOX_GRAIN_FILES | R_SANDBOX_GRAIN_DISK)) {
		return NULL;
	}

	char *fortunedir = r_xdg_datadir ("fortunes");
	char *subdir = r_file_new (fortunedir, type, NULL);
	free (fortunedir);
	if (subdir && r_file_is_directory (subdir)) {
		return subdir;
	}
	free (subdir);

	subdir = r_file_new (r_sys_prefix (NULL), R2_FORTUNES, type, NULL);
	if (subdir && r_file_is_directory (subdir)) {
		return subdir;
	}
	free (subdir);

	r_strf_var (fname, 64, "fortunes.%s", type);
	fortunedir = r_xdg_datadir ("fortunes");
	char *path = r_file_new (fortunedir, fname, NULL);
	free (fortunedir);
	if (path && r_file_exists (path)) {
		return path;
	}
	free (path);
	path = r_file_new (r_sys_prefix (NULL), R2_FORTUNES, fname, NULL);
	if (path && r_file_exists (path)) {
		return path;
	}
	free (path);
	return NULL;
}

static bool _push_types(RList *type_list, char *fortune_dir) {
	RList *files = r_sys_dir (fortune_dir);
	if (!files) {
		return false;
	}
	RListIter *iter;
	char *file;

	r_list_foreach (files, iter, file) {
		if (r_str_startswith (file, "fortunes.") && file[9]) {
			r_list_push (type_list, strdup (file + 9));
		} else {
			char *fullpath = r_file_new (fortune_dir, file, NULL);
			if (fullpath && r_file_is_directory (fullpath)) {
				r_list_push (type_list, strdup (file));
			}
			free (fullpath);
		}
	}
	r_list_free (files);
	return true;
}

R_IPI RList *r_core_fortune_types(void) {
	if (!r_sandbox_check (R_SANDBOX_GRAIN_FILES | R_SANDBOX_GRAIN_DISK)) {
		return NULL;
	}
	RList *types = r_list_newf (free);
	if (!types) {
		return NULL;
	}
	char *fortune_dir = r_file_new (r_sys_prefix (NULL), R2_FORTUNES, NULL);
	if (!fortune_dir) {
		r_list_free (types);
		return NULL;
	}
	if (!_push_types (types, fortune_dir)) {
		free (fortune_dir);
		r_list_free (types);
		return NULL;
	}
	free (fortune_dir);
	fortune_dir = r_xdg_datadir ("fortunes");
	if (fortune_dir) {
		_push_types (types, fortune_dir);
		free (fortune_dir);
	}
	return types;
}

static void core_fortune_list_types(RCore *core) {
	RList *types = r_core_fortune_types ();
	if (types) {
		char *fts = r_str_list_join (types, "\n");
		if (fts) {
			r_cons_println (core->cons, fts);
			free (fts);
		}
		r_list_free (types);
	}
}

static void _collect_lines(RList *lines, const char *filepath) {
	char *content = r_file_slurp (filepath, NULL);
	if (content) {
		RList *file_lines = r_str_split_list (content, "\n", 0);
		if (file_lines) {
			RListIter *iter;
			char *line;
			r_list_foreach (file_lines, iter, line) {
				if (R_STR_ISNOTEMPTY (line)) {
					r_list_push (lines, strdup (line));
				}
			}
			r_list_free (file_lines);
		}
		free (content);
	}
}

static void _collect_lines_from_path(RList *lines, const char *path) {
	if (r_file_is_directory (path)) {
		RList *dir_files = r_sys_dir (path);
		if (dir_files) {
			RListIter *iter;
			char *file;
			r_list_foreach (dir_files, iter, file) {
				if (r_str_endswith (file, ".txt")) {
					char *txt_path = r_file_new (path, file, NULL);
					_collect_lines (lines, txt_path);
					free (txt_path);
				}
			}
			r_list_free (dir_files);
		}
	} else {
		_collect_lines (lines, path);
	}
}

static void _print_fortune_file(RCore *core, const char *fortune_file_path) {
	RList *lines = r_list_newf (free);
	_collect_lines_from_path (lines, fortune_file_path);
	RListIter *iter;
	char *line;
	r_list_foreach (lines, iter, line) {
		if (R_STR_ISNOTEMPTY (line)) {
			r_cons_println (core->cons, line);
		}
	}
	r_list_free (lines);
}

R_API void r_core_fortune_list(RCore *core, bool list_types_instead_of_fortunes) {
	R_RETURN_IF_FAIL (core);
	if (list_types_instead_of_fortunes) {
		core_fortune_list_types (core);
		return;
	}
	if (!r_sandbox_check (R_SANDBOX_GRAIN_FILES | R_SANDBOX_GRAIN_DISK)) {
		return;
	}
	const char *types = (char *)r_config_get (core->config, "cfg.fortunes.type");

	RList *ftypes = r_core_fortune_types ();
	if (!ftypes) {
		return;
	}
	RListIter *iter;
	char *fortunes;
	r_list_foreach (ftypes, iter, fortunes) {
		if (strstr (types, fortunes)) {
			char *file = getFortuneFile (core, fortunes);
			if (file) {
				_print_fortune_file (core, file);
				free (file);
			}
		}
	}
	r_list_free (ftypes);
}

static char *getrandomline(RCore *core) {
	const char *ft = r_config_get (core->config, "cfg.fortunes.type")
	RList *types = r_str_split_duplist (ft, ",", false);
	if (r_list_empty (types)) {
		r_list_free (types);
		return NULL;
	}
	RList *all_lines = r_list_newf (free);
	RListIter *iter;
	char *type;
	r_list_foreach (types, iter, type) {
		char *file = getFortuneFile (core, type);
		if (file) {
			_collect_lines_from_path (all_lines, file);
			free (file);
		}
	}
	r_list_free (types);

	const char *result = strdup (r_list_get_n (all_lines, r_num_rand (r_list_length (all_lines))));
	r_list_free (all_lines);
	return result;
}

R_API void r_core_fortune_print_random(RCore *core) {
	R_RETURN_IF_FAIL (core);
	if (!r_sandbox_check (R_SANDBOX_GRAIN_FILES | R_SANDBOX_GRAIN_DISK)) {
		return;
	}
	char *line = getrandomline (core);
	if (R_STR_ISNOTEMPTY (line)) {
		if (r_config_get_b (core->config, "cfg.fortunes.clippy")) {
			r_core_clippy (core, line);
		} else {
			r_cons_printf (core->cons, " -- %s\n", line);
		}
		if (r_config_get_b (core->config, "cfg.fortunes.tts")) {
			r_sys_tts (line, true);
		}
		free (line);
	}
}
