/* radare2 - LGPL - Copyright 2009-2025 - pancake, condret */

#include <r_core.h>

static char *check_path(char *base_path, const char *name, bool (*check_func)(const char *)) {
	char *path = r_file_new (base_path, name, NULL);
	if (path && check_func (path)) {
		return path;
	}
	free (path);
	return NULL;
}

static char *getFortuneFile(RCore *core, const char *type) {
	if (!r_sandbox_check (R_SANDBOX_GRAIN_FILES | R_SANDBOX_GRAIN_DISK)) {
		return NULL;
	}
	char *xdg_fortunes = r_xdg_datadir ("fortunes");
	char *sys_fortunes = r_file_new (r_sys_prefix (NULL), R2_FORTUNES, NULL);
	char *result = check_path (xdg_fortunes, type, r_file_is_directory);
	if (!result) {
		result = check_path (sys_fortunes, type, r_file_is_directory);
		if (!result) {
			r_strf_var (fname, 64, "fortunes.%s", type);
			result = check_path (xdg_fortunes, fname, r_file_exists);
			if (!result) {
				result = check_path (sys_fortunes, fname, r_file_exists);
			}
		}
	}
	free (xdg_fortunes);
	free (sys_fortunes);
	return result;
}

static char *getrandomline(RCore *core) {
	const char *ft = r_config_get (core->config, "cfg.fortunes.type");
	RList *types = r_str_split_duplist (ft, ",", false);
	if (r_list_empty (types)) {
		r_list_free (types);
		return NULL;
	}
	int num_types = r_list_length (types);
	int rand_type_idx = r_num_rand (num_types);
	char *type = r_list_get_n (types, rand_type_idx);
	char *file = getFortuneFile (core, type);
	r_list_free (types);
	if (!file) {
		return NULL;
	}
	char *selected_file = NULL;
	if (r_file_is_directory (file)) {
		RList *files = r_sys_dir (file);
		if (files) {
			RList *txt_files = r_list_newf (free);
			RListIter *iter;
			char *f;
			r_list_foreach (files, iter, f) {
				if (r_str_endswith (f, ".txt")) {
					r_list_push (txt_files, strdup (f));
				}
			}
			r_list_free (files);
			if (!r_list_empty (txt_files)) {
				int num_txt = r_list_length (txt_files);
				int rand_idx = r_num_rand (num_txt);
				char *txt_file = r_list_get_n (txt_files, rand_idx);
				selected_file = r_file_new (file, txt_file, NULL);
			}
			r_list_free (txt_files);
		}
	} else {
		selected_file = strdup (file);
	}
	free (file);
	if (!selected_file) {
		return NULL;
	}
	char *content = r_file_slurp (selected_file, NULL);
	free (selected_file);
	if (!content) {
		return NULL;
	}
	RList *line_starts = r_str_split_list (content, "\n", false);
	if (r_list_empty (line_starts)) {
		r_list_free (line_starts);
		free (content);
		return NULL;
	}
	int num_lines = r_list_length (line_starts);
	int rand_idx = r_num_rand (num_lines);
	char *selected_line = r_list_get_n (line_starts, rand_idx);
	char *result = strdup (selected_line);
	r_list_free (line_starts);
	free (content);
	return result;
}

R_IPI RList *r_core_fortune_types(void) {
	RList *types = r_list_newf (free);
	if (!types) {
		return NULL;
	}
	
	// Try to find fortune types from system directories
	if (r_sandbox_check (R_SANDBOX_GRAIN_FILES | R_SANDBOX_GRAIN_DISK)) {
		char *xdg_fortunes = r_xdg_datadir ("fortunes");
		char *sys_fortunes = r_file_new (r_sys_prefix (NULL), R2_FORTUNES, NULL);
		
		// Check XDG fortunes directory
		if (xdg_fortunes && r_file_is_directory (xdg_fortunes)) {
			RList *files = r_sys_dir (xdg_fortunes);
			if (files) {
				RListIter *iter;
				char *file;
				r_list_foreach (files, iter, file) {
					if (*file != '.') {
						char *path = r_file_new (xdg_fortunes, file, NULL);
						if (path) {
							char *type = NULL;
							
							// Only handle files starting with "fortunes."
							if (r_str_startswith (file, "fortunes.") && !r_file_is_directory (path)) {
								type = strdup (file + 9); // Skip "fortunes."
							}
							free (path);
						}
					}
				}
				r_list_free (files);
			}
		}
		
		// Check system fortunes directory
		if (sys_fortunes && r_file_is_directory (sys_fortunes)) {
			RList *files = r_sys_dir (sys_fortunes);
			if (files) {
				RListIter *iter;
				char *file;
				r_list_foreach (files, iter, file) {
					if (*file != '.') {
						char *path = r_file_new (sys_fortunes, file, NULL);
						if (path) {
							char *type = NULL;
							// Only handle files starting with "fortunes."
							if (r_str_startswith (file, "fortunes.") && !r_file_is_directory (path)) {
								type = strdup (file + 9); // Skip "fortunes."
							}
							free (path);
						}
					}
				}
				r_list_free (files);
			}
		}
		
		free (xdg_fortunes);
		free (sys_fortunes);
	}
	if (r_list_empty (types)) {
		r_list_append (types, strdup ("plugins"));
		r_list_append (types, strdup ("tips"));
		r_list_append (types, strdup ("fun"));
	}
	return types;
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
