/* radare2 - LGPL - Copyright 2009-2025 - pancake, condret */

#include <r_core.h>

static char *check_path(char *base_path, const char *name, bool(*check_func)(const char *)) {
	char *path = r_file_new (base_path, name, NULL);
	if (path && check_func (path)) {
		return path;
	}
	free (path);
	return NULL;
}

static void collect_fortune_types_from_dir(RList *types, const char *base_path) {
	RList *files = r_sys_dir (base_path);
	if (files) {
		RListIter *iter;
		char *file;
		r_list_foreach (files, iter, file) {
			if (*file != '.' && r_str_startswith (file, "fortunes.") && file[9]) {
				r_list_append (types, strdup (file + 9));
			}
		}
		r_list_free (files);
	}
}

static char *getFortuneFile(RCore *core, const char *type) {
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

static char *slurp_directory_contents(const char *dir_path) {
	RList *files = r_sys_dir (dir_path);
	if (!files) {
		return NULL;
	}

	RStrBuf *content_buf = r_strbuf_new (NULL);
	RListIter *iter;
	char *f;

	r_list_foreach (files, iter, f) {
		if (r_str_endswith (f, ".txt")) {
			char *file_path = r_file_new (dir_path, f, NULL);
			if (file_path) {
				char *file_content = r_file_slurp (file_path, NULL);
				if (file_content) {
					r_strbuf_append (content_buf, file_content);
					free (file_content);
				}
				free (file_path);
			}
		}
	}
	r_list_free (files);
	return r_strbuf_drain (content_buf);
}

static char *getRandomLine(RCore *core) {
	if (!r_sandbox_check (R_SANDBOX_GRAIN_FILES | R_SANDBOX_GRAIN_DISK)) {
		return NULL;
	}
	const char *ft = r_config_get (core->config, "cfg.fortunes.type");
	RList *types = r_str_split_duplist (ft, ",", false);
	if (r_list_empty (types)) {
		r_list_free (types);
		return NULL;
	}
	int rand_type_idx = r_num_rand (r_list_length (types));
	char *type = r_list_get_n (types, rand_type_idx);
	char *file = getFortuneFile (core, type);
	r_list_free (types);
	if (!file) {
		return NULL;
	}
	char *content = r_file_is_directory (file)
		? slurp_directory_contents (file)
		: r_file_slurp (file, NULL);
	free (file);
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

R_API RList *r_core_fortune_types(RCore *core) {
	RList *types = r_list_newf (free);
	if (r_sandbox_check (R_SANDBOX_GRAIN_FILES | R_SANDBOX_GRAIN_DISK)) {
		char *xdg_fortunes = r_xdg_datadir ("fortunes");
		char *sys_fortunes = r_file_new (r_sys_prefix (NULL), R2_FORTUNES, NULL);
		collect_fortune_types_from_dir (types, xdg_fortunes);
		collect_fortune_types_from_dir (types, sys_fortunes);
		free (xdg_fortunes);
		free (sys_fortunes);
	}
	return types;
}

R_API void r_core_fortune_print_random(RCore *core) {
	R_RETURN_IF_FAIL (core);
	if (!r_sandbox_check (R_SANDBOX_GRAIN_FILES | R_SANDBOX_GRAIN_DISK)) {
		return;
	}
	char *line = getRandomLine (core);
	if (line) {
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
