/* radare2 - LGPL - Copyright 2009-2025 - pancake, condret */

#include <r_core.h>

static char *check_path(const char *base_path, const char *name, bool(*check_func)(const char *)) {
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
			if (*file == '.') {
				continue;
			}
			// Check for .txt files (new format: <type>.txt)
			if (r_str_endswith (file, ".txt")) {
				size_t len = strlen (file) - 4;
				char *type = r_str_ndup (file, len);
				if (type && !r_list_find (types, type, (RListComparator)strcmp)) {
					r_list_append (types, type);
				} else {
					free (type);
				}
			} else {
				// Check for directories (directory name is the type)
				char *full_path = r_file_new (base_path, file, NULL);
				if (full_path && r_file_is_directory (full_path) && !r_list_find (types, file, (RListComparator)strcmp)) {
					r_list_append (types, strdup (file));
				}
				free (full_path);
			}
		}
		r_list_free (files);
	}
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
			char *file_content = r_file_slurp (file_path, NULL);
			if (file_content) {
				r_strbuf_append (content_buf, file_content);
				free (file_content);
			}
			free (file_path);
		}
	}
	r_list_free (files);
	return r_strbuf_drain (content_buf);
}

static char *slurp_fortune_path(const char *path) {
	R_RETURN_VAL_IF_FAIL (path, NULL);
	return r_file_is_directory (path)
		? slurp_directory_contents (path)
		: r_file_slurp (path, NULL);
}

static char *getFortuneContent(RCore *core, const char *type) {
	char *xdg_fortunes = r_xdg_datadir ("fortunes");
	const char *fortunes_dir = r_config_get (core->config, "dir.fortunes");
	RStrBuf *sb = r_strbuf_new (NULL);
	r_strf_var (fname, 64, "%s.txt", type);

// AITODO duplicated code here
	// Collect from xdg path (directory or .txt file)
	char *path = check_path (xdg_fortunes, type, r_file_is_directory)
		?: check_path (xdg_fortunes, fname, r_file_exists);
	if (path) {
		char *content = slurp_fortune_path (path);
		if (content) {
			r_strbuf_append (sb, content);
			free (content);
		}
		free (path);
	}

// AITODO duplicated code here
	// Collect from system path (directory or .txt file)
	path = check_path (fortunes_dir, type, r_file_is_directory)
		?: check_path (fortunes_dir, fname, r_file_exists);
	if (path) {
		char *content = slurp_fortune_path (path);
		if (content) {
			r_strbuf_append (sb, content);
			free (content);
		}
		free (path);
	}

	free (xdg_fortunes);
	return r_strbuf_drain (sb);
}

static char *getRandomLine(RCore *core) {
	if (!r_sandbox_check (R_SANDBOX_GRAIN_FILES | R_SANDBOX_GRAIN_DISK)) {
		return NULL;
	}
	/* pick a random fortune type */
	const char *ft = r_config_get (core->config, "cfg.fortunes.type");
	RList *types = r_str_split_duplist (ft, ",", false);
	if (r_list_empty (types)) {
		r_list_free (types);
		return NULL;
	}
	int rand_type_idx = r_num_rand (r_list_length (types));
	char *type = r_list_get_n (types, rand_type_idx);
	char *content = getFortuneContent (core, type);
	r_list_free (types);
	if (R_STR_ISEMPTY (content)) {
		free (content);
		return NULL;
	}
	/* pick a random fortune message, filtering out empty lines */
	RList *all_lines = r_str_split_list (content, "\n", false);
	char *result = NULL;
	char *line;
	RListIter *iter;
	
	// Count non-empty lines first
	int count = 0;
	r_list_foreach (all_lines, iter, line) {
		if (R_STR_ISNOTEMPTY (line)) {
			count++;
		}
	}
	
	if (count > 0) {
		int rand_idx = r_num_rand (count);
		int current = 0;
		r_list_foreach (all_lines, iter, line) {
			if (R_STR_ISNOTEMPTY (line)) {
				if (current == rand_idx) {
					result = strdup (line);
					break;
				}
				current++;
			}
		}
	}
	r_list_free (all_lines);
	free (content);
	return result;
}

R_API RList *r_core_fortune_types(RCore *core) {
	RList *types = r_list_newf (free);
	if (r_sandbox_check (R_SANDBOX_GRAIN_FILES | R_SANDBOX_GRAIN_DISK)) {
		char *xdg_fortunes = r_xdg_datadir ("fortunes");
		if (xdg_fortunes) {
			collect_fortune_types_from_dir (types, xdg_fortunes);
			free (xdg_fortunes);
		}
		const char *fortunes_dir = r_config_get (core->config, "dir.fortunes");
		collect_fortune_types_from_dir (types, fortunes_dir);
	}
	return types;
}

R_API void r_core_fortune_print_random(RCore *core) {
	R_RETURN_IF_FAIL (core);
	if (!r_sandbox_check (R_SANDBOX_GRAIN_FILES | R_SANDBOX_GRAIN_DISK)) {
		return;
	}
	char *line = getRandomLine (core);
	if (R_STR_ISEMPTY (line)) {
		R_LOG_WARN ("No fortune in this cookie");
	} else {
		if (r_config_get_b (core->config, "cfg.fortunes.clippy")) {
			r_core_clippy (core, line);
		} else {
			r_cons_printf (core->cons, " -- %s\n", line);
		}
		if (r_config_get_b (core->config, "cfg.fortunes.tts")) {
			r_sys_tts (line, true);
		}
	}
	free (line);
}
