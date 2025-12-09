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

static void collect_types(RList *types, const char *base_path) {
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
				r_list_append (types, type);
			} else {
				// Check for directories (directory name is the type)
				char *full_path = r_file_new (base_path, file, NULL);
				if (r_file_is_directory (full_path)) {
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
	RStrBuf *sb = r_strbuf_new (NULL);
	char *f;
	RListIter *iter;
	r_list_foreach (files, iter, f) {
		if (r_str_endswith (f, ".txt")) {
			char *file_path = r_file_new (dir_path, f, NULL);
			char *file_content = r_file_slurp (file_path, NULL);
			if (file_content) {
				r_strbuf_append (sb, file_content);
				free (file_content);
			}
			free (file_path);
		}
	}
	r_list_free (files);
	return r_strbuf_drain (sb);
}

static void collect_fortunes(RStrBuf *sb, const char *base_path, const char *type, const char *fname) {
	char *path = check_path (base_path, type, r_file_is_directory)
		?: check_path (base_path, fname, r_file_exists);
	if (path) {
		char *content = slurp_directory_contents (path) ?: r_file_slurp (path, NULL);
		if (content) {
			r_strbuf_append (sb, content);
			free (content);
		}
		free (path);
	}
}

static char *getFortuneContent(RCore *core, const char *type) {
	char *xdg_fortunes = r_xdg_datadir ("fortunes");
	const char *fortunes_dir = r_config_get (core->config, "dir.fortunes");
	RStrBuf *sb = r_strbuf_new (NULL);
	r_strf_var (fname, 64, "%s.txt", type);
	collect_fortunes (sb, xdg_fortunes, type, fname);
	collect_fortunes (sb, fortunes_dir, type, fname);
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
	int rand_idx = r_num_rand (r_list_length (all_lines));
	char *line = r_list_get_n (all_lines, rand_idx);
	if (line) {
		result = strdup (line);
	}
	if (R_STR_ISEMPTY (result)) {
		free (result); // sometimes we pick empty lines
		result = getRandomLine (core);
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
			collect_types (types, xdg_fortunes);
			free (xdg_fortunes);
		}
		collect_types (types, r_config_get (core->config, "dir.fortunes"));
		r_list_uniq_inplace (types, (RListComparatorItem)r_str_hash64);
	}
	return types;
}

R_API void r_core_fortune_print_random(RCore *core) {
	R_RETURN_IF_FAIL (core);
	if (r_sandbox_check (R_SANDBOX_GRAIN_FILES | R_SANDBOX_GRAIN_DISK)) {
		char *line = getRandomLine (core);
		if (R_STR_ISEMPTY (line)) {
			r_cons_println (core->cons, " -- No cookie is also a cookie");
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
}
