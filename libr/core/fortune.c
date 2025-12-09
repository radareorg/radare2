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
	RList *line_starts = r_list_new ();
	char *p = content;
	char *start = content;
	while (*p) {
		if (*p == '\n') {
			*p = '\0';
			if (R_STR_ISNOTEMPTY (start)) {
				r_list_push (line_starts, start);
			}
			start = p + 1;
		}
		p++;
	}
	if (R_STR_ISNOTEMPTY (start)) {
		r_list_push (line_starts, start);
	}
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
