/* radare2 - LGPL - Copyright 2009-2024 - pancake, condret */

#include <r_core.h>

static char *getFortuneFile(RCore *core, const char *type) {
	if (!r_sandbox_check (R_SANDBOX_GRAIN_FILES | R_SANDBOX_GRAIN_DISK)) {
		return NULL;
	}
	r_strf_var (fname, 64, "fortunes.%s", type);
	char *fortunedir = r_xdg_datadir ("fortunes");
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
			char *str = r_file_slurp (file, NULL);
			if (!str) {
				free (file);
				continue;
			}
			r_cons_println (core->cons, str);
			free (str);
			free (file);
		}
	}
	r_list_free (ftypes);
}

static char *getrandomline(RCore *core) {
	RList *types = r_str_split_duplist (
		r_config_get (core->config, "cfg.fortunes.type"), ",", false);
	if (r_list_empty (types)) {
		r_list_free (types);
		return NULL;
	}
	const char *file = (const char *)r_list_get_n (types, r_num_rand (r_list_length (types)));
	char *type = R_STR_DUP (file);
	r_list_free (types);
	if (!type) {
		return NULL;
	}
	char *line = NULL, *templine;
	RList *ftypes = r_core_fortune_types ();
	if (!ftypes) {
		free (type);
		return NULL;
	}
	RListIter *iter;
	char *fortunes;
	r_list_foreach (ftypes, iter, fortunes) {
		if (!strcmp (type, fortunes)) {
			int lines = 0;
			char *file = getFortuneFile (core, fortunes);
			if (file) {
				templine = r_file_slurp_random_line_count (file, &lines);
				if (templine && *templine) {
					free (line);
					line = templine;
				}
				free (file);
			}
		}
	}
	free (type);
	r_list_free (ftypes);
	return line;
}

R_API void r_core_fortune_print_random(RCore *core) {
	R_RETURN_IF_FAIL (core);
	if (!r_sandbox_check (R_SANDBOX_GRAIN_FILES | R_SANDBOX_GRAIN_DISK)) {
		return;
	}
	char *line = getrandomline (core);
	if (!line) {
		line = getrandomline (core);
	}
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
