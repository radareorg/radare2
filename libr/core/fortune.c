/* radare2 - LGPL - Copyright 2009-2022 - pancake, condret */

#include <r_core.h>
#include <r_util.h>

static char *getFortuneFile(RCore *core, const char *type) {
	char *home = r_sys_getenv (R_SYS_HOME);
	if (!home) {
		return NULL;
	}
	char *path = r_str_newf (R_JOIN_3_PATHS ("%s", R2_HOME_FORTUNES, "fortunes.%s"),
		home, type);
	free (home);
	if (path && r_file_exists (path)) {
		return path;
	}
	free (path);
	return r_str_newf (R_JOIN_3_PATHS ("%s", R2_FORTUNES, "fortunes.%s"),
		r_sys_prefix (NULL), type);
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
			r_list_push (type_list, r_str_new (file + 9));
		}
	}
	r_list_free (files);
	return true;
}

R_IPI RList *r_core_fortune_types(void) {	// R_API 5.8
	RList *types = r_list_newf (free);
	if (!types) {
		return NULL;
	}
	char *fortune_dir = r_str_newf (R_JOIN_2_PATHS ("%s", R2_FORTUNES), r_sys_prefix (NULL));
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
	fortune_dir = r_str_home (R2_HOME_FORTUNES);
	if (fortune_dir) {
		_push_types (types, fortune_dir);
		free (fortune_dir);
	}
	return types;
}

R_API void r_core_fortune_list_types(void) {
	RList *types = r_core_fortune_types ();
	char *fts = r_str_list_join (types, "\n");
	r_list_free (types);
	r_cons_println (fts);
	free (fts);
}

R_API void r_core_fortune_list(RCore *core) {
	// TODO: use file.fortunes // can be dangerous in sandbox mode
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
			r_cons_println (str);
			free (str);
			free (file);
		}
	}
	r_list_free (ftypes);
}

static char *getrandomline(RCore *core) {
	const char *types = (char *)r_config_get (core->config, "cfg.fortunes.type");
	char *line = NULL, *templine;
	RList *ftypes = r_core_fortune_types ();
	if (!ftypes) {
		return NULL;
	}
	RListIter *iter;
	char *fortunes;
	r_list_foreach (ftypes, iter, fortunes) {
		if (strstr (types, fortunes)) {
			int lines = 0;
			char *file = getFortuneFile (core, fortunes);
			templine = r_file_slurp_random_line_count (file, &lines);
			if (templine && *templine) {
				free (line);
				line = templine;
			}
			free (file);
		}
	}
	r_list_free (ftypes);
	return line;
}

R_API void r_core_fortune_print_random(RCore *core) {
	// TODO: use file.fortunes // can be dangerous in sandbox mode
	char *line = getrandomline (core);
	if (!line) {
		line = getrandomline (core);
	}
	if (R_STR_ISNOTEMPTY (line)) {
		if (r_config_get_b (core->config, "cfg.fortunes.clippy")) {
			r_core_clippy (core, line);
		} else {
			r_cons_printf (" -- %s\n", line);
		}
		if (r_config_get_b (core->config, "cfg.fortunes.tts")) {
			r_sys_tts (line, true);
		}
		free (line);
	}
}
