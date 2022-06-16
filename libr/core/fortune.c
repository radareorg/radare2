/* radare2 - LGPL - Copyright 2009-2022 - pancake, condret */

#include <r_core.h>
#include <r_util.h>

static char *getFortuneFile(RCore *core, const char *type) {
	return r_str_newf (R_JOIN_3_PATHS ("%s", R2_FORTUNES, "fortunes.%s"),
		r_sys_prefix (NULL), type);
}

R_API RList *r_core_fortune_types(void) {
	RList *types = r_list_newf (free);
	if (!types) {
		return NULL;
	}
	char *fortune_dir = r_str_newf (R_JOIN_2_PATHS ("%s", R2_FORTUNES), r_sys_prefix (NULL));
	if (!fortune_dir) {
		r_list_free (types);
	}
	RList *files = r_sys_dir (fortune_dir);
	free (fortune_dir);
	if (!files) {
		r_list_free (types);
		return NULL;
	}
	RListIter *iter;
	char *file;
	r_list_foreach (files, iter, file) {
		if (r_str_startswith (file, "fortunes.") && file[9]) {
			r_list_append (types, r_str_new (&file[9]));
		}
	}
	r_list_free (files);
	return types;
}

R_API void r_core_fortune_list_types(void) {
	RList *types = r_core_fortune_types ();
	while (!r_list_empty (types)) {
		char *type = r_list_pop (types);
		r_cons_printf ("%s\n", type);
		free (type);
	}
	r_list_free (types);
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
			r_cons_printf ("%s\n", str);
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
			char *file = getFortuneFile(core, fortunes);
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
