/* radare2 - LGPL - Copyright 2009-2020 - pancake */

#include <r_core.h>

static const char *fortunes[] = {
	"tips", "fun",
};

static char *getFortuneFile(RCore *core, const char *type) {
	return r_str_newf (R_JOIN_3_PATHS ("%s", R2_FORTUNES, "fortunes.%s"),
		r_sys_prefix (NULL), type);
}

R_API void r_core_fortune_list_types(void) {
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (fortunes); i++) {
		r_cons_printf ("%s\n", fortunes[i]);
	}
}

R_API void r_core_fortune_list(RCore *core) {
	// TODO: use file.fortunes // can be dangerous in sandbox mode
	const char *types = (char *)r_config_get (core->config, "cfg.fortunes.type");
	size_t i, j;
	for (i = 0; i < R_ARRAY_SIZE (fortunes); i++) {
		if (strstr (types, fortunes[i])) {
			char *file = getFortuneFile (core, fortunes[i]);
			char *str = r_file_slurp (file, NULL);
			if (!str) {
				free (file);
				continue;
			}
			for (j = 0; str[j]; j++) {
				if (str[j] == '\n') {
					if (i < j) {
						str[j] = '\0';
						r_cons_printf ("%s\n", str + i);
					}
					i = j + 1;
				}
			}
			free (str);
			free (file);
		}
	}
}

static char *getrandomline(RCore *core) {
	size_t i;
	const char *types = (char *)r_config_get (core->config, "cfg.fortunes.type");
	char *line = NULL, *templine;
	for (i = 0; i < R_ARRAY_SIZE (fortunes); i++) {
		if (strstr (types, fortunes[i])) {
			int lines = 0;
			char *file = getFortuneFile(core, fortunes[i]);
			templine = r_file_slurp_random_line_count (file, &lines);
			if (templine && *templine) {
				free (line);
				line = templine;
			}
			free (file);
		}
	}
	return line;
}

R_API void r_core_fortune_print_random(RCore *core) {
	// TODO: use file.fortunes // can be dangerous in sandbox mode
	char *line = getrandomline (core);
	if (!line) {
		line = getrandomline (core);
	}
	if (line) {
		if (r_config_get_i (core->config, "cfg.fortunes.clippy")) {
			r_core_clippy (core, line);
		} else {
			r_cons_printf (" -- %s\n", line);
		}
		if (r_config_get_i (core->config, "cfg.fortunes.tts")) {
			r_sys_tts (line, true);
		}
		free (line);
	}
}
