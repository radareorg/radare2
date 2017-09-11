#include "r_core.h"

static const struct {
	const char *type;
	const char *filename;
} fortunes[] = {
	{"tips" , R2_PREFIX "/share/doc/radare2/fortunes.tips"},
	{"fuun" , R2_PREFIX "/share/doc/radare2/fortunes.fun"},
	{"nsfw" , R2_PREFIX "/share/doc/radare2/fortunes.nsfw"},
	{"crep" , R2_PREFIX "/share/doc/radare2/fortunes.creepy"},
};

R_API void r_core_fortune_list_types(void) {
	int i;
	for (i = 0; i < R_ARRAY_SIZE (fortunes); i++) {
		r_cons_printf ("%s\n", fortunes[i].type);
	}
}

R_API void r_core_fortune_list(RCore *core) {
	// TODO: use file.fortunes // can be dangerous in sandbox mode
	const char *types = (char *)r_config_get (core->config, "cfg.fortunes.type");
	char *str;
	int i, j;
	for (i = 0; i < R_ARRAY_SIZE (fortunes); i++) {
		if (strstr (types, fortunes[i].type) && (str = r_file_slurp (fortunes[i].filename, NULL))) {
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
		}
	}
}

static char *getrandomline(RCore *core) {
	int i, lines = 0;
	const char *types = (char *)r_config_get (core->config, "cfg.fortunes.type");
	char *line = NULL, *templine;
	for (i = 0; i < R_ARRAY_SIZE (fortunes); i++) {
		if (strstr (types, fortunes[i].type)) {
			templine = r_file_slurp_random_line_count (fortunes[i].filename, &lines);
			if (templine && *templine) {
				free (line);
				line = templine;
			}
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
			r_core_clippy (line);
		} else {
			r_cons_printf (" -- %s\n", line);
		}
		if (r_config_get_i (core->config, "cfg.fortunes.tts")) {
			r_sys_tts (line, true);
		}
		free (line);
	}
}
