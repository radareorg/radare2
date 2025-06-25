/* radare - LGPL - Copyright 2009-2025 - pancake */

#if R_INCLUDE_BEGIN

static RCoreHelpMessage help_msg_q = {
	"Usage:",  "q[!][!] [retval]", "",
	"q", "", "quit program",
	"q!", "", "force quit (no questions)",
	"q!!", "", "force quit without saving history",
	"q!!!", "", "force quit without freeing anything",
	"q", " 1", "quit with return value 1",
	"q", " a-b", "quit with return value a-b",
	"q[y/n][y/n]", "", "quit, chose to kill process, chose to save project ",
	"Q", "", "same as q!!",
	NULL
};

static int cmd_Quit(void *data, const char *input) {
	RCore *core = (RCore *)data;
	const char *arg = strchr (input, ' ');
	unsigned int exclamations = 0;
	if (!arg) {
		while (*input == '!') {
			if (exclamations < 4) {
				exclamations++;
			}
			input++;
		}
		arg = input;
	}
	const int rv = arg? r_num_math (core->num, arg): 0;
	if (exclamations > 0) { // "q!"
		r_config_set_b (core->config, "scr.hist.save", false);
		if (exclamations > 1) {
			if (!r_sandbox_enable (false)) {
				r_cons_flush (core->cons);
				exit (rv);
			}
			return R_CMD_RC_QUIT;
		}
	}
	r_core_return_code (core, rv);
	return R_CMD_RC_QUIT;
}

static int cmd_quit(void *data, const char *input) {
	RCore *core = (RCore *)data;
	if (input)
	switch (*input) {
	case '?':
		r_core_cmd_help (core, help_msg_q);
		break;
	case '!': // "q!"
		return cmd_Quit (core, input);
	case '\0': // "q"
		r_core_return_code (core, 0);
		return R_CMD_RC_QUIT;
	default:
		input = r_str_trim_head_ro (input);
		if (*input) {
			r_core_return_code (core, r_num_math (core->num, input));
		} else {
			core->num->value = 0LL;
			r_core_return_code (core, 0);
		}
		if (*input == 'y') {
			core->num->value = 5;
		} else if (*input == 'n') {
			core->num->value = 1;
		}
		if (input[1] == 'y') {
			core->num->value += 10;
		} else if (input[1] == 'n') {
			core->num->value += 2;
		}
		return R_CMD_RC_QUIT;
	}
	return R_CMD_RC_SUCCESS;
}

#endif
