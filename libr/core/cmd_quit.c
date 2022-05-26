/* radare - LGPL - Copyright 2009-2022 - pancake */

#include "r_core.h"

static const char *help_msg_q[] = {
	"Usage:",  "q[!][!] [retval]", "",
	"q","","quit program",
	"q!","","force quit (no questions)",
	"q!!","","force quit without saving history",
	"q!!!","","force quit without freeing anything",
	"q"," 1","quit with return value 1",
	"q"," a-b","quit with return value a-b",
	"q[y/n][y/n]","","quit, chose to kill process, chose to save project ",
	"Q","", "same as q!!",
	NULL
};

static int cmd_Quit(void *data, const char *input) {
	RCore *core = (RCore *)data;
	if (input[0] == '!') {
		if (input[1] == '!' || !input[1]) {
			if (!r_sandbox_enable (false)) {
				r_cons_flush ();
				exit (0);
			}
			return R_CMD_RC_QUIT;
		}
		r_config_set (core->config, "scr.hist.save", "false");
	}
	if (IS_DIGIT (input[0]) || input[0] == ' ') {
		r_core_return_code (core, r_num_math (core->num, input));
	} else {
		r_core_return_code (core, R_CMD_RC_QUIT);
	}
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
		r_core_return_code (core, R_CMD_RC_QUIT);
		return R_CMD_RC_QUIT;
	default:
		while (*input == ' ') {
			input++;
		}
		if (*input) {
			r_num_math (core->num, input);
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
