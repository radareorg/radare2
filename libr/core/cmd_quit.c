/* radare - LGPL - Copyright 2009-2016 - pancake */

#include "r_core.h"

static int cmd_Quit(void *data, const char *input) {
	RCore *core = (RCore *)data;
	if (input[0] == '!') {
		r_config_set (core->config, "scr.histsave", "false");
	}
	if (IS_DIGIT (input[0]) || input[0] == ' ') {
		core->num->value = r_num_math (core->num, input);
	} else {
		core->num->value = -1;
	}
	return -2;
}

static int cmd_quit(void *data, const char *input) {
	RCore *core = (RCore *)data;
	const char* help_msg[] = {
		"Usage:",  "q[!][!] [retval]", "",
		"q","","Выйти из программы",
		"q!","","Принудительный выход (без вопросов)",
		"q!!","","Принудительный выход без сохранения истории",
		"q"," 1","Выйти с возвращаемым значением 1",
		"q"," a-b","Выйти с возвращаемым значением a-b",
		"q[y/n][y/n]","","Выход, убив процесс или сохранив проект ",
		NULL};
	if (input)
	switch (*input) {
	case '?':
		r_core_cmd_help (core, help_msg);
		break;
	case '!':
		return cmd_Quit (core, input);
	case '\0':
		core->num->value = 0LL;
		return -2;
	default:
		while (*input == ' ') {
			input++;
		}
		if (*input) {
			r_num_math (core->num, input);
		} else {
			core->num->value = 0LL;
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
		//exit (*input?r_num_math (core->num, input+1):0);
		//if (core->http_up) return false; // cancel quit when http is running
		return -2;
	}
	return false;
}
