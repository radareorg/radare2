/* radare2 - LGPL - Copyright 2017 - pancake */

#include <r_util.h>

typedef char* (*CommandCallback)(const char *args);

typedef struct {
	const char *cmd;
	CommandCallback cb;
} BbCommands;

static BbCommands bbcmds[] = {
	{ "cat", r_syscmd_cat },
	{ "ls", r_syscmd_ls },
	NULL
};

static int run(int i, const char *arg) {
	char *res = bbcmds[i].cb (arg);
	if (res) {
		printf ("%s", res);
		free (res);
		return 0;
	}
	return 1;
}

int main(int argc, char **argv) {
	int i;
	for (i = 0; bbcmds[i].cmd; i++) {
		if (!strcmp (bbcmds[i].cmd, argv[0])) {
			const char *arg = argc > 1? argv[1]: NULL;
			return run (i, arg);
		}
	}
	if (argc > 1) {
		for (i = 0; bbcmds[i].cmd; i++) {
			if (!strcmp (bbcmds[i].cmd, argv[1])) {
				const char *arg = argc > 2? argv[2]: NULL;
				return run (i, arg);
			}
		}
	}
	for (i = 0; bbcmds[i].cmd; i++) {
		printf ("%s\n", bbcmds[i].cmd);
	}
	return 1;
}
