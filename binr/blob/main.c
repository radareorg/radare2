/* radare - LGPL - Copyright 2012-2013 - pancake */

#include <stdio.h>
#include <string.h>

int radare2_main(int argc, char **argv);
int rasm2_main(int argc, char **argv);
int ragg2_main(int argc, char **argv);
int rabin2_main(int argc, char **argv);
int rarun2_main(int argc, char **argv);
int rafind2_main(int argc, char **argv);
int radiff2_main(int argc, char **argv);
int rax2_main(int argc, char **argv);

typedef struct {
	char *name;
	int (*main)(int argc, char **argv);
} Main;

static Main foo[] = {
	{ "r2", radare2_main },
	{ "rax2", rax2_main },
	{ "radiff2", radiff2_main },
	{ "rafind2", rafind2_main },
	{ "rarun2", rarun2_main },
	{ "rasm2", rasm2_main },
	{ "ragg2", ragg2_main },
	{ "rabin2", rabin2_main },
	{ "radare2", radare2_main },
	{ NULL, NULL }
};

int main(int argc, char **argv) {
	int i=0;
	while (foo[i].name) {
		if (strstr (argv[0], foo[i].name))
			return foo[i].main (argc, argv);
		i++;
	}
	for (i=0; foo[i].name; i++)
		printf ("%s\n", foo[i].name);
	return 1;
}
