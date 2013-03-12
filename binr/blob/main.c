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

Main foo[] = {
	{ "r2", radare2_main },
	{ "rax", rax2_main },
	{ "radiff", radiff2_main },
	{ "rafind", rafind2_main },
	{ "rarun", rarun2_main },
	{ "rasm", rasm2_main },
	{ "ragg", ragg2_main },
	{ "rabin", rabin2_main },
	{ "radare", radare2_main },
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
