/* radare2 - LGPL - Copyright 2017 - pancake */

#include <r_util.h>

int main(int argc, char **argv) {
	// char *res = r_syscmd_ls ("/");
	char *res = r_syscmd_cat (" /etc/services");
	if (res) {
		printf ("%s", res);
		free (res);
	}
	return 0;
}
