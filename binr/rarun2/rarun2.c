/* radare2 - Copyleft 2011-2024 - pancake */

#include <r_main.h>

int main(int argc, const char **argv) {
	char *ea = r_sys_getenv ("RARUN2_ARGS");
	if (R_STR_ISNOTEMPTY (ea)) {
		char **argv = r_str_argv (ea, &argc);
		r_sys_setenv ("RARUN2_ARGS", NULL);
		int res = r_main_rarun2 (argc, (const char **)argv);
		free (ea);
		free (argv);
		return res;
	}
	free (ea);
	return r_main_rarun2 (argc, argv);
}
