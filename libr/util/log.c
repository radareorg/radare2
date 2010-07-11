/* radare - LGPL - Copyright 2007-2010 pancake<nopcode.org> */

#include <r_util.h>

static const char *logfile = "radare.log";

R_API void r_log_file(const char *str) {
	FILE *fd = fopen (logfile, "a+");
	if (fd) {
		fputs (str, fd);
		fclose (fd);
	} else eprintf ("ERR: Cannot open %s\n", logfile);
}

R_API void r_log_msg(const char *str) {
	fputs ("LOG: ", stderr);
	fputs (str, stderr);
	r_log_file (str);
}

R_API void r_log_error(const char *str) {
	fputs ("ERR: ", stderr);
	fputs (str, stderr);
	r_log_file(str);
}

R_API void r_log_progress(const char *str, int percent) {
	printf ("%d%%: %s\n", percent, str);
}
