/* radare - LGPL - Copyright 2007-2010 pancake<nopcode.org> */

R_API int r_log_msg(const char *str) {
	fputs ("LOG: ", stderr);
	fputs (str, stderr);
	return R_TRUE;
}

R_API int r_log_error(const char *str) {
	fputs ("ERR: ", stderr);
	fputs (str, stderr);
	return R_TRUE;
}

R_API int r_log_progress(const char *str, int percent) {
	// TODO
	return R_TRUE;
}
