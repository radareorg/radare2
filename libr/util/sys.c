/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_types.h>
/* TODO: import stuff fron bininfo/p/bininfo_addr2line */

R_API char *r_sys_cmd_str(const char *cmd)
{
	return NULL;
}

R_API char *r_sys_cmd_strf(const char *cmd, ...)
{
	return NULL;
}

R_API int r_sys_sleep(int secs)
{
#if __UNIX__
	return sleep(secs);
#else
	Sleep(secs);
	return 0;
#endif
}

R_API int r_sys_usleep(int usecs)
{
#if __UNIX__
	return usleep(usecs);
#else
	/* TODO */
	return -1;
#endif
}

R_API int r_sys_setenv(const char *key, const char *value, int ow)
{
#if __UNIX__
	return setenv(key, value, ow);
#else
#warning TODO: r_sys_setenv
#endif
}

R_API const char *r_sys_getenv(const char *key)
{
#if __UNIX__
	return getenv(key);
#else
#warning TODO: r_sys_getenv
#endif
}
