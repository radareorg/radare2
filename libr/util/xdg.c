/* radare2 - LGPL - Copyright 2022 - pancake */

// move into file.c ?
#include <r_util.h>
#if 0
macOS:
*  ~/Library/radare2?
Windows
* %AppData% ?= XDG_DATA_HOME
* %LocalAppData% ?= XDG_CACHE_HOME
#endif

static char *xdg(const char *env, const char *a, const char *s) {
	char *dir = r_sys_getenv (env);
	if (R_STR_ISEMPTY (dir)) {
		free (dir);
		dir = r_str_home (a);
	}
	char *res = r_file_new (dir, "radare2", s, NULL);
	free (dir);
	return res;
}

// XDG_CONFIG_HOME	User-specific configuration files	~/.var/app/<app-id>/config
R_API char *r_xdg_configdir(const char *s) {
	return xdg ("XDG_CONFIG_HOME", ".config", s);
}

// XDG_DATA_HOME	User-specific data	~/.var/app/<app-id>/data
R_API char *r_xdg_datadir(const char *s) {
	return xdg ("XDG_DATA_HOME", ".local/share", s);
}

// XDG_CACHE_HOME	Non-essential user-specific data	~/.var/app/<app-id>/cache
R_API char *r_xdg_cachedir(const char *s) {
	return xdg ("XDG_CACHE_HOME", ".cache", s);
}
