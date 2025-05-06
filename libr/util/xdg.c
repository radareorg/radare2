/* radare2 - LGPL - Copyright 2022-2025 - pancake */

#include <r_util.h>

#if 0
Linux:
* ~/.local/share/radare2/
macOS:
*  ~/Library/radare2?
Windows
* %AppData% ?= XDG_DATA_HOME
* %LocalAppData% ?= XDG_CACHE_HOME
#endif

static char * R_NULLABLE xdg(const char * R_NONNULL env, const char *a, const char *s) {
	char *dir = r_sys_getenv (env);
	if (R_STR_ISEMPTY (dir)) {
		free (dir);
		dir = r_file_home (a);
		if (R_STR_ISEMPTY (dir)) {
			free (dir);
			return NULL;
		}
	}
	if (s) {
		char *res = r_file_new (dir, "radare2", s, NULL);
		free (dir);
		return res;
	}
	return dir;
}

// XDG_CONFIG_HOME : User-specific configuration files (~/.var/app/<app-id>/config)
R_API char * R_NULLABLE r_xdg_configdir(const char * R_NULLABLE s) {
	return xdg ("XDG_CONFIG_HOME", ".config", s);
}

// XDG_DATA_HOME : User-specific data (~/.var/app/<app-id>/data)
R_API char * R_NULLABLE r_xdg_datadir(const char * R_NULLABLE s) {
	return xdg ("XDG_DATA_HOME", ".local" R_SYS_DIR "share", s);
}

// XDG_CACHE_HOME : Non-essential user-specific data (~/.var/app/<app-id>/cache)
R_API char * R_NULLABLE r_xdg_cachedir(const char * R_NULLABLE s) {
	return xdg ("XDG_CACHE_HOME", ".cache", s);
}
