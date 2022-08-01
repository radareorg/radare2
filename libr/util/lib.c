/* radare - LGPL - Copyright 2008-2022 - pancake */

#include <r_util.h>
#include <r_lib.h>

R_LIB_VERSION(r_lib);

/* TODO: avoid globals */
#define IFDBG if(__has_debug)
static R_TH_LOCAL bool __has_debug = false;

/* XXX : this must be registered in runtime */
static const char *r_lib_types[] = {
	"io", "dbg", "lang", "asm", "anal", "parse", "bin", "bin_xtr", "bin_ldr",
	"bp", "syscall", "fastcall", "crypto", "core", "egg", "fs", NULL
};

static const char *__lib_types_get(int idx) {
	if (idx < 0 || idx > R_LIB_TYPE_LAST - 1) {
		return "unk";
	}
	return r_lib_types[idx];
}

R_API int r_lib_types_get_i(const char *str) {
	int i;
	for (i = 0; r_lib_types[i]; i++) {
		if (!strcmp (str, r_lib_types[i])) {
			return i;
		}
	}
	return -1;
}

R_API void *r_lib_dl_open(const char *libname) {
	void *ret = NULL;
#if WANT_DYLINK
#if __UNIX__
	if (libname) {
#if __linux__
		ret = dlopen (libname, RTLD_NOW);
#endif
		if (!ret) {
			ret = dlopen (libname, RTLD_GLOBAL | RTLD_LAZY);
		}
	} else {
		ret = dlopen (NULL, RTLD_NOW);
	}
	if (!ret && __has_debug) {
		eprintf ("r_lib_dl_open: error: %s (%s)\n", libname, dlerror ());
	}
#elif __WINDOWS__
	LPTSTR libname_;
	if (libname && *libname) {
		libname_ = r_sys_conv_utf8_to_win (libname);
	} else {
		libname_ = calloc (MAX_PATH, sizeof (TCHAR));
		if (!libname_) {
			return NULL;
		}
		if (!GetModuleFileName (NULL, libname_, MAX_PATH)) {
			libname_[0] = '\0';
		}
	}
	ret = LoadLibrary (libname_);
	free (libname_);
	if (!ret && __has_debug) {
		eprintf ("r_lib_dl_open: error: %s\n", libname);
	}
#endif
#endif
	return ret;
}

R_API void *r_lib_dl_sym(void *handler, const char *name) {
#if WANT_DYLINK
#if __UNIX__
	return dlsym (handler, name);
#elif __WINDOWS__
	return GetProcAddress (handler, name);
#else
	return NULL;
#endif
#else
	return NULL;
#endif
}

R_API int r_lib_dl_close(void *handler) {
#if __UNIX__ && WANT_DYLINK
	return dlclose (handler);
#else
	return handler? 0: -1;
#endif
}

R_API char *r_lib_path(const char *libname) {
#if __WINDOWS__
	char *tmp = r_str_newf ("%s." R_LIB_EXT, libname);
	if (!tmp) {
		return NULL;
	}
	WCHAR *name = r_utf8_to_utf16 (tmp);
	free (tmp);
	WCHAR *path = NULL;
	if (!name) {
		goto err;
	}

	int count;
	if (!(count = SearchPathW (NULL, name, NULL, 0, NULL, NULL))) {
		r_sys_perror ("SearchPath");
		goto err;
	}
	path = malloc (count * sizeof (WCHAR));
	if (!path) {
		goto err;
	}
	if (!(count = SearchPathW (NULL, name, NULL, count, path, NULL))) {
		R_FREE (path);
		r_sys_perror ("SearchPath");
		goto err;
	}
	tmp = r_utf16_to_utf8 (path);
	free (name);
	free (path);
	return tmp;
err:
	free (name);
	return NULL;
#else
#if __APPLE__
	char *env = r_sys_getenv ("DYLD_LIBRARY_PATH");
	env = r_str_append (env, ":/lib:/usr/lib:/usr/local/lib");
#elif __UNIX__
	char *env = r_sys_getenv ("LD_LIBRARY_PATH");
	env = r_str_append (env, ":/lib:/usr/lib:/usr/local/lib");
#endif
	if (!env) {
		env = strdup (".");
	}
	char *next, *path0 = env;
	do {
		next = strchr (path0, ':');
		if (next) {
			*next = 0;
		}
		char *libpath = r_str_newf ("%s"R_SYS_DIR"%s." R_LIB_EXT, path0, libname);
		if (r_file_exists (libpath)) {
			free (env);
			return libpath;
		}
		free (libpath);
		path0 = next + 1;
	} while (next);
	free (env);
	return NULL;
#endif
}

R_API RLib *r_lib_new(const char *symname, const char *symnamefunc) {
	RLib *lib = R_NEW (RLib);
	if (lib) {
		__has_debug = r_sys_getenv_asbool ("R2_DEBUG");
		lib->ignore_version = r_sys_getenv_asbool ("R2_IGNVER");
		lib->handlers = r_list_newf (free);
		lib->plugins = r_list_newf (free);
		lib->symname = strdup (symname? symname: R_LIB_SYMNAME);
		lib->symnamefunc = strdup (symnamefunc? symnamefunc: R_LIB_SYMFUNC);
	}
	return lib;
}

R_API void r_lib_free(RLib *lib) {
	if (lib) {
		r_lib_close (lib, NULL);
		r_list_free (lib->handlers);
		r_list_free (lib->plugins);
		free (lib->symname);
		free (lib->symnamefunc);
		free (lib);
	}
}

static bool __lib_dl_check_filename(const char *file) {
	return r_str_endswith (file, "." R_LIB_EXT);
}

R_API int r_lib_run_handler(RLib *lib, RLibPlugin *plugin, RLibStruct *symbol) {
	RLibHandler *h = plugin->handler;
	if (h && h->constructor) {
		IFDBG eprintf ("PLUGIN LOADED %p fcn %p\n", h, h->constructor);
		return h->constructor (plugin, h->user, symbol->data);
	}
	IFDBG R_LOG_ERROR ("Cannot find plugin constructor");
	return -1;
}

R_API RLibHandler *r_lib_get_handler(RLib *lib, int type) {
	RLibHandler *h;
	RListIter *iter;
	r_list_foreach (lib->handlers, iter, h) {
		if (h->type == type) {
			return h;
		}
	}
	return NULL;
}

R_API int r_lib_close(RLib *lib, const char *file) {
	RLibPlugin *p;
	RListIter *iter, *iter2;
	r_list_foreach_safe (lib->plugins, iter, iter2, p) {
		if ((!file || !strcmp (file, p->file))) {
			int ret = 0;
			if (p->handler && p->handler->destructor) {
				ret = p->handler->destructor (p, p->handler->user, p->data);
			}
			if (p->free) {
				p->free (p->data);
			}
			free (p->file);
			r_list_delete (lib->plugins, iter);
			if (file) {
				return ret;
			}
		}
	}
	if (!file) {
		return 0;
	}
	// delete similar plugin name
	r_list_foreach (lib->plugins, iter, p) {
		if (strstr (p->file, file)) {
			int ret = 0;
			if (p->handler && p->handler->destructor) {
				ret = p->handler->destructor (p,
					p->handler->user, p->data);
			}
			eprintf ("Unloaded %s\n", p->file);
			free (p->file);
			r_list_delete (lib->plugins, iter);
			return ret;
		}
	}
	return -1;
}

static bool __already_loaded(RLib *lib, const char *file) {
	const char *fileName = r_str_rstr (file, R_SYS_DIR);
	RLibPlugin *p;
	RListIter *iter;
	if (fileName) {
		r_list_foreach (lib->plugins, iter, p) {
			const char *pFileName = r_str_rstr (p->file, R_SYS_DIR);
			if (pFileName && !strcmp (fileName, pFileName)) {
				return true;
			}
		}
	}
	return false;
}

R_API int r_lib_open(RLib *lib, const char *file) {
	/* ignored by filename */
	if (!__lib_dl_check_filename (file)) {
		eprintf ("Invalid library extension: %s\n", file);
		return -1;
	}

	if (__already_loaded (lib, file)) {
		eprintf ("Not loading library because it has already been loaded from somewhere else: '%s'\n", file);
		return -1;
	}

	void *handler = r_lib_dl_open (file);
	if (!handler) {
		IFDBG R_LOG_ERROR ("Cannot open library: '%s'", file);
		return -1;
	}

	RLibStructFunc strf = (RLibStructFunc) r_lib_dl_sym (handler, lib->symnamefunc);
	RLibStruct *stru = NULL;
	if (strf) {
		stru = strf ();
	}
	if (!stru) {
		stru = (RLibStruct *) r_lib_dl_sym (handler, lib->symname);
	}
	if (!stru) {
		IFDBG R_LOG_ERROR ("Cannot find symbol '%s' in library '%s'",
			lib->symname, file);
		r_lib_dl_close (handler);
		return -1;
	}

	int res = r_lib_open_ptr (lib, file, handler, stru);
	if (strf) {
		free (stru);
	}
	return res;
}

static char *major_minor(const char *s) {
	char *a = strdup (s);
	char *p = strchr (a, '.');
	if (p) {
		p = strchr (p + 1, '.');
		if (p) {
			*p = 0;
		}
	}
	return a;
}

R_API int r_lib_open_ptr(RLib *lib, const char *file, void *handler, RLibStruct *stru) {
	r_return_val_if_fail (lib && file && stru, -1);
	if (stru->version && !lib->ignore_version) {
		char *mm0 = major_minor (stru->version);
		char *mm1 = major_minor (R2_VERSION);
		bool mismatch = strcmp (mm0, mm1);
		free (mm0);
		free (mm1);
		if (mismatch) {
			R_LOG_WARN ("Module version mismatch %s (%s) vs (%s)", file, stru->version, R2_VERSION);
			const char *dot = strchr (stru->version, '.');
			int major = atoi (stru->version);
			int minor = dot ? atoi (dot + 1) : 0;
			// The pkgname member was introduced in 4.2.0
			if (major > 4 || (major == 4 && minor >= 2)) {
				if (stru->pkgname) {
					printf ("r2pm -ci %s\n", stru->pkgname);
				}
			}
			return -1;
		}
	}
	RLibPlugin *p = R_NEW0 (RLibPlugin);
	p->type = stru->type;
	p->data = stru->data;
	p->file = strdup (file);
	p->dl_handler = handler;
	p->handler = r_lib_get_handler (lib, p->type);
	p->free = stru->free;

	int ret = r_lib_run_handler (lib, p, stru);
	if (ret == -1) {
		R_LOG_DEBUG ("Library handler has failed for '%s'", file);
		free (p->file);
		free (p);
		r_lib_dl_close (handler);
	} else {
		r_list_append (lib->plugins, p);
	}

	return ret;
}

R_API bool r_lib_opendir(RLib *lib, const char *path) {
#if WANT_DYLINK
	r_return_val_if_fail (lib && path, false);
#if __WINDOWS__
	wchar_t file[1024];
	WIN32_FIND_DATAW dir;
	HANDLE fh;
	wchar_t directory[MAX_PATH];
	wchar_t *wcpath;
	char *wctocbuff;
#else
	char file[1024];
	struct dirent *de;
	DIR *dh;
#endif
#ifdef R2_LIBR_PLUGINS
	if (!path) {
		path = R2_LIBR_PLUGINS;
	}
#endif
	if (!path) {
		return false;
	}
#if __WINDOWS__
	wcpath = r_utf8_to_utf16 (path);
	if (!wcpath) {
		return false;

	}
	swprintf (directory, _countof (directory), L"%ls\\*.*", wcpath);
	fh = FindFirstFileW (directory, &dir);
	if (fh == INVALID_HANDLE_VALUE) {
		IFDBG R_LOG_ERROR ("Cannot open directory %ls", wcpath);
		free (wcpath);
		return false;
	}
	do {
		swprintf (file, _countof (file), L"%ls/%ls", wcpath, dir.cFileName);
		wctocbuff = r_utf16_to_utf8 (file);
		if (wctocbuff) {
			if (__lib_dl_check_filename (wctocbuff)) {
				r_lib_open (lib, wctocbuff);
			} else {
				IFDBG R_LOG_ERROR ("Cannot open %ls", dir.cFileName);
			}
			free (wctocbuff);
		}
	} while (FindNextFileW (fh, &dir));
	FindClose (fh);
	free (wcpath);
#else
	dh = opendir (path);
	if (!dh) {
		IFDBG R_LOG_ERROR ("Cannot open directory '%s'", path);
		return false;
	}
	while ((de = (struct dirent *)readdir (dh))) {
		if (de->d_name[0] == '.' || strstr (de->d_name, ".dSYM")) {
			continue;
		}
		snprintf (file, sizeof (file), "%s/%s", path, de->d_name);
		if (__lib_dl_check_filename (file)) {
			IFDBG R_LOG_INFO ("Loading %s", file);
			r_lib_open (lib, file);
		} else {
			IFDBG R_LOG_ERROR ("Cannot open %s", file);
		}
	}
	closedir (dh);
#endif
#endif
	return true;
}

R_API bool r_lib_add_handler(RLib *lib,
	int type, const char *desc,
	int (*cb)(RLibPlugin *, void *, void *),  /* constructor */
	int (*dt)(RLibPlugin *, void *, void *),  /* destructor */
	void *user)
{
	RLibHandler *h;
	RListIter *iter;
	RLibHandler *handler = NULL;

	r_list_foreach (lib->handlers, iter, h) {
		if (type == h->type) {
			IFDBG eprintf ("Redefining library handler constructor for %d\n", type);
			handler = h;
			break;
		}
	}
	if (!handler) {
		handler = R_NEW (RLibHandler);
		if (!handler) {
			return false;
		}
		handler->type = type;
		r_list_append (lib->handlers, handler);
	}
	strncpy (handler->desc, desc, sizeof (handler->desc)-1);
	handler->user = user;
	handler->constructor = cb;
	handler->destructor = dt;

	return true;
}

R_API bool r_lib_del_handler(RLib *lib, int type) {
	RLibHandler *h;
	RListIter *iter;
	// TODO: remove all handlers for that type? or only one?
	/* No _safe loop necessary because we return immediately after the delete. */
	r_list_foreach (lib->handlers, iter, h) {
		if (type == h->type) {
			r_list_delete (lib->handlers, iter);
			return true;
		}
	}
	return false;
}

// TODO _list methods should not exist.. only used in ../core/cmd_log.c: r_lib_list (core->lib);
R_API void r_lib_list(RLib *lib) {
	RListIter *iter;
	RLibPlugin *p;
	r_list_foreach (lib->plugins, iter, p) {
		printf (" %5s %p %s \n", __lib_types_get (p->type),
			p->dl_handler, p->file);
	}
}
