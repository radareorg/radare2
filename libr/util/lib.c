/* radare - LGPL - Copyright 2008-2018 - pancake */

#include "r_types.h"
#include "r_util.h"
#include "r_lib.h"
#include <stdio.h>

R_LIB_VERSION(r_lib);

/* TODO: support for nested plugins ?? here */

#if __UNIX__
#include <dlfcn.h>
  #define DLOPEN(x)  dlopen(x, RTLD_GLOBAL | RTLD_LAZY)
  #define DLSYM(x,y) dlsym(x,y)
  #define DLCLOSE(x) dlclose(x)
#elif __WINDOWS__
#include <windows.h>
  #define DLOPEN(x)  LoadLibrary(x)
  #define DLSYM(x,y) GetProcAddress(x,y)
  #define DLCLOSE(x) 0//(x)
//CloseLibrary(x)
#else
  #define DLOPEN(x)  NULL
  #define DLSYM(x,y) NULL
  #define DLCLOSE(x) NULL
#endif

/* XXX : this must be registered in runtime */
static const char *r_lib_types[] = {
	"io", "dbg", "lang", "asm", "anal", "parse", "bin", "bin_xtr",
	"bp", "syscall", "fastcall", "crypto", "core", "egg", "fs", NULL
};

static int __has_debug = 0;

#define IFDBG if(__has_debug)

/* XXX: Rename this helper function */
R_API const char *r_lib_types_get(int idx) {
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
	void *ret;
#if __UNIX__
	if (!libname) {
		return dlopen (NULL, RTLD_NOW);
	}
#endif
	if (!libname || !*libname) {
		return NULL;
	}
#if __WINDOWS__
	LPTSTR libname_;

	libname_ = r_sys_conv_utf8_to_utf16 (libname);
	ret = DLOPEN (libname_);
#else
	ret = DLOPEN (libname);
#endif
	if (__has_debug && !ret) {
#if __UNIX__
		eprintf ("dlerror(%s): %s\n", libname, dlerror ());
#else
		eprintf ("r_lib_dl_open: Cannot open '%s'\n", libname);
#endif
	}
#if __WINDOWS__
	free (libname_);
#endif
	return ret;
}

R_API void *r_lib_dl_sym(void *handler, const char *name) {
	return DLSYM (handler, name);
}

R_API int r_lib_dl_close(void *handler) {
	int ret = -1;
	if (handler) {
		ret = DLCLOSE (handler);
	}
	return ret;
}

/* ---- */

R_API char *r_lib_path(const char *libname) {
	char *next, *path0, libpath[1024];
#if __APPLE__
	char *env = r_sys_getenv ("DYLD_LIBRARY_PATH");
	const char *ext = ".dylib";
	env = r_str_append (env, ":/lib:/usr/lib:/usr/local/lib");
#elif __UNIX__
	char *env = r_sys_getenv ("LD_LIBRARY_PATH");
	const char *ext = ".so";
	env = r_str_append (env, ":/lib:/usr/lib:/usr/local/lib");
#else
	char *env = strdup (".:../../../../../../../windows/system32");
	const char *ext = ".dll";
#endif
	if (!env) {
		env = strdup (".");
	}
	path0 = env;
	do {
		next = strchr (path0, ':');
		if (next) {
			*next = 0;
		}
		snprintf (libpath, sizeof (libpath), "%s/%s%s", path0, libname, ext);
		//eprintf ("--> %s\n", libpath);
		if (r_file_exists (libpath)) {
			free (env);
			return strdup (libpath);
		}
		path0 = next+1;
	} while (next);
	free (env);
	return NULL;
}

R_API RLib *r_lib_new(const char *symname) {
	RLib *lib = R_NEW (RLib);
	char *env_debug;
	if (lib) {
		env_debug = r_sys_getenv ("R_DEBUG");
		__has_debug = env_debug ? true : false;
		if (env_debug) {
			free (env_debug);
		}
		lib->handlers = r_list_newf (free);
		lib->plugins = r_list_newf (free);
		strncpy (lib->symname, symname, sizeof (lib->symname)-1);
	}
	return lib;
}

R_API RLib *r_lib_free(RLib *lib) {
	if (!lib) {
		return NULL;
	}
	r_lib_close (lib, NULL);
	r_list_free (lib->handlers);
	r_list_free (lib->plugins);
	free (lib);
	return NULL;
}

/* THIS IS WRONG */
R_API int r_lib_dl_check_filename(const char *file) {
	return (strstr (file, "."R_LIB_EXT)) != NULL;
}

/* high level api */

R_API int r_lib_run_handler(RLib *lib, RLibPlugin *plugin, RLibStruct *symbol) {
	RLibHandler *h = plugin->handler;
	if (h && h->constructor) {
		IFDBG eprintf ("PLUGIN OK %p fcn %p\n", h, h->constructor);
		return h->constructor (plugin, h->user, symbol->data);
	}
	IFDBG eprintf ("Cannot find plugin constructor\n");
	return R_FAIL;
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
	RListIter *iter, *iter_tmp;
	r_list_foreach_safe (lib->plugins, iter, iter_tmp, p) {
		if ((file==NULL || (!strcmp (file, p->file)))) {
			int ret = 0;
			if (p->handler && p->handler->destructor) {
				ret = p->handler->destructor (p, p->handler->user, p->data);
			}
			if (p->free) {
				p->free (p->data);
			}
			free (p->file);
			r_list_delete (lib->plugins, iter);
			if (file != NULL) {
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

// XXX ugly hack ?
static int samefile(const char *a, const char *b) {
	char *sa = strdup (a);
	char *sb = strdup (b);
	char *ptr;
	int len, ret = false;

	if (sa != NULL && sb != NULL) {
		do {
			ptr = strstr (sa, "//");
			if (ptr) {
				len = strlen (ptr+1) + 1;
				memmove (ptr, ptr+1, len);
			}
		} while (ptr);
		do {
			ptr = strstr (sb, "//");
			if (ptr) {
				len = strlen (ptr+1) + 1;
				memmove (ptr, ptr+1, len);
			}
		} while (ptr);
		ret = strcmp (sa,sb)? false: true;
	}

	free (sa);
	free (sb);
	return ret;
}

R_API int r_lib_open(RLib *lib, const char *file) {
	RLibStruct *stru;
	void *handler;

	/* ignored by filename */
	if (!r_lib_dl_check_filename (file)) {
		eprintf ("Invalid library extension: %s\n", file);
		return R_FAIL;
	}

	handler = r_lib_dl_open (file);
	if (!handler) {
		IFDBG eprintf ("Cannot open library: '%s'\n", file);
		return R_FAIL;
	}

	stru = (RLibStruct *) r_lib_dl_sym (handler, lib->symname);
	if (!stru) {
		IFDBG eprintf ("Cannot find symbol '%s' in library '%s'\n",
			lib->symname, file);
		r_lib_dl_close (handler);
		return R_FAIL;
	}

	return r_lib_open_ptr (lib, file, handler, stru);
}

R_API int r_lib_open_ptr (RLib *lib, const char *file, void *handler, RLibStruct *stru) {
	RLibPlugin *p;
	RListIter *iter;
	int ret = false;

	if (!lib || !file || !stru) {
		return R_FAIL;
	}
	if (stru->version) {
		if (strcmp (stru->version, R2_VERSION)) {
			eprintf ("Module version mismatch %s (%s) vs (%s)\n",
				file, stru->version, R2_VERSION);
			return R_FAIL;
		}
	}
	// TODO: Use Sdb here. just a single line
	if (handler) {
		r_list_foreach (lib->plugins, iter, p) {
			if (samefile (file, p->file)) {
				IFDBG eprintf ("Dupped\n");
				// TODO: reload if opening again?
				// TODO: store timestamp of file
				// TODO: autoreload plugins if updated \o/
				r_lib_dl_close (handler);
				return R_FAIL;
			}
		}
	}

	p = R_NEW0 (RLibPlugin);
	p->type = stru->type;
	p->data = stru->data;
	p->file = strdup (file);
	p->dl_handler = handler;
	p->handler = r_lib_get_handler (lib, p->type);
	p->free = stru->free;

	ret = r_lib_run_handler (lib, p, stru);
	if (ret == R_FAIL) {
		IFDBG eprintf ("Library handler has failed for '%s'\n", file);
		free (p->file);
		free (p);
		r_lib_dl_close (handler);
	} else {
		r_list_append (lib->plugins, p);
	}

	return ret;
}

R_API int r_lib_opendir(RLib *lib, const char *path) {
#if __WINDOWS__ && !defined(__CYGWIN__)
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
#if __WINDOWS__ && !defined(__CYGWIN__)
	wcpath = r_utf8_to_utf16 (path);
	if (!wcpath) {
		return false;	

	}
#if __MINGW32__
	swprintf (directory, L"%ls\\*.*", wcpath);
#else
	swprintf (directory, sizeof (directory), L"%ls\\*.*", wcpath);
#endif
	fh = FindFirstFileW (directory, &dir);
	if (fh == INVALID_HANDLE_VALUE) {
		IFDBG eprintf ("Cannot open directory %ls\n", wcpath);
		free (wcpath);
		return false;
	}
	do {
#if __MINGW32__
		swprintf (file, L"%ls/%ls", wcpath, dir.cFileName);
#else
		swprintf (file, sizeof (file), L"%ls/%ls", wcpath, dir.cFileName);
#endif
		wctocbuff = r_utf16_to_utf8 (file);
		if (wctocbuff) {
			if (r_lib_dl_check_filename (wctocbuff)) {
				r_lib_open (lib, wctocbuff);
			} else {
				IFDBG eprintf ("Cannot open %ls\n", dir.cFileName);
			}
			free (wctocbuff);
		}
	} while (FindNextFileW (fh, &dir));
	FindClose (fh);
	free (wcpath);
#else
	dh = opendir (path);
	if (!dh) {
		IFDBG eprintf ("Cannot open directory '%s'\n", path);
		return false;
	}
	while ((de = (struct dirent *)readdir (dh))) {
		if (de->d_name[0] == '.' || strstr (de->d_name, ".dSYM")) {
			continue;
		}
		snprintf (file, sizeof (file), "%s/%s", path, de->d_name);
		if (r_lib_dl_check_filename (file)) {
			IFDBG eprintf ("Loading %s\n", file);
			r_lib_open (lib, file);
		} else {
			IFDBG eprintf ("Cannot open %s\n", file);
		}
	}
	closedir (dh);
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

R_API void r_lib_list(RLib *lib) {
	RListIter *iter;
	RLibPlugin *p;
	r_list_foreach (lib->plugins, iter, p) {
		printf (" %5s %p %s \n", r_lib_types_get (p->type),
			p->dl_handler, p->file);
	}
}
