/* radare - LGPL - Copyright 2008-2025 - pancake */

#include <r_util.h>
#include <r_lib.h>

R_LIB_VERSION (r_lib);

/* XXX : this must be registered at runtime instead of hardcoded */
static const char *const r_lib_types[] = {
	"io", "dbg", "lang", "asm", "anal", "parse", "bin", "bin_xtr", "bin_ldr",
	"bp", "syscall", "fastcall", "muta", "core", "egg", "fs", "arch", NULL
};

R_API void *r_lib_dl_open(const char *libname, bool safe_mode) {
	void *ret = NULL;
#if WANT_DYLINK
#if R2__UNIX__
	if (libname) {
		if (safe_mode) {
			// In safe loading mode, try to open with flags that don't run constructors
#if defined(RTLD_NOLOAD)
			// First try with NOLOAD flag to validate without executing constructors
			// RTLD_NOLOAD will only succeed if the library is already loaded
			ret = dlopen (libname, RTLD_LAZY | RTLD_NOLOAD);
			if (!ret) {
				// If library isn't already loaded, use RTLD_LAZY which is safer than RTLD_NOW
				ret = dlopen (libname, RTLD_LAZY);
			}
#else
			// If RTLD_NOLOAD is not available, use RTLD_LAZY which is safer than RTLD_NOW
			ret = dlopen (libname, RTLD_LAZY);
#endif
		} else {
			// Normal loading with full initialization
#if __linux__
			ret = dlopen (libname, RTLD_LOCAL | RTLD_NOW);
			if (ret) {
				// Success - use this handle
			} else {
				// Try with different flags for specific libraries
				if (strstr (libname, "python")) {
					ret = dlopen (libname, RTLD_GLOBAL | RTLD_NOW);
				} else {
					ret = dlopen (libname, RTLD_NOW);
				}
			}
#endif
			if (!ret) {
				ret = dlopen (libname, RTLD_GLOBAL | RTLD_LAZY);
			}
		}
	} else {
		// Self-loading
		ret = dlopen (NULL, RTLD_NOW);
	}
	if (!ret) {
		R_LOG_DEBUG ("r_lib_dl_open failed %s (%s)", libname, dlerror ());
	}
#elif R2__WINDOWS__
	LPTSTR libname_;
	if (R_STR_ISNOTEMPTY (libname)) {
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
	if (safe_mode) {
		// Use DONT_RESOLVE_DLL_REFERENCES to load without executing constructors
		ret = LoadLibraryEx (libname_, NULL, DONT_RESOLVE_DLL_REFERENCES);
	} else {
		// Normal loading with full initialization
		ret = LoadLibrary (libname_);
	}
	free (libname_);
	if (!ret) {
		R_LOG_DEBUG ("r_lib_dl_open failed %s", libname);
	}
#endif
#endif
	return ret;
}

R_API void *r_lib_dl_sym(void *handler, const char *name) {
#if WANT_DYLINK
#if R2__UNIX__
	return dlsym (handler, name);
#elif R2__WINDOWS__
	return GetProcAddress (handler, name);
#else
	return NULL;
#endif
#else
	return NULL;
#endif
}

R_API bool r_lib_dl_close(void *handler) {
#if R2__UNIX__ && WANT_DYLINK
	return dlclose (handler);
#else
	return handler != NULL;
#endif
}

R_API char *r_lib_path(const char *libname) {
#if R2__WINDOWS__
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
#elif R2__UNIX__
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
	if (r_sys_getenv_asbool ("R2_DEBUG")) {
		r_log_set_level (R_LOG_LEVEL_DEBUG);
	}
	lib->ignore_version = r_sys_getenv_asbool ("R2_IGNVER");
	lib->ignore_abiversion = r_sys_getenv_asbool ("R2_IGNABI");
	lib->safe_loading = r_sys_getenv_asbool ("R2_SAFE_PLUGINS");
	lib->abiversion = R2_ABIVERSION;
	lib->handlers = r_list_newf (free);
	int i;
	for (i = 0; i < R_LIB_TYPE_LAST; i++) {
		lib->handlers_bytype[i] = NULL;
	}
	lib->plugins = r_list_newf (free);
	lib->plugins_ht = ht_pp_new0 ();
	lib->symname = strdup (symname? symname: R_LIB_SYMNAME);
	lib->symnamefunc = strdup (symnamefunc? symnamefunc: R_LIB_SYMFUNC);
	return lib;
}

R_API void r_lib_free(RLib * R_NULLABLE lib) {
	if (lib) {
		r_lib_close (lib, NULL);
		r_list_free (lib->handlers);
		r_list_free (lib->plugins);
		ht_pp_free(lib->plugins_ht);
		free (lib->symname);
		free (lib->symnamefunc);
		free (lib);
	}
}

static bool check_filename(const char *file) {
	return r_str_endswith (file, "." R_LIB_EXT);
}

R_API bool r_lib_run_handler(RLib *lib, RLibPlugin *plugin, RLibStruct *symbol) {
	RLibHandler *h = plugin->handler;
	if (h) {
		if (h->constructor) {
			R_LOG_DEBUG ("PLUGIN %s LOADED %p fcn %p", h->desc, h, h->constructor);
			return h->constructor (plugin, h->user, symbol->data);
		}
		R_LOG_DEBUG ("Cannot find plugin constructor");
	}
	return false;
}

R_API RLibHandler *r_lib_get_handler(RLib *lib, int type) {
	if (type < 0 || type >= R_LIB_TYPE_LAST) {
		return NULL;
	}
	return lib->handlers_bytype[type];
}

static bool delete_plugin(RLib *lib, RLibPlugin *plugin) {
	bool found;
	if (plugin->name == NULL) {
		return false;
	}
	ht_pp_find (lib->plugins_ht, plugin->name, &found);
	if (found) {
		ht_pp_delete (lib->plugins_ht, plugin->name);
	}
	bool ret = false;
	if (plugin->handler && plugin->handler->destructor) {
		// some plugins will return true here for sucess
		ret = plugin->handler->destructor (plugin, plugin->handler->user, plugin->data);
	}
	if (plugin->free) {
		plugin->free (plugin->data);
	}
	free (plugin->file);
	return ret;
}

R_API bool r_lib_close(RLib *lib, const char *file) {
	RLibPlugin *p;
	RListIter *iter, *iter2;

	r_list_foreach_safe (lib->plugins, iter, iter2, p) {
		if ((!file || !strcmp (file, p->file) || !strcmp (file, p->name))) {
			bool ret = delete_plugin (lib, p);
			r_list_delete (lib->plugins, iter);
			if (file) {
				return ret;
			}
		}
	}
	if (!file) {
		return true;
	}
	// delete similar plugin name
	r_list_foreach (lib->plugins, iter, p) {
		R_LOG_DEBUG ("similar p->file: %s", p->file);
		if (strstr (p->file, file)) {
			R_LOG_DEBUG ("similar deleting: %s", p->file);
			bool ret = delete_plugin (lib, p);
			r_list_delete (lib->plugins, iter);
			return ret;
		}
	}
	return false;
}

static bool already_loaded(RLib *lib, const char *name) {
	if (name) {
		bool found;
		RLibPlugin *p = ht_pp_find (lib->plugins_ht, name, &found);
		if (found && p) {
			R_LOG_ERROR ("Not loading library because it has already been loaded from '%s'", p->file);
			return true;
		}
	}
	return false;
}

R_API bool r_lib_open(RLib *lib, const char *file) {
	/* ignored by filename */
	if (!check_filename (file)) {
		R_LOG_ERROR ("Invalid library extension: %s", file);
		return false;
	}

	// Step 1: Open with safe mode if enabled
	bool using_safe_mode = lib->safe_loading;
	void *handle = r_lib_dl_open (file, using_safe_mode);
	if (!handle) {
		// If safe mode failed, try normal mode
		if (using_safe_mode) {
			R_LOG_DEBUG ("Safe loading failed for '%s', falling back to normal loading", file);
			handle = r_lib_dl_open (file, false);
			using_safe_mode = false;
		}
		if (!handle) {
			R_LOG_DEBUG ("Cannot open library: '%s'", file);
			return false;
		}
	}

	// Step 2: Get plugin struct pointer
	RLibStructFunc strf = (RLibStructFunc)r_lib_dl_sym (handle, lib->symnamefunc);
	RLibStruct *stru = NULL;
	if (strf) {
		stru = strf ();
	}
	if (!stru) {
		stru = (RLibStruct *)r_lib_dl_sym (handle, lib->symname);
	}
	if (!stru) {
		R_LOG_DEBUG ("Cannot find symbol '%s' in library '%s'", lib->symname, file);
		r_lib_dl_close (handle);
		return false;
	}

	// Step 3: Check plugin metadata and ABI version
	RPluginMeta *meta = (RPluginMeta *)(stru->data);
	if (already_loaded (lib, meta->name)) {
		r_lib_dl_close (handle);
		return false;
	}

	if (!r_lib_validate_plugin (lib, file, stru)) {
		R_LOG_DEBUG ("Plugin '%s' validation failed", file);
		r_lib_dl_close (handle);
		if (strf) {
			free (stru);
		}
		return false;
	}

	// Step 4: If safe mode used, reload with full initialization
	if (using_safe_mode) {
		r_lib_dl_close (handle);
		// Reopen with normal mode to allow constructors to run
		handle = r_lib_dl_open (file, false);
		if (!handle) {
			R_LOG_DEBUG ("Cannot reopen library: '%s'", file);
			if (strf) {
				free (stru);
			}
			return false;
		}

		// Re-get the function pointer and structure
		strf = (RLibStructFunc)r_lib_dl_sym (handle, lib->symnamefunc);
		if (strf) {
			if (stru) {
				free (stru);
			}
			stru = strf ();
		}
		if (!stru) {
			stru = (RLibStruct *)r_lib_dl_sym (handle, lib->symname);
		}
		if (!stru) {
			R_LOG_DEBUG ("Cannot find symbol '%s' in library '%s'", lib->symname, file);
			r_lib_dl_close (handle);
			return false;
		}
	}

	// Step 5: Register and initialize the plugin
	int res = r_lib_open_ptr (lib, file, handle, stru);
	if (strf) {
		free (stru);
	}
	return res;
}

char *major_minor(const char *s) {
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

R_API bool r_lib_validate_plugin(RLib *lib, const char *file, RLibStruct *stru) {
	R_RETURN_VAL_IF_FAIL (lib && file && stru, false);

	// Check for proper plugin type
	if (stru->type < 0 || stru->type >= R_LIB_TYPE_LAST) {
		R_LOG_WARN ("Invalid plugin type %d for '%s'", stru->type, file);
		return false;
	}

	// Check ABI compatibility
	if (stru->abiversion && !lib->ignore_abiversion) {
		if (stru->abiversion != lib->abiversion) {
			R_LOG_WARN ("ABI version mismatch: (ABI %d) vs radare2 (ABI %d) for '%s'", stru->abiversion, lib->abiversion, file);
			return false;
		}
	} else if (stru->version && !lib->ignore_version) {
		// Check version compatibility
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
			return false;
		}
	}

	return true;
}


R_API bool r_lib_open_ptr(RLib *lib, const char *file, void *handle, RLibStruct *stru) {
	R_RETURN_VAL_IF_FAIL (lib && file && stru, false);

	RLibPlugin *p = R_NEW0 (RLibPlugin);
	p->type = stru->type;
	p->data = stru->data;
	p->file = strdup (file);
	p->dl_handler = handle;
	p->handler = r_lib_get_handler (lib, p->type);
	p->free = stru->free;

	// Run plugin handler (constructor)
	bool ret = r_lib_run_handler (lib, p, stru);
	if (!ret) {
		R_LOG_DEBUG ("Library handler has failed for '%s'", file);
		free (p->file);
		if (p->name) {
			free (p->name);
		}
		free (p);
	} else {
		r_list_append (lib->plugins, p);
		if (p->name) {
			ht_pp_insert (lib->plugins_ht, strdup (p->name), p);
		}
	}
	return ret;
}

R_API bool r_lib_opendir(RLib *lib, const char *path) {
#if WANT_DYLINK
	R_RETURN_VAL_IF_FAIL (lib && path, false);
#ifdef R2_LIBR_PLUGINS
	if (!path) {
		path = R2_LIBR_PLUGINS;
	}
#endif
	if (!path) {
		return false;
	}
#if R2__WINDOWS__
	wchar_t file[1024];
	WIN32_FIND_DATAW dir;
	HANDLE fh;
	wchar_t directory[MAX_PATH];
	char *wctocbuff;
	wchar_t *wcpath = r_utf8_to_utf16 (path);
	if (!wcpath) {
		return false;

	}
	swprintf (directory, _countof (directory), L"%ls\\*.*", wcpath);
	fh = FindFirstFileW (directory, &dir);
	if (fh == INVALID_HANDLE_VALUE) {
		R_LOG_DEBUG ("Cannot open directory %ls", wcpath);
		free (wcpath);
		return false;
	}
	do {
		swprintf (file, _countof (file), L"%ls/%ls", wcpath, dir.cFileName);
		wctocbuff = r_utf16_to_utf8 (file);
		if (wctocbuff) {
			if (check_filename (wctocbuff)) {
				R_LOG_DEBUG ("Loading %s", file);
				r_lib_open (lib, wctocbuff);
			} else {
				R_LOG_DEBUG ("Cannot open %ls", dir.cFileName);
			}
			free (wctocbuff);
		}
	} while (FindNextFileW (fh, &dir));
	FindClose (fh);
	free (wcpath);
#else
	char file[1024];
	struct dirent *de;
	DIR *dh = opendir (path);
	if (!dh) {
		R_LOG_DEBUG ("Cannot open directory '%s'", path);
		return false;
	}
	while ((de = (struct dirent *)readdir (dh))) {
		if (de->d_name[0] == '.' || strstr (de->d_name, ".dSYM")) {
			continue;
		}
		snprintf (file, sizeof (file), "%s/%s", path, de->d_name);
		if (check_filename (file)) {
			R_LOG_DEBUG ("Loading %s", file);
			r_lib_open (lib, file);
		} else {
			R_LOG_DEBUG ("Skip/Ignore %s", file);
		}
	}
	closedir (dh);
#endif
#endif
	return true;
}

R_API bool r_lib_add_handler(RLib *lib, int type, const char *desc, RLibCallback cb, RLibCallback dt, void *user) {
	R_RETURN_VAL_IF_FAIL (lib && desc, false);
	// TODO r2_590 resolve using lib->handlers_ht
	RLibHandler *handler = NULL;
	if (lib->handlers_bytype[type]) {
		R_LOG_DEBUG ("Redefining library handler constructor for %d", type);
		handler = lib->handlers_bytype[type];
	}
	if (!handler) {
		handler = R_NEW (RLibHandler);
		handler->type = type;
		r_list_append (lib->handlers, handler);
		if (lib->handlers_bytype[type]) {
			R_LOG_WARN ("we have a handler for this type already set");
		}
		lib->handlers_bytype[type] = handler;
	}
	if (desc) {
		r_str_ncpy (handler->desc, desc, sizeof (handler->desc) - 1);
	}
	handler->user = user;
	handler->constructor = cb;
	handler->destructor = dt;

	return true;
}

// R2_590 - delete handler by type doesnt make sense. lets do it by plug name instead
R_API bool r_lib_del_handler(RLib *lib, int type) {
	RLibHandler *h = NULL;
	RListIter *iter;
#if R2_600
	// XXX slow - delete plugin by name, by filename or by type >? wtf this function is broken
	{
		bool found;
		h = ht_pp_find (lib->plugins_ht, fileName, &found);
		if (found && h) {
			// ht_pp_delete (lib->plugins_ht, fileName);
			return true;
		}
	}
#endif
	// TODO: remove all handlers for that type? or only one?
	/* No _safe loop necessary because we return immediately after the delete. */
	lib->handlers_bytype[type] = NULL;
	r_list_foreach (lib->handlers, iter, h) {
		if (type == h->type) {
			r_list_delete (lib->handlers, iter);
// TODOL delete handler from hashtable
			return true;
		}
	}
	return false;
}

static inline const char *libtype_byidx(int idx) {
	if (idx < 0 || idx > R_LIB_TYPE_LAST - 1) {
		return "unk";
	}
	return r_lib_types[idx];
}

// TODO _list methods should not exist.. only used in ../core/cmd_log.c: r_lib_list (core->lib);
R_API void r_lib_list(RLib *lib) {
	RListIter *iter;
	RLibPlugin *p;
	r_list_foreach (lib->plugins, iter, p) {
		printf (" %5s %p %s \n", libtype_byidx (p->type),
			p->dl_handler, p->file);
	}
}

// TODO: pj_o should be inside rlibmetapj
R_API RList *r_lib_get_loaded_plugins(RLib *lib) {
	R_RETURN_VAL_IF_FAIL (lib, NULL);
	return lib->plugins;
}

R_API void r_lib_meta_pj(PJ *pj, const RPluginMeta *meta) {
	R_RETURN_IF_FAIL (pj && meta);
	if (meta->name) {
		pj_ks (pj, "name", meta->name);
	}
	if (meta->desc) {
		pj_ks (pj, "desc", meta->desc);
	}
	if (meta->copyright) {
		pj_ks (pj, "copyright", meta->copyright);
	}
	if (meta->contact) {
		pj_ks (pj, "contact", meta->contact);
	}
	if (meta->author) {
		pj_ks (pj, "author", meta->author);
	}
	if (meta->version) {
		pj_ks (pj, "version", meta->version);
	}
	if (meta->license) {
		pj_ks (pj, "license", meta->license);
	}
}
