/* radare - LGPL - Copyright 2021-2024 - pancake */

#define R_LOG_ORIGIN "r2pm"

#include <r_main.h>
#include <r_lib.h>

#define R2PM_GITURL "https://github.com/radareorg/radare2-pm"

static int r2pm_install(RList *targets, bool uninstall, bool clean, bool force, bool global);

static const char *helpmsg =
	"Usage: r2pm [-flags] [pkgs...]\n"
	"Commands:\n"
	" -a [repository]   add or -delete external repository\n"
	" -c ([git/dir])    clear source cache (R2PM_GITDIR)\n"
	" -ci <pkgname>     clean + install\n"
	" -cp               clean the user's home plugin directory\n"
	" -d,doc [pkgname]  show documentation and source for given package\n"
	" -e [pkgname]      edit using $EDITOR the given package script\n"
	" -f                force operation (Use in combination of -U, -i, -u, ..)\n"
	" -gi <pkg>         global install (system-wide)\n"
	" -h                display this help message\n"
	" -H ([variable])   list all or selected r2pm environment variables\n"
	" -i <pkgname>      install/update package and its dependencies (see -c, -g)\n"
	" -I                information about the repository and installed packages\n"
	" -l                list installed packages\n"
	" -q                be quiet\n"
	" -r [cmd ...args]  run shell command with R2PM_BINDIR in PATH\n"
	" -R <pkgname>      reload plugin (See R2PM_RELOAD code block package)\n"
	" -s [<keyword>]    search available packages in database matching a string\n"
	" -t [YYYY-MM-DD]   set a moment in time to pull the code from the git packages\n"
	" -u <pkgname>      uninstall package (see -f to force uninstall)\n"
	" -uci <pkgname>    uninstall + clean + install\n"
	" -ui <pkgname>     uninstall + install\n"
	" -U                download/initialize or update database (-f for a clean clone)\n"
	" -UU               same as -U but upgrade all the installed r2 plugins\n"
	" -v                show version\n";

typedef struct r_r2pm_t {
	bool add;
	bool clean;
	bool doc;
	bool edit;
	bool envhelp;
	bool force;
	bool global;
	bool help;
	bool info;
	bool init;
	bool install;
	bool list;
	bool plugdir; // requires -c/clean
	bool quiet;
	bool run;
	bool search;
	bool reload;
	bool uninstall;
	bool upgrade;
	bool version;

	int rc;
	const char *time;
} R2Pm;

static int git_pull(const char *dir, bool verbose, bool reset) {
	if (strchr (dir, ' ')) {
		R_LOG_ERROR ("Directory '%s' cannot contain spaces", dir);
		return -1;
	}
	if (!r_file_is_directory (dir)) {
		R_LOG_ERROR ("Directory '%s' does not exist", dir);
		return -1;
	}
	if (reset) {
		char *s = r_str_newf ("cd %s && git clean -xdf && git reset --hard @~2 && git checkout", dir);
		R_UNUSED_RESULT (r_sandbox_system (s, 1));
		free (s);
	}
	const char *quiet = verbose? "": "--quiet";
#if R2__WINDOWS__
	char *s = r_str_newf ("cd %s && git pull %s && git diff", dir, quiet);
#else
	char *s = r_str_newf ("cd '%s' && git pull %s", dir, quiet);
#endif
	int rc = r_sandbox_system (s, 1);
	free (s);
	return rc;
}

static int git_clone(const char *dir, const char *url) {
	if (strchr (dir, ' ')) {
		R_LOG_ERROR ("Directory '%s' cannot contain spaces", dir);
		return -1;
	}
	char *git = r_file_path ("git");
	if (!git) {
		R_LOG_ERROR ("Cannot find `git` in $PATH");
		return 1;
	}
	free (git);

	char *cmd = r_str_newf ("git clone --depth=1 --recursive %s %s", url, dir);
	R_LOG_INFO ("%s", cmd);
	int rc = r_sandbox_system (cmd, 1);
	free (cmd);
	return rc;
}

static bool r2pm_add(R2Pm *r2pm, const char *repository) {
	R_LOG_INFO ("r2pm.add is not implemented");
	return false;
}

static char *r2pm_bindir(void) {
	return r_xdg_datadir ("prefix/bin");
}

static char *r2pm_gitdir(void) {
	char *e = r_sys_getenv ("R2PM_GITDIR");
	if (R_STR_ISNOTEMPTY (e)) {
		return e;
	}
	free (e);
	return r_xdg_datadir ("r2pm/git");
}

static char *r2pm_dbdir(void) {
	char *e = r_sys_getenv ("R2PM_DBDIR");
	if (R_STR_ISNOTEMPTY (e)) {
		return e;
	}
	free (e);
	char *gitdir = r2pm_gitdir ();
	char *res = r_str_newf ("%s/radare2-pm/db", gitdir);
	free (gitdir);
	return res;
}

static char *r2pm_pkgdir(void) {
	return r_xdg_datadir ("r2pm/pkg");
}

typedef enum {
	TT_TEXTLINE,
	TT_TEXTLINE_LIST,
	TT_CODEBLOCK,
	TT_ENDQUOTE,
} R2pmTokenType;

static void r2pm_register(const char *pkg, bool g) {
	char *pkgdir = r2pm_pkgdir ();
	r_sys_mkdirp (pkgdir);
	char *f = r_str_newf ("%s/%s", pkgdir, pkg);
	free (pkgdir);
	if (f) {
		RStrBuf *sb = r_strbuf_new ("");
		r_strbuf_appendf (sb, "Global: %s\n", r_str_bool (g));
		char *s = r_time_secs_tostring (r_time_today ());
		r_strbuf_appendf (sb, "InstallationDate: %s\n", s);
		free (s);
		char *ss = r_strbuf_drain (sb);
		r_file_dump (f, (const ut8 *)ss, strlen (ss), false);
		free (ss);
		free (f);
	}
}

static void r2pm_unregister(const char *pkg) {
	char *pkgdir = r2pm_pkgdir ();
	char *f = r_str_newf ("%s/%s", pkgdir, pkg);
	free (pkgdir);
	if (R_LIKELY (f)) {
		r_file_rm (f);
		free (f);
	}
}

static char *r2pm_pkgpath(const char *file) {
	char *dbdir = r2pm_dbdir ();
	char *path = r_str_newf ("%s/%s", dbdir, file);
	free (dbdir);
	if (r_file_exists (path)) {
		return path;
	}
	free (path);
	return NULL;
}

static char *find_newline(char *s) {
	char *r = strchr (s, '\r');
	char *n = strchr (s, '\n');
	if (r && n) {
		return (r < n)? r: n;
	}
	if (r) {
		return r;
	}
	return n;

}
static char *r2pm_get(const char *file, const char *token, R2pmTokenType type) {
	char *res = NULL;
	char *dbdir = r2pm_dbdir ();
	char *path = r_str_newf ("%s/%s", dbdir, file);
	free (dbdir);
	char *data = r_file_slurp (path, NULL);
	free (path);
	if (!data) {
		return NULL;
	}
	const char *needle = token; // "\nR2PM_DESC ";
	char *descptr = strstr (data, needle);
	if (descptr) {
		char *nl = NULL;
		switch (type) {
		case TT_TEXTLINE:
			descptr += strlen (needle);
			nl = find_newline (descptr);
			if (nl) {
				*nl = 0;
				nl--;
				if (*nl == '"') {
					*nl = 0;
				}
			}
			descptr = (char *)r_str_trim_head_ro (descptr);
			if (*descptr == '"') {
				descptr++;
			}
			res = strdup (descptr);
			break;
		case TT_TEXTLINE_LIST:
			descptr += strlen (needle);
			nl = find_newline (descptr);
			if (nl) {
				*nl = 0;
			}
			res = strdup (descptr);
			break;
		case TT_ENDQUOTE:
			nl = find_newline (descptr + strlen (token));
			if (nl) {
				char *begin = nl + 1;
				char *eoc = strstr (begin, "\n\"\n"); // windows have \r\n
				if (eoc) {
					return r_str_ndup (begin, eoc - begin);
				}
				R_LOG_ERROR ("Cannot find end of thing");
				free (data);
				return NULL;
			}
			break;
		case TT_CODEBLOCK: {
			char *begin = descptr + strlen (token);
			char *eoc = strstr (begin, "\n}\n");
			if (eoc) {
				char *res = r_str_ndup (begin, eoc - begin);
				free (data);
				return res;
			}
			R_LOG_ERROR ("Cannot find end of thing");
			free (data);
			return NULL;
		} break;
		}
	}
	free (data);
	return res;
}

static void striptrim(RList *list) {
	char *s;
	RListIter *iter, *iter2;
	r_list_foreach_safe (list, iter, iter2, s) {
		if (R_STR_ISEMPTY (s)) {
			r_list_delete (list, iter);
		}
	}
}

static void r2pm_upgrade(bool force) {
#if R2__UNIX__
	char *s = r_sys_cmd_str ("radare2 -NNqcq -- 2>&1 | grep r2pm | sed -e 's,$,;,g'", NULL, 0);
	r_str_trim (s);
	RList *list = r_str_split_list (s, "\n", -1);
	striptrim (list);
	if (r_list_length (list) < 1) {
		R_LOG_INFO ("No packages to upgrade");
	} else {
		r2pm_install (list, false, true, force, false);
	}
	free (s);
	r_list_free (list);
#else
	R_LOG_INFO ("Auto upgrade feature is not yet supported on windows");
#endif
}

static char *r2pm_desc(const char *file) {
	return r2pm_get (file, "\nR2PM_DESC ", TT_TEXTLINE);
}

static char *r2pm_list(void) {
	char *path = r2pm_pkgdir ();
	RList *files = r_sys_dir (path);
	free (path);
	if (!files) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new ("");
	RListIter *iter;
	const char *file;
	r_list_foreach (files, iter, file) {
		if (*file != '.') {
			r_strbuf_appendf (sb, "%s\n", file);
		}
	}
	r_list_free (files);
	return r_strbuf_drain (sb);
}

static int r2pm_update(bool force) {
	char *gpath = r2pm_gitdir ();
	if (!gpath) {
		R_LOG_ERROR ("Cannot find gitdir");
		return -1;
	}
	char *pmpath = r_str_newf ("%s/%s", gpath, "radare2-pm");
	r_sys_mkdirp (gpath);
	if (force) {
		r_file_rm_rf (pmpath);
	}
	int rc = 0;
	if (r_file_is_directory (pmpath)) {
		R_LOG_INFO ("Running git pull on %s", pmpath);
		if (git_pull (pmpath, true, force) != 0) {
			R_LOG_ERROR ("git pull");
			rc = 1;
		}
	} else {
		char *giturl = r_sys_getenv ("R2PM_GITURL");
		if (R_STR_ISEMPTY (giturl)) {
			free (giturl);
			giturl = strdup ("R2PM_GITURL");
		}
		rc = git_clone (pmpath, giturl);
		free (giturl);
	}
	free (gpath);
	free (pmpath);
	return rc;
}

static void r2pm_setenv(R2Pm *r2pm) {
	char *gmake = r_file_path ("gmake");
	if (gmake) {
		r_sys_setenv ("MAKE", gmake);
	} else {
		r_sys_setenv ("MAKE", "make");
	}
	free (gmake);

	if (r2pm->global) {
		// the r2pm_plugdir changes when using -g
		char *r2_plugdir = r_str_newf (R2_LIBDIR "/radare2/" R2_VERSION);
		r_sys_setenv ("R2PM_PLUGDIR", r2_plugdir);
		free (r2_plugdir);
	} else {
		char *r2_plugdir = r_xdg_datadir ("plugins");
		r_sys_setenv ("R2PM_PLUGDIR", r2_plugdir);
		free (r2_plugdir);
	}

	if (r2pm->time) {
		// set R2PM_TIME env var
		r_sys_setenv ("R2PM_TIME", r2pm->time);
	}
	r_sys_setenv ("R2_LIBEXT", R_LIB_EXT);

	char *gdir = r2pm_gitdir ();
	r_sys_setenv ("R2PM_GITDIR", gdir);
	free (gdir);

	char *gurl = r_sys_getenv ("R2PM_GITURL");
	if (R_STR_ISEMPTY (gurl)) {
		r_sys_setenv ("R2PM_GITURL", R2PM_GITURL);
	}
	free (gurl);

	char *dbdir = r2pm_dbdir ();
	r_sys_setenv ("R2PM_DBDIR", dbdir);
	free (dbdir);

	char *pd = r_sys_cmd_str ("radare2 -NN -H R2_USER_PLUGINS", NULL, NULL);
	if (pd) {
		if (R_STR_ISNOTEMPTY (pd)) {
			r_str_trim (pd);
			r_sys_setenv ("R2_USER_PLUGINS", pd);
			r_sys_mkdirp (pd);
		}
		R_FREE (pd);
	}

	char *r2_prefix = r_xdg_datadir ("prefix");
	if (!r2_prefix) {
		R_LOG_ERROR ("Cannot resolve xdg.datadir('prefix')");
		return;
	}
	r_sys_setenv ("R2PM_PREFIX", r2_prefix);

	char *pkgcfg = r_sys_getenv ("PKG_CONFIG_PATH");
	char *r2pm_pkgcfg = r_xdg_datadir ("prefix/lib/pkgconfig");
	if (R_STR_ISNOTEMPTY (pkgcfg)) {
		char *pcp = r_str_newf ("%s%s%s%s%s",r2pm_pkgcfg,
				R_SYS_ENVSEP, R2_PREFIX "/lib/pkgconfig",
				R_SYS_ENVSEP, pkgcfg);
		r_sys_setenv ("PKG_CONFIG_PATH", pcp);
		free (pcp);
	} else {
		char *pcp = r_str_newf ("%s%s%s", r2pm_pkgcfg,
				R_SYS_ENVSEP, R2_PREFIX "/lib/pkgconfig");
		r_sys_setenv ("PKG_CONFIG_PATH", pcp);
		free (pcp);
	}
	free (r2pm_pkgcfg);
	free (pkgcfg);

	char *bindir = r_str_newf ("%s/bin", r2_prefix);
	r_sys_setenv ("R2PM_BINDIR", bindir);
	free (bindir);

	char *mandir = r_str_newf ("%s/man", r2_prefix);
	r_sys_setenv("R2PM_MANDIR", mandir);
	free (mandir);

	char *libdir = r_str_newf ("%s/lib", r2_prefix);
	r_sys_setenv ("R2PM_LIBDIR", libdir);
	free (libdir);

	char *incdir = r_str_newf ("%s/include", r2_prefix);
	r_sys_setenv ("R2PM_INCDIR", incdir);
	free (incdir);

	char *oldpath = r_sys_getenv ("PATH");
	if (!oldpath) {
		oldpath = strdup ("/bin");
	}
	if (!strstr (oldpath, r2_prefix)) {
		char *newpath = r_str_newf ("%s/bin%s%s", r2_prefix, R_SYS_ENVSEP, oldpath);
		r_sys_setenv ("PATH", newpath);
		free (newpath);
	}
	free (oldpath);
#if R2__WINDOWS__
	const char *ldpathvar = NULL;
#elif __HAIKU__
	const char *ldpathvar = "LIBRARY_PATH";
#elif __APPLE__
	const char *ldpathvar = "DYLD_LIBRARY_PATH";
#else
	const char *ldpathvar = "LD_LIBRARY_PATH";
#endif
	char *opath = r_sys_getenv ("PATH");
	if (opath) {
		char *bindir = r2pm_bindir ();
		r_sys_mkdirp (bindir);
		const char *sep = R_SYS_ENVSEP;
		char *newpath = r_str_newf ("%s%s%s", bindir, sep, opath);
		r_sys_setenv ("PATH", newpath);
		free (newpath);
		free (opath);
		free (bindir);
	}

	char *ldpath = r_sys_getenv (ldpathvar);
	if (!ldpath) {
		ldpath = strdup ("");
	}
	if (!strstr (ldpath, r2_prefix)) {
		char *newpath = r_str_newf ("%s/lib%s%s", r2_prefix, R_SYS_ENVSEP, ldpath);
		r_sys_setenv (ldpathvar, newpath);
		free (ldpath);
		ldpath = newpath;
	}
	char *gr2_prefix = r_sys_cmd_str ("radare2 -NN -H R2_PREFIX", NULL, NULL);
	if (gr2_prefix) {
		r_str_trim (gr2_prefix);
		if (R_STR_ISNOTEMPTY (gr2_prefix)) {
			if (!strstr (ldpath, gr2_prefix)) {
				char *newpath = r_str_newf ("%s/lib%s%s", gr2_prefix, R_SYS_ENVSEP, ldpath);
				r_sys_setenv (ldpathvar, newpath);
				free (newpath);
			}
		}
		free (gr2_prefix);
	}

	if (!strstr (ldpath, r2_prefix)) {
		char *newpath = r_str_newf ("%s/lib%s%s", r2_prefix, R_SYS_ENVSEP, ldpath);
		r_sys_setenv (ldpathvar, newpath);
		free (newpath);
	}
	free (ldpath);
	free (r2_prefix);
	// GLOBAL = 0 # depends on r2pm.global, which is set on r2pm_install
	static const char *python_bins[] = {
		"python3",
		"python2",
		"python",
		NULL
	};
	const char *bin = python_bins[0];
	char *bin_path = NULL;
	int i;
	char *env_python = r_sys_getenv ("PYTHON");
	if (R_STR_ISNOTEMPTY (env_python)) {
		free (env_python);
		return;
	}

	for (i = 0; python_bins[i]; i++) {
		bin = python_bins[i];
		bin_path = r_file_path (bin);
		if (bin_path) {
			break;
		}
	}

	if (bin_path) {
		r_sys_setenv ("PYTHON", bin_path);
	}
	free (bin_path);
}

static int r2pm_doc_pkg(const char *pkg) {
	char *docstr = r2pm_get (pkg, "\nR2PM_DOC=\"", TT_ENDQUOTE);
	if (docstr) {
		printf ("%s\n", docstr);
		free (docstr);
		return 0;
	}
	// R_LOG_ERROR ("Cannot find documentation for '%s'", pkg);
	char *dbdir = r2pm_dbdir ();
	char *pkgfile = r_str_newf ("%s/%s", dbdir, pkg);
	int rc = 0;
	char *script = r_file_slurp (pkgfile, NULL);
	if (script) {
		printf ("%s\n", script);
		free (script);
	} else {
		R_LOG_ERROR ("Cannot find package: %s", pkg);
		rc = 1;
	}
	free (pkgfile);
	free (dbdir);
	return rc;
}

static int r2pm_clean_pkg(const char *pkg) {
	R_LOG_INFO ("Cleaning %s", pkg);
	// TODO. make clean/mrproper instead maybe better?
	char *srcdir = r2pm_gitdir ();
	if (R_STR_ISNOTEMPTY (srcdir)) {
		char *d = r_file_new (srcdir, pkg, NULL);
		if (d && r_file_is_directory (d)) {
			r_file_rm_rf (d);
		}
		free (d);
	}
	free (srcdir);
	return 0;
}

static bool r2pm_have_builddir(const char *pkg) {
	char *url = r2pm_get (pkg, "\nR2PM_TGZ", TT_TEXTLINE);
	if (!url) {
		url = r2pm_get (pkg, "\nR2PM_GIT", TT_TEXTLINE);
	}
	if (url) {
		free (url);
		return true;
	}
	return false;
}

// looks copypaste with r2pm_install_pkg()
static int r2pm_uninstall_pkg(const char *pkg, bool global) {
	R_LOG_INFO ("Uninstalling %s", pkg);
	char *srcdir = r2pm_gitdir ();
	const bool have_builddir = r2pm_have_builddir (pkg);
#if R2__WINDOWS__
	char *script = r2pm_get (pkg, "\nR2PM_UNINSTALL_WINDOWS() {\n", TT_CODEBLOCK);
	if (!script) {
		R_LOG_ERROR ("This package does not have R2PM_UNINSTALL_WINDOWS instructions");
		free (srcdir);
		return 1;
	}
	char *s = have_builddir
		? r_str_newf ("cd %s && cd %s && %s", srcdir, pkg, script)
		: r_str_newf ("%s", script);
	int res = r_sandbox_system (s, 1);
	free (s);
#else
	char *script = r2pm_get (pkg, "\nR2PM_UNINSTALL() {\n", TT_CODEBLOCK);
	if (!script) {
		R_LOG_ERROR ("Cannot find the R2PM_UNINSTALL() {} script block for '%s'", pkg);
		free (srcdir);
		return 1;
	}
	char *s = have_builddir
		? r_str_newf ("cd %s/%s\nexport MAKE=make\nR2PM_FAIL(){\n  echo $@\n}\n%s", srcdir, pkg, script)
		: r_str_newf ("export MAKE=make\nR2PM_FAIL(){\n  echo $@\n}\n%s", script);
	int res = r_sandbox_system (s, 1);
	free (s);

	r2pm_unregister (pkg);
#endif
	free (srcdir);
	return res;
}

static bool download(const char *url, const char *outfile) {
	/// XXX add support for windows powershell download
	char *tool = r_file_path ("curl");
	int res = 1;
	R_LOG_INFO ("download: %s into %s", url, outfile);
	if (tool) {
		res = r_sys_cmdf ("%s -sfL -o '%s' '%s'", tool, outfile, url);
		free (tool);
		return res == 0;
	}
	tool = r_file_path ("wget");
	if (tool) {
		res = r_sys_cmdf ("%s -qO '%s' '%s'", tool, outfile, url);
		free (tool);
		return res == 0;
	}
	R_LOG_ERROR ("Please install `curl` or `wget`");
	return false;
}

static bool unzip(const char *file, const char *dir) {
	if (r_str_endswith (file, ".tgz") || r_str_endswith (file, ".tar.gz")) {
		return 0 == r_sys_cmdf ("tar -xzvf '%s' -C '%s'", file, dir);
	}
	if (r_str_endswith (file, ".zip")) {
		return 0 == r_sys_cmdf ("unzip '%s' -d '%s'", file, dir);
	}
	return false;
}

static int r2pm_clone(const char *pkg) {
	char *pkgdir = r2pm_gitdir ();
	char *srcdir = r_file_new (pkgdir, pkg, NULL);
	free (pkgdir);

#if R2__WINDOWS__
	char *script = r2pm_get (pkg, "\nR2PM_INSTALL_WINDOWS() {\n", TT_CODEBLOCK);
	if (!script) {
		R_LOG_ERROR ("This package does not have R2PM_INSTALL_WINDOWS instructions");
		free (srcdir);
		return 1;
	}
	free (script);
#endif

	bool offline = r_sys_getenv_asbool ("R2PM_OFFLINE");
	if (offline) {
		free (srcdir);
		return 0;
	}
	bool git_source = false;
	if (r_file_is_directory (srcdir)) {
		git_source = git_pull (srcdir, true, 0);
	} else {
		char *url_list = r2pm_get (pkg, "\nR2PM_GIT ", TT_TEXTLINE_LIST);
		if (url_list) {
			r_str_replace_ch (url_list, ',', ' ', true);
			int url_ct, i;
			char **urls = r_str_argv (url_list, &url_ct);
			for (i = 0; i < url_ct; i++) {
				if (!git_clone (srcdir, urls[i])) {
					break;
				}
			}
			git_source = true;
			r_str_argv_free (urls);
			free (url_list);
		} else {
			char *url = r2pm_get (pkg, "\nR2PM_TGZ", TT_TEXTLINE);
			if (!url) {
				R_LOG_INFO ("Nothing to pull");
				free (srcdir);
				return 0;
			}
			const char *filename = r_file_basename (url);
			char *outfile = r_str_newf ("%s/%s", srcdir, filename);
			r_sys_mkdirp (srcdir);
			if (download (url, outfile)) {
				if (unzip (outfile, srcdir)) {
					R_LOG_INFO ("download and unzip works!");
					free (srcdir);
					free (url);
					return 0;
				} else {
					R_LOG_ERROR ("unzip has failed");
				}
			} else {
				R_LOG_ERROR ("download has failed");
			}
			free (srcdir);
			free (url);
			return 1;
		}
	}
	free (srcdir);
	char *r2pm_time = r_sys_getenv ("R2PM_TIME");
	if (r2pm_time) {
		if (git_source) {
			char *gitdir = r2pm_gitdir ();
			R_LOG_INFO ("Going back to %s", r2pm_time);
			int rc = r_sys_cmdf ("cd %s/%s && git reset --hard && git pull --tags && git reset --hard %s",
				gitdir, pkg, r2pm_time);
			free (gitdir);
			if (rc != 0) {
				R_LOG_ERROR ("Unable to travel back in time");
				free (r2pm_time);
				return 1;
			}
		} else {
			R_LOG_WARN ("Cannot go back in time with tarball packages");
		}
		free (r2pm_time);
	}
	return 0;
}

static bool r2pm_check(const char *program) {
	char *s = r_file_path (program);
	bool found = s != NULL;
	free (s);
	return found;
}

static int r2pm_install_pkg(const char *pkg, bool clean, bool global) {
	bool have_builddir = r2pm_have_builddir (pkg);
	R_LOG_INFO ("Starting install for %s", pkg);
	char *needs = r2pm_get (pkg, "\nR2PM_NEEDS ", TT_TEXTLINE);
	if (needs) {
		bool error = false;
		char *dep;
		RListIter *iter;
		RList *l = r_str_split_list (needs, " ", 0);
		r_list_foreach (l, iter, dep) {
			if (!r2pm_check (dep)) {
				R_LOG_ERROR ("R2PM_NEEDS: Cannot find %s in PATH", dep);
				error = true;
			} else {
				R_LOG_INFO ("R2PM_NEEDS: Found %s in PATH", dep);
			}
		}
		r_list_free (l);
		free (needs);
		if (error) {
			if (r2pm_check ("apt") && r_file_is_directory ("/system/bin")) {
				if (r_cons_yesno ('y', "Install system dependencies (Y/n)")) {
					const char *const cmd = "apt install build-essential git make patch python wget binutils";
					R_LOG_INFO ("Running %s", cmd);
					r_sys_cmd (cmd);
					return r2pm_install_pkg (pkg, clean, global);
				}
			}
			return -1;
		}
	}
	char *conflict = r2pm_get (pkg, "\nR2PM_CONFLICT ", TT_TEXTLINE);
	if (conflict) {
		RListIter *iter, *iter2;
		RList *l = r_str_split_list (conflict, " ", 0); // conflictive packages
		char *pkgdir = r2pm_pkgdir (); // installed packages
		RList *files = r_sys_dir (pkgdir);
		free (pkgdir);
		if (!files) {
			return -1;
		}
		const char *file, *dep;
		r_list_foreach (files, iter, file) {
			if (*file != '.') {
				r_list_foreach (l, iter2, dep) {
					if (!strcmp (dep, file)) {
						R_LOG_ERROR ("This package conflicts with %s", file);
						return -1;
					}
				}
			}
		}
		r_list_free (files);
		r_list_free (l);
	}
	char *deps = r2pm_get (pkg, "\nR2PM_DEPS ", TT_TEXTLINE);
	if (deps) {
		char *dep;
		RListIter *iter;
		RList *l = r_str_split_list (deps, " ", 0);
		char *pkgdir = r2pm_gitdir ();
		r_list_foreach (l, iter, dep) {
			if (!clean) {
				// skip dep if already installed
				char *srcdir = r_file_new (pkgdir, pkg, NULL);
				bool is_installed = r_file_is_directory (srcdir);
				free (srcdir);
				if (is_installed) {
					continue;
				}
			}
			if (r2pm_clone (dep) == 0) {
				r2pm_install_pkg (dep, clean, false); // XXX get current pkg global value
			} else {
				R_LOG_ERROR ("Cannot clone %s", dep);
				// ignore return -1;
			}
		}
		free (pkgdir);
	}
	char *srcdir = r2pm_gitdir ();
	R_LOG_DEBUG ("Entering %s", srcdir);
	char *qjs_script = r2pm_get (pkg, "\nR2PM_INSTALL_QJS() {\n", TT_CODEBLOCK);
	if (qjs_script) {
		int res = 0;
#if R2__UNIX__ && !defined(__wasi__)
		const char *const argv[5] = {
			"radare2", "-j", "-e", qjs_script, NULL
		};
		int child = fork ();
		if (child == -1) {
			R_LOG_ERROR ("Cannot find radare2 in PATH");
			return -1;
		}
		if (child) {
			int status;
			res = waitpid (child, &status, 0);
		} else {
			execv (argv[0], (char *const *)argv);
			exit (1);
		}
#else
		R_LOG_WARN ("r2pm.qjs support is experimental");
		res = 1;
#endif
		// run script!
		free (qjs_script);
		free (srcdir);
		return res;
	}
#if R2__WINDOWS__
	char *script = r2pm_get (pkg, "\nR2PM_INSTALL_WINDOWS() {\n", TT_CODEBLOCK);
	if (!script) {
		R_LOG_ERROR ("This package does not have R2PM_INSTALL_WINDOWS instructions");
		return 1;
	}
	char *dirname = r2pm_get (pkg, "\nR2PM_DIR ", TT_TEXTLINE);
	char *s = r_str_newf ("cd %s && cd %s && %s", srcdir, pkg, script);
	if (dirname) {
		free (s);
		s = r_str_newf ("cd %s && cd %s && %s", srcdir, dirname, script);
	}
	int res = r_sandbox_system (s, 1);
	free (s);
#else
	char *script = r2pm_get (pkg, "\nR2PM_INSTALL() {\n", TT_CODEBLOCK);
	if (!script) {
		R_LOG_ERROR ("Cannot find '%s' package or missing R2PM_INSTALL block", pkg);
		free (srcdir);
		return 1;
	}
	R_LOG_INFO ("SCRIPT=<<EOF");
	R_LOG_INFO ("%s", script);
	R_LOG_INFO ("EOF");
	char *pkgdir = r_str_newf ("%s/%s", srcdir, pkg);
	char *dirname = r2pm_get (pkg, "\nR2PM_DIR ", TT_TEXTLINE);
	if (dirname) {
		free (pkgdir);
		pkgdir = r_str_newf ("%s/%s/%s", srcdir, pkg, dirname);
	}
	if (have_builddir && !r_file_is_directory (pkgdir)) {
		R_LOG_ERROR ("Cannot find directory: %s", pkgdir);
		free (pkgdir);
		return 1;
	}
	char *s = have_builddir
		? r_str_newf ("cd '%s'\nexport MAKE=make\nR2PM_FAIL(){\n  echo $@\n}\n%s", pkgdir, script)
		: r_str_newf ("export MAKE=make\nR2PM_FAIL(){\n  echo $@\n}\n%s", script);
	// if no srcdir is defined because no file to pull just dont cd
	free (pkgdir);
	int res = r_sandbox_system (s, 1);
	free (s);
	if (res == 0) {
		r2pm_register (pkg, global);
	}
#endif
	free (script);
	free (srcdir);
	return res;
}

static bool r2pm_have_packages(void) {
	char *gpath = r2pm_gitdir ();
	char *pmpath = r_str_newf ("%s/%s", gpath, "radare2-pm");
	bool res = r_file_is_directory (pmpath);
	free (gpath);
	free (pmpath);
	return res;
}

static int r2pm_install(RList *targets, bool uninstall, bool clean, bool force, bool global) {
	RListIter *iter;
	const char *t;
	int rc = 0;
	char *r2v = r_sys_cmd_str ("radare2 -NNqv", NULL, NULL);
	if (R_STR_ISEMPTY (r2v)) {
		R_LOG_ERROR ("Cannot run radare2 -qv");
		free (r2v);
		return -1;
	}
	r_str_trim (r2v);
	R_LOG_INFO ("Using r2-%s and r2pm-" R2_VERSION, r2v);
	free (r2v);
	if (global) {
		r_sys_setenv ("GLOBAL", "1");
		r_sys_setenv ("R2PM_GLOBAL", "1");
		char *sudo = r_sys_getenv ("SUDO");
		if (R_STR_ISEMPTY (sudo)) {
			free (sudo);
			sudo = strdup ("sudo");
		}
		r_sys_setenv ("R2PM_SUDO", sudo);
		r_sys_setenv ("SUDO", sudo);
		free (sudo);
	} else {
		r_sys_setenv ("GLOBAL", "0");
		r_sys_setenv ("R2PM_GLOBAL", "0");
		r_sys_setenv ("R2PM_SUDO", "");
		r_sys_setenv ("SUDO", "");
	}
	if (!r2pm_have_packages ()) {
		R_LOG_ERROR ("Please run r2pm -U to initialize/update the database");
		return 1;
	}
	r_list_foreach (targets, iter, t) {
		if (R_STR_ISEMPTY (t)) {
			continue;
		}
		if (uninstall) {
			r2pm_uninstall_pkg (t, global);
		}
		if (clean) {
			r2pm_clean_pkg (t);
		}
		if (r2pm_clone (t) == 0) {
			rc |= r2pm_install_pkg (t, clean, global);
		} else {
			R_LOG_ERROR ("Cannot clone %s", t);
			rc = 1;
		}
	}
	return rc;
}

static int r2pm_edit(RList *targets) {
	RListIter *iter;
	const char *t;
	int rc = 0;
	r_list_foreach (targets, iter, t) {
		char *pkgpath = r2pm_pkgpath (t);
		if (pkgpath) {
			char *editor = r_sys_getenv ("EDITOR");
			if (R_STR_ISNOTEMPTY (editor)) {
				rc = r_sys_cmdf ("%s '%s'", editor, pkgpath);
			} else {
#if R2__WINDOWS__
				rc = r_sys_cmdf ("notepad '%s'", pkgpath);
#else
				rc = r_sys_cmdf ("vim '%s'", pkgpath);
#endif
			}
#if 0
			r_line_dietline_init ();
			r_cons_editor (pkgpath, NULL);
			int rc = r_sys_cmdf ("r2 -c 'oe %s;q' --", pkgpath);
#endif
			if (rc != 0) {
				printf ("%s\n", pkgpath);
			}
		} else {
			R_LOG_ERROR ("Unknown package");
		}
		free (pkgpath);
	}
	return rc;
}

static int r2pm_doc(RList *targets) {
	RListIter *iter;
	const char *t;
	int rc = 0;
	r_list_foreach (targets, iter, t) {
		rc |= r2pm_doc_pkg (t);
	}
	return rc;
}

static int r2pm_clean(RList *targets) {
	RListIter *iter;
	const char *t;
	int rc = 0;
	r_list_foreach (targets, iter, t) {
		rc |= r2pm_clean_pkg (t);
	}
	return rc;
}

static int r2pm_uninstall(RList *targets, bool global) {
	RListIter *iter;
	const char *t;
	int rc = 0;
	r_list_foreach (targets, iter, t) {
		rc |= r2pm_uninstall_pkg (t, global);
	}
	return rc;
}

static bool is_valid_package(const char *dbdir, const char *pkg) {
	if (*pkg == '.') {
		return false;
	}
	char *script = r2pm_get (pkg, "\nR2PM_INSTALL() {\n", TT_CODEBLOCK);
	if (!script) {
		R_LOG_DEBUG ("Unable to find R2PM_INSTALL script in '%s'", pkg);
		return false;
	}
	free (script);
	return true;
}

static int count_available(void) {
	char *dbdir = r2pm_dbdir ();
	RListIter *iter;
	const char *c;
	RList *dbfiles = r_sys_dir (dbdir);
	int count = 0;
	r_list_foreach (dbfiles, iter, c) {
		if (is_valid_package (dbdir, c)) {
			count++;
		}
	}
	r_list_free (dbfiles);
	free (dbdir);
	return count;
}

static int count_installed(void) {
	char *dbdir = r2pm_pkgdir ();
	RListIter *iter;
	const char *c;
	RList *dbfiles = r_sys_dir (dbdir);
	int count = 0;
	r_list_foreach (dbfiles, iter, c) {
		if (*c != '.') {
			count++;
		}
	}
	r_list_free (dbfiles);
	free (dbdir);
	return count;
}

static int r2pm_info(void) {
	const int installed_packages = count_installed ();
	const int available_packages = count_available ();
	printf ("Installed %d packages of %d in database\n",
		installed_packages, available_packages);
	return 0;
}

static char *r2pm_search(const char *grep) {
	char *path = r2pm_dbdir ();
	RList *files = r_sys_dir (path);
	free (path);
	if (!files) {
		return NULL;
	}
	RListIter *iter;
	const char *file;
	RStrBuf *sb = r_strbuf_new ("");
	r_list_foreach (files, iter, file) {
		if (*file != '.') {
			bool match = R_STR_ISEMPTY (grep) || r_str_casestr (file, grep);
			char *desc = r2pm_desc (file);
			if (desc) {
				if (match || r_str_casestr (desc, grep)) {
					r_strbuf_appendf (sb, "%s%s%s\n", file, r_str_pad (' ', 20 - strlen (file)), desc);
				}
				free (desc);
			}
		}
	}
	r_list_free (files);
	return r_strbuf_drain (sb);
}

static void r2pm_envhelp(void) {
	int r2pm_log_level = r_sys_getenv_asint ("R2_LOG_LEVEL");
	char *r2pm_plugdir = r_sys_getenv ("R2PM_PLUGDIR");
	char *r2pm_bindir = r_sys_getenv ("R2PM_BINDIR");
	char *r2pm_mandir = r_sys_getenv ("R2PM_MANDIR");
	char *r2pm_libdir = r_sys_getenv ("R2PM_LIBDIR");
	char *r2pm_dbdir = r_sys_getenv ("R2PM_DBDIR");
	char *r2pm_prefix = r_sys_getenv ("R2PM_PREFIX");
	char *r2pm_gitdir = r_sys_getenv ("R2PM_GITDIR");
	char *r2pm_giturl = r_sys_getenv ("R2PM_GITURL");
	bool r2pm_offline = r_sys_getenv_asbool ("R2PM_OFFLINE");
	char *r2pm_plugdir2 = r_str_newf (R2_LIBDIR "/radare2/" R2_VERSION);
	printf ("R2_LOG_LEVEL=%d         # define log.level for r2pm\n"
		"SUDO=sudo              # path to the SUDO executable\n"
		"MAKE=make              # path to the GNU MAKE executable\n"
		"R2PM_OFFLINE=%d         # don't git pull\n"
		"R2PM_LEGACY=0\n"
		"R2PM_TIME=YYYY-MM-DD\n"
		"R2PM_PLUGDIR=%s\n"
		"R2PM_PLUGDIR=%s (global)\n"
		"R2PM_PREFIX=%s\n"
		"R2PM_BINDIR=%s\n"
		"R2PM_MANDIR=%s\n"
		"R2PM_LIBDIR=%s\n"
		"R2PM_DBDIR=%s\n"
		"R2PM_GITDIR=%s\n"
		"R2PM_GITURL=%s\n",
		r2pm_log_level,
		r2pm_offline,
		r2pm_plugdir,
		r2pm_plugdir2,
		r2pm_prefix,
		r2pm_bindir,
		r2pm_mandir,
		r2pm_libdir,
		r2pm_dbdir,
		r2pm_gitdir,
		r2pm_giturl);
	free (r2pm_plugdir);
	free (r2pm_plugdir2);
	free (r2pm_prefix);
	free (r2pm_bindir);
	free (r2pm_mandir);
	free (r2pm_dbdir);
	free (r2pm_gitdir);
	free (r2pm_giturl);
}

static void r2pm_varprint(const char *name) {
	char *v = r_sys_getenv (name);
	if (R_STR_ISNOTEMPTY (v)) {
		printf ("%s\n", v);
	}
	free (v);
}

R_API int r_main_r2pm(int argc, const char **argv) {
	bool havetoflush = false;
	if (!r_cons_is_initialized ()) {
		havetoflush = true;
		r_cons_new ();
	}
#if R2__UNIX__
	char *wd = getcwd (NULL, 0);
	while (!wd) {
		if (chdir ("..") == -1) {
			R_LOG_ERROR ("Cannot chdir one dir up");
			return 1;
		}
		free (wd);
		wd = getcwd (NULL, 0);
	}
	free (wd);
#endif
	int level = r_sys_getenv_asint ("R2_LOG_LEVEL");
	if (level > 0) {
		r_log_set_level (level);
	} else {
		level = 2;
	}
	char *levelstr = r_str_newf ("%d", level);
	r_sys_setenv ("R2_LOG_LEVEL", levelstr);
	free (levelstr);

	R2Pm r2pm = {
		0
	};
	RGetopt opt;
	r_getopt_init (&opt, argc, argv, "aqecdiIhH:flgrRpst:uUv");
	int i, c;
	bool action = false;
	// -H option without argument
	if (argc == 2 && !strcmp (argv[1], "-H")) {
		r2pm_setenv (&r2pm);
		r2pm_envhelp ();
		return 0;
	}
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'a':
			r2pm.add = true;
			action = true;
			break;
		case 'q':
			r2pm.quiet = true;
			break;
		case 'c':
			r2pm.clean = true;
			action = true;
			break;
		case 'i':
			r2pm.install = true;
			action = true;
			break;
		case 'd':
			r2pm.doc = true;
			action = true;
			break;
		case 'p':
			r2pm.plugdir = true;
			break;
		case 'I':
			r2pm.info = true;
			action = true;
			break;
		case 'u':
			r2pm.uninstall = true;
			action = true;
			break;
		case 'e':
			r2pm.edit = true;
			action = true;
			break;
		case 'f':
			r2pm.force = true;
			break;
		case 'U':
			if (r2pm.init) {
				r2pm.upgrade = true;
			}
			r2pm.init = true;
			action = true;
			break;
		case 'l':
			r2pm.list = true;
			action = true;
			break;
		case 's':
			r2pm.search = true;
			action = true;
			break;
		case 't':
			r2pm.time = opt.arg;
			break;
		case 'R':
			r2pm.reload = true;
			action = true;
			break;
		case 'r':
			r2pm.run = true;
			action = true;
			break;
		case 'g':
			r2pm.global = true;
			break;
		case 'H':
			r2pm.envhelp = true;
			action = true;
			break;
		case 'h':
			r2pm.help = true;
			action = true;
			break;
		case 'v':
			r2pm.version = true;
			action = true;
			break;
		default:
			r2pm.help = true;
			break;
		}
	}
	r2pm_setenv (&r2pm);
	if (!action && opt.ind < argc) {
		r2pm.help = true;
		r2pm.rc = 1;
	}
	if (r2pm.plugdir) {
		if (r2pm.clean) {
			char *plugdir = r_xdg_datadir ("plugins");
			if (R_STR_ISNOTEMPTY (plugdir)) {
				r_file_rm_rf (plugdir);
				free (plugdir);
			}
		} else {
			R_LOG_ERROR ("-p requires -c");
			return 1;
		}
	}
	if (r2pm.init) {
		r2pm_update (r2pm.force);
	}
	if (r2pm.upgrade) {
		r2pm_upgrade (r2pm.force);
	}
	if (r2pm.version) {
		int mode = 0;
		if (r2pm.quiet) {
			mode = 'q';
		}
		return r_main_version_print ("r2pm", mode);
	}
	if (r2pm.envhelp) {
		r2pm_varprint (opt.arg);
		return r2pm.rc;
	}
	if (r2pm.help || argc == 1) {
		printf ("%s", helpmsg);
		return r2pm.rc;
	}
	{
		char *dbdir = r2pm_dbdir ();
		char *readme = r_file_new (dbdir, "..", "README.md", NULL);
		if (!r_file_exists (readme)) {
			r2pm.init = true;
		}
		free (readme);
		free (dbdir);
	}
	if (r2pm.run) {
		int i;
		RStrBuf *sb = r_strbuf_new ("");
		for (i = opt.ind; i < argc; i++) {
			r_strbuf_appendf (sb, " %s", argv[i]);
		}
		char *cmd = r_strbuf_drain (sb);
		int res = r_sandbox_system (cmd, 1);
		free (cmd);
		if (res > 255) {
			res = 1;
		}
		return res;
	}
	if (r2pm.add) {
		if (opt.ind == argc) {
			printf (R2PM_GITURL "\n");
		} else {
			for (i = opt.ind; i < argc; i++) {
				r2pm_add (&r2pm, argv[i]);
			}
		}
		return 0;
	}
	RList *targets = r_list_newf (free);
	for (i = opt.ind; i < argc; i++) {
		r_list_append (targets, strdup (argv[i]));
	}
	int res = -1;
	if (r2pm.clean) {
		res = r2pm_clean (targets);
	}
	if (r2pm.search) {
		char *s = r2pm_search (argv[opt.ind]);
		if (s) {
			r_cons_print (s);
			if (havetoflush) {
				r_cons_flush ();
			}
			res = 0;
			free (s);
		} else {
			res = 1;
		}
	} else if (r2pm.info) {
		res = r2pm_info ();
	} else if (r2pm.doc) {
		res = r2pm_doc (targets);
	} else if (r2pm.edit) {
		res = r2pm_edit (targets);
	} else if (r2pm.install) {
		res = r2pm_install (targets, r2pm.uninstall, r2pm.clean, r2pm.force, r2pm.global);
	} else if (r2pm.uninstall) {
		res = r2pm_uninstall (targets, r2pm.global);
	} else if (r2pm.clean) {
		res = r2pm_clean (targets);
	} else if (r2pm.list) {
		char *s = r2pm_list ();
		if (s) {
			r_cons_print (s);
			if (havetoflush) {
				r_cons_flush ();
			}
			res = 0;
		} else {
			res = 1;
		}
	}
	if (r2pm.reload) {
		RListIter *iter;
		const char *pkg;
		r_list_foreach (targets, iter, pkg) {
			char *s = r2pm_get (pkg, "\nR2PM_RELOAD() {", TT_CODEBLOCK);
			if (s) {
				char *t = r_str_trim_lines (s);
				r_cons_print (t);
				free (t);
				free (s);
			}
		}
		if (havetoflush) {
			r_cons_flush ();
		}
	}
	r_list_free (targets);
	if (res != -1) {
		return res;
	}
	if (r2pm.init || opt.ind == 1) {
		return 0;
	}
	return 1;
}
