/* radare - LGPL - Copyright 2021-2022 - pancake */

#define R_LOG_ORIGIN "r2pm"

#include <r_main.h>
#include <r_lib.h>

#define R2PM_GITURL "https://github.com/radareorg/radare2-pm"

static int r2pm_install(RList *targets, bool uninstall, bool clean, bool global);

static int r_main_r2pm_sh(int argc, const char **argv) {
#if __WINDOWS__
	R_LOG_ERROR ("r2pm.sh: not implemented");
	return 1;
#else
	int i;
	char *r2pm_sh = r_file_path ("r2pm.sh");
	if (*r2pm_sh != '/') {
		free (r2pm_sh);
		return 1;
	}
	RStrBuf *sb = r_strbuf_new (r2pm_sh);
	free (r2pm_sh);
	for (i = 1; i < argc; i++) {
		r_strbuf_appendf (sb, " %s", argv[i]);
	}
	char *cmd = r_strbuf_drain (sb);
	int res = cmd? r_sandbox_system (cmd, 0): -1;
	free (cmd);
	return res;
#endif
}

static const char *helpmsg = \
"Usage: r2pm [-flags] [pkgs...]\n"\
"Commands:\n"\
" -a [repository]   add or -delete external repository\n"\
" -c ([git/dir])    clear source cache (R2PM_GITDIR)\n"\
" -ci <pkgname>     clean + install\n"\
" -cp               clean the user's home plugin directory\n"\
" -d,doc [pkgname]  show documentation and source for given package\n"\
" -f                force operation (install, uninstall, ..)\n"\
" -gi <pkg>         global install (system-wide)\n"\
" -h                display this help message\n"\
" -H variable       show the value of given internal environment variable\n"\
" -i <pkgname>      install/update package and its dependencies (see -c, -g)\n"\
" -I                information about repository and installed packages\n"\
" -l                list installed packages\n"\
" -q                be quiet\n"\
" -r [cmd ...args]  run shell command with R2PM_BINDIR in PATH\n"\
" -s [<keyword>]    search available packages in database matching a string\n"\
" -u <pkgname>      r2pm -u baleful (See -f to force uninstall)\n"\
" -uci <pkgname>    uninstall + clean + install\n"\
" -ui <pkgname>     uninstall + install\n"\
" -U                initialize/update database and upgrade all outdated packages\n"\
" -v                show version\n";

typedef struct r_r2pm_t {
	bool help;
	bool envhelp;
	bool clean;
	bool force;
	bool global;
	bool list;
	bool add;
	bool init;
	bool run;
	bool doc;
	bool search;
	bool version;
	bool quiet;
	bool info;
	bool install;
	bool uninstall;
} R2Pm;

static int git_pull(const char *dir) {
	char *s = r_str_newf ("cd %s && git pull ; git diff", dir);
	int rc = r_sandbox_system (s, 1);
	free (s);
	return rc;
}

static int git_clone(const char *dir, const char *url) {
	char *cmd = r_str_newf ("git clone --depth=10 --recursive %s %s", url, dir);
	int rc = r_sandbox_system (cmd, 1);
	free (cmd);
	return rc;
}

static bool r2pm_actionword(R2Pm *r2pm, const char *action) {
	if (!strcmp (action, "init") || !strcmp (action, "update")) {
		R_LOG_WARN ("Action words will be deprecated in r2-5.9.x, use -U instead of %s", action);
		r2pm->init = true;
	} else if (!strcmp (action, "help")) {
		R_LOG_WARN ("Action words will be deprecated in r2-5.9.x, use -h instead of %s", action);
		r2pm->help = true;
	} else if (!strcmp (action, "info")) {
		R_LOG_WARN ("Action words will be deprecated in r2-5.9.x, use -I instead of %s", action);
		r2pm->info = true;
	} else {
		return false;
	}
	return true;
}

static bool r2pm_add(R2Pm *r2pm, const char *repository) {
	R_LOG_INFO ("r2pm.add is not implemented");
	return false;
}
static char *r2pm_bindir(void) {
	return r_xdg_datadir ("prefix/bin");
}

static char *r2pm_gitdir(void) {
	return r_xdg_datadir ("r2pm/git");
}

static char *r2pm_dbdir(void) {
	return r_xdg_datadir ("r2pm/db");
}

static char *r2pm_pkgdir(void) {
	return r_xdg_datadir ("r2pm/pkg");
}

typedef enum {
	TT_TEXTLINE,
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
		char *s = r_time_stamp_to_str (time (0));
		r_strbuf_appendf (sb, "InstallationDate: %s\n", s);
		free (s);
		char *ss = r_strbuf_drain (sb);
		r_file_dump (f, (const ut8*)ss, strlen (ss), false);
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

static char *r2pm_get(const char *file, const char *token, R2pmTokenType type) {
	char *res = NULL;
	char *dbdir = r2pm_dbdir ();
	char *path = r_str_newf ("%s/%s", dbdir, file);
	free (dbdir);
	char *data = r_file_slurp (path, NULL);
	if (!data) {
		free (path);
		return NULL;
	}
	const char *needle = token; // "\nR2PM_DESC ";
	char *descptr = strstr (data, needle);
	if (descptr) {
		char *nl = NULL;
		switch (type) {
		case TT_TEXTLINE:
			descptr += strlen (needle);
			nl = strchr (descptr, '\n');
			if (nl) {
				*nl = 0;
				nl--;
				if (*nl == '"') {
					*nl = 0;
				}
			}
			if (*descptr == '"') {
				descptr++;
			}
			res = strdup (descptr);
			break;
		case TT_ENDQUOTE:
			nl = strchr (descptr + strlen (token), '\n');
			if (nl) {
				char *begin = nl + 1;
				char *eoc = strstr (begin, "\n\"\n");
				if (eoc) {
					return r_str_ndup (begin, eoc-begin);
				} else {
					R_LOG_ERROR ("Cannot find end of thing");
					return NULL;
				}
			}
			break;
		case TT_CODEBLOCK:
			nl = strchr (descptr + strlen (token), '\n');
			if (nl) {
				char *begin = nl + 1;
				char *eoc = strstr (begin, "\n}\n");
				if (eoc) {
					return r_str_ndup (begin, eoc-begin);
				} else {
					R_LOG_ERROR ("Cannot find end of thing");
					return NULL;
				}
			}
			break;
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

static void r2pm_upgrade(void) {
	char *s = r_sys_cmd_str ("radare2 -qcq -- 2>&1 | grep r2pm | sed -e 's,$,;,g'", NULL, 0);
	r_str_trim (s);
	RList *list = r_str_split_list (s, "\n", -1);
	striptrim (list);
	if (r_list_length (list) < 1) {
		R_LOG_INFO ("Nothing to upgrade");
	} else {
		r2pm_install (list, false, true, false);
	}
	free (s);
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

static int r2pm_update(void) {
	char *gpath = r2pm_gitdir ();
	char *pmpath = r_str_newf ("%s/%s", gpath, "radare2-pm");
	r_sys_mkdirp (gpath);
	if (r_file_is_directory (pmpath)) {
		if (git_pull (pmpath) != 0) {
			R_LOG_ERROR ("git pull");
			free (pmpath);
			free (gpath);
			return 1;
		}
	} else {
		git_clone (pmpath, R2PM_GITURL);
	}
	char *dbpath = r2pm_dbdir ();

	// copy files from git into db
	r_sys_mkdirp (dbpath);
	char *pmdbpath = r_str_newf ("%s/db", pmpath);
	RList *files = r_sys_dir (pmdbpath);
	if (files) {
		RListIter *iter;
		const char *file;
		r_list_foreach (files, iter, file) {
			if (*file != '.') {
				char *src = r_str_newf ("%s/%s", pmdbpath, file);
				char *dst = r_str_newf ("%s/%s", dbpath, file);
				if (r_file_copy (src, dst)) {
					R_LOG_DEBUG ("Copying '%s' into '%s'", src, dst);
				} else {
					R_LOG_WARN ("Cannot copy '%s' into '%s'", file, dbpath);
				}
				free (src);
				free (dst);
			}
		}
		r_list_free (files);
	}
	free (pmdbpath);
	free (pmpath);
	free (gpath);
	free (dbpath);
	return 0;
}

static void r2pm_setenv(void) {
	char *gmake = r_file_path ("gmake");
	if (gmake && *gmake == '/') {
		r_sys_setenv ("MAKE", gmake);
	} else {
		r_sys_setenv ("MAKE", "make");
	}
	free (gmake);
	char *r2_plugdir = r_xdg_datadir ("plugins");
	r_sys_setenv ("R2PM_PLUGDIR", r2_plugdir);
	free (r2_plugdir);

	char *dbdir = r2pm_dbdir ();
	r_sys_setenv ("R2PM_DBDIR", dbdir);
	free (dbdir);

	r_sys_setenv ("R2_LIBEXT", R_LIB_EXT);

	char *gdir = r2pm_gitdir ();
	r_sys_setenv ("R2PM_GITDIR", gdir);
	free (gdir);

	char *pd = r_sys_cmd_str ("radare2 -H R2_USER_PLUGINS", NULL, NULL);
	r_str_trim (pd);
	r_sys_setenv ("R2_USER_PLUGINS", pd);
	free (pd);

	char *r2_prefix = r_xdg_datadir ("prefix");
	r_sys_setenv ("R2PM_PREFIX", r2_prefix);

	char *pkgcfg = r_sys_getenv ("PKG_CONFIG_PATH");
	char *r2pm_pkgcfg = r_xdg_datadir ("prefix/lib/pkgconfig");
	if (R_STR_ISNOTEMPTY (pkgcfg)) {
		char *pcp = r_str_newf ("%s:%s:%s", R2_PREFIX "/lib/pkgconfig", r2pm_pkgcfg, pkgcfg);
		r_sys_setenv ("PKG_CONFIG_PATH", pcp);
		free (pcp);
	} else {
		char *pcp = r_str_newf ("%s:%s", r2pm_pkgcfg, R2_PREFIX "/lib/pkgconfig");
		r_sys_setenv ("PKG_CONFIG_PATH", pcp);
		free (pcp);
	}
	free (r2pm_pkgcfg);
	free (pkgcfg);

	char *bindir = r_str_newf ("%s/bin", r2_prefix);
	r_sys_setenv ("R2PM_BINDIR", bindir);
	free (bindir);

	char *oldpath = r_sys_getenv ("PATH");
	if (!strstr (oldpath, r2_prefix)) {
		char *newpath = r_str_newf ("%s/bin:%s", r2_prefix, oldpath);
		r_sys_setenv ("PATH", newpath);
		free (newpath);
	}
	free (oldpath);
	free (r2_prefix);

	char *opath = r_sys_getenv ("PATH");
	if (opath) {
		char *bindir = r2pm_bindir ();
		const char *sep = R_SYS_ENVSEP;
		char *newpath = r_str_newf ("%s%s%s", bindir, sep, opath);
		r_sys_setenv ("PATH", newpath);
		free (newpath);
		free (opath);
		free (bindir);
	}

	// GLOBAL = 0 # depends on r2pm.global, which is set on r2pm_install
	char *python = r_sys_getenv ("PYTHON");
	if (!python) {
		python = r_file_path ("python3");
		if (!python) {
			python = r_file_path ("python");
			if (!python) {
				python = r_file_path ("python2");
			}
		}
		if (python) {
			r_sys_setenv ("PYTHON", python);
		}
	}
	free (python);
}

static int r2pm_install_pkg(const char *pkg, bool global) {
	R_LOG_INFO ("Starting install for %s", pkg);
	char *deps = r2pm_get (pkg, "\nR2PM_DEPS ", TT_TEXTLINE);
	if (deps) {
		char *dep;
		RListIter *iter;
		RList *l = r_str_split_list (deps, " ", 0);
		r_list_foreach (l, iter, dep) {
			r2pm_install_pkg (dep, false); // XXX get current pkg global value
		}
	}
	char *srcdir = r2pm_gitdir ();
	r2pm_setenv ();
	R_LOG_DEBUG ("Entering %s", srcdir);
#if __WINDOWS__
	char *script = r2pm_get (pkg, "\nR2PM_INSTALL_WINDOWS() {", TT_CODEBLOCK);
	if (!script) {
		R_LOG_ERROR ("This package does not have R2PM_INSTALL_WINDOWS instructions");
		return 1;
	}
	char *s = r_str_newf ("cd %s\ncd %s\n%s", srcdir, pkg, script);
	int res = r_sandbox_system (s, 1);
	free (s);
#else
	char *script = r2pm_get (pkg, "\nR2PM_INSTALL() {", TT_CODEBLOCK);
	if (!script) {
		R_LOG_ERROR ("Invalid package name or script '%s'", pkg);
		free (srcdir);
		return 1;
	}
	R_LOG_DEBUG ("script (%s)", script);
	char *s = r_str_newf ("cd '%s/%s'\nexport MAKE=make\nR2PM_FAIL(){\n  echo $@\n}\n%s", srcdir, pkg, script);
	int res = r_sandbox_system (s, 1);
	free (s);
	if (res == 0) {
		r2pm_register (pkg, global);
	}
#endif
	free (srcdir);
	return res;
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
		if (d && r_file_exists (d)) {
			r_file_rm_rf (d);
		}
		free (d);
	}
	free (srcdir);
	return 0;
}

static int r2pm_uninstall_pkg(const char *pkg) {
	R_LOG_INFO ("Uninstalling %s", pkg);
	char *srcdir = r2pm_gitdir ();
	r2pm_setenv ();
#if __WINDOWS__
	char *script = r2pm_get (pkg, "\nR2PM_UNINSTALL_WINDOWS() {", TT_CODEBLOCK);
	if (!script) {
		R_LOG_ERROR ("This package does not have R2PM_UNINSTALL_WINDOWS instructions");
		free (srcdir);
		return 1;
	}
	char *s = r_str_newf ("cd %s\ncd %s\n%s", srcdir, pkg, script);
	int res = r_sandbox_system (s, 1);
	free (s);
#else
	char *script = r2pm_get (pkg, "\nR2PM_UNINSTALL() {", TT_CODEBLOCK);
	if (!script) {
		R_LOG_ERROR ("Cannot parse package");
		free (srcdir);
		return 1;
	}
	char *s = r_str_newf ("cd %s/%s\nexport MAKE=make\nR2PM_FAIL(){\n  echo $@\n}\n%s",
		srcdir, pkg, script);
	int res = r_sandbox_system (s, 1);
	free (s);

	r2pm_unregister (pkg);
#endif
	free (srcdir);
	return res;
}

static int r2pm_clone(const char *pkg) {
	char *pkgdir = r2pm_gitdir ();
	char *srcdir = r_file_new (pkgdir, pkg, NULL);
	free (pkgdir);
	if (r_file_is_directory (srcdir)) {
		git_pull (srcdir);
	} else {
		char *url = r2pm_get (pkg, "\nR2PM_GIT ", TT_TEXTLINE);
		if (url) {
			char *dir = strchr (url, ' ');
			if (dir) {
				*dir++ = 0;
				if (strcmp (dir, pkg)) {
					R_LOG_WARN ("pkgname != clonedir");
				}
			}
			git_clone (srcdir, url);
			free (url);
		} else {
			char *url = r2pm_get (pkg, "\nR2PM_TGZ", TT_TEXTLINE);
			bool use_c_impl = false;
			if (use_c_impl) {
				R_LOG_TODO ("wget tarball from '%s'", url);
			} else {
				// TODO. run wget
			}
			free (srcdir);
			free (url);
			return 1;
		}
	}
	free (srcdir);
	return 0;
}

static int r2pm_install(RList *targets, bool uninstall, bool clean, bool global) {
	RListIter *iter;
	const char *t;
	int rc = 0;
	char *r2v = r_sys_cmd_str ("radare2 -qv", NULL, NULL);
	if (R_STR_ISEMPTY (r2v)) {
		R_LOG_ERROR ("Cannot run radare2 -qv");
		free (r2v);
		return -1;
	}
	r_str_trim (r2v);
	R_LOG_INFO ("Using r2-%s and r2pm-"R2_VERSION, r2v);
	free (r2v);
	if (global) {
		r_sys_setenv ("GLOBAL", "1");
	} else {
		r_sys_setenv ("GLOBAL", "0");
	}
	r_list_foreach (targets, iter, t) {
		if (R_STR_ISEMPTY (t)) {
			continue;
		}
		if (uninstall) {
			r2pm_uninstall_pkg (t);
		}
		if (clean) {
			r2pm_clean_pkg (t);
		}
		r2pm_clone (t);
		rc |= r2pm_install_pkg (t, global);
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

static int r2pm_uninstall(RList *targets) {
	RListIter *iter;
	const char *t;
	int rc = 0;
	r_list_foreach (targets, iter, t) {
		rc |= r2pm_uninstall_pkg (t);
	}
	return rc;
}

static bool is_valid_package(const char *dbdir, const char *pkg) {
	if (*pkg == '.') {
		return false;
	}
	char *script = r2pm_get (pkg, "\nR2PM_INSTALL() {", TT_CODEBLOCK);
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
			count ++;
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
			count ++;
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
			bool match = R_STR_ISEMPTY (grep) || strstr (file, grep);
			char *desc = r2pm_desc (file);
			if (desc) {
				if (match || strstr (desc, grep)) {
					r_strbuf_appendf (sb, "%s%s%s\n", file, r_str_pad (' ', 20 - strlen (file)), desc);
				}
				free (desc);
			}
		}
	}
	r_list_free (files);
	return r_strbuf_drain (sb);
}

static void r2pm_envhelp(bool verbose) {
	if (verbose) {
		char *r2pm_plugdir = r_sys_getenv ("R2PM_PLUGDIR");
		char *r2pm_bindir = r_sys_getenv ("R2PM_BINDIR");
		char *r2pm_dbdir = r_sys_getenv ("R2PM_DBDIR");
		char *r2pm_gitdir = r_sys_getenv ("R2PM_GITDIR");
		char *r2pm_gitskip = strdup ("");
		printf ("Environment:\n"\
			" R2_LOG_LEVEL=2         # define log.level for r2pm\n"\
			" SUDO=sudo              # path to the SUDO executable\n"\
			" MAKE=make              # path to the GNU MAKE executable\n"\
			" R2PM_PLUGDIR=%s\n"\
			" R2PM_BINDIR=%s\n"\
			" R2PM_OFFLINE=0\n"\
			" R2PM_LEGACY=0\n"\
			" R2PM_DBDIR=%s\n"\
			" R2PM_GITDIR=%s\n"\
			" R2PM_GITSKIP=%s\n",
				r2pm_plugdir,
				r2pm_bindir,
				r2pm_dbdir,
				r2pm_gitdir,
				r2pm_gitskip
		       );
		free (r2pm_plugdir);
		free (r2pm_bindir);
		free (r2pm_dbdir);
		free (r2pm_gitdir);
		free (r2pm_gitskip);
	} else {
		printf ("R2_LOG_LEVEL\n"\
			"R2PM_PLUGDIR\n"\
			"R2PM_BINDIR\n"\
			"R2PM_OFFLINE\n"\
			"R2PM_LEGACY\n"\
			"R2PM_DBDIR\n"\
			"R2PM_GITDIR\n"\
			"R2PM_GITSKIP\n");
	}
}

static void r2pm_varprint(const char *name) {
	if (R_STR_ISEMPTY (name)) {
		r2pm_envhelp (false);
	} else if (r_str_startswith (name, "R2PM_")) {
		r2pm_setenv ();
		char *v = r_sys_getenv (name);
		printf ("%s\n", v);
		free (v);
	}
}

static int r_main_r2pm_c(int argc, const char **argv) {
	bool havetoflush = false;
	if (!r_cons_is_initialized ()) {
		havetoflush = true;
		r_cons_new ();
	}
	R2Pm r2pm = {0};
	RGetopt opt;
	r_getopt_init (&opt, argc, argv, "aqcdiIhHflgrsuUv");
	if (opt.ind < argc) {
		// TODO: fully deprecate during the 5.9.x cycle
		r2pm_actionword (&r2pm, argv[opt.ind]);
	}
	int level = r_sys_getenv_asint ("R2_LOG_LEVEL");
	if (level > 0) {
		r_log_set_level (level);
	}
	int i, c;
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'a':
			r2pm.add = true;
			break;
		case 'q':
			r2pm.quiet = true;
			break;
		case 'c':
			r2pm.clean = true;
			break;
		case 'i':
			r2pm.install = true;
			break;
		case 'd':
			r2pm.doc = true;
			break;
		case 'I':
			r2pm.info = true;
			break;
		case 'u':
			r2pm.uninstall = true;
			break;
		case 'f':
			r2pm.force = true;
			break;
		case 'U':
			r2pm.init = true;
			r2pm_upgrade ();
			break;
		case 'l':
			r2pm.list = true;
			break;
		case 's':
			r2pm.search = true;
			break;
		case 'r':
			r2pm.run = true;
			break;
		case 'g':
			r2pm.global = true;
			break;
		case 'H':
			r2pm_varprint (argv[opt.ind]);
			break;
		case 'h':
			if (r2pm.help) {
				r2pm.envhelp = true;
			} else {
				r2pm.help = true;
			}
			break;
		case 'v':
			r2pm.version = true;
			break;
		}
	}
	if (r2pm.version) {
		if (r2pm.quiet) {
			printf ("%s\n", R2_VERSION);
			return 0;
		}
		return r_main_version_print ("r2pm");
	}
	if (r2pm.help || argc == 1) {
		r2pm_setenv ();
		printf ("%s", helpmsg);
		if (r2pm.envhelp) {
			r2pm_envhelp (true);
		}
		return 0;
	}
	if (r2pm.init) {
		return r2pm_update ();
	}
	if (r2pm.run) {
		int i;
		RStrBuf *sb = r_strbuf_new ("");
		for (i = opt.ind; i < argc; i++) {
			r_strbuf_appendf (sb, " %s", argv[i]);
		}
		char *cmd = r_strbuf_drain (sb);
		r2pm_setenv ();
		int res = r_sandbox_system (cmd, 1);
		free (cmd);
		return res;
	}
	if (r2pm.add) {
		if (opt.ind == argc) {
			printf ("https://github.com/radareorg/radare2-pm\n");
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
	} else if (r2pm.install) {
		res = r2pm_install (targets, r2pm.uninstall, r2pm.clean, r2pm.global);
	} else if (r2pm.uninstall) {
		res = r2pm_uninstall (targets);
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
	r_list_free (targets);
	if (res != -1) {
		return res;
	}
	if (opt.ind == 1) {
		return 0;
	}
	return 1;
}

R_API int r_main_r2pm(int argc, const char **argv) {
	bool use_sh_impl = r_sys_getenv_asbool ("R2PM_LEGACY");
	if (use_sh_impl) {
		return r_main_r2pm_sh (argc, argv);
	}
	return r_main_r2pm_c (argc, argv);
}
