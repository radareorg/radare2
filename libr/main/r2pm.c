/* radare - LGPL - Copyright 2021-2022 - pancake */

#include <r_main.h>

#if R2_580
#define R2PM_DEFAULT_NATIVE 1
#else
#define R2PM_DEFAULT_NATIVE 0
#endif

static int r_main_r2pm_sh(int argc, const char **argv) {
#if __WINDOWS__
	eprintf ("r2pm.sh: not implemented\n");
	return 1;
#else
	int i;
	RStrBuf *sb = r_strbuf_new ("r2pm.sh");
	for (i = 1; i < argc; i++) {
		r_strbuf_appendf (sb, " %s", argv[i]);
	}
	char *cmd = r_strbuf_drain (sb);
	int res = r_sandbox_system (cmd, 1);
	free (cmd);
	return res;
#endif
}

static const char *helpmsg = \
"Usage: r2pm [-flags] [pkgs...]\n"\
"Commands:\n"\
" -c ([git/dir])    clear source cache (GITDIR)\n"\
" -ci <pkgname>     clean + install\n"\
" -cp               clean the user's home plugin directory\n"\
" -d,doc [pkgname]  show documentation for given package\n"\
" -f                force operation (install, uninstall, ..)\n"\
" -gi <pkg>         global install (system-wide)\n"\
" -h                show this message\n"\
" -H variable       show value of given variable\n"\
" -I                information about repository and installed packages\n"\
" -i <pkgname>      install/update package and its dependencies (see -c, -g)\n"\
" -l                list installed pkgs\n"\
" -r [cmd ...args]  run shell command with R2PM_BINDIR in PATH\n"\
" -s [<keyword>]    search in database\n"\
" -uci <pkgname>    uninstall + clean + install\n"\
" -ui <pkgname>     uninstall + install\n"\
" -u <pkgname>      r2pm -u baleful (See -f to force uninstall)\n"\
" -U                r2pm -U (upgrade all outdated packages)\n"\
" -v                show version\n";

typedef struct r_r2pm_t {
	bool help;
	bool clean;
	bool force;
	bool global;
	bool list;
	bool init;
	bool run;
	bool doc;
	bool search;
	bool version;
	bool info;
	bool install;
	bool uninstall;
} R2Pm;

static int git_pull(const char *dir) {
	char *s = r_str_newf ("cd %s\ngit pull", dir);
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
		r2pm->init = true;
	} else if (!strcmp (action, "help")) {
		r2pm->help = true;
	} else if (!strcmp (action, "info")) {
		r2pm->info = true;
	} else if (!strcmp (action, "help")) {
		r2pm->help = true;
	} else {
		return false;
	}
	return true;
}

static char *r2pm_bindir(void) {
	return r_str_home (".local/share/radare2/prefix/bin");
}

static char *r2pm_gitdir(void) {
	return r_str_home (".local/share/radare2/r2pm/git");
}

static char *r2pm_dbdir(void) {
	return r_str_home (".local/share/radare2/r2pm/db");
}

static char *r2pm_pkgdir(void) {
	return r_str_home (".local/share/radare2/r2pm/pkg");
}

typedef enum {
	TT_TEXTLINE,
	TT_CODEBLOCK,
	TT_ENDQUOTE,
} R2pmTokenType;

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
					eprintf ("Cannot find end of thing\n");
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
					eprintf ("Cannot find end of thing\n");
					return NULL;
				}
			}
			break;
		}
	}
	free (data);
	return res;
}

static char *r2pm_desc(const char *file) {
	return r2pm_get (file, "\nR2PM_DESC ", TT_TEXTLINE);
}

static int r2pm_list(void) {
	char *path = r2pm_pkgdir ();
	RList *files = r_sys_dir (path);
	free (path);
	if (!files) {
		return 1;
	}
	RListIter *iter;
	const char *file;
	r_list_foreach (files, iter, file) {
		if (*file != '.') {
			printf ("%s\n", file);
		}
	}
	r_list_free (files);
	return 0;
}

static int r2pm_update(void) {
	char *gpath = r2pm_gitdir ();
	char *pmpath = r_str_newf ("%s/%s", gpath, "radare2-pm");
	r_sys_mkdirp (gpath);
	if (r_file_exists (pmpath)) {
		if (git_pull (pmpath) != 0) {
			eprintf ("Error\n");
			free (pmpath);
			free (gpath);
			return 1;
		}
	} else {
		const char *giturl = "https://github.com/radareorg/radare2-pm";
		git_clone (pmpath, giturl);
	}

	// copy files from git into db
	char *dbpath = r2pm_dbdir ();
	r_sys_mkdirp (dbpath);
	RList *files = r_sys_dir (pmpath);
	if (files) {
		RListIter *iter;
		const char *file;
		r_list_foreach (files, iter, file) {
			if (*file != '.') {
				char *src = r_str_newf ("%s/%s", pmpath, file);
				char *dst = r_str_newf ("%s/%s", dbpath, file);
				if (!r_file_copy (src, dst)) {
					eprintf ("Warning: Cannot copy '%s' into '%s'.\n", file, dbpath);
				}
				free (src);
				free (dst);
			}
		}
		r_list_free (files);
	}
	free (pmpath);
	free (gpath);
	free (dbpath);
	return 0;
}

static void r2pm_setenv(void) {
	r_sys_setenv ("MAKE", "make");
	char *r2_plugdir = r_str_home (R2_HOME_PLUGINS);
	r_sys_setenv ("R2PM_PLUGDIR", r2_plugdir);
	free (r2_plugdir);

	char *dbdir = r2pm_dbdir ();
	r_sys_setenv ("R2PM_DBDIR", dbdir);
	free (dbdir);

	char *gdir = r2pm_gitdir ();
	r_sys_setenv ("R2PM_GITDIR", gdir);
	free (gdir);

	char *r2_prefix = r_str_home (R2_HOME_DATADIR "/prefix");
	r_sys_setenv ("R2PM_PREFIX", r2_prefix);

	char *r2pm_bindir = r_str_newf ("%s/bin", r2_prefix);
	r_sys_setenv ("R2PM_BINDIR", r2pm_bindir);
	free (r2pm_bindir);

	char *oldpath = r_sys_getenv ("PATH");
	if (!strstr (oldpath, r2_prefix)) {
		char *newpath = r_str_newf ("%s/bin:%s", r2_prefix, oldpath);
		r_sys_setenv ("PATH", newpath);
		free (newpath);
	}
	free (oldpath);
	free (r2_prefix);

	// GLOBAL=0 # depends on r2pm.global, which is set on r2pm_install
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

static int r2pm_install_pkg(const char *pkg) {
	printf ("[r2pm] Installing %s ...\n", pkg);
	char *deps = r2pm_get (pkg, "\nR2PM_DEPS ", TT_TEXTLINE);
	if (deps) {
		char *dep;
		RListIter *iter;
		RList *l = r_str_split_list (deps, " ", 0);
		r_list_foreach (l, iter, dep) {
			eprintf ("(%s)\n", dep);
			r2pm_install_pkg (dep);
		}
	}
	char *srcdir = r2pm_gitdir ();
	r2pm_setenv ();
#if __WINDOWS__
	char *script = r2pm_get (pkg, "\nR2PM_INSTALL_WINDOWS() {", TT_CODEBLOCK);
	if (!script) {
		eprintf ("This package does not have R2PM_INSTALL_WINDOWS instructions\n");
		return 1;
	}
	char *s = r_str_newf ("cd %s\ncd %s\n%s", srcdir, pkg, script);
	int res = r_sandbox_system (s, 1);
	free (s);
#else
	char *script = r2pm_get (pkg, "\nR2PM_INSTALL() {", TT_CODEBLOCK);
	if (!script) {
		eprintf ("Invalid package name or script\n");
		return 1;
	}
	char *s = r_str_newf ("cd '%s/%s'\nexport MAKE=make\nR2PM_FAIL(){\n  echo $@\n}\n%s", srcdir, pkg, script);
	int res = r_sandbox_system (s, 1);
	free (s);
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
	eprintf ("Cannot find documentation for '%s'\n", pkg);
	return 1;
}

static int r2pm_clean_pkg(const char *pkg) {
	printf ("[r2pm] Cleaning %s ...\n", pkg);
	// TODO. make clean/mrproper instead maybe better?
	char *srcdir = r2pm_gitdir ();
	if (R_STR_ISNOTEMPTY (srcdir)) {
		char *d = r_file_new (srcdir, pkg, NULL);
		if (d && r_file_exists (d)) {
			eprintf ("rm -rf '%s'\n", d);
			r_file_rm_rf (d);
		}
		free (d);
	}
	free (srcdir);
	return 0;
}

static int r2pm_uninstall_pkg(const char *pkg) {
	printf ("[r2pm] Uninstalling %s ...\n", pkg);
	char *script = r2pm_get (pkg, "\nR2PM_UNINSTALL() {", TT_CODEBLOCK);
	if (!script) {
		eprintf ("Cannot parse package\n");
		return 1;
	}
	r2pm_setenv ();
	char *srcdir = r2pm_gitdir ();
	char *s = r_str_newf ("cd %s/%s\nexport MAKE=make\nR2PM_FAIL(){\n  echo $@\n}\n%s",
		srcdir, pkg, script);
	int res = r_sandbox_system (s, 1);
	free (s);
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
			git_clone (srcdir, url);
			free (url);
		} else {
			char *url = r2pm_get (pkg, "\nR2PM_TGZ", TT_TEXTLINE);
			bool use_c_impl = false;
			if (use_c_impl) {
				eprintf ("TODO: wget tarball from '%s'\n", url); 
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
	printf ("[r2pm] Using r2-"R2_VERSION"\n");
	if (global) {
		r_sys_setenv ("GLOBAL", "1");
	} else {
		r_sys_setenv ("GLOBAL", "0");
	}
	r_list_foreach (targets, iter, t) {
		if (uninstall) {
			r2pm_uninstall_pkg (t);
		}
		if (clean) {
			r2pm_clean_pkg (t);
		}
		r2pm_clone (t);
		rc |= r2pm_install_pkg (t);
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
		eprintf ("Warning: Unable to find R2PM_INSTALL script in '%s'\n", pkg);
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

static int r2pm_search(const char *grep) {
eprintf ("Pene\n");
	char *path = r2pm_dbdir ();
	RList *files = r_sys_dir (path);
	free (path);
	if (!files) {
		return 1;
	}
	RListIter *iter;
	const char *file;
	r_list_foreach (files, iter, file) {
		if (*file != '.') {
			char *desc = r2pm_desc (file);
			if (desc) {
				if (!grep || (strstr (desc, grep) || strstr (file, grep))) {
					eprintf ("%s%s%s\n", file, r_str_pad (' ', 20 - strlen (file)), desc);
				}
				free (desc);
			}
		}
	}
	r_list_free (files);
	return 0;
}

static int r_main_r2pm_c(int argc, const char **argv) {
	R2Pm r2pm = {0};
	RGetopt opt;
	r_getopt_init (&opt, argc, argv, "cdiIhflgrsu");
	if (opt.ind < argc) {
		// TODO: deprecate, only use flags imho
		r2pm_actionword (&r2pm, argv[opt.ind]);
	}
	int i, c;
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
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
		case 'h':
			r2pm.help = true;
			break;
		}
	}
	if (r2pm.help || argc == 1) {
		r2pm_setenv ();
		char *r2pm_plugdir = r_sys_getenv ("R2PM_PLUGDIR");
		char *r2pm_bindir = r_sys_getenv ("R2PM_BINDIR");
		char *r2pm_dbdir = r_sys_getenv ("R2PM_DBDIR");
		char *r2pm_gitdir = r_sys_getenv ("R2PM_GITDIR");
		char *r2pm_gitskip = strdup ("");
		printf ("%s", helpmsg);
		printf ("Environment:\n"\
				" SUDO=sudo         use this tool as sudo\n"\
				" R2PM_PLUGDIR=%s\n"\
				" R2PM_BINDIR=%s\n"\
				" R2PM_OFFLINE=0    disabled by default, avoid init/update calls if set to !=0\n"\
				" R2PM_NATIVE=0     set to 1 to use the native C codepath for r2pm\n"\
				" R2PM_DBDIR=%s\n"\
				" R2PM_GITDIR=%s\n"\
				" R2PM_GITSKIP=%s\n",
				r2pm_plugdir,
				r2pm_bindir,
				r2pm_dbdir,
				r2pm_gitdir,
				r2pm_gitskip
		       );
		return 0;
	}
	if (r2pm.init) {
		return r2pm_update ();
	}
	if (r2pm.run) {
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
		int i;
		RStrBuf *sb = r_strbuf_new ("");
		for (i = opt.ind; i < argc; i++) {
			r_strbuf_appendf (sb, " %s", argv[i]);
		}
		char *cmd = r_strbuf_drain (sb);
		int res = r_sandbox_system (cmd, 1);
		free (cmd);
		return res;
	}
	RList *targets = r_list_newf (free);
	for (i = opt.ind; i < argc; i++) {
		r_list_append (targets, strdup (argv[i]));
	}
	int res = -1;
	if (r2pm.search) {
		res = r2pm_search (argv[opt.ind]);
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
		res = r2pm_list ();
	}
	r_list_free (targets);
	if (res != -1) {
		return res;
	}
	if (opt.ind == 1) {
		return 0;
	}
#if __WINDOWS__
	bool use_c_impl = true;
#else
	bool use_c_impl = r_sys_getenv_asbool ("R2PM_NATIVE");
#endif
	if (use_c_impl) {
		return 1;
	}
	return r_main_r2pm_sh (argc, argv);
}

R_API int r_main_r2pm(int argc, const char **argv) {
#if __WINDOWS__ || R2PM_DEFAULT_NATIVE
	bool use_c_impl = true;
#else
	bool use_c_impl = r_sys_getenv_asbool ("R2PM_NATIVE");
#endif
	if (use_c_impl) {
		return r_main_r2pm_c (argc, argv);
	}
	return r_main_r2pm_sh (argc, argv);
}
