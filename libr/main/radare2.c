/* radare - LGPL - Copyright 2009-2020 - pancake */

#define USE_THREADS 1
#define ALLOW_THREADED 0
#define UNCOLORIZE_NONTTY 0
#ifdef _MSC_VER
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

#include <r_core.h>

static bool is_valid_gdb_file(RCoreFile *fh) {
	RIODesc *d = fh && fh->core ? r_io_desc_get (fh->core->io, fh->fd) : NULL;
	return d && strncmp (d->name, "gdb://", 6);
}

static char* get_file_in_cur_dir(const char *filepath) {
	filepath = r_file_basename (filepath);
	if (r_file_exists (filepath) && !r_file_is_directory (filepath)) {
		return r_file_abspath (filepath);
	}
	return NULL;
}

static int r_main_version_verify(int show) {
	int i, ret;
	typedef const char* (*vc)();
	const char *base = R2_GITTAP;
	struct vcs_t {
		const char *name;
		vc callback;
	} vcs[] = {
		{ "r_anal", r_anal_version },
		{ "r_lib", r_lib_version },
		{ "r_egg", r_egg_version },
		{ "r_asm", r_asm_version },
		{ "r_bin", r_bin_version },
		{ "r_cons", r_cons_version },
		{ "r_flag", r_flag_version },
		{ "r_core", r_core_version },
		{ "r_crypto", r_crypto_version },
		{ "r_bp", r_bp_version },
		{ "r_debug", r_debug_version },
		{ "r_main", r_main_version },
		{ "r_hash", r_hash_version },
		{ "r_fs", r_fs_version },
		{ "r_io", r_io_version },
#if !USE_LIB_MAGIC
		{ "r_magic", r_magic_version },
#endif
		{ "r_parse", r_parse_version },
		{ "r_reg", r_reg_version },
		{ "r_sign", r_sign_version },
		{ "r_search", r_search_version },
		{ "r_syscall", r_syscall_version },
		{ "r_util", r_util_version },
		/* ... */
		{NULL,NULL}
	};

	if (show) {
		printf ("%s  r2\n", base);
	}
	for (i = ret = 0; vcs[i].name; i++) {
		struct vcs_t *v = &vcs[i];
		const char *name = v->callback ();
		if (!ret && strcmp (base, name)) {
			ret = 1;
		}
		if (show) {
			printf ("%s  %s\n", name, v->name);
		}
	}
	if (ret) {
		if (show) {
			eprintf ("WARNING: r2 library versions mismatch!\n");
		} else {
			eprintf ("WARNING: r2 library versions mismatch! See r2 -V\n");
		}
	}
	return ret;
}

static int main_help(int line) {
	if (line < 2) {
		printf ("Usage: r2 [-ACdfLMnNqStuvwzX] [-P patch] [-p prj] [-a arch] [-b bits] [-i file]\n"
			"          [-s addr] [-B baddr] [-m maddr] [-c cmd] [-e k=v] file|pid|-|--|=\n");
	}
	if (line != 1) {
		printf (
		" --           run radare2 without opening any file\n"
		" -            same as 'r2 malloc://512'\n"
		" =            read file from stdin (use -i and -c to run cmds)\n"
		" -=           perform !=! command to run all commands remotely\n"
		" -0           print \\x00 after init and every command\n"
		" -2           close stderr file descriptor (silent warning messages)\n"
		" -a [arch]    set asm.arch\n"
		" -A           run 'aaa' command to analyze all referenced code\n"
		" -b [bits]    set asm.bits\n"
		" -B [baddr]   set base address for PIE binaries\n"
		" -c 'cmd..'   execute radare command\n"
		" -C           file is host:port (alias for -c+=http://%%s/cmd/)\n"
		" -d           debug the executable 'file' or running process 'pid'\n"
		" -D [backend] enable debug mode (e cfg.debug=true)\n"
		" -e k=v       evaluate config var\n"
		" -f           block size = file size\n"
		" -F [binplug] force to use that rbin plugin\n"
		" -h, -hh      show help message, -hh for long\n"
		" -H ([var])   display variable\n"
		" -i [file]    run script file\n"
		" -I [file]    run script file before the file is opened\n"
		" -k [OS/kern] set asm.os (linux, macos, w32, netbsd, ...)\n"
		" -l [lib]     load plugin file\n"
		" -L           list supported IO plugins\n"
		" -m [addr]    map file at given address (loadaddr)\n"
		" -M           do not demangle symbol names\n"
		" -n, -nn      do not load RBin info (-nn only load bin structures)\n"
		" -N           do not load user settings and scripts\n"
		" -NN          do not load any script or plugin\n"
		" -q           quiet mode (no prompt) and quit after -i\n"
		" -qq          quit after running all -c and -i\n"
		" -Q           quiet mode (no prompt) and quit faster (quickLeak=true)\n"
		" -p [prj]     use project, list if no arg, load if no file\n"
		" -P [file]    apply rapatch file and quit\n"
		" -r [rarun2]  specify rarun2 profile to load (same as -e dbg.profile=X)\n"
		" -R [rr2rule] specify custom rarun2 directive\n"
		" -s [addr]    initial seek\n"
		" -S           start r2 in sandbox mode\n"
#if USE_THREADS && ALLOW_THREADED
		" -t           load rabin2 info in thread\n"
#endif
		" -T           do not compute file hashes\n"
		" -u           set bin.filter=false to get raw sym/sec/cls names\n"
		" -v, -V       show radare2 version (-V show lib versions)\n"
		" -w           open file in write mode\n"
		" -x           open without exec-flag (asm.emu will not work), See io.exec\n"
		" -X           same as -e bin.usextr=false (useful for dyldcache)\n"
		" -z, -zz      do not load strings or load them even in raw\n");
	}
	if (line == 2) {
		char *datahome = r_str_home (R2_HOME_DATADIR);
		const char *dirPrefix = r_sys_prefix (NULL);
		printf (
		"Scripts:\n"
		" system       ${R2_PREFIX}/share/radare2/radare2rc\n"
		" user         ~/.radare2rc " R_JOIN_2_PATHS ("~", R2_HOME_RC) " (and " R_JOIN_3_PATHS ("~", R2_HOME_RC_DIR,"") ")\n"
		" file         ${filename}.r2\n"
		"Plugins:\n"
		" binrc        " R_JOIN_4_PATHS ("~", R2_HOME_BINRC, "bin-<format>",  "") " (elf, elf64, mach0, ..)\n"
		" R2_USER_PLUGINS " R_JOIN_2_PATHS ("~", R2_HOME_PLUGINS) "\n"
		" R2_LIBR_PLUGINS " R_JOIN_2_PATHS ("%s", R2_PLUGINS) "\n"
		" R2_USER_ZIGNS " R_JOIN_2_PATHS ("~", R2_HOME_ZIGNS) "\n"
		"Environment:\n"
		" R2_CFG_NEWSHELL sets cfg.newshell=true\n"
		" R2_DEBUG      if defined, show error messages and crash signal\n"
		" R2_DEBUG_ASSERT=1 set a breakpoint when hitting an assert\n"
		" R2_MAGICPATH " R_JOIN_2_PATHS ("%s", R2_SDB_MAGIC) "\n"
		" R2_NOPLUGINS do not load r2 shared plugins\n"
		" R2_RCFILE    ~/.radare2rc (user preferences, batch script)\n" // TOO GENERIC
		" R2_RDATAHOME %s\n" // TODO: rename to RHOME R2HOME?
		" R2_VERSION   contains the current version of r2\n" 
		"Paths:\n"
		" R2_PREFIX    "R2_PREFIX"\n"
		" R2_INCDIR    "R2_INCDIR"\n"
		" R2_LIBDIR    "R2_LIBDIR"\n"
		" R2_LIBEXT    "R_LIB_EXT"\n"
		, dirPrefix, datahome, dirPrefix);
		free (datahome);
	}
	return 0;
}

static int main_print_var(const char *var_name) {
	int i = 0;
#ifdef __WINDOWS__
	char *incdir = r_str_r2_prefix (R2_INCDIR);
	char *libdir = r_str_r2_prefix (R2_LIBDIR);
#else
	char *incdir = strdup (R2_INCDIR);
	char *libdir = strdup (R2_LIBDIR);
#endif
	char *confighome = r_str_home (R2_HOME_CONFIGDIR);
	char *datahome = r_str_home (R2_HOME_DATADIR);
	char *cachehome = r_str_home (R2_HOME_CACHEDIR);
	char *homeplugins = r_str_home (R2_HOME_PLUGINS);
	char *homezigns = r_str_home (R2_HOME_ZIGNS);
	char *plugins = r_str_r2_prefix (R2_PLUGINS);
	char *magicpath = r_str_r2_prefix (R2_SDB_MAGIC);
	struct radare2_var_t {
		const char *name;
		const char *value;
	} r2_vars[] = {
		{ "R2_VERSION", R2_VERSION },
		{ "R2_PREFIX", R2_PREFIX },
		{ "R2_MAGICPATH", magicpath },
		{ "R2_INCDIR", incdir },
		{ "R2_LIBDIR", libdir },
		{ "R2_LIBEXT", R_LIB_EXT },
		{ "R2_RCONFIGHOME", confighome },
		{ "R2_RDATAHOME", datahome },
		{ "R2_RCACHEHOME", cachehome },
		{ "R2_LIBR_PLUGINS", plugins },
		{ "R2_USER_PLUGINS", homeplugins },
		{ "R2_USER_ZIGNS", homezigns },
		{ NULL, NULL }
	};
	int delta = 0;
	if (var_name && strncmp (var_name, "R2_", 3)) {
		delta = 3;
	}
	if (var_name) {
		while (r2_vars[i].name) {
			if (!strcmp (r2_vars[i].name + delta, var_name)) {
				printf ("%s\n", r2_vars[i].value);
				break;
			}
			i++;
		}
	} else {
		while (r2_vars[i].name) {
			printf ("%s=%s\n", r2_vars[i].name, r2_vars[i].value);
			i++;
		}
	}
	free (incdir);
	free (libdir);
	free (confighome);
	free (datahome);
	free (cachehome);
	free (homeplugins);
	free (homezigns);
	free (plugins);
	free (magicpath);
	return 0;
}

static bool run_commands(RCore *r, RList *cmds, RList *files, bool quiet, int do_analysis) {
	RListIter *iter;
	const char *cmdn;
	const char *file;
	int ret;
	/* -i */
	r_list_foreach (files, iter, file) {
		if (!r_file_exists (file)) {
			eprintf ("Script '%s' not found.\n", file);
			goto beach;
		}
		ret = r_core_run_script (r, file);
		if (ret == -2) {
			eprintf ("[c] Cannot open '%s'\n", file);
		}
		if (ret < 0 || (ret == 0 && quiet)) {
			r_cons_flush ();
			return false;
		}
	}
	/* -c */
	r_list_foreach (cmds, iter, cmdn) {
		//r_core_cmd0 (r, cmdn);
		r_core_cmd_lines (r, cmdn);
		r_cons_flush ();
	}
beach:
	if (quiet) {
		if (do_analysis) {
			return true;
		}
		if (cmds && !r_list_empty (cmds)) {
			return true;
		}
		if (!r_list_empty (files)) {
			return true;
		}
	}
	return false;
}

static bool mustSaveHistory(RConfig *c) {
	if (!r_config_get_i (c, "scr.histsave")) {
		return false;
	}
	if (!r_cons_is_interactive ()) {
		return false;
	}
	return true;
}

// Try to set the correct scr.color for the current terminal.
static void set_color_default(RCore *r) {
#ifdef __WINDOWS__
	char *alacritty = r_sys_getenv ("ALACRITTY_LOG");
	if (alacritty) {
		// Despite the setting of env vars to the contrary, Alacritty on
		// Windows may not actually support >16 colors out-of-the-box
		// (https://github.com/jwilm/alacritty/issues/1662).
		// TODO: Windows 10 version check.
		r_config_set_i (r->config, "scr.color", COLOR_MODE_16);
		free (alacritty);
		return;
	}
#endif
	char *tmp = r_sys_getenv ("COLORTERM");
	if (tmp) {
		if ((r_str_endswith (tmp, "truecolor") || r_str_endswith (tmp, "24bit"))) {
			r_config_set_i (r->config, "scr.color", COLOR_MODE_16M);
		}
	} else {
		tmp = r_sys_getenv ("TERM");
		if (!tmp) {
			return;
		}
		if (r_str_endswith (tmp, "truecolor") || r_str_endswith (tmp, "24bit")) {
			r_config_set_i (r->config, "scr.color", COLOR_MODE_16M);
		} else if (r_str_endswith (tmp, "256color")) {
			r_config_set_i (r->config, "scr.color", COLOR_MODE_256);
		} else if (!strcmp (tmp, "dumb")) {
			// Dumb terminals don't get color by default.
			r_config_set_i (r->config, "scr.color", COLOR_MODE_DISABLED);
		}
	}
	free (tmp);
}

R_API int r_main_radare2(int argc, const char **argv) {
	RCore *r;
	bool forcequit = false;
	bool haveRarunProfile = false;
	RListIter *iter;
	int do_analysis = 0;
	char *cmdn, *tmp;
	RCoreFile *fh = NULL;
	RIODesc *iod = NULL;
	const char *patchfile = NULL;
	const char *prj = NULL;
	int debug = 0;
	int zflag = 0;
	bool do_connect = false;
	bool fullfile = false;
	int has_project;
	bool zerosep = false;
	int help = 0;
	enum { LOAD_BIN_ALL, LOAD_BIN_NOTHING, LOAD_BIN_STRUCTURES_ONLY } load_bin = LOAD_BIN_ALL;
	bool run_rc = true;
 	int ret, c, perms = R_PERM_RX;
	bool sandbox = false;
	ut64 baddr = UT64_MAX;
	ut64 seek = UT64_MAX;
	bool do_list_io_plugins = false;
	char *file = NULL;
	char *pfile = NULL;
	char *debugbackend = strdup ("native");
	const char *asmarch = NULL;
	const char *asmos = NULL;
	const char *forcebin = NULL;
	const char *asmbits = NULL;
	char *customRarunProfile = NULL;
	ut64 mapaddr = 0LL;
	bool quiet = false;
	bool quietLeak = false;
	int is_gdb = false;
	const char * s_seek = NULL;
	bool compute_hashes = true;
	RList *cmds = r_list_new ();
	RList *evals = r_list_new ();
	RList *files = r_list_new ();
	RList *prefiles = r_list_new ();

#define LISTS_FREE() \
		{ \
			r_list_free (cmds); \
			r_list_free (evals); \
			r_list_free (files); \
			r_list_free (prefiles); \
		}

	bool noStderr = false;

#ifdef __UNIX
	sigset_t sigBlockMask;
	sigemptyset (&sigBlockMask);
	sigaddset (&sigBlockMask, SIGWINCH);
	r_signal_sigmask (SIG_BLOCK, &sigBlockMask, NULL);
#endif

	r_sys_env_init ();
	// Create rarun2 profile with startup environ
	char **env = r_sys_get_environ ();
	char *envprofile = r_run_get_environ_profile (env);

	if (r_sys_getenv_asbool ("R2_DEBUG")) {
		char *sysdbg = r_sys_getenv ("R2_DEBUG_TOOL");
		char *fmt = (sysdbg && *sysdbg)
			? r_str_newf ("%s %%d", sysdbg)
#if __APPLE__
			: r_str_newf ("lldb -p %%d");
#else
			: r_str_newf ("gdb --pid %%d");
#endif
		r_sys_crash_handler (fmt);
		free (fmt);
		free (sysdbg);
	}
	if (argc < 2) {
		LISTS_FREE ();
		return main_help (1);
	}
	r = r_core_new ();
	if (!r) {
		eprintf ("Cannot initialize RCore\n");
		LISTS_FREE ();
		return 1;
	}
	r->r_main_radare2 = r_main_radare2;
	r->r_main_radiff2 = r_main_radiff2;
	r->r_main_rafind2 = r_main_rafind2;
	r->r_main_rabin2 = r_main_rabin2;
	r->r_main_ragg2 = r_main_ragg2;
	r->r_main_rasm2 = r_main_rasm2;
	r->r_main_rax2 = r_main_rax2;

	r->io->envprofile = envprofile;

	r_core_task_sync_begin (&r->tasks);
	if (argc == 2 && !strcmp (argv[1], "-p")) {
		r_core_project_list (r, 0);
		r_cons_flush ();
		LISTS_FREE ();
		return 0;
	}
	// HACK TO PERMIT '#!/usr/bin/r2 - -i' hashbangs
	if (argc > 2 && !strcmp (argv[1], "-") && !strcmp (argv[2], "-i")) {
		argv[1] = argv[0];
		argc--;
		argv++;
	}

	// -H option without argument
	if (argc == 2 && !strcmp (argv[1], "-H")) {
		main_print_var (NULL);
		LISTS_FREE ();
		return 0;
	}

	set_color_default (r);
	bool load_l = true;

	RGetopt opt;
	r_getopt_init (&opt, argc, argv, "=02AMCwxfF:H:hm:e:nk:NdqQs:p:b:B:a:Lui:I:l:P:R:r:c:D:vVSTzuXt");
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case '=':
			R_FREE (r->cmdremote);
			r->cmdremote = strdup ("");
			break;
		case '2':
			noStderr = true;
			break;
		case '0':
			zerosep = true;
			/* implicit -q */
			r_config_set (r->config, "scr.interactive", "false");
			r_config_set (r->config, "scr.prompt", "false");
			r_config_set_i (r->config, "scr.color", COLOR_MODE_DISABLED);
			quiet = true;
			break;
		case 'u':
			r_config_set (r->config, "bin.filter", "false");
			break;
		case 'a':
			asmarch = opt.arg;
			break;
		case 'z':
			zflag++;
			break;
		case 'A':
			do_analysis += do_analysis ? 1: 2;
			break;
		case 'b':
			asmbits = opt.arg;
			break;
		case 'B':
			baddr = r_num_math (r->num, opt.arg);
			break;
		case 'X':
			r_config_set (r->config, "bin.usextr", "false");
			break;
		case 'c':
			r_list_append (cmds, (void*)opt.arg);
			break;
		case 'C':
			do_connect = true;
			break;
#if DEBUGGER
		case 'd': debug = 1; break;
#else
		case 'd': eprintf ("Sorry. No debugger backend available.\n"); return 1;
#endif
		case 'D':
			debug = 2;
			free (debugbackend);
			debugbackend = strdup (opt.arg);
			if (!strcmp (opt.arg, "?")) {
				r_debug_plugin_list (r->dbg, 'q');
				r_cons_flush();
				LISTS_FREE ();
				return 0;
			}
			break;
		case 'e':
			if (!strcmp (opt.arg, "q")) {
				r_core_cmd0 (r, "eq");
			} else {
				r_config_eval (r->config, opt.arg, false);
				r_list_append (evals, (void*)opt.arg);
			}
			break;
		case 'f':
			fullfile = true;
			break;
		case 'F':
			forcebin = opt.arg;
			break;
		case 'h':
			help++;
			break;
		case 'H':
			main_print_var (opt.arg);
			LISTS_FREE ();
			return 0;
		case 'i':
			if (R_STR_ISEMPTY (opt.arg)) {
				eprintf ("Cannot open empty script path\n");
				ret = 1;
				goto beach;
			}
			r_list_append (files, (void*)opt.arg);
			break;
		case 'I':
			if (R_STR_ISEMPTY (opt.arg)) {
				eprintf ("Cannot open empty script path\n");
				ret = 1;
				goto beach;
			}
			r_list_append (prefiles, (void*)opt.arg);
			break;
		case 'k':
			asmos = opt.arg;
			break;
		case 'l':
			r_lib_open (r->lib, opt.arg);
			break;
		case 'L':
			do_list_io_plugins = true;
			break;
		case 'm':
			mapaddr = r_num_math (r->num, opt.arg);
			s_seek = opt.arg;
			r_config_set_i (r->config, "file.offset", mapaddr);
			break;
		case 'M':
			r_config_set (r->config, "bin.demangle", "false");
			r_config_set (r->config, "asm.demangle", "false");
			break;
		case 'n':
			if (load_bin == LOAD_BIN_ALL) { // "-n"
				load_bin = LOAD_BIN_NOTHING;
			} else if (load_bin == LOAD_BIN_NOTHING) { // second n => "-nn"
				load_bin = LOAD_BIN_STRUCTURES_ONLY;
			}
			r_config_set (r->config, "file.info", "false");
			break;
		case 'N':
			if (run_rc) {
				run_rc = false;
			} else {
				load_l = false;
			}
			break;
		case 'p':
			if (!strcmp (opt.arg, "?")) {
				r_core_project_list (r, 0);
				r_cons_flush ();
				LISTS_FREE ();
				return 0;
			}
			r_config_set (r->config, "prj.name", opt.arg);
			break;
		case 'P':
			if (R_STR_ISEMPTY (opt.arg)) {
				eprintf ("Cannot open empty rapatch path\n");
				ret = 1;
				goto beach;
			}
			patchfile = opt.arg;
			break;
		case 'Q':
			quiet = true;
			quietLeak = true;
			break;
		case 'q':
			r_config_set (r->config, "scr.interactive", "false");
			r_config_set (r->config, "scr.prompt", "false");
			r_config_set (r->config, "cfg.fortunes", "false");
			if (quiet) {
				forcequit = true;
			}
			quiet = true;
			break;
		case 'r':
			if (R_STR_ISEMPTY (opt.arg)) {
				eprintf ("Cannot open empty rarun2 profile path\n");
				ret = 1;
				goto beach;
			}
			haveRarunProfile = true;
			r_config_set (r->config, "dbg.profile", opt.arg);
			break;
		case 'R':
			customRarunProfile = r_str_appendf (customRarunProfile, "%s\n", opt.arg);
			break;
		case 's':
			s_seek = opt.arg;
			break;
		case 'S':
			sandbox = true;
			break;
#if USE_THREADS
		case 't':
#if ALLOW_THREADED
			threaded = true;
#else
			eprintf ("WARNING: -t is temporarily disabled!\n");
#endif
			break;
#endif
		case 'T':
			compute_hashes = false;
			break;
		case 'v':
			if (quiet) {
				printf ("%s\n", R2_VERSION);
				LISTS_FREE ();
				free (customRarunProfile);
				return 0;
			} else {
				r_main_version_verify (0);
				LISTS_FREE ();
				free (customRarunProfile);
				return r_main_version_print ("radare2");
			}
		case 'V':
			return r_main_version_verify (1);
		case 'w':
			perms |= R_PERM_W;
			break;
		case 'x':
			perms &= ~R_PERM_X;
			r_config_set (r->config, "io.exec", "false");
			break;
		default:
			help++;
		}
	}
	if (noStderr) {
		if (-1 == close (2)) {
			eprintf ("Failed to close stderr");
			LISTS_FREE ();
			R_FREE (debugbackend);
			return 1;
		}
		const char nul[] = R_SYS_DEVNULL;
		int new_stderr = open (nul, O_RDWR);
		if (-1 == new_stderr) {
			eprintf ("Failed to open %s", nul);
			LISTS_FREE ();
			R_FREE (debugbackend);
			return 1;
		}
		if (2 != new_stderr) {
			if (-1 == dup2 (new_stderr, 2)) {
				eprintf ("Failed to dup2 stderr");
				LISTS_FREE ();
				R_FREE (debugbackend);
				return 1;
			}
			if (-1 == close (new_stderr)) {
				eprintf ("Failed to close %s", nul);
				LISTS_FREE ();
				R_FREE (debugbackend);
				return 1;
			}
		}
	}
	{
		const char *dbg_profile = r_config_get (r->config, "dbg.profile");
		if (dbg_profile && *dbg_profile) {
			char *msg = r_file_slurp (dbg_profile, NULL);
			if (msg) {
				char *program = strstr (msg, "program=");
				if (program) {
					program += 8;
					char *p = 0;
					p = strstr (program, "\r\n");
					if (!p) {
						p = strchr (program, '\n');
					}
					if (p) {
						*p = 0;
						pfile = strdup (program);
					}
				}
				free (msg);
			} else {
				eprintf ("Cannot read dbg.profile '%s'\n", dbg_profile);
				pfile = NULL; //strdup ("");
			}
		} else {
			pfile = argv[opt.ind] ? strdup (argv[opt.ind]) : NULL;
		}
	}

	if (pfile && !*pfile) {
		eprintf ("Cannot open empty path\n");
		ret = 1;
		goto beach;
	}

	if (do_list_io_plugins) {
		if (r_config_get_i (r->config, "cfg.plugins")) {
			r_core_loadlibs (r, R_CORE_LOADLIBS_ALL, NULL);
		}
		run_commands (r, NULL, prefiles, false, do_analysis);
		run_commands (r, cmds, files, quiet, do_analysis);
		if (quietLeak) {
			exit (0);
		}
		r_io_plugin_list (r->io);
		r_cons_flush ();
		LISTS_FREE ();
		free (pfile);
		R_FREE (debugbackend);
		return 0;
	}

	if (help > 0) {
		LISTS_FREE ();
		free (pfile);
		R_FREE (debugbackend);
		return main_help (help > 1? 2: 0);
	}
#if __WINDOWS__
	pfile = r_acp_to_utf8 (pfile);
#endif // __WINDOWS__
	if (customRarunProfile) {
		char *tfn = r_file_temp (".rarun2");
		if (!r_file_dump (tfn, (const ut8*)customRarunProfile, strlen (customRarunProfile), 0)) {
			eprintf ("Cannot create %s\n", tfn);
		} else {
			haveRarunProfile = true;
			r_config_set (r->config, "dbg.profile", tfn);
		}
		free (tfn);
	}
	if (debug == 1) {
		if (opt.ind >= argc && !haveRarunProfile) {
			eprintf ("Missing argument for -d\n");
			LISTS_FREE ();
			R_FREE (debugbackend);
			return 1;
		}
		const char *src = haveRarunProfile? pfile: argv[opt.ind];
		if (src && *src) {
			char *uri = strdup (src);
			if (uri) {
				char *p = strstr (uri, "://");
				if (p) {
					*p = 0;
					// TODO: this must be specified by the io plugin, not hardcoded here
					if (!strcmp (uri, "winedbg")) {
						debugbackend = strdup ("io");
					} else {
						debugbackend = uri;
						uri = NULL;
					}
					debug = 2;
				}
				free (uri);
			}
		}
	}

	tmp = NULL;
	if (!load_l || (tmp = r_sys_getenv ("R2_NOPLUGINS"))) {
		r_config_set_i (r->config, "cfg.plugins", 0);
		free (tmp);
	}
	if (r_config_get_i (r->config, "cfg.plugins")) {
		r_core_loadlibs (r, R_CORE_LOADLIBS_ALL, NULL);
	}
	ret = run_commands (r, NULL, prefiles, false, do_analysis);
	r_list_free (prefiles);
	prefiles = NULL;

	r_bin_force_plugin (r->bin, forcebin);

	prj = r_config_get (r->config, "prj.name");
	if (prj && *prj) {
		r_core_project_open (r, prj, false);
		r_config_set (r->config, "bin.strings", "false");
	}

	if (do_connect) {
		const char *uri = argv[opt.ind];
		if (opt.ind >= argc) {
			eprintf ("Missing URI for -C\n");
			LISTS_FREE ();
			R_FREE (debugbackend);
			return 1;
		}
		if (strstr (uri, "://")) {
			r_core_cmdf (r, "=+ %s", uri);
		} else {
			argv[opt.ind] = r_str_newf ("http://%s/cmd/", argv[opt.ind]);
			r_core_cmdf (r, "=+ %s", argv[opt.ind]);
		}
		r_core_cmd0 (r, "=!=0");
		argv[opt.ind] = "-";
	}

	switch (zflag) {
	case 1:
		r_config_set (r->config, "bin.strings", "false");
		break;
	case 2:
		r_config_set (r->config, "bin.rawstr", "true");
		break;
	}
	if (zflag > 3) {
		eprintf ("Sleeping now...\n");
		r_sys_sleep (zflag);
	}

	if (run_rc) {
		r_core_parse_radare2rc (r);
	} else {
		r_config_set (r->config, "scr.utf8", "false");
	}

	if (r_config_get_i (r->config, "zign.autoload")) {
		char *path = r_file_abspath (r_config_get (r->config, "dir->zigns"));
		char *complete_path = NULL;
		RList *list = r_sys_dir (path);
		RListIter *iter;
		char *file = NULL;
		r_list_foreach (list, iter, file) {
			if (file && *file && *file != '.') {
				complete_path = r_str_newf ("%s"R_SYS_DIR"%s", path, file);
				if (r_str_endswith (complete_path, "gz")) {
					r_sign_load_gz (r->anal, complete_path);
				} else {
					r_sign_load (r->anal, complete_path);
				}
				free (complete_path);
			}
		}
		r_list_free (list);
		free (path);
	}

	if (pfile && r_file_is_directory (pfile)) {
		if (debug) {
			eprintf ("Error: Cannot debug directories, yet.\n");
			LISTS_FREE ();
			free (pfile);
			R_FREE (debugbackend);
			return 1;
		}
		if (r_sys_chdir (argv[opt.ind])) {
			eprintf ("[d] Cannot open directory\n");
			LISTS_FREE ();
			free (pfile);
			R_FREE (debugbackend);
			return 1;
		}
	} else if (argv[opt.ind] && !strcmp (argv[opt.ind], "=")) {
		int sz;
		/* stdin/batch mode */
		char *buf = r_stdin_slurp (&sz);
		eprintf ("^D\n");
		r_cons_set_raw (false);
#if __UNIX__
		// TODO: keep flags :?
		(void)freopen ("/dev/tty", "rb", stdin);
		(void)freopen ("/dev/tty", "w", stdout);
		(void)freopen ("/dev/tty", "w", stderr);
#else
		eprintf ("Cannot reopen stdin without UNIX\n");
		free (buf);
		return 1;
#endif
		if (buf && sz > 0) {
			char *path = r_str_newf ("malloc://%d", sz);
			fh = r_core_file_open (r, path, perms, mapaddr);
			if (!fh) {
				r_cons_flush ();
				free (buf);
				eprintf ("[=] Cannot open '%s'\n", path);
				LISTS_FREE ();
				free (path);
				return 1;
			}
			r_io_map_new (r->io, fh->fd, 7, 0LL, mapaddr,
					r_io_fd_size (r->io, fh->fd));
			r_io_write_at (r->io, mapaddr, (const ut8 *)buf, sz);
			r_core_block_read (r);
			free (buf);
			free (path);
			// TODO: load rbin thing
		} else {
			eprintf ("Cannot slurp from stdin\n");
			free (buf);
			LISTS_FREE ();
			return 1;
		}
	} else if (strcmp (argv[opt.ind - 1], "--") && !(r_config_get (r->config, "prj.name") && r_config_get (r->config, "prj.name")[0]) ) {
		if (debug) {
			if (asmbits) {
				r_config_set (r->config, "asm.bits", asmbits);
			}
			r_config_set (r->config, "search.in", "dbg.map"); // implicit?
			r_config_set (r->config, "cfg.debug", "true");
			perms = R_PERM_RWX;
			if (opt.ind >= argc) {
				eprintf ("No program given to -d\n");
				LISTS_FREE ();
				R_FREE (debugbackend);
				return 1;
			}
			if (debug == 2) {
				// autodetect backend with -D
				r_config_set (r->config, "dbg.backend", debugbackend);
				if (strcmp (debugbackend, "native")) {
					if (!haveRarunProfile) {
						pfile = strdup (argv[opt.ind++]);
					}
					perms = R_PERM_RX; // XXX. should work with rw too
					debug = 2;
					if (!strstr (pfile, "://")) {
						opt.ind--; // take filename
					}
#if __WINDOWS__
					pfile = r_acp_to_utf8 (pfile);
#endif // __WINDOWS__
					fh = r_core_file_open (r, pfile, perms, mapaddr);
					iod = (r->io && fh) ? r_io_desc_get (r->io, fh->fd) : NULL;
					if (!strcmp (debugbackend, "gdb")) {
						const char *filepath = r_config_get (r->config, "dbg.exe.path");
						ut64 addr = baddr;
						if (addr == UINT64_MAX) {
							addr = r_config_get_i (r->config, "bin.baddr");
						}
						if (r_file_exists (filepath) && !r_file_is_directory (filepath)) {
							char *newpath = r_file_abspath (filepath);
							if (newpath) {
								if (iod) {
									free (iod->name);
									iod->name = newpath;
								}
								if (addr == UINT64_MAX) {
									addr = r_debug_get_baddr (r->dbg, newpath);
								}
								r_core_bin_load (r, NULL, addr);
							}
						} else if (is_valid_gdb_file (fh)) {
							filepath = iod->name;
							if (r_file_exists (filepath) && !r_file_is_directory (filepath)) {
								if (addr == UINT64_MAX) {
									addr = r_debug_get_baddr (r->dbg, filepath);
								}
								r_core_bin_load (r, filepath, addr);
							} else if ((filepath = get_file_in_cur_dir (filepath))) {
								// Present in local directory
								if (iod) {
									free (iod->name);
									iod->name = (char*) filepath;
								}
								if (addr == UINT64_MAX) {
									addr = r_debug_get_baddr (r->dbg, filepath);
								}
								r_core_bin_load (r, NULL, addr);
							}
						}
					}
				}
			} else {
				const char *f = (haveRarunProfile && pfile)? pfile: argv[opt.ind];
				is_gdb = (!memcmp (f, "gdb://", R_MIN (f? strlen (f):0, 6)));
				if (!is_gdb) {
					pfile = strdup ("dbg://");
				}
#if __UNIX__
				/* implicit ./ to make unix behave like windows */
				if (f) {
					char *path, *escaped_path;
					if (strchr (f, '/')) {
						// f is a path
						path = strdup (f);
					} else {
						// f is a filename
						if (r_file_exists (f)) {
							path = r_str_prepend (strdup (f), "./");
						} else {
							path = r_file_path (f);
						}
					}
					escaped_path = r_str_arg_escape (path);
					pfile = r_str_append (pfile, escaped_path);
					file = pfile; // probably leaks
					R_FREE (escaped_path);
					R_FREE (path);
				}
#else
#	if __WINDOWS__
				f = r_acp_to_utf8 (f);
#	endif // __WINDOWS__
				if (f) {
					char *escaped_path = r_str_arg_escape (f);
					pfile = r_str_append (pfile, escaped_path);
					free (escaped_path);
					file = pfile; // r_str_append (file, escaped_path);
				}
#endif
				opt.ind++;
				while (opt.ind < argc) {
					char *escaped_arg = r_str_arg_escape (argv[opt.ind]);
					file = r_str_append (file, " ");
					file = r_str_append (file, escaped_arg);
					free (escaped_arg);
					opt.ind++;
				}
				pfile = file;
			}
		}
		if (asmarch) {
			r_config_set (r->config, "asm.arch", asmarch);
		}
		if (asmbits) {
			r_config_set (r->config, "asm.bits", asmbits);
		}
		if (asmos) {
			r_config_set (r->config, "asm.os", asmos);
		}

		if (!debug || debug == 2) {
			const char *dbg_profile = r_config_get (r->config, "dbg.profile");
			if (opt.ind == argc && dbg_profile && *dbg_profile) {
				if (R_STR_ISEMPTY (pfile)) {
					eprintf ("Missing file to open\n");
					ret = 1;
					R_FREE (debugbackend);
					goto beach;
				}
				fh = r_core_file_open (r, pfile, perms, mapaddr);
				if (fh) {
					r_core_bin_load (r, pfile, baddr);
				}
			}
			if (opt.ind < argc) {
				R_FREE (pfile);
				while (opt.ind < argc) {
					pfile = strdup (argv[opt.ind++]);
#if __WINDOWS__
					pfile = r_acp_to_utf8 (pfile);
#endif
					fh = r_core_file_open (r, pfile, perms, mapaddr);
					if (!fh && perms & R_PERM_W) {
						perms |= R_PERM_CREAT;
						fh = r_core_file_open (r, pfile, perms, mapaddr);
					}
					if (perms & R_PERM_CREAT) {
						if (fh) {
							r_config_set_i (r->config, "io.va", false);
						} else {
							 eprintf ("r_io_create: Permission denied.\n");
						}
					}
					if (fh) {
						iod = r->io ? r_io_desc_get (r->io, fh->fd) : NULL;
						if (iod && perms & R_PERM_X) {
							iod->perm |= R_PERM_X;
						}
						if (load_bin == LOAD_BIN_ALL) {
							const char *filepath = NULL;
							if (debug) {
								// XXX: incorrect for PIE binaries
								filepath = file? strstr (file, "://"): NULL;
								filepath = filepath ? filepath + 3 : pfile;
							}
							if (r->file && iod && (iod->fd == r->file->fd) && iod->name) {
								filepath = iod->name;
							}
							/* Load rbin info from r2 dbg:// or r2 /bin/ls */
							/* the baddr should be set manually here */
							(void)r_core_bin_load (r, filepath, baddr);
							// check if bin info is loaded and complain if -B was used
							RBinFile *bi = r_bin_cur (r->bin);
							bool haveBinInfo = bi && bi->o && bi->o->info && bi->o->info->type;
							if (!haveBinInfo && baddr != UT64_MAX) {
								eprintf ("Warning: Don't use -B on unknown files. Consider using -m.\n");
							}
						} else {
							r_io_map_new (r->io, iod->fd, perms, 0LL, mapaddr, r_io_desc_size (iod));
							if (load_bin == LOAD_BIN_STRUCTURES_ONLY) {
								r_core_bin_load_structs (r, iod->name);
							}
						}
					}
				}
			} else {
				const char *prj = r_config_get (r->config, "prj.name");
				if (prj && *prj) {
					pfile = r_core_project_info (r, prj);
					if (pfile) {
						if (!fh) {
							fh = r_core_file_open (r, pfile, perms, mapaddr);
						}
						// load_bin = LOAD_BIN_NOTHING;
						load_bin = LOAD_BIN_STRUCTURES_ONLY;
					} else {
						eprintf ("Cannot find project file\n");
					}
				} else {
					if (fh) {
						iod = r->io ? r_io_desc_get (r->io, fh->fd) : NULL;
						if (iod) {
							perms = iod->perm;
							r_io_map_new (r->io, iod->fd, perms, 0LL, 0LL, r_io_desc_size (iod));
						}
					}
				}
			}
			if (mapaddr) {
				if (r_config_get_i (r->config, "file.info")) {
					eprintf ("Warning: using oba to load the syminfo from different mapaddress.\n");
					// load symbols when using r2 -m 0x1000 /bin/ls
					r_core_cmdf (r, "oba 0 0x%"PFMT64x, mapaddr);
					r_core_cmd0 (r, ".ies*");
				}
			}
		} else {
			RCoreFile *f = r_core_file_open (r, pfile, perms, mapaddr);
			if (f) {
				fh = f;
			}
			if (fh) {
				r_debug_use (r->dbg, is_gdb ? "gdb" : debugbackend);
			}
			/* load symbols when doing r2 -d ls */
			// NOTE: the baddr is redefined to support PIE/ASLR
			baddr = r_debug_get_baddr (r->dbg, pfile);

			if (baddr != UT64_MAX && baddr != 0 && r->dbg->verbose) {
				eprintf ("bin.baddr 0x%08" PFMT64x "\n", baddr);
			}
			if (load_bin == LOAD_BIN_ALL) {
				if (baddr && baddr != UT64_MAX && r->dbg->verbose) {
					eprintf ("Using 0x%" PFMT64x "\n", baddr);
				}
				if (r_core_bin_load (r, pfile, baddr)) {
					RBinObject *obj = r_bin_cur_object (r->bin);
					if (obj && obj->info) {
						if (r->dbg->verbose) {
							eprintf ("asm.bits %d\n", obj->info->bits);
						}
#if __linux__ && __GNU_LIBRARY__ && __GLIBC__ && __GLIBC_MINOR__ && __x86_64__
						ut64 bitness = r_config_get_i (r->config, "asm.bits");
						if (bitness == 32) {
							eprintf ("glibc.fc_offset = 0x00148\n");
							r_config_set_i (r->config, "dbg.glibc.fc_offset", 0x00148);
						}
#endif
					}
				}
			}
			r_core_cmd0 (r, ".dm*");
			// Set Thumb Mode if necessary
			r_core_cmd0 (r, "dr? thumb;?? e asm.bits=16");
			r_cons_reset ();
		}
		if (!pfile) {
			pfile = file;
		}
		if (!fh) {
			if (pfile && *pfile) {
				r_cons_flush ();
				if (perms & R_PERM_W) {
					eprintf ("[w] Cannot open '%s' for writing.\n", pfile);
				} else {
					eprintf ("[r] Cannot open '%s'\n", pfile);
				}
			} else {
				eprintf ("Missing file to open\n");
			}
			ret = 1;
			goto beach;
		}
		if (!r->file) { // no given file
			ret = 1;
			goto beach;
		}
		if (r->bin->cur && r->bin->cur->o && r->bin->cur->o->info && r->bin->cur->o->info->rclass && !strcmp ("fs", r->bin->cur->o->info->rclass)) {
			const char *fstype = r->bin->cur->o->info->bclass;
			r_core_cmdf (r, "m /root %s @ 0", fstype);
		}
		r_core_cmd0 (r, "=!"); // initalize io subsystem
		iod = r->io ? r_io_desc_get (r->io, fh->fd) : NULL;
		if (mapaddr) {
			r_core_seek (r, mapaddr, true);
		}
		r_list_foreach (evals, iter, cmdn) {
			r_config_eval (r->config, cmdn, false);
			r_cons_flush ();
		}
		if (asmarch) {
			r_config_set (r->config, "asm.arch", asmarch);
		}
		if (asmbits) {
			r_config_set (r->config, "asm.bits", asmbits);
		}
		if (asmos) {
			r_config_set (r->config, "asm.os", asmos);
		}

		debug = r->file && iod && (r->file->fd == iod->fd) && iod->plugin && \
			iod->plugin->isdbg;
		if (debug) {
			r_core_setup_debugger (r, debugbackend, baddr == UT64_MAX);
		}
		R_FREE (debugbackend);
		RBinObject *o = r_bin_cur_object (r->bin);
		if (!debug && o && !o->regstate) {
			RFlagItem *fi = r_flag_get (r->flags, "entry0");
			if (fi) {
				r_core_seek (r, fi->offset, true);
			} else {
				if (o) {
					RList *sections = r_bin_get_sections (r->bin);
					RListIter *iter;
					RBinSection *s;
					r_list_foreach (sections, iter, s) {
						if (s->perm & R_PERM_X) {
							ut64 addr = s->vaddr? s->vaddr: s->paddr;
							r_core_seek (r, addr, true);
							break;
						}
					}
				}
			}
		}
		if (o && compute_hashes) {
			// TODO: recall with limit=0 ?
			ut64 limit = r_config_get_i (r->config, "bin.hashlimit");
			r_bin_file_set_hashes (r->bin, r_bin_file_compute_hashes (r->bin, limit));
		}
		if (s_seek) {
			seek = r_num_math (r->num, s_seek);
			if (seek != UT64_MAX) {
				r_core_seek (r, seek, true);
			}
		}

		if (fullfile) {
			r_core_block_size (r, r_io_desc_size (iod));
		}

		r_core_seek (r, r->offset, true); // read current block

		/* check if file.path has changed */
		if (iod && !strstr (iod->uri, "://")) {
			const char *npath;
			char *path = strdup (r_config_get (r->config, "file.path"));
			has_project = r_core_project_open (r, r_config_get (r->config, "prj.name"), false);
			iod = r->io ? r_io_desc_get (r->io, fh->fd) : NULL;
			if (has_project) {
				r_config_set (r->config, "bin.strings", "false");
			}
			npath = r_config_get (r->config, "file.path");
			if (!quiet && path && *path && npath && strcmp (path, npath)) {
				eprintf ("WARNING: file.path change: %s => %s\n", path, npath);
			}
			free (path);
		}

		r_list_foreach (evals, iter, cmdn) {
			r_config_eval (r->config, cmdn, false);
			r_cons_flush ();
		}

		// no flagspace selected by default the beginning
		r_flag_space_set (r->flags, NULL);
		/* load <file>.r2 */
		{
			char* f = r_str_newf ("%s.r2", pfile);
			const char *uri_splitter = strstr (f, "://");
			const char *path = uri_splitter? uri_splitter + 3: f;
			if (r_file_exists (path)) {
				// TODO: should 'q' unset the interactive bit?
				bool isInteractive = r_cons_is_interactive ();
				if (isInteractive && r_cons_yesno ('n', "Do you want to run the '%s' script? (y/N) ", path)) {
					r_core_cmd_file (r, path);
				}
			}
			free (f);
		}
	} else {
		r_core_block_read (r);
	}
	{
		char *global_rc = r_str_r2_prefix (R2_GLOBAL_RC);
		if (r_file_exists (global_rc)) {
			(void)r_core_run_script (r, global_rc);
		}
		free (global_rc);
	}

	// only analyze if file contains entrypoint
	{
		char *s = r_core_cmd_str (r, "ieq");
		if (s && *s) {
			int da = r_config_get_i (r->config, "file.analyze");
			if (da > do_analysis) {
				do_analysis = da;
			}
		}
		free (s);
	}
	if (do_analysis > 0) {
		switch (do_analysis) {
		case 1: r_core_cmd0 (r, "aa"); break;
		case 2: r_core_cmd0 (r, "aaa"); break;
		case 3: r_core_cmd0 (r, "aaaa"); break;
		default: r_core_cmd0 (r, "aaaaa"); break;
		}
		r_cons_flush ();
	}
#if UNCOLORIZE_NONTTY
#if __UNIX__
	if (!r_cons_isatty ()) {
		r_config_set_i (r->config, "scr.color", COLOR_MODE_DISABLED);
	}
#endif
#endif
	if (fullfile) {
		r_core_block_size (r, r_io_desc_size (iod));
	}
	if (perms & R_PERM_W) {
		r_core_cmd0 (r, "omfg+w");
	}
	ret = run_commands (r, cmds, files, quiet, do_analysis);
	r_list_free (cmds);
	r_list_free (evals);
	r_list_free (files);
	cmds = evals = files = NULL;
	if (forcequit) {
		ret = 1;
	}
	if (ret) {
		ret = 0;
		goto beach;
	}
	if (r_config_get_i (r->config, "scr.prompt")) {
		if (run_rc && r_config_get_i (r->config, "cfg.fortunes")) {
			r_core_fortune_print_random (r);
			r_cons_flush ();
		}
	}
	if (sandbox) {
		r_config_set (r->config, "cfg.sandbox", "true");
	}
	if (quiet) {
		r_config_set (r->config, "scr.wheel", "false");
		r_config_set (r->config, "scr.interactive", "false");
		r_config_set (r->config, "scr.prompt", "false");
	}
	r->num->value = 0;
	if (patchfile) {
		char *data = r_file_slurp (patchfile, NULL);
		if (data) {
			ret = r_core_patch (r, data);
			r_core_seek (r, 0, true);
			free (data);
		} else {
			eprintf ("[p] Cannot open '%s'\n", patchfile);
		}
	}
	if ((patchfile && !quiet) || !patchfile) {
		if (zerosep) {
			r_cons_zero ();
		}
		if (seek != UT64_MAX) {
			r_core_seek (r, seek, true);
		}

		// no flagspace selected by default the beginning
		r_flag_space_set (r->flags, NULL);
		if (!debug && r->bin && r->bin->cur && r->bin->cur->o && r->bin->cur->o->info) {
			if (r->bin->cur->o->info->arch) {
				r_core_cmd0 (r, "aeip");
			}
		}
		for (;;) {
			r_core_prompt_loop (r);
			ret = r->num->value;
			debug = r_config_get_i (r->config, "cfg.debug");
			if (ret != -1 && r_cons_is_interactive ()) {
				char *question;
				bool no_question_debug = ret & 1;
				bool no_question_save = (ret & 2) >> 1;
				bool y_kill_debug = (ret & 4) >> 2;
				bool y_save_project = (ret & 8) >> 3;

				if (r_core_task_running_tasks_count (&r->tasks) > 0) {
					if (r_cons_yesno ('y', "There are running background tasks. Do you want to kill them? (Y/n)")) {
						r_core_task_break_all (&r->tasks);
						r_core_task_join (&r->tasks, r->tasks.main_task, -1);
					} else {
						continue;
					}
				}

				if (debug) {
					if (no_question_debug) {
						if (r_config_get_i (r->config, "dbg.exitkills") && y_kill_debug){
							r_debug_kill (r->dbg, r->dbg->pid, r->dbg->tid, 9); // KILL
						}
					} else {
						if (r_cons_yesno ('y', "Do you want to quit? (Y/n)")) {
							if (r_config_get_i (r->config, "dbg.exitkills") &&
									r_cons_yesno ('y', "Do you want to kill the process? (Y/n)")) {
								r_debug_kill (r->dbg, r->dbg->pid, r->dbg->tid, 9); // KILL
							} else {
								r_debug_detach (r->dbg, r->dbg->pid);
							}
						} else {
							continue;
						}
					}
				}

				prj = r_config_get (r->config, "prj.name");
				if (no_question_save) {
					if (prj && *prj && y_save_project){
						r_core_project_save (r, prj);
					}
				} else {
					question = r_str_newf ("Do you want to save the '%s' project? (Y/n)", prj);
					if (prj && *prj && r_cons_yesno ('y', "%s", question)) {
						r_core_project_save (r, prj);
					}
					free (question);
				}

				if (r_config_get_i (r->config, "scr.confirmquit")) {
					if (!r_cons_yesno ('n', "Do you want to quit? (Y/n)")) {
						continue;
					}
				}
			} else {
				// r_core_project_save (r, prj);
				if (debug && r_config_get_i (r->config, "dbg.exitkills")) {
					r_debug_kill (r->dbg, 0, false, 9); // KILL
				}

			}
			break;
		}
	}

	if (mustSaveHistory (r->config)) {
		r_line_hist_save (R2_HOME_HISTORY);
	}

	/* capture return value */
	ret = r->num->value;
beach:
	if (quietLeak) {
		exit (ret);
		return ret;
	}

	r_core_task_sync_end (&r->tasks);

	// not really needed, cause r_core_fini will close the file
	// and this fh may be come stale during the command
	// execution.
	//r_core_file_close (r, fh);
	r_core_free (r);
	r_cons_set_raw (0);
	r_cons_free ();
	LISTS_FREE ();
	R_FREE (pfile);
	return ret;
}
