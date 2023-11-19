/* radare - LGPL - Copyright 2009-2023 - pancake */

#define USE_THREADS 1
#define ALLOW_THREADED 1
#define UNCOLORIZE_NONTTY 0
#ifdef _MSC_VER
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

#include <r_core.h>

static char* get_file_in_cur_dir(const char *filepath) {
	filepath = r_file_basename (filepath);
	if (r_file_exists (filepath) && !r_file_is_directory (filepath)) {
		return r_file_abspath (filepath);
	}
	return NULL;
}

static void json_plugins(RCore *core, PJ *pj, const char *name, const char *cmd) {
	char *lcj = r_core_cmd_str (core, cmd);
	r_str_trim (lcj);
	if (*lcj == '[') {
		pj_k (pj, name);
		pj_raw (pj, lcj);
	}
	free (lcj);
}

static int r_main_version_verify(RCore *core, bool show, bool json) {
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
		{ NULL, NULL }
	};

	if (json) {
		PJ *pj = pj_new ();
		pj_o (pj);
#if 1
		pj_ko (pj, "radare2");
			pj_ks (pj, "version", R2_VERSION);
			pj_ks (pj, "birth", R2_BIRTH);
			pj_ks (pj, "commit", R2_GITTIP);
			pj_ki (pj, "commits", R2_VERSION_COMMIT);
			pj_ks (pj, "license", "LGPLv3");
			pj_ks (pj, "tap", R2_GITTAP);
			pj_ko (pj, "semver");
			pj_ki (pj, "major", R2_VERSION_MAJOR);
			pj_ki (pj, "minor", R2_VERSION_MINOR);
			pj_ki (pj, "patch", R2_VERSION_MINOR);
			pj_end (pj);
		pj_end (pj);
#endif
		pj_ko (pj, "libraries");
		if (show) {
			pj_ks (pj, "r2", base);
		}
		for (i = ret = 0; vcs[i].name; i++) {
			struct vcs_t *v = &vcs[i];
			const char *name = v->callback ();
			if (!ret && strcmp (base, name)) {
				ret = 1;
			}
			if (show) {
				pj_ks (pj, v->name, name);
			}
		}
		pj_end (pj);
		if (ret) {
			pj_ks (pj, "warning", "r2 library versions mismatch! Check r2 -V");
		}
		{
			pj_ko (pj, "thirdparty");
			{
				pj_ko (pj, "capstone");
				pj_ks (pj, "destdir", "shlr/capstone");
				pj_ks (pj, "git", "https://github.com/capstone-engine/capstone");
				pj_ks (pj, "branch", "v5");
				pj_ks (pj, "commit", "097c04d9413c59a58b00d4d1c8d5dc0ac158ffaa");
				pj_end (pj);
			}
			{
				pj_ko (pj, "sdb");
				pj_ks (pj, "destdir", "shlr/sdb");
				pj_ks (pj, "git", "https://github.com/radareorg/sdb");
				pj_ks (pj, "branch", "master");
				pj_ks (pj, "commit", "c4db2b24dacd25403ecb084c9b8e7840889ca236");
				pj_end (pj);
			}
			{
				pj_ko (pj, "arm64v35");
				pj_ks (pj, "destdir", "libr/arch/p/arm/v35/arch-arm64");
				pj_ks (pj, "git", "https://github.com/radareorg/vector35-arch-arm64");
				pj_ks (pj, "commit", "55d73c6bbb94448a5c615933179e73ac618cf876");
				pj_ks (pj, "branch", "master");
				pj_end (pj);
			}
			{
				pj_ko (pj, "armv7v35");
				pj_ks (pj, "destdir", "libr/arch/p/arm/v35/arch-armv7");
				pj_ks (pj, "git", "https://github.com/radareorg/vector35-arch-armv7");
				pj_ks (pj, "commit", "f270a6cc99644cb8e76055b6fa632b25abd26024");
				pj_ks (pj, "branch", "master");
				pj_end (pj);
			}
			pj_end (pj);
		}
		pj_ko (pj, "plugins");
		{
			r_core_loadlibs (core, R_CORE_LOADLIBS_ALL, NULL);
			json_plugins (core, pj, "core", "Lcj");
			json_plugins (core, pj, "bin", "Lbj");
			json_plugins (core, pj, "arch", "Laj");
			json_plugins (core, pj, "debug", "Ldj");
			json_plugins (core, pj, "egg", "Lgj");
			json_plugins (core, pj, "fs", "Lmj");
			json_plugins (core, pj, "asm", "LAj");
		}
		pj_end (pj);
		pj_end (pj);
		char *s = pj_drain (pj);
		printf ("%s\n", s);
		free (s);
	} else {
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
			R_LOG_WARN ("r2 library versions mismatch! Check r2 -V");
		}
	}
	return ret;
}

static int main_help(int line) {
	if (line < 2) {
		printf ("Usage: r2 [-ACdfjLMnNqStuvwzX] [-P patch] [-p prj] [-a arch] [-b bits] [-c cmd]\n"
			"          [-s addr] [-B baddr] [-m maddr] [-i script] [-e k=v] file|pid|-|--|=\n");
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
		" -j           use json for -v, -L and maybe others\n"
		" -k [OS/kern] set asm.os (linux, macos, w32, netbsd, ...)\n"
		" -l [lib]     load plugin file\n"
		" -L, -LL      list supported IO plugins (-LL list core plugins)\n"
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
		" -u           set bin.filter=false to get raw sym/sec/cls names\n"
		" -v, -V       show radare2 version (-V show lib versions)\n"
		" -w           open file in write mode\n"
		" -x           open without exec-flag (asm.emu will not work), See io.exec\n"
		" -X           same as -e bin.usextr=false (useful for dyldcache)\n"
		" -z, -zz      do not load strings or load them even in raw\n");
	}
	if (line == 2) {
		char *datahome = r_xdg_datadir (NULL);
		const char *dirPrefix = r_sys_prefix (NULL);
		RStrBuf *sb = r_strbuf_new ("");

		r_strbuf_append (sb, "Scripts:\n");
		r_strbuf_appendf (sb, " system          %s/share/radare2/radare2rc\n", dirPrefix);
		r_strbuf_append (sb, " user            ~/.radare2rc ${XDG_CONFIG_DIR:=~/.local/share/}/radare2/radare2rc{.d/}\n");
		r_strbuf_append (sb, " file            ${filename}.r2\n");
		r_strbuf_append (sb, "Plugins:\n");
		r_strbuf_appendf (sb, " R2_LIBR_PLUGINS " R_JOIN_2_PATHS ("%s", R2_PLUGINS) "\n"
		" R2_USER_PLUGINS ${XDG_DATA_DIR:=~/.local/share/radare2}/plugins\n"
		" R2_USER_ZIGNS   ${XDG_DATA_DIR:=~/.local/share/radare2}/zigns\n"
		"Environment:\n"
		" R2_COLOR        sets the initial value for 'scr.color'. set to 0 for no color\n"
		" R2_ARGS         ignore cli arguments and use these ones instead\n"
		" R2_DEBUG        if defined, show error messages and crash signal.\n"
		" R2_DEBUG_NOPAPI do not load r2papi in the -j qjs shell\n"
		" R2_DEBUG_ASSERT set a breakpoint when hitting an assert.\n"
		" R2_IGNVER       load plugins ignoring the specified version. (be careful)\n"
		" R2_MAGICPATH    %s/"R2_SDB_MAGIC"\n"
		" R2_NOPLUGINS    do not load r2 shared plugins\n", dirPrefix, dirPrefix);
		r_strbuf_append (sb, " R2_HISTORY      ${XDG_CACHE_DIR:=~/.cache/radare2}/history\n");
		r_strbuf_append (sb, " R2_RCFILE       ~/.radare2rc (user preferences, batch script)\n" // TOO GENERIC
		" R2_CURL         set to '1' to use system curl program instead of r2 apis\n"
		);
		r_strbuf_appendf (sb, " R2_DATA_HOME    %s\n"
		" R2_VERSION      contains the current version of r2\n"
		" R2_LOG_LEVEL    numeric value of the max level of messages to show\n"
		" R2_LOG_FILE     dump all logs to a file\n"
		"Paths:\n"
		" R2_INCDIR    "R2_INCDIR"\n"
		" R2_LIBDIR    "R2_LIBDIR"\n"
		" R2_LIBEXT    "R_LIB_EXT"\n"
		" R2_PREFIX    "R2_PREFIX"\n"
		, datahome);
		free (datahome);

		char *helpmsg = r_strbuf_drain (sb);
		if (helpmsg) {
			printf ("%s", helpmsg);
			free (helpmsg);
		}
	}
	return 0;
}

static int main_print_var(const char *var_name) {
	int i = 0;
#ifdef R2__WINDOWS__
	char *incdir = r_str_r2_prefix (R2_INCDIR);
	char *libdir = r_str_r2_prefix (R2_LIBDIR);
#else
	char *incdir = strdup (R2_INCDIR);
	char *libdir = strdup (R2_LIBDIR);
#endif
	char *confighome = r_xdg_configdir (NULL);
	char *datahome = r_xdg_datadir (NULL);
	char *cachehome = r_xdg_cachedir (NULL);
	char *homeplugins = r_xdg_datadir ("plugins");
	char *homezigns = r_xdg_datadir ("zigns");
	char *plugins = r_str_r2_prefix (R2_PLUGINS);
	char *magicpath = r_str_r2_prefix (R2_SDB_MAGIC);
	char *historyhome = r_xdg_cachedir ("history");
	const char *r2prefix = r_sys_prefix (NULL);
	struct {
		const char *name;
		const char *value;
	} r2_vars[] = {
		{ "R2_VERSION", R2_VERSION },
		{ "R2_PREFIX", r2prefix },
		{ "R2_MAGICPATH", magicpath },
		{ "R2_INCDIR", incdir },
		{ "R2_LIBDIR", libdir },
		{ "R2_LIBEXT", R_LIB_EXT },
		{ "R2_RDATAHOME", datahome },
		{ "R2_HISTORY", historyhome },
		{ "R2_CONFIG_HOME", confighome }, // from xdg
		{ "R2_CACHE_HOME", cachehome }, //  fro xdg
		{ "R2_LIBR_PLUGINS", plugins },
		{ "R2_USER_PLUGINS", homeplugins },
		{ "R2_ZIGNS_HOME", homezigns },
		{ NULL, NULL }
	};
	int delta = 0;
	if (var_name && strncmp (var_name, "R2_", 3)) {
		delta = 3;
	}
	while (r2_vars[i].name) {
		if (var_name) {
			if (!strcmp (r2_vars[i].name + delta, var_name)) {
				printf ("%s\n", r2_vars[i].value);
				break;
			}
		} else {
			printf ("%s=%s\n", r2_vars[i].name, r2_vars[i].value);
		}
		i++;
	}
	free (incdir);
	free (libdir);
	free (confighome);
	free (historyhome);
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
	/* -i */
	bool has_failed = false;
	r_list_foreach (files, iter, file) {
		if (!r_file_exists (file)) {
			R_LOG_ERROR ("Script '%s' not found", file);
			goto beach;
		}
		int ret = r_core_run_script (r, file);
		r_cons_flush ();
		if (ret == -2) {
			R_LOG_ERROR ("Cannot open '%s'", file);
		}
		if (ret < 0) {
			has_failed = true;
			break;
		}
	}
	/* -c */
	r_list_foreach (cmds, iter, cmdn) {
		r_core_cmd_lines (r, cmdn);
		r_cons_flush ();
	}
beach:
	if (quiet && !has_failed) {
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
	return has_failed;
}

static bool mustSaveHistory(RConfig *c) {
	if (!r_config_get_b (c, "scr.hist.save")) {
		return false;
	}
	if (!r_cons_is_interactive ()) {
		return false;
	}
	return true;
}

static inline void autoload_zigns(RCore *r) {
	char *path = r_file_abspath (r_config_get (r->config, "dir.zigns"));
	if (R_STR_ISNOTEMPTY (path)) {
		RList *list = r_sys_dir (path);
		RListIter *iter;
		char *file;
		r_list_foreach (list, iter, file) {
			if (file && *file && *file != '.') {
				char *complete_path = r_str_newf ("%s" R_SYS_DIR "%s", path, file);
				if (r_str_endswith (complete_path, "gz")) {
					r_sign_load_gz (r->anal, complete_path, false);
				} else {
					r_sign_load (r->anal, complete_path, false);
				}
				free (complete_path);
			}
		}
		r_list_free (list);
	}
	free (path);
}

// Try to set the correct scr.color for the current terminal.
static void set_color_default(RCore *r) {
#ifdef R2__WINDOWS__
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
	char *log_level = r_sys_getenv ("R2_LOG_LEVEL");
	if (R_STR_ISNOTEMPTY (log_level)) {
		r_config_set (r->config, "log.level", log_level);
	}
	R_FREE (log_level);
	char *log_file = r_sys_getenv ("R2_LOG_FILE");
	if (R_STR_ISNOTEMPTY (log_file)) {
		r_config_set (r->config, "log.file", log_file);
	}
	R_FREE (log_file);
	int scr_color = -1;
	char *r2c = r_sys_getenv ("R2_COLOR");
	if (r2c) {
		if (*r2c) {
			int v = atoi (r2c);
			if (v) {
				r_config_set_i (r->config, "scr.color", v);
				scr_color = v;
			} else {
				if (*r2c == '0') {
					scr_color = 0;
					r_config_set_i (r->config, "scr.color", 0);
				}
			}
		}
		free (r2c);
	}
	if (scr_color == -1) {
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
}

typedef struct {
	char *filepath;
	ut64 baddr;
	RCore *core;
	int do_analysis;
	RThread *th_bin;
} ThreadData;

static void perform_analysis(RCore *r, int do_analysis) {
	r->times->file_anal_time = r_time_now_mono ();
	const char *acmd = "aaaaa";
	switch (do_analysis) {
	case 0: acmd = ""; break;
	case 1: acmd = "aa"; break;
	case 2: acmd = "aaa"; break;
	case 3: acmd = "aaaa"; break;
	}
	r_core_cmd_call (r, acmd);
	r_cons_flush ();
	r->times->file_anal_time = r_time_now_mono () - r->times->file_anal_time;
}

static RThreadFunctionRet th_analysis(RThread *th) {
	ThreadData *td = (ThreadData*)th->user;
	if (td->th_bin) {
		R_LOG_INFO ("Waiting for rbin parsing");
		r_th_wait (td->th_bin);
		r_th_free (td->th_bin);
		td->th_bin = NULL;
	}
	R_LOG_INFO ("Loading binary information in background");
	r_cons_thready ();
	r_cons_new ();
	perform_analysis (td->core, td->do_analysis);
	R_FREE (th->user);
	R_LOG_INFO ("bin.load done");
	return false;
}

static RThreadFunctionRet th_binload(RThread *th) {
	R_LOG_INFO ("Loading binary information in background");
	r_cons_thready ();
	r_cons_new ();
	ThreadData *td = (ThreadData*)th->user;
	RCore *r = td->core;
	const char *filepath = td->filepath;
	const ut64 baddr = UT64_MAX;
	(void)r_core_bin_load (r, filepath, baddr);
	// check if bin info is loaded and complain if -B was used
	RBinFile *bi = r_bin_cur (r->bin);
	bool haveBinInfo = bi && bi->bo && bi->bo->info && bi->bo->info->type;
	if (!haveBinInfo && baddr != UT64_MAX) {
		R_LOG_WARN ("Don't use -B on unknown files. Consider using -m");
	}
	free (td->filepath);
	R_FREE (th->user);
	R_LOG_INFO ("bin.load done");
	return false;
}

static void binload(RCore *r, const char *filepath, ut64 baddr) {
	(void)r_core_bin_load (r, filepath, baddr);
	// check if bin info is loaded and complain if -B was used
	RBinFile *bi = r_bin_cur (r->bin);
	bool haveBinInfo = bi && bi->bo && bi->bo->info && bi->bo->info->type;
	if (!haveBinInfo && baddr != UT64_MAX) {
		R_LOG_WARN ("Don't use -B on unknown files. Consider using -m");
	}
}

typedef enum {
	LOAD_BIN_ALL,
	LOAD_BIN_NOTHING,
	LOAD_BIN_STRUCTURES_ONLY
} LoadBinMode;

typedef struct {
	RCore *r;
	bool forcequit;
	bool haveRarunProfile;
	int do_analysis;
	RIODesc *fh;
	RIODesc *iod;
	int debug;
	int zflag;
	bool do_connect;
	bool fullfile;
	bool zerosep;
	int help;
	LoadBinMode load_bin;
	bool run_rc;
	int perms;
	bool sandbox;
	ut64 baddr;
	ut64 seek;
	bool do_list_io_plugins;
	bool do_list_core_plugins;
	char *patchfile;
	char *file;
	char *pfile;
	char *asmarch;
	char *asmos;
	char *forcebin;
	char *asmbits;
	char *customRarunProfile;
	char *s_seek;
	ut64 mapaddr;
	bool quiet;
	bool quiet_leak;
	bool is_gdb;
	RThread *th_bin;
	RThread *th_ana;
	// bool compute_hashes = true;
	RList *cmds;
	RList *evals;
	RList *files;
	RList *prefiles;
	bool show_version;
	bool show_versions;
	bool json;
	bool threaded;
	bool load_l;
	char *envprofile;
	char *debugbackend;
	char *project_name;
	char *qjs_script;
	bool noStderr;
} RMainRadare2;

static void mainr2_init(RMainRadare2 *mr) {
	memset (mr, 0, sizeof (RMainRadare2));
	mr->load_l = true;
	mr->run_rc = true;
	mr->debugbackend = strdup ("native");
	mr->load_bin = LOAD_BIN_ALL;
	mr->baddr = UT64_MAX;
	mr->seek = UT64_MAX;
	mr->perms = R_PERM_RX;
	mr->cmds = r_list_new ();
	mr->evals = r_list_new ();
	mr->files = r_list_new ();
	mr->prefiles = r_list_new ();
}

static void mainr2_fini(RMainRadare2 *mr) {
	r_list_free (mr->cmds);
	r_list_free (mr->evals);
	r_list_free (mr->files);
	r_list_free (mr->prefiles);
	free (mr->patchfile);
	free (mr->file);
	free (mr->pfile);
	free (mr->asmarch);
	free (mr->asmos);
	free (mr->forcebin);
	free (mr->asmbits);
	free (mr->customRarunProfile);
	free (mr->s_seek);
	free (mr->envprofile);
	free (mr->debugbackend);
	free (mr->project_name);
	free (mr->qjs_script);
	r_core_free (mr->r);
}

R_API int r_main_radare2(int argc, const char **argv) {
	int c, ret;
	RMainRadare2 mr;
	mainr2_init (&mr);

#ifdef __UNIX
	sigset_t sigBlockMask;
	sigemptyset (&sigBlockMask);
	sigaddset (&sigBlockMask, SIGWINCH);
	r_signal_sigmask (SIG_BLOCK, &sigBlockMask, NULL);
#endif

	r_sys_env_init ();
	// Create rarun2 profile with startup environ
	char **env = r_sys_get_environ ();
	mr.envprofile = r_run_get_environ_profile (env);

	if (r_sys_getenv_asbool ("R2_DEBUG")) {
		r_log_set_level (R_LOGLVL_DEBUG);
		char *sysdbg = r_sys_getenv ("R2_DEBUG_TOOL");
		char *fmt = (sysdbg && *sysdbg)
			? strdup (sysdbg)
#if __APPLE__
			: strdup ("lldb -p");
#else
			: strdup ("gdb --pid");
#endif
		r_sys_crash_handler (fmt);
		free (fmt);
		free (sysdbg);
	}
	if (argc < 2) {
		mainr2_fini (&mr);
		return main_help (1);
	}
	RCore *r = r_core_new ();
	if (!r) {
		R_LOG_ERROR ("Cannot initialize RCore");
		mainr2_fini (&mr);
		return 1;
	}
	mr.r = r;
	r->r_main_radare2 = r_main_radare2;
	r->r_main_radiff2 = r_main_radiff2;
	r->r_main_rafind2 = r_main_rafind2;
	r->r_main_rabin2 = r_main_rabin2;
	r->r_main_ragg2 = r_main_ragg2;
	r->r_main_rasm2 = r_main_rasm2;
	r->r_main_rax2 = r_main_rax2;
	r->r_main_ravc2 = r_main_ravc2;
	r->r_main_r2pm = r_main_r2pm;

	r->io->envprofile = mr.envprofile;

	r_core_task_sync_begin (&mr.r->tasks);
	if (argc == 2 && !strcmp (argv[1], "-p")) {
		r_core_project_list (r, 0);
		r_cons_flush ();
		mainr2_fini (&mr);
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
		mainr2_fini (&mr);
		return 0;
	}

	set_color_default (r);

	RGetopt opt;
	r_getopt_init (&opt, argc, argv, "=02AjMCwxfF:H:hm:e:nk:NdqQs:p:b:B:a:Lui:I:l:P:R:r:c:D:vVSzuXt");
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'j':
			mr.json = true;
			break;
		case '=':
			R_FREE (r->cmdremote);
			r->cmdremote = strdup ("");
			break;
		case '2':
			mr.noStderr = true;
			break;
		case '0':
			mr.zerosep = true;
			/* implicit -q */
			r_config_set_b (r->config, "scr.interactive", false);
			r_config_set_b (r->config, "scr.prompt", false);
			r_config_set_i (r->config, "scr.color", COLOR_MODE_DISABLED);
			mr.quiet = true;
			break;
		case 'u':
			r_config_set_b (r->config, "bin.filter", false);
			break;
		case 'a':
			free (mr.asmarch);
			mr.asmarch = strdup (opt.arg);
			break;
		case 'z':
			mr.zflag++;
			break;
		case 'A':
			mr.do_analysis += mr.do_analysis ? 1: 2;
			break;
		case 'b':
			free (mr.asmbits);
			mr.asmbits = strdup (opt.arg);
			r_config_set (r->config, "asm.bits", opt.arg);
			break;
		case 'B':
			mr.baddr = r_num_math (r->num, opt.arg);
			break;
		case 'X':
			r_config_set_b (r->config, "bin.usextr", false);
			break;
		case 'c':
			r_list_append (mr.cmds, (void*)strdup (opt.arg));
			break;
		case 'C':
			mr.do_connect = true;
			break;
		case 'd':
#if DEBUGGER
			mr.debug = 1;
#else
			R_LOG_ERROR ("Sorry. I'm built without debugger support");
			return 1;
#endif
			break;
		case 'D':
			mr.debug = 2;
			free (mr.debugbackend);
			mr.debugbackend = strdup (opt.arg);
			if (!strcmp (opt.arg, "?")) {
				r_debug_plugin_list (r->dbg, 'q');
				r_cons_flush ();
				mainr2_fini (&mr);
				return 0;
			}
			break;
		case 'e':
			if (mr.json) {
				// eval qjs script here!
				free (mr.qjs_script);
				mr.qjs_script = strdup (opt.arg);
			} else {
				if (!strcmp (opt.arg, "q")) {
					r_core_cmd0 (r, "eq");
				} else {
					r_config_eval (r->config, opt.arg, false);
					r_list_append (mr.evals, (void*)strdup (opt.arg));
				}
			}
			break;
		case 'f':
			mr.fullfile = true;
			break;
		case 'F':
			free (mr.forcebin);
			mr.forcebin = strdup (opt.arg);
			break;
		case 'h':
			mr.help++;
			break;
		case 'H':
			main_print_var (opt.arg);
			mainr2_fini (&mr);
			return 0;
		case 'i':
			if (R_STR_ISEMPTY (opt.arg)) {
				R_LOG_ERROR ("Cannot open empty script path");
				ret = 1;
				goto beach;
			}
			r_list_append (mr.files, strdup (opt.arg));
			break;
		case 'I':
			if (R_STR_ISEMPTY (opt.arg)) {
				R_LOG_ERROR ("Cannot open empty script path");
				ret = 1;
				goto beach;
			}
			r_list_append (mr.prefiles, (void*)strdup (opt.arg));
			break;
		case 'k':
			free (mr.asmos);
			mr.asmos = strdup (opt.arg);
			break;
		case 'l':
			r_lib_open (r->lib, opt.arg);
			break;
		case 'L':
			if (mr.do_list_io_plugins) {
				mr.do_list_core_plugins = true;
			} else {
				mr.do_list_io_plugins = true;
			}
			break;
		case 'm':
			r_config_set_i (r->config, "io.va", 1);
			mr.mapaddr = r_num_math (r->num, opt.arg);
			mr.s_seek = strdup (opt.arg);
			break;
		case 'M':
			r_config_set_b (r->config, "bin.demangle", false);
			r_config_set_b (r->config, "asm.demangle", false);
			break;
		case 'n':
			if (mr.load_bin == LOAD_BIN_ALL) { // "-n"
				mr.load_bin = LOAD_BIN_NOTHING;
			} else if (mr.load_bin == LOAD_BIN_NOTHING) { // second n => "-nn"
				mr.load_bin = LOAD_BIN_STRUCTURES_ONLY;
				r_config_set_b (r->config, "bin.types", true);
			}
			r_config_set_b (r->config, "file.info", false);
			break;
		case 'N':
			if (mr.run_rc) {
				mr.run_rc = false;
			} else {
				mr.load_l = false;
				r_sys_setenv ("R2_NOPLUGINS", "1");
			}
			break;
		case 'p':
			if (!strcmp (opt.arg, "?")) {
				r_core_project_list (r, 0);
				r_cons_flush ();
				mainr2_fini (&mr);
				return 0;
			}
			free (mr.project_name);
			mr.project_name = strdup (opt.arg);
			break;
		case 'P':
			if (R_STR_ISEMPTY (opt.arg)) {
				R_LOG_ERROR ("Cannot open empty rapatch path");
				ret = 1;
				goto beach;
			}
			free (mr.patchfile);
			mr.patchfile = strdup (opt.arg);
			break;
		case 'Q':
			mr.quiet = true;
			mr.quiet_leak = true;
			break;
		case 'q':
			r_config_set_b (r->config, "scr.interactive", false);
			r_config_set_b (r->config, "scr.prompt", false);
			r_config_set_b (r->config, "cfg.fortunes", false);
			if (mr.quiet) {
				mr.forcequit = true;
			}
			mr.quiet = true;
			break;
		case 'r':
			if (R_STR_ISEMPTY (opt.arg)) {
				R_LOG_ERROR ("Cannot open empty rarun2 profile path");
				ret = 1;
				goto beach;
			}
			mr.haveRarunProfile = true;
			r_config_set (r->config, "dbg.profile", opt.arg);
			break;
		case 'R':
			mr.customRarunProfile = r_str_appendf (mr.customRarunProfile, "%s\n", opt.arg);
			break;
		case 's':
			free (mr.s_seek);
			mr.s_seek = strdup (opt.arg);
			break;
		case 'S':
			mr.sandbox = true;
			break;
#if USE_THREADS
		case 't':
#if ALLOW_THREADED
			mr.threaded = true;
#else
			R_LOG_WARN ("Warning: -t is temporarily disabled!");
#endif
			break;
#endif
		case 'v':
			mr.show_version = true;
			break;
		case 'V':
			mr.show_versions = true;
			break;
		case 'w':
			mr.perms |= R_PERM_W;
			break;
		case 'x':
			mr.perms &= ~R_PERM_X;
			r_config_set_b (r->config, "io.exec", false);
			break;
		default:
			mr.help++;
		}
	}
	if (mr.show_versions) {
		int rc = r_main_version_verify (r, 1, mr.json);
		mainr2_fini (&mr);
		return rc;
	}
	if (mr.show_version) {
		if (mr.json) {
			PJ *pj = pj_new ();
			pj_o (pj);
			pj_ks (pj, "name", "radare2");
			pj_ks (pj, "version", R2_VERSION);
			pj_ks (pj, "birth", R2_BIRTH);
			pj_ks (pj, "commit", R2_GITTIP);
			pj_ki (pj, "commits", R2_VERSION_COMMIT);
			pj_ks (pj, "license", "LGPLv3");
			pj_ks (pj, "tap", R2_GITTAP);
			pj_ko (pj, "semver");
			pj_ki (pj, "major", R2_VERSION_MAJOR);
			pj_ki (pj, "minor", R2_VERSION_MINOR);
			pj_ki (pj, "patch", R2_VERSION_MINOR);
			pj_end (pj);
			pj_end (pj);
			char *s = pj_drain (pj);
			printf ("%s\n", s);
			free (s);
		} else if (mr.quiet) {
			printf ("%s\n", R2_VERSION);
			mainr2_fini (&mr);
		} else {
			r_main_version_verify (r, 0, mr.json);
			mainr2_fini (&mr);
			return r_main_version_print ("radare2");
		}
		return 0;
	}
	if (mr.noStderr) {
		if (close (2) == -1) {
			R_LOG_ERROR ("Failed to close stderr");
			mainr2_fini (&mr);
			return 1;
		}
		const char nul[] = R_SYS_DEVNULL;
		int new_stderr = open (nul, O_RDWR);
		if (new_stderr == -1) {
			R_LOG_ERROR ("Failed to open %s for stderr", nul);
			mainr2_fini (&mr);
			return 1;
		}
		if (new_stderr != 2) {
#if !__wasi__
			if (dup2 (new_stderr, 2) == -1) {
				R_LOG_ERROR ("Failed to dup2 stderr");
				mainr2_fini (&mr);
				return 1;
			}
#endif
			if (close (new_stderr) == -1) {
				R_LOG_ERROR ("Failed to close %s", nul);
				mainr2_fini (&mr);
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
						mr.pfile = strdup (program);
					}
				}
				free (msg);
			} else {
				R_LOG_ERROR ("Cannot read dbg.profile '%s'", dbg_profile);
				R_FREE (mr.pfile);
			}
		} else {
			mr.pfile = argv[opt.ind] ? strdup (argv[opt.ind]) : NULL;
		}
	}

	if (mr.pfile && !*mr.pfile) {
		R_LOG_ERROR ("Cannot open empty path");
		ret = 1;
		goto beach;
	}

	if (mr.do_list_core_plugins) { // "-LL"
		r_core_cmd0 (r, mr.json? "Lcj": "Lc");
		r_cons_flush ();
		mainr2_fini (&mr);
		return 0;
	}
	if (mr.do_list_io_plugins) { // "-L"
		if (r_config_get_b (r->config, "cfg.plugins")) {
			r_core_loadlibs (r, R_CORE_LOADLIBS_ALL, NULL);
		}
		run_commands (r, NULL, mr.prefiles, false, mr.do_analysis);
		run_commands (r, mr.cmds, mr.files, mr.quiet, mr.do_analysis);
		if (mr.quiet_leak) {
			exit (0);
		}
		if (mr.json) {
			r_io_plugin_list_json (r->io);
		} else {
			r_io_plugin_list (r->io);
		}
		r_cons_newline ();
		r_cons_flush ();
		mainr2_fini (&mr);
		return 0;
	}
	if (mr.json) {
		if (mr.qjs_script) {
			r_core_cmd_callf (r, "js %s", mr.qjs_script);
		} else if (opt.ind < argc) {
			r_core_cmd_callf (r, "js:%s", argv[opt.ind]);
		} else {
			r_core_cmd_call (r, "js:");
		}
		r_core_free (r);
		return 0;
	}

	if (mr.help > 0) {
		int ret = main_help (mr.help > 1? 2: 0);
		mainr2_fini (&mr);
		return ret;
	}
#if R2__WINDOWS__
	{
		char *pfile = r_acp_to_utf8 (mr.pfile);
		free (mr.pfile);
		mr.pfile = pfile;
	}
#endif // R2__WINDOWS__
	if (mr.customRarunProfile) {
		char *tfn = r_file_temp (".rarun2");
		if (!r_file_dump (tfn, (const ut8*)mr.customRarunProfile, strlen (mr.customRarunProfile), 0)) {
			R_LOG_ERROR ("Cannot create %s", tfn);
		} else {
			mr.haveRarunProfile = true;
			r_config_set (r->config, "dbg.profile", tfn);
		}
		free (tfn);
		R_FREE (mr.customRarunProfile);
	}
	if (mr.debug == 1) {
		if (opt.ind >= argc && !mr.haveRarunProfile) {
			R_LOG_ERROR ("Missing argument for -d");
			mainr2_fini (&mr);
			return 1;
		}
		const char *src = mr.haveRarunProfile? mr.pfile: argv[opt.ind];
		if (R_STR_ISNOTEMPTY (src)) {
			char *uri = strdup (src);
			if (uri) {
				char *p = strstr (uri, "://");
				if (p) {
					*p = 0;
					// TODO: this must be specified by the io plugin, not hardcoded here
					if (!strcmp (uri, "winedbg")) {
						mr.debugbackend = strdup ("io");
					} else {
						mr.debugbackend = uri;
						uri = NULL;
					}
					mr.debug = 2;
				}
				free (uri);
			}
		}
	}

	if (!mr.load_l || r_sys_getenv_asbool ("R2_NOPLUGINS")) {
		r_config_set_b (r->config, "cfg.plugins", false);
	}
	if (r_config_get_b (r->config, "cfg.plugins")) {
		r_core_loadlibs (r, R_CORE_LOADLIBS_ALL, NULL);
	}
	ret = run_commands (r, NULL, mr.prefiles, false, mr.do_analysis);
	r_list_free (mr.prefiles);
	mr.prefiles = NULL;

	r_bin_force_plugin (r->bin, mr.forcebin);

	if (mr.project_name) {
		if (!r_core_project_open (r, mr.project_name)) {
			R_LOG_ERROR ("Cannot find project");
			mainr2_fini (&mr);
			return 1;
		}
	}

	if (mr.do_connect) {
		const char *uri = argv[opt.ind];
		if (opt.ind >= argc) {
			R_LOG_ERROR ("Missing URI for -C");
			mainr2_fini (&mr);
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

	switch (mr.zflag) {
	case 1:
		r_config_set_b (r->config, "bin.strings", false);
		break;
	case 2:
		r_config_set_b (r->config, "bin.str.raw", true);
		break;
	}
	if (mr.zflag > 3) {
		R_LOG_INFO ("Sleeping in progress");
		r_sys_sleep (mr.zflag);
	}

	if (mr.run_rc) {
		r_core_parse_radare2rc (r);
	} else {
		r_config_set_b (r->config, "scr.utf8", false);
	}

	char *histpath = r_file_home (".cache/radare2/history");
	if (histpath) {
		r_line_hist_load (histpath);
		free (histpath);
	}

	if (r_config_get_b (r->config, "zign.autoload")) {
		autoload_zigns (r);
	}

	if (R_STR_ISNOTEMPTY (mr.pfile) && r_file_is_directory (mr.pfile)) {
		if (mr.debug) {
			R_LOG_ERROR ("Cannot debug directories, yet");
			mainr2_fini (&mr);
			return 1;
		}
		if (!r_sys_chdir (argv[opt.ind])) {
			R_LOG_ERROR ("Cannot open directory");
			mainr2_fini (&mr);
			return 1;
		}
	} else if (argv[opt.ind] && !strcmp (argv[opt.ind], "=")) {
		int sz;
		/* stdin/batch mode */
		char *buf = r_stdin_slurp (&sz);
		eprintf ("^D\n");
		r_cons_set_raw (false);
#if R2__UNIX__
		// TODO: keep flags :?
		R_UNUSED_RESULT (freopen ("/dev/tty", "rb", stdin));
		R_UNUSED_RESULT (freopen ("/dev/tty", "w", stdout));
		R_UNUSED_RESULT (freopen ("/dev/tty", "w", stderr));
#else
		R_LOG_ERROR ("Cannot reopen stdin without UNIX");
		free (buf);
		mainr2_fini (&mr);
		return 1;
#endif
		if (buf && sz > 0) {
			char *path = r_str_newf ("malloc://%d", sz);
			mr.fh = r_core_file_open (r, path, mr.perms, mr.mapaddr);
			if (!mr.fh) {
				r_cons_flush ();
				free (buf);
				R_LOG_ERROR ("Cannot open '%s'", path);
				free (path);
				mainr2_fini (&mr);
				return 1;
			}
			size_t size = r_io_fd_size (r->io, mr.fh->fd);
			r_io_map_add (r->io, mr.fh->fd, 7, 0LL, mr.mapaddr, size);
			r_io_write_at (r->io, mr.mapaddr, (const ut8 *)buf, sz);
			r_core_block_read (r);
			free (buf);
			free (path);
			// TODO: load rbin thing
		} else {
			R_LOG_ERROR ("Cannot slurp from stdin");
			free (buf);
			mainr2_fini (&mr);
			return 1;
		}
	} else if (strcmp (argv[opt.ind - 1], "--") && !mr.project_name) {
		if (mr.asmarch) {
			r_config_set (r->config, "asm.arch", mr.asmarch);
		}
		if (mr.asmbits) {
			r_config_set (r->config, "asm.bits", mr.asmbits);
		}
		if (mr.asmos) {
			r_config_set (r->config, "asm.os", mr.asmos);
		}
		if (mr.pfile && strstr (mr.pfile, "sysgdb://")) {
			mr.debug = 2;
		}
		if (mr.debug) {
			if (mr.asmbits) {
				r_config_set (r->config, "asm.bits", mr.asmbits);
			}
			r_config_set (r->config, "search.in", "dbg.map"); // implicit?
			r_config_set_b (r->config, "cfg.debug", true);
			mr.perms = R_PERM_RWX;
			if (opt.ind >= argc) {
				R_LOG_ERROR ("No program given to -d");
				mainr2_fini (&mr);
				return 1;
			}
			if (mr.debug == 2) {
				if (strstr (mr.pfile, "sysgdb://")) {
					free (mr.debugbackend);
					mr.debugbackend = strdup ("io");
				}
				// autodetect backend with -D when it's not native or esil
				r_config_set (r->config, "dbg.backend", mr.debugbackend);
				if (strcmp (mr.debugbackend, "native") && strcmp (mr.debugbackend, "esil")) {
					if (!mr.haveRarunProfile) {
						free (mr.pfile);
						mr.pfile = strdup (argv[opt.ind++]);
					}
					mr.perms = R_PERM_RX; // XXX. should work with rw too
					mr.debug = 2;
					if (!strstr (mr.pfile, "://")) {
						opt.ind--; // take filename
					}
#if R2__WINDOWS__
					{
						char *pfile = r_acp_to_utf8 (mr.pfile);
						free (mr.pfile);
						mr.pfile = pfile;
					}
#endif
					mr.fh = r_core_file_open (r, mr.pfile, mr.perms, mr.mapaddr);
					mr.iod = (r->io && mr.fh) ? r_io_desc_get (r->io, mr.fh->fd) : NULL;
					if (!strcmp (mr.debugbackend, "gdb")) {
						const char *filepath = r_config_get (r->config, "dbg.exe.path");
						if (R_STR_ISNOTEMPTY (filepath)) {
							ut64 addr = mr.baddr;
							if (addr == UT64_MAX) {
								addr = r_config_get_i (r->config, "bin.baddr");
							}
							if (r_file_exists (filepath) && !r_file_is_directory (filepath)) {
								char *newpath = r_file_abspath (filepath);
								if (newpath) {
									if (mr.iod) {
										free (mr.iod->name);
										mr.iod->name = newpath;
									}
									if (addr == UT64_MAX) {
										addr = r_debug_get_baddr (r->dbg, newpath);
									}
									r_core_bin_load (r, NULL, addr);
								}
							} else if (mr.fh && mr.fh->name && r_str_startswith (mr.fh->name, "gdb://")) {
								filepath = mr.iod->name;
								if (r_file_exists (filepath) && !r_file_is_directory (filepath)) {
									if (addr == UT64_MAX) {
										addr = r_debug_get_baddr (r->dbg, filepath);
									}
									r_core_bin_load (r, filepath, addr);
								} else if ((filepath = get_file_in_cur_dir (filepath))) {
									// Present in local directory
									if (mr.iod) {
										free (mr.iod->name);
										mr.iod->name = (char*) filepath;
									}
									if (addr == UT64_MAX) {
										addr = r_debug_get_baddr (r->dbg, filepath);
									}
									r_core_bin_load (r, NULL, addr);
								}
							}
						}
					}
				}
			} else {
				char *f = (mr.haveRarunProfile && mr.pfile)? strdup (mr.pfile): strdup (argv[opt.ind]);
				mr.is_gdb = r_str_startswith (f, "gdb://");
				if (!mr.is_gdb) {
					free (mr.pfile);
					mr.pfile = strdup ("dbg://");
				}
#if R2__UNIX__
				/* implicit ./ to make unix behave like windows */
				if (f) {
					char *path;
					if (strchr (f, '/')) {
						// f is a path
						path = strdup (f);
					} else {
						if (isdigit (*f)) {
							path = strdup (f);
						} else if (r_file_exists (f)) {
							// f is a filename
							path = r_str_prepend (strdup (f), "./");
						} else {
							path = r_file_path (f);
						}
					}
					if (path) {
						char *escaped_path = r_str_arg_escape (path);
						mr.pfile = r_str_append (mr.pfile, escaped_path);
						mr.file = mr.pfile; // probably leaks
						R_FREE (escaped_path);
						free (path);
					}
				}
#elif R2__WINDOWS__
				char *acpfile = r_acp_to_utf8 (f);
				// backslashes must be escaped because they are unscaped when parsing the uri
				char *r = r_str_replace (acpfile, "\\", "\\\\", true);
				if (r) {
					acpfile = r;
				}
				mr.file = r_str_newf ("dbg://%s", acpfile);
#else
				if (f) {
					char *escaped_path = r_str_arg_escape (f);
					mr.pfile = r_str_append (mr.pfile, escaped_path);
					free (escaped_path);
					mr.file = mr.pfile; // r_str_append (file, escaped_path);
				}
#endif
				opt.ind++;
				free (f);
				while (opt.ind < argc) {
					char *escaped_arg = r_str_arg_escape (argv[opt.ind]);
					mr.file = r_str_appendf (mr.file, " %s", escaped_arg);
					free (escaped_arg);
					opt.ind++;
				}
				mr.pfile = strdup (mr.file);
			}
		}
		if (!mr.debug || mr.debug == 2) {
			const char *dbg_profile = r_config_get (r->config, "dbg.profile");
			if (opt.ind == argc && dbg_profile && *dbg_profile) {
				if (R_STR_ISEMPTY (mr.pfile)) {
					R_LOG_ERROR ("Missing file to open");
					ret = 1;
					goto beach;
				}
				mr.fh = r_core_file_open (r, mr.pfile, mr.perms, mr.mapaddr);
				if (mr.fh) {
					r_core_bin_load (r, mr.pfile, mr.baddr);
				}
			}
			if (opt.ind < argc) {
				R_FREE (mr.pfile);
				while (opt.ind < argc) {
					R_FREE (mr.pfile);
#if R2__WINDOWS__
					mr.pfile = r_acp_to_utf8 (mr.pfile);
#else
					mr.pfile = strdup (argv[opt.ind++]);
#endif
					mr.fh = r_core_file_open (r, mr.pfile, mr.perms, mr.mapaddr);
					if (!mr.fh && mr.perms & R_PERM_W) {
						mr.perms |= R_PERM_CREAT;
						mr.fh = r_core_file_open (r, mr.pfile, mr.perms, mr.mapaddr);
					}
					if (mr.perms & R_PERM_CREAT) {
						if (mr.fh) {
							r_config_set_i (r->config, "io.va", false);
						} else {
							 R_LOG_ERROR ("Permission denied");
						}
					}
					if (mr.baddr == UT64_MAX) {
						const ut64 io_plug_baddr = r_config_get_i (r->config, "bin.baddr");
						if (io_plug_baddr != UT64_MAX) {
							mr.baddr = io_plug_baddr;
						}
					}
					if (mr.fh) {
						mr.iod = r->io ? r_io_desc_get (r->io, mr.fh->fd) : NULL;
						if (mr.iod && mr.perms & R_PERM_X) {
							mr.iod->perm |= R_PERM_X;
						}
						if (r_str_startswith (mr.pfile, "frida://")) {
							r_core_cmd0 (r, ".:init");
							mr.load_bin = 0;
						}
						if (mr.load_bin == LOAD_BIN_ALL) {
							const char *filepath = NULL;
							if (mr.debug) {
								// XXX: incorrect for PIE binaries
								filepath = mr.file? strstr (mr.file, "://"): NULL;
								filepath = filepath ? filepath + 3 : mr.pfile;
							}
							if (r->io->desc && mr.iod && (mr.iod->fd == r->io->desc->fd) && mr.iod->name) {
								filepath = mr.iod->name;
							}
							/* Load rbin info from r2 dbg:// or r2 /bin/ls */
							/* the baddr should be set manually here */
							if (R_STR_ISNOTEMPTY (filepath)) {
								if (mr.threaded) {
									ThreadData *td = R_NEW0 (ThreadData);
									if (!td) {
										return -1;
									}
									td->filepath = strdup (filepath);
									td->baddr = mr.baddr;
									td->core = r;
									mr.th_bin = r_th_new (th_binload, td, false);
									r_th_start (mr.th_bin, true);
								} else {
									binload (r, filepath, mr.baddr);
								}
							}
						} else {
							r_io_map_add (r->io, mr.iod->fd, mr.perms, 0LL, mr.mapaddr, r_io_desc_size (mr.iod));
							if (mr.load_bin == LOAD_BIN_STRUCTURES_ONLY) {
								r_core_bin_load_structs (r, mr.iod->name);
							}
						}
					}
				}
			} else {
				if (mr.project_name) {
					free (mr.pfile);
					mr.pfile = r_core_project_name (r, mr.project_name);
					if (mr.pfile) {
						if (!mr.fh) {
							mr.fh = r_core_file_open (r, mr.pfile, mr.perms, mr.mapaddr);
						}
						// load_bin = LOAD_BIN_NOTHING;
						mr.load_bin = LOAD_BIN_STRUCTURES_ONLY;
					} else {
						R_LOG_ERROR ("Cannot find project file");
					}
				} else {
					if (mr.fh) {
						mr.iod = r->io ? r_io_desc_get (r->io, mr.fh->fd) : NULL;
						if (mr.iod) {
							mr.perms = mr.iod->perm;
							r_io_map_add (r->io, mr.iod->fd, mr.perms, 0LL, 0LL, r_io_desc_size (mr.iod));
						}
					}
				}
			}
			if (mr.mapaddr) { // XXX use UT64_MAX?
				if (r_config_get_b (r->config, "file.info")) {
					R_LOG_WARN ("using oba to load the syminfo from different mapaddress");
					// load symbols when using r2 -m 0x1000 /bin/ls
					r_core_cmdf (r, "oba 0 0x%"PFMT64x, mr.mapaddr);
					r_core_cmd0 (r, ".ies*");
				}
			}
		} else if (mr.pfile) {
			RIODesc *f = r_core_file_open (r, mr.pfile, mr.perms, mr.mapaddr);
			if (f) {
				mr.fh = f;
			}
			if (mr.fh) {
				r_debug_use (r->dbg, mr.is_gdb ? "gdb" : mr.debugbackend);
			}
			/* load symbols when doing r2 -d ls */
			// NOTE: the baddr is redefined to support PIE/ASLR
			mr.baddr = r_debug_get_baddr (r->dbg, mr.pfile);

			if (mr.load_bin == LOAD_BIN_ALL) {
				if (r_core_bin_load (r, mr.pfile, mr.baddr)) {
					RBinObject *obj = r_bin_cur_object (r->bin);
					if (obj && obj->info) {
#if __linux__ && __GNU_LIBRARY__ && __GLIBC__ && __GLIBC_MINOR__ && __x86_64__
						ut64 bitness = r_config_get_i (r->config, "asm.bits");
						if (bitness == 32) {
							R_LOG_INFO ("glibc.fc_offset = 0x00148");
							r_config_set_i (r->config, "dbg.glibc.fc_offset", 0x00148);
						}
#endif
					}
				}
			}
			r_core_cmd0 (r, ".dm*");
			if (mr.asmarch && r_str_startswith (mr.asmarch, "arm") && r_config_get_i (r->config, "asm.bits") < 64) {
				// Set Thumb Mode if necessary
				r_core_cmd0 (r, "dr? thumb;?? e asm.bits=16");
			}
			r_cons_reset ();
		}
		if (!mr.pfile) {
			mr.pfile = mr.file;
		}
		if (!mr.fh) {
			if (R_STR_ISNOTEMPTY (mr.pfile)) {
				r_cons_flush ();
				if (mr.perms & R_PERM_W) {
					R_LOG_ERROR ("Cannot open '%s' for writing", mr.pfile);
				} else {
					R_LOG_ERROR ("Cannot open '%s'", mr.pfile);
				}
			} else {
				R_LOG_ERROR ("Missing file to open");
			}
			ret = 1;
			goto beach;
		}
		if (!r->io->desc) { // no given file
			ret = 1;
			goto beach;
		}
		if (r->bin->cur && r->bin->cur->bo && r->bin->cur->bo->info && r->bin->cur->bo->info->rclass && !strcmp ("fs", r->bin->cur->bo->info->rclass)) {
			const char *fstype = r->bin->cur->bo->info->bclass;
			r_core_cmdf (r, "m /root %s @ 0", fstype);
		}
		r_core_cmd0 (r, "=!"); // initalize io subsystem
		mr.iod = r->io ? r_io_desc_get (r->io, mr.fh->fd) : NULL;
		if (mr.mapaddr) {
			r_core_seek (r, mr.mapaddr, true);
		}
		RListIter *iter;
		char *cmdn;
		r_list_foreach (mr.evals, iter, cmdn) {
			r_config_eval (r->config, cmdn, false);
			r_cons_flush ();
		}
		if (mr.asmbits) {
			r_config_set (r->config, "asm.bits", mr.asmbits);
		}
		if (mr.asmarch) {
			r_config_set (r->config, "asm.arch", mr.asmarch);
		}
		if (mr.asmos) {
			r_config_set (r->config, "asm.os", mr.asmos);
		}

		mr.debug = r->io->desc && mr.iod && (r->io->desc->fd == mr.iod->fd) && mr.iod->plugin && mr.iod->plugin->isdbg;
		if (mr.debug) {
			r_core_setup_debugger (r, mr.debugbackend, mr.baddr == UT64_MAX);
		}
		R_FREE (mr.debugbackend);
		RBinObject *o = r_bin_cur_object (r->bin);
		if (!mr.debug && o && !o->regstate) {
			RFlagItem *fi = r_flag_get (r->flags, "entry0");
			if (fi) {
				r_core_seek (r, fi->offset, true);
			} else {
				fi = r_flag_get (r->flags, "section.0.__TEXT.__text");
				if (fi) {
					r_core_seek (r, fi->offset, true);
				} else if (o) {
					RList *sections = r_bin_get_sections (r->bin);
					RListIter *iter;
					RBinSection *s;
					r_list_foreach (sections, iter, s) {
						if (s->perm & R_PERM_X) {
							ut64 addr = s->vaddr? s->vaddr: s->paddr;
							if (addr) {
								r_core_seek (r, addr, true);
								break;
							}
						}
					}
				}
			}
		}
#if 0
		if (o && o->info && compute_hashes) {
			// TODO: recall with !limit ?
			ut64 limit = r_config_get_i (r->config, "bin.hashlimit");
			r_bin_file_set_hashes (r->bin, r_bin_file_compute_hashes (r->bin, limit));
		}
#endif
		if (mr.s_seek) {
			mr.seek = r_num_math (r->num, mr.s_seek);
			if (mr.seek != UT64_MAX) {
				r_core_seek (r, mr.seek, true);
			}
		}

		if (mr.fullfile) {
			r_core_block_size (r, r_io_desc_size (mr.iod));
		}

		r_core_seek (r, r->offset, true); // read current block

		r_list_foreach (mr.evals, iter, cmdn) {
			r_config_eval (r->config, cmdn, false);
			r_cons_flush ();
		}

		// no flagspace selected by default the beginning
		r_flag_space_set (r->flags, NULL);
		/* load <file>.r2 */
		{
			char* f = r_str_newf ("%s.r2", mr.pfile);
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
		if (R_STR_ISNOTEMPTY (s)) {
			int da = r_config_get_i (r->config, "file.analyze");
			if (da > mr.do_analysis) {
				mr.do_analysis = da;
			}
		}
		free (s);
	}
	if (r_config_get_b (r->config, "scr.demo")) {
		int count = 0;
		while (true) {
			const char *msg = "Loading shards...";
			if (count > 17) {
				break;
			} else if (count > 15) {
				msg = "OK";
			} else if (count > 10) {
				msg = "Deltifying monads...";
			}
			r_print_spinbar (r->print, msg);
			count ++;
			r_sys_usleep (100000);
		}
		eprintf ("\r");
	}
	if (mr.do_analysis > 0) {
		if (mr.threaded) {
			ThreadData *td = R_NEW0 (ThreadData);
			if (!td) {
				return -1;
			}
			td->th_bin = mr.th_bin;
			td->do_analysis = mr.do_analysis;
			td->core = r;
			R_LOG_INFO ("Running analysis level %d in background", mr.do_analysis);
			mr.th_ana = r_th_new (th_analysis, td, false);
			r_th_start (mr.th_ana, false);
			mr.th_bin = NULL;
		} else {
			perform_analysis (r, mr.do_analysis);
		}
	}
#if UNCOLORIZE_NONTTY
#if R2__UNIX__
	if (!r_cons_is_tty ()) {
		r_config_set_i (r->config, "scr.color", COLOR_MODE_DISABLED);
	}
#endif
#endif
	if (mr.fullfile) {
		r_core_block_size (r, r_io_desc_size (mr.iod));
	}
	if (mr.perms & R_PERM_W) {
		r_core_cmd0 (r, "omfg+w");
	}
	ret = run_commands (r, mr.cmds, mr.files, mr.quiet, mr.do_analysis);
	r_list_free (mr.cmds);
	r_list_free (mr.evals);
	r_list_free (mr.files);
	mr.cmds = mr.evals = mr.files = NULL;
	if (mr.forcequit || mr.quiet_leak) {
		ret = r->rc;
		goto beach;
	}
	if (ret) {
		ret = r->rc;
		goto beach;
	}
	if (r_config_get_b (r->config, "scr.prompt")) {
		if (mr.run_rc && r_config_get_i (r->config, "cfg.fortunes")) {
			r_core_fortune_print_random (r);
			r_cons_flush ();
		}
	}
	if (mr.sandbox) {
		r_config_set_b (r->config, "cfg.sandbox", true);
	}
	R_CRITICAL_ENTER (r);
	if (mr.quiet) {
		r_config_set_b (r->config, "scr.wheel", false);
		r_config_set_b (r->config, "scr.interactive", false);
		r_config_set_b (r->config, "scr.prompt", false);
	}
	r->num->value = 0;
	if (mr.patchfile) {
		char *data = r_file_slurp (mr.patchfile, NULL);
		if (data) {
			ret = r_core_patch (r, data);
			r_core_seek (r, 0, true);
			free (data);
		} else {
			R_LOG_ERROR ("Cannot open '%s'", mr.patchfile);
		}
	}
	R_CRITICAL_LEAVE (r);
	if ((mr.patchfile && !mr.quiet) || !mr.patchfile) {
		if (mr.zerosep) {
			r_cons_zero ();
		}
		if (mr.seek != UT64_MAX) {
			r_core_seek (r, mr.seek, true);
		}
		// no flagspace selected by default the beginning
		r_flag_space_set (r->flags, NULL);
		if (!mr.debug && r->bin && r->bin->cur && r->bin->cur->bo && r->bin->cur->bo->info) {
			if (r->bin->cur->bo->info->arch) {
				r_core_cmd0 (r, "aeip");
			}
		}
		r_core_project_undirty (r);
		for (;;) {
			if (!r_core_prompt_loop (r)) {
				mr.quiet_leak = true;
			}
			ret = r->num->value;
			mr.debug = r_config_get_b (r->config, "cfg.debug");
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

				if (mr.debug) {
					if (no_question_debug) {
						if (r_config_get_i (r->config, "dbg.exitkills") && y_kill_debug) {
							r_debug_kill (r->dbg, r->dbg->pid, r->dbg->tid, 9); // KILL
						}
					} else {
						if (r_cons_yesno ('y', "Do you want to quit? (Y/n)")) {
							if (r_config_get_b (r->config, "dbg.exitkills") &&
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

				const char *prj = r_config_get (r->config, "prj.name");
				if (R_STR_ISNOTEMPTY (prj)) {
					if (r_core_project_is_dirty (r) && !r_config_get_b (r->config, "prj.alwaysprompt")) {
						break;
					}
					if (no_question_save) {
						if (y_save_project) {
							r_core_project_save (r, prj);
						}
					} else {
						question = r_str_newf ("Do you want to save the '%s' project? (Y/n)", prj);
						if (r_cons_yesno ('y', "%s", question)) {
							r_core_project_save (r, prj);
						}
						free (question);
					}
				}
				if (r_config_get_b (r->config, "scr.confirmquit")) {
					if (!r_cons_yesno ('n', "Do you want to quit? (Y/n)")) {
						continue;
					}
				}
			} else {
				// r_core_project_save (r, prj);
				if (mr.debug && r_config_get_b (r->config, "dbg.exitkills")) {
					r_debug_kill (r->dbg, 0, false, 9); // KILL
				}

			}
			break;
		}
	}

	if (mustSaveHistory (r->config)) {
		char *history_file = r_xdg_cachedir ("history");
		if (history_file) {
			r_line_hist_save (history_file);
			free (history_file);
		}
	}

	ret = r->rc;
beach:
	if (mr.quiet_leak) {
		exit (r->rc);
		return ret;
	}
	if (mr.th_bin) {
		r_th_wait (mr.th_bin);
		r_th_free (mr.th_bin);
		mr.th_bin = NULL;
	}
	if (mr.th_ana) {
		r_th_wait (mr.th_ana);
		r_th_free (mr.th_ana);
	}

	r_core_task_sync_end (&r->tasks);

	// not really needed, cause r_core_fini will close the file
	// and this fh may be come stale during the command execution.
	// r_core_file_close (r, fh);
	mainr2_fini (&mr);
	return (ret < 0 ? 0 : ret);
}
