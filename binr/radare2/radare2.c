/* radare - LGPL - Copyright 2009-2016 - pancake */

#define USE_THREADS 1
#define UNCOLORIZE_NONTTY 0

#include <sdb.h>
#include <r_core.h>
#include <r_io.h>
#include <stdio.h>
#include <getopt.c>
#include "../blob/version.c"

#if USE_THREADS
#include <r_th.h>
static char *rabin_cmd = NULL;
#endif
static bool threaded = false;
static struct r_core_t r;

static int verify_version(int show) {
	int i, ret;
	typedef const char* (*vc)();
	const char *base = R2_GITTAP;
	struct vcs_t {
		const char *name;
		vc callback;
	} vcs[] = {
		{ "r_anal", &r_anal_version },
		{ "r_lib", &r_lib_version },
		{ "r_egg", &r_egg_version },
		{ "r_asm", &r_asm_version },
		{ "r_bin", &r_bin_version },
		{ "r_cons", &r_cons_version },
		{ "r_flag", &r_flag_version },
		{ "r_core", &r_core_version },
		{ "r_crypto", &r_crypto_version },
		{ "r_bp", &r_bp_version },
		{ "r_debug", &r_debug_version },
		{ "r_hash", &r_hash_version },
		{ "r_fs", &r_fs_version },
		{ "r_io", &r_io_version },
		{ "r_magic", &r_magic_version },
		{ "r_parse", &r_parse_version },
		{ "r_reg", &r_reg_version },
		{ "r_sign", &r_sign_version },
		{ "r_search", &r_search_version },
		{ "r_syscall", &r_syscall_version },
		{ "r_util", &r_util_version },
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

// we should probably move this functionality into the r_debug API
// r_debug_get_baddr
static ut64 getBaddrFromDebugger(RCore *r, const char *file) {
	char *abspath;
	RListIter *iter;
	RDebugMap *map;
	if (!r || !r->io || !r->io->desc) {
		return 0LL;
	}
#if __WINDOWS__
	typedef struct {
		int pid;
		int tid;
		PROCESS_INFORMATION pi;
	} RIOW32Dbg;
	RIODesc *d = r->io->desc;
	if (!strcmp ("w32dbg", d->plugin->name)) {
		RIOW32Dbg *g = d->data;
		r->io->desc->fd = g->pid;
		r_debug_attach (r->dbg,g->pid);
	}
	return r->io->winbase;
#else
	if (r_debug_attach (r->dbg, r->io->desc->fd) == -1) {
		return 0LL;
	}
#endif
	r_debug_map_sync (r->dbg);
	abspath = r_file_abspath (file);
	if (!abspath) abspath = strdup (file);
	r_list_foreach (r->dbg->maps, iter, map) {
		if (!strcmp (abspath, map->name)) {
			free (abspath);
			return map->addr;
		}
	}
	free (abspath);
	// fallback resolution (osx/w32?)
	// we asume maps to be loaded in order, so lower addresses come first
	r_list_foreach (r->dbg->maps, iter, map) {
		if (map->perm == 5) { // r-x
			return map->addr;
		}
	}
	return 0LL;
}

static int main_help(int line) {
	if (line < 2) {
		printf ("Usage: r2 [-ACdfLMnNqStuvwz] [-P patch] [-p prj] [-a arch] [-b bits] [-i file]\n"
			"          [-s addr] [-B baddr] [-M maddr] [-c cmd] [-e k=v] file|pid|-|--|=\n");
	}
	if (line != 1) {
		printf (
		" --           open radare2 on an empty file\n"
		" -            equivalent of 'r2 malloc://512'\n"
		" =            read file from stdin (use -i and -c to run cmds)\n"
		" -=           perform !=! command to run all commands remotely\n"
		" -0           print \\x00 after init and every command\n"
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
		" -k [k=v]     perform sdb query into core->sdb\n"
		" -l [lib]     load plugin file\n"
		" -L           list supported IO plugins\n"
		" -m [addr]    map file at given address (loadaddr)\n"
		" -M           do not demangle symbol names\n"
		" -n, -nn      do not load RBin info (-nn only load bin structures)\n"
		" -N           do not load user settings and scripts\n"
		" -o [OS/kern] set asm.os (linux, macos, w32, netbsd, ...)\n"
		" -q           quiet mode (no prompt) and quit after -i\n"
		" -p [prj]     use project, list if no arg, load if no file\n"
		" -P [file]    apply rapatch file and quit\n"
		" -R [rarun2]  specify rarun2 profile to load (same as -e dbg.profile=X)\n"
		" -s [addr]    initial seek\n"
		" -S           start r2 in sandbox mode\n"
#if USE_THREADS
		" -t           load rabin2 info in thread\n"
#endif
		" -u           set bin.filter=false to get raw sym/sec/cls names\n"
		" -v, -V       show radare2 version (-V show lib versions)\n"
		" -w           open file in write mode\n"
		" -z, -zz      do not load strings or load them even in raw\n");
	}
	if (line == 2) {
		char *homedir = r_str_home (R2_HOMEDIR);
		printf (
		"Scripts:\n"
		" system   "R2_PREFIX"/share/radare2/radare2rc\n"
		" user     ~/.radare2rc ${RHOMEDIR}/radare2/radare2rc (and radare2rc.d/)\n"
		" file     ${filename}.r2\n"
		"Plugins:\n"
		" plugins  "R2_PREFIX"/lib/radare2/last\n"
		" user     ~/.config/radare2/plugins\n"
		" LIBR_PLUGINS "R2_PREFIX"/lib/radare2/"R2_VERSION"\n"
		"Environment:\n"
		" RHOMEDIR     %s\n" // TODO: rename to RHOME R2HOME?
		" RCFILE       ~/.radare2rc (user preferences, batch script)\n" // TOO GENERIC
		" MAGICPATH    "R_MAGIC_PATH"\n"
		" R_DEBUG      if defined, show error messages and crash signal\n"
		" VAPIDIR      path to extra vapi directory\n"
		" R2_NOPLUGINS do not load r2 shared plugins\n"
		"Paths:\n"
		" PREFIX       "R2_PREFIX"\n"
		" INCDIR       "R2_INCDIR"\n"
		" LIBDIR       "R2_LIBDIR"\n"
		" LIBEXT       "R_LIB_EXT"\n"
		, homedir);
		free (homedir);
	}
	return 0;
}

static int main_print_var(const char *var_name) {
	int i = 0;
	struct radare2_var_t {
		const char *name;
		const char *value;
	} r2_vars[] = {
		{ "R2_PREFIX", R2_PREFIX },
		{ "LIBR_PLUGINS", R2_PREFIX"/lib/radare2/"R2_VERSION },
		{ "MAGICPATH", R_MAGIC_PATH },
		{ "PREFIX", R2_PREFIX },
		{ "INCDIR", R2_INCDIR },
		{ "LIBDIR", R2_LIBDIR },
		{ "LIBEXT", R_LIB_EXT },
		{ "RHOMEDIR", R2_HOMEDIR },
		{ NULL, NULL }
	};

	if (var_name) {
		while (r2_vars[i].name) {
			if (!strcmp (r2_vars[i].name, var_name)) {
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
	return 0;
}

// Load the binary information from rabin2
// TODO: use thread to load this, split contents line, per line and use global lock
#if USE_THREADS
static int rabin_delegate(RThread *th) {
	if (rabin_cmd && r_file_exists (r.file->desc->name)) {
		char *nptr, *ptr, *cmd = r_sys_cmd_str (rabin_cmd, NULL, NULL);
		ptr = cmd;
		if (ptr)
			do {
				if (th) {
					r_th_lock_enter (th->user);
				}
				nptr = strchr (ptr, '\n');
				if (nptr) {
					*nptr = 0;
				}
				r_core_cmd (&r, ptr, 0);
				if (nptr) {
					ptr = nptr + 1;
				}
				if (th) {
					r_th_lock_leave(th->user);
				}
			} while (nptr);
		//r_core_cmd (&r, cmd, 0);
		r_str_free (rabin_cmd);
		rabin_cmd = NULL;
	}
	if (th) eprintf ("rabin2: done\n");
	return 0;
}
#endif

static void radare2_rc(RCore *r) {
	char *homerc = r_str_home (".radare2rc");
	if (homerc) {
		r_core_cmd_file (r, homerc);
		free (homerc);
	}
	homerc = r_str_home ("/.config/radare2/radare2rc");
	if (homerc) {
		r_core_cmd_file (r, homerc);
		free (homerc);
	}
	homerc = r_str_home ("/.config/radare2/radare2rc.d");
	if (homerc) {
		if (r_file_is_directory (homerc)) {
			char *file;
			RListIter *iter;
			RList *files = r_sys_dir (homerc);
			r_list_foreach (files, iter, file) {
				if (*file != '.') {
					char *path = r_str_newf ("%s/%s", homerc, file);
					if (r_file_is_regular (path)) {
						r_core_cmd_file (r, path);
					}
					free (path);
				}
			}
			r_list_free (files);
		}
		free (homerc);
	}
}

static bool run_commands(RList *cmds, RList *files, bool quiet) {
	RListIter *iter;
	const char *cmdn;
	const char *file;
	int ret;
	/* -i */
	r_list_foreach (files, iter, file) {
		if (!r_file_exists (file)) {
			eprintf ("Script '%s' not found.\n", file);
			return false;
		}
		ret = r_core_run_script (&r, file);
		if (ret == -2) {
			eprintf ("Cannot open '%s'\n", file);
		}
		if (ret < 0 || (ret == 0 && quiet)) {
			r_cons_flush ();
			return false;
		}
	}
	/* -c */
	r_list_foreach (cmds, iter, cmdn) {
		r_core_cmd0 (&r, cmdn);
		r_cons_flush ();
	}
	if (quiet) {
		if (cmds && !r_list_empty (cmds)) {
			return true;
		}
		if (!r_list_empty (files)) {
			return true;
		}
	}
	return false;
}

int main(int argc, char **argv, char **envp) {
#if USE_THREADS
	RThreadLock *lock = NULL;
	RThread *rabin_th = NULL;
#endif
	RListIter *iter;
	char *cmdn, *tmp;
	RCoreFile *fh = NULL;
	const char *patchfile = NULL;
	const char *prj = NULL;
	int debug = 0;
	int zflag = 0;
	int do_analysis = 0;
	int do_connect = 0;
	bool fullfile = false;
	int has_project;
	int prefile = 0;
	bool zerosep = false;
	int help = 0;
	int run_anal = 1;
	int run_rc = 1;
 	int ret, c, perms = R_IO_READ;
	bool sandbox = false;
	ut64 baddr = UT64_MAX;
	ut64 seek = UT64_MAX;
	bool do_list_io_plugins = false;
	char *pfile = NULL, *file = NULL;
	const char *debugbackend = "native";
	const char *asmarch = NULL;
	const char *asmos = NULL;
	const char *forcebin = NULL;
	const char *asmbits = NULL;
	ut64 mapaddr = 0LL;
	int quiet = false;
	int is_gdb = false;
	RList *cmds = r_list_new ();
	RList *evals = r_list_new ();
	RList *files = r_list_new ();
	RList *prefiles = r_list_new ();
	int va = 1; // set va = 0 to load physical offsets from rbin

	r_sys_set_environ (envp);

	if (r_sys_getenv ("R_DEBUG"))
		r_sys_crash_handler ("gdb --pid %d");

	if (argc < 2) {
		r_list_free (cmds);
		r_list_free (evals);
		r_list_free (files);
		r_list_free (prefiles);
		return main_help (1);
	}
	r_core_init (&r);
	if (argc == 2 && !strcmp (argv[1], "-p")) {
		r_core_project_list (&r, 0);
		r_cons_flush ();
		return 0;
	}
	// HACK TO PERMIT '#!/usr/bin/r2 - -i' hashbangs
	if (argc > 1 && !strcmp (argv[1], "-")) {
		argv[1] = argv[0];
		prefile = 1;
		argc--;
		argv++;
	} else {
		prefile = 0;
	}

	// -H option without argument
	if (argc == 2 && !strcmp (argv[1], "-H")) {
		main_print_var (NULL);
		return 0;
	}

	while ((c = getopt (argc, argv, "=0AMCwfF:hH::m:e:nk:Ndqs:p:b:B:a:Lui:I:l:P:R:c:D:vVSzu"
#if USE_THREADS
"t"
#endif
	)) != -1) {
		switch (c) {
		case '=':
			r.cmdremote = 1;
			break;
		case '0':
			zerosep = true;
			//r_config_set (r.config, "scr.color", "false");
			/* implicit -q */
			r_config_set (r.config, "scr.interactive", "false");
			r_config_set (r.config, "scr.prompt", "false");
			r_config_set (r.config, "scr.color", "false");
			quiet = true;
			break;
		case 'u':
			r_config_set (r.config, "bin.filter", "false");
			break;
		case 'a': asmarch = optarg; break;
		case 'z': zflag++; break;
		case 'A':
			if (!do_analysis) do_analysis ++;
			do_analysis++;
			break;
		case 'b': asmbits = optarg; break;
		case 'B':
			baddr = r_num_math (r.num, optarg);
			va = 2;
			break;
		case 'c': r_list_append (cmds, optarg); break;
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
			debugbackend = optarg;
			if (!strcmp (optarg, "?")) {
				r_debug_plugin_list (r.dbg, 'q');
				r_cons_flush();
				return 0;
			}
			break;
		case 'e':
			if (!strcmp (optarg, "q")) {
				r_core_cmd0 (&r, "eq");
			} else {
				r_config_eval (r.config, optarg);
				r_list_append (evals, optarg);
			}
			break;
		case 'f':
			fullfile = true;
			break;
		case 'F': forcebin = optarg; break;
		case 'h': help++; break;
		case 'H': main_print_var (optarg); return 0; break;
		case 'i':
			r_list_append (files, optarg);
			break;
		case 'I':
			r_list_append (prefiles, optarg);
			break;
		case 'k':
			asmos = optarg;
			break;
		case 'l':
			r_lib_open (r.lib, optarg);
			break;
		case 'L':
			do_list_io_plugins = true;
			break;
		case 'm':
			mapaddr = r_num_math (r.num, optarg); break;
			break;
		case 'M':
			r_config_set (r.config, "bin.demangle", "false");
			r_config_set (r.config, "asm.demangle", "false");
			break;
		case 'n':
			run_anal--;
			break;
		case 'N':
			run_rc = 0;
			break;
		case 'p':
			if (!strcmp (optarg, "?")) {
				r_core_project_list (&r, 0);
				r_cons_flush ();
				return 0;
			} else {
				r_config_set (r.config, "prj.name", optarg);
			}
			break;
		case 'P':
			patchfile = optarg;
			break;
		case 'q':
			r_config_set (r.config, "scr.interactive", "false");
			r_config_set (r.config, "scr.prompt", "false");
			r_config_set (r.config, "cfg.fortunes", "false");
			quiet = true;
			break;
		case 'R':
			r_config_set (r.config, "dbg.profile", optarg);
			break;
		case 's':
			seek = r_num_math (r.num, optarg);
			break;
		case 'S':
			sandbox = true;
			break;
#if USE_THREADS
		case 't':
			threaded = true;
			break;
#endif
		case 'v':
			if (quiet) {
				printf ("%s\n", R2_VERSION);
				return 0;
			} else {
				verify_version (0);
				return blob_version ("radare2");
			}
		case 'V':
			return verify_version (1);
		case 'w':
			perms = R_IO_READ | R_IO_WRITE;
			break;
		default:
			help++;
		}
	}
	if (do_list_io_plugins) {
		if (r_config_get_i (r.config, "cfg.plugins")) {
			r_core_loadlibs (&r, R_CORE_LOADLIBS_ALL, NULL);
		}
		run_commands (cmds, files, quiet);
		r_io_plugin_list (r.io);
		r_cons_flush ();
		r_list_free (evals);
		r_list_free (files);
		r_list_free (cmds);
		return 0;
	}

	if (help > 0) {
		r_list_free (evals);
		r_list_free (files);
		r_list_free (cmds);
		return main_help (help > 1? 2: 0);
	}
	if (debug == 1) {
		if (optind >= argc) {
			eprintf ("Missing argument for -d\n");
			return 1;
		}
		char *uri = strdup (argv[optind]);
		char *p = strstr (uri, "://");
		if (p) {
			*p = 0;
			debugbackend = uri;
			debug = 2;
		} else {
			free (uri);
		}
	}

	if ((tmp = r_sys_getenv ("R2_NOPLUGINS"))) {
		r_config_set_i (r.config, "cfg.plugins", 0);
		free (tmp);
	}
	if (r_config_get_i (r.config, "cfg.plugins")) {
		r_core_loadlibs (&r, R_CORE_LOADLIBS_ALL, NULL);
	}
	ret = run_commands (NULL, prefiles, false);
	r_list_free (prefiles);

	// HACK TO PERMIT '#!/usr/bin/r2 - -i' hashbangs
	if (prefile) {
		optind = 1;
		argc = 2;
		argv[1] = "-";
	}
	r_bin_force_plugin (r.bin, forcebin);

	//cverify_version (0);
	if (do_connect) {
		const char *uri = argv[optind];
		if (optind >= argc) {
			eprintf ("Missing URI for -C\n");
			return 1;
		}
		if (!strncmp (uri, "http://", 7)) {
			r_core_cmdf (&r, "=+%s", uri);
		} else {
			r_core_cmdf (&r, "=+http://%s/cmd/", argv[optind]);
		}
		return 0;
	}

	switch (zflag) {
	case 1:
		r_config_set (r.config, "bin.strings", "false");
		break;
	case 2:
		r_config_set (r.config, "bin.rawstr", "true");
		break;
	}

	switch (va) {
	case 0:
		r_config_set_i (r.config, "io.va", false);
		baddr = UT64_MAX;
		break;
	}

	if (run_rc) {
		radare2_rc (&r);
	}
	if (argv[optind] && r_file_is_directory (argv[optind])) {
		if (debug) {
			eprintf ("Error: Cannot debug directories, yet.\n");
			return 1;
		}
		if (chdir (argv[optind])) {
			eprintf ("Cannot open directory\n");
			return 1;
		}
	} else if (argv[optind] && !strcmp (argv[optind], "=")) {
		int sz;
		/* stdin/batch mode */
		ut8 *buf = (ut8 *)r_stdin_slurp (&sz);
		close (0);
		if (sz > 0) {
			char path[1024];
			snprintf (path, sizeof (path) - 1, "malloc://%d", sz);
			fh = r_core_file_open (&r, path, perms, mapaddr);
			if (fh) {
				r_io_write_at (r.io, 0, buf, sz);
				r_core_block_read (&r);
				free (buf);
				// TODO: load rbin thing
			} else {
				r_cons_flush ();
				eprintf ("Cannot open %s\n", path);
				return 1;
			}
		} else {
			eprintf ("Cannot slurp from stdin\n");
			return 1;
		}
	} else if (strcmp (argv[optind-1], "--")) {
		if (debug) {
			if (asmbits) r_config_set (r.config, "asm.bits", asmbits);
			r_config_set (r.config, "search.in", "dbg.map"); // implicit?
			r_config_set_i (r.config, "io.va", false); // implicit?
			r_config_set (r.config, "cfg.debug", "true");
			perms = R_IO_READ | R_IO_WRITE;
			if (optind >= argc) {
				eprintf ("No program given to -d\n");
				return 1;
			}
			if (debug == 2) {
				// autodetect backend with -D
				r_config_set (r.config, "dbg.backend", debugbackend);
				if (strcmp (debugbackend, "native")) {
					pfile = argv[optind++];
					perms = R_IO_READ; // XXX. should work with rw too
					debug = 2;
					if (!strstr (pfile, "://"))
						optind--; // take filename
					fh = r_core_file_open (&r, pfile, perms, mapaddr);
					r_config_set (r.config, "io.raw", "false");
/*
					if (fh) {
						r_core_bin_load (&r, pfile);
						r_debug_use (r.dbg, debugbackend);
					}
*/
				}
			} else {
				const char *f = argv[optind];
				is_gdb = (!memcmp (argv[optind], "gdb://", 6));
				if (!is_gdb) file = strdup ("dbg://");
#if __UNIX__
				/* implicit ./ to make unix behave like windows */
				{
					char *path, *escaped_path;
					if (strchr (f, '/') != NULL) {
						// f is a path
						path = strdup (f);
					} else {
						// f is a filename
						if (r_file_exists (f))
							path = r_str_prefix (strdup (f), "./");
						else
							path = r_file_path (f);
					}
					escaped_path = r_str_arg_escape (path);
					file = r_str_concat (file, escaped_path);
					free (escaped_path);
					free (path);
				}
#else
				{
					char *escaped_path = r_str_arg_escape (f);
					file = r_str_concat (file, escaped_path);
					free (escaped_path);
				}
#endif

				optind++;
				while (optind < argc) {
					char *escaped_arg = r_str_arg_escape (argv[optind]);
					file = r_str_concat (file, " ");
					file = r_str_concat (file, escaped_arg);
					free (escaped_arg);
					optind++;
				}
				{
					char *diskfile = strstr (file, "://");
					diskfile = diskfile? diskfile + 3: file;
					fh = r_core_file_open (&r, file, perms, mapaddr);
					if (fh != NULL) {
						r_debug_use (r.dbg, is_gdb ? "gdb" : debugbackend);
					}
					/* load symbols when doing r2 -d ls */
					// NOTE: the baddr is redefined to support PIE/ASLR
					baddr = getBaddrFromDebugger (&r, diskfile);
					if (baddr != UT64_MAX && baddr != 0) {
						eprintf ("bin.baddr 0x%08"PFMT64x"\n", baddr);
						va = 2;
					}
					if (run_anal > 0) {
						if (r_core_bin_load (&r, diskfile, baddr)) {
							RBinObject *obj = r_bin_get_object (r.bin);
							if (obj && obj->info)
								eprintf ("asm.bits %d\n", obj->info->bits);
						}
					}
					r_core_cmd0 (&r, ".dm*");
					// Set Thumb Mode if necessary
					r_core_cmd0 (&r, "dr? thumb;?? e asm.bits=16");
					r_cons_reset ();
				}
			}
		}

		if (!debug || debug == 2) {
			if (optind < argc) {
				while (optind < argc) {
					pfile = argv[optind++];
					fh = r_core_file_open (&r, pfile, perms, mapaddr);
					if ((perms & R_IO_WRITE) && !fh) {
						if (r_io_create (r.io, pfile, 0644, 0)) {
							fh = r_core_file_open (&r, pfile, perms, mapaddr);
						} else eprintf ("r_io_create: Permission denied.\n");
					}
					if (fh) {
						if (run_anal > 0) {
#if USE_THREADS
							if (!rabin_th)
#endif
							{
								const char *filepath = NULL;
								if (debug) {
									// XXX: incorrect for PIE binaries
									filepath = file? strstr (file, "://"): NULL;
									filepath = filepath ? filepath + 3 : pfile;
								}
								if (r.file && r.file->desc && r.file->desc->name)
									filepath = r.file->desc->name;

								/* Load rbin info from r2 dbg:// or r2 /bin/ls */
								/* the baddr should be set manually here */
								if (!r_core_bin_load (&r, filepath, baddr)) {
									r_config_set_i (r.config, "io.va", false);
								}
							}
						} else {
							if (run_anal < 0) {
								// PoC -- must move -rk functionalitiy into rcore
								// this may be used with caution (r2 -nn $FILE)
								r_core_cmdf (&r, "Sf");
								r_core_cmdf (&r, ".!rabin2 -rk. '%s'", r.file->desc->name);
							}
						}
					}
				}
			} else {
				const char *prj = r_config_get (r.config, "prj.name");
				if (prj && *prj) {
					pfile = r_core_project_info (&r, prj);
					if (pfile) {
						fh = r_core_file_open (&r, pfile, perms, mapaddr);
						// run_anal = 0;
						run_anal = -1;
					} else {
						eprintf ("Cannot find project file\n");
					}
				}
			}
		}
		if (!pfile) {
			pfile = file;
		}
		if (!fh) {
			if (pfile && *pfile) {
				r_cons_flush ();
				if (perms & R_IO_WRITE) {
					eprintf ("Cannot open '%s' for writing.\n", pfile);
				} else {
					eprintf ("Cannot open '%s'\n", pfile);
				}
			} else {
				eprintf ("Missing file to open\n");
			}
			return 1;
		}
		if (!r.file) { // no given file
			return 1;
		}
#if USE_THREADS
		if (run_anal > 0 && threaded) {
			// XXX: if no rabin2 in path that may fail
			// TODO: pass -B 0 ? for pie bins?
			rabin_cmd = r_str_newf ("rabin2 -rSIeMzisR%s %s",
					(debug || r.io->va) ? "" : "p", r.file->desc->name);
			/* TODO: only load data if no project is used */
			lock = r_th_lock_new ();
			rabin_th = r_th_new (&rabin_delegate, lock, 0);
			// rabin_delegate (NULL);
		} // else eprintf ("Metadata loaded from 'prj.name'\n");
#endif
		if (mapaddr) {
			r_core_seek (&r, mapaddr, 1);
		}

		r_list_foreach (evals, iter, cmdn) {
			r_config_eval (r.config, cmdn);
			r_cons_flush ();
		}
#if 0
// Do not autodetect utf8 terminals to avoid problems on initial
// stdin buffer and some terminals that just hang (android/ios)
		if (!quiet && r_cons_is_utf8 ()) {
			r_config_set_i (r.config, "scr.utf8", true);
		}
#endif
		if (asmarch) r_config_set (r.config, "asm.arch", asmarch);
		if (asmbits) r_config_set (r.config, "asm.bits", asmbits);
		if (asmos) r_config_set (r.config, "asm.os", asmos);

		(void)r_core_bin_update_arch_bits (&r);

		debug = r.file && r.file->desc && r.file->desc->plugin && \
			r.file->desc->plugin->isdbg;
		if (debug) {
			if (baddr != UT64_MAX) {
				//setup without attach again because there is dpa call
				//producing two attach and it's annoying
				r_core_setup_debugger (&r, debugbackend, false);
			} else {
				r_core_setup_debugger (&r, debugbackend, true);
			}
		}

		if (!debug && r_flag_get (r.flags, "entry0")) {
			r_core_cmd0 (&r, "s entry0");
		}
		if (seek != UT64_MAX) {
			r_core_seek (&r, seek, 1);
		}

		if (fullfile) {
			r_core_block_size (&r, r_io_desc_size (r.io, r.file->desc));
		}

		r_core_seek (&r, r.offset, 1); // read current block

		/* check if file.sha1 has changed */
		if (!strstr (r.file->desc->uri, "://")) {
			const char *npath, *nsha1;
			char *path = strdup (r_config_get (r.config, "file.path"));
			char *sha1 = strdup (r_config_get (r.config, "file.sha1"));
			has_project = r_core_project_open (&r, r_config_get (r.config, "prj.name"), threaded);
			if (has_project) {
				r_config_set (r.config, "bin.strings", "false");
			}
			if (r_core_hash_load (&r, r.file->desc->name) == false) {
				//eprintf ("WARNING: File hash not calculated\n");
			}
			nsha1 = r_config_get (r.config, "file.sha1");
			npath = r_config_get (r.config, "file.path");
			if (sha1 && *sha1 && strcmp (sha1, nsha1))
				eprintf ("WARNING: file.sha1 change: %s => %s\n", sha1, nsha1);
			if (path && *path && strcmp (path, npath))
				eprintf ("WARNING: file.path change: %s => %s\n", path, npath);
			free (sha1);
			free (path);
			if (has_project && !zerosep) {
				r_config_set_i (r.config, "scr.interactive", true);
				r_config_set_i (r.config, "scr.prompt", true);
				r_config_set_i (r.config, "scr.color", true);
			}
		}

		r_list_foreach (evals, iter, cmdn) {
			r_config_eval (r.config, cmdn);
			r_cons_flush ();
		}
		r_list_free (evals);

		// no flagspace selected by default the beginning
		r.flags->space_idx = -1;
		/* load <file>.r2 */
		{
			char f[128];
			snprintf (f, sizeof (f), "%s.r2", pfile);
			if (r_file_exists (f)) {
				if (!quiet)
					eprintf ("NOTE: Loading '%s' script.\n", f);
				r_core_cmd_file (&r, f);
			}
		}
	}
	{
		const char *global_rc = R2_PREFIX"/share/radare2/radare2rc";
		if (r_file_exists (global_rc))
			(void)r_core_run_script (&r, global_rc);
	}
	// only analyze if file contains entrypoint
	{
		char *s = r_core_cmd_str (&r, "ieq");
		if (s && *s) {
			int da = r_config_get_i (r.config, "file.analyze");
			if (da > do_analysis)
				do_analysis = da;
		}
		free (s);
	}
	if (do_analysis > 0) {
		switch (do_analysis) {
		case 1: r_core_cmd0 (&r, "aa"); break;
		case 2: r_core_cmd0 (&r, "aaa"); break;
		case 3: r_core_cmd0 (&r, "aaaa"); break;
		default: r_core_cmd0 (&r, "aaaaa"); break;
		}
		r_cons_flush ();
	}
#if UNCOLORIZE_NONTTY
#if __UNIX__
	if (!r_cons_isatty ()) {
		r_config_set_i (r.config, "scr.color", 0);
	}
#endif
#endif
	if (fullfile) {
		r_core_block_size (&r, r_io_desc_size (r.io, r.file->desc));
	}
	ret = run_commands (cmds, files, quiet);
	r_list_free (cmds);
	r_list_free (files);
	if (ret) {
		ret = 0;
		goto beach;
	}
	if (r_config_get_i (r.config, "scr.prompt")) {
		if (run_rc && r_config_get_i (r.config, "cfg.fortunes")) {
			r_core_cmd (&r, "fo", 0);
			r_cons_flush ();
		}
	}
	if (sandbox) {
		r_config_set (r.config, "cfg.sandbox", "true");
	}
	if (quiet) {
		r_config_set (r.config, "scr.wheel", "false");
		r_config_set (r.config, "scr.interactive", "false");
		r_config_set (r.config, "scr.prompt", "false");
	}
	r.num->value = 0;
	if (patchfile) {
		char *data = r_file_slurp (patchfile, NULL);
		if (data) {
			r_core_patch (&r, data);
			r_core_seek (&r, 0, 1);
			free (data);
		} else {
			eprintf ("Cannot open '%s'\n", patchfile);
		}
	}
	if ((patchfile && !quiet) || !patchfile) {
		if (zerosep)
			r_cons_zero ();
		if (seek != UT64_MAX)
			r_core_seek (&r, seek, 1);

		// no flagspace selected by default the beginning
		r.flags->space_idx = -1;
		for (;;) {
#if USE_THREADS
			do {
				int err = r_core_prompt (&r, false);
				if (err < 1) {
					// handle ^D
					r.num->value = 0;
					break;
				}
				if (lock) r_th_lock_enter (lock);
				/* -1 means invalid command, -2 means quit prompt loop */
				if ((ret = r_core_prompt_exec (&r)) == -2)
					break;
				if (lock) r_th_lock_leave (lock);
				if (rabin_th && !r_th_wait_async (rabin_th)) {
					eprintf ("rabin thread end \n");
					r_th_free (rabin_th);
					r_th_lock_free (lock);
					lock = NULL;
					rabin_th = NULL;
				}
			} while (ret != R_CORE_CMD_EXIT);
#else
			r_core_prompt_loop (&r);
#endif
			ret = r.num->value;
			debug = r_config_get_i (r.config, "cfg.debug");
			if (ret != -1 && r_config_get_i (r.config, "scr.interactive")) {
				char *question;
				bool no_question_debug = ret & 1;
				bool no_question_save = (ret & 2) >> 1;
				bool y_kill_debug = (ret & 4) >> 2;
				bool y_save_project = (ret & 8) >> 3;

				if (debug) {
					if (no_question_debug) {
						if (r_config_get_i (r.config, "dbg.exitkills") && y_kill_debug){
							r_debug_kill (r.dbg, 0, false, 9); // KILL
						}
					} else {
						if (r_cons_yesno ('y', "Do you want to quit? (Y/n)")) {
							if (r_config_get_i (r.config, "dbg.exitkills") &&
									r_cons_yesno ('y', "Do you want to kill the process? (Y/n)")) {
								r_debug_kill (r.dbg, 0, false, 9); // KILL
							}
						} else continue;
					}
				}

				prj = r_config_get (r.config, "prj.name");
				if (no_question_save) {
					if (prj && *prj && y_save_project){
						r_core_project_save (&r, prj);
					}
				} else {
					question = r_str_newf ("Do you want to save the '%s' project? (Y/n)", prj);
					if (prj && *prj && r_cons_yesno ('y', "%s", question)) {
						r_core_project_save (&r, prj);
					}
					free (question);
				}
			} else {
				// r_core_project_save (&r, prj);
				if (debug && r_config_get_i (r.config, "dbg.exitkills")) {
					r_debug_kill (r.dbg, 0, false, 9); // KILL
				}

			}
			break;
		}
	}
	if (r_config_get_i (r.config, "scr.histsave") &&
			r_config_get_i (r.config, "scr.interactive") &&
			!r_sandbox_enable (0)) {
		r_line_hist_save (R2_HOMEDIR"/history");
	}
	// TODO: kill thread

	/* capture return value */
	ret = r.num->value;

beach:
	// not really needed, cause r_core_fini will close the file
	// and this fh may be come stale during the command
	// exectution.
	//r_core_file_close (&r, fh);
	r_core_fini (&r);
	r_cons_set_raw (0);
	free (file);
	r_str_const_free ();
	r_cons_free ();
	return ret;
}
