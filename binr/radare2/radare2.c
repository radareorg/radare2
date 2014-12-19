/* radare - LGPL - Copyright 2009-2014 - pancake */

#define USE_THREADS 1

#include <sdb.h>
#include <r_core.h>
#include <r_io.h>
#include <stdio.h>
#include <getopt.c>
#include "../blob/version.c"

#if USE_THREADS
#include <r_th.h>
static char *rabin_cmd = NULL;
static int threaded = 0;
#endif
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
		{ "r_flags", &r_flag_version }, // XXX inconsistency
		{ "r_core", &r_core_version },
		{ "r_crypto", &r_crypto_version },
		{ "r_db", &r_db_version },
		{ "r_bp", &r_bp_version },
		{ "r_debug", &r_debug_version },
		{ "r_hash", &r_hash_version },
		{ "r_diff", &r_diff_version },
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

	if (show) printf ("%s  r2\n", base);
	for (i=ret=0; vcs[i].name; i++) {
		struct vcs_t *v = &vcs[i];
		const char *name = v->callback ();
		if (!ret && strcmp (base, name))
			ret = 1;
		if (show) printf ("%s  %s\n", name, v->name);
	}
	if (ret) {
		if (show) eprintf ("WARNING: r2 library versions mismatch!\n");
		else	eprintf ("WARNING: r2 library versions mismatch! See r2 -V\n");
	}
	return ret;
}

// we should probably move this functionality into the r_debug API
// r_debug_get_baddr
static ut64 getBaddrFromDebugger(RCore *r, const char *file) {
	RListIter *iter;
	RDebugMap *map;
	if (!r || !r->io || !r->io->desc)
		return 0LL;
	r_debug_attach (r->dbg, r->io->desc->fd);
	r_debug_map_sync (r->dbg);
	r_list_foreach (r->dbg->maps, iter, map) {
		if (!strcmp (file, map->name)) {
			return map->addr;
		}
	}
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
	if (line<2)
		printf ("Usage: r2 [-dDwntLqv] [-P patch] [-p prj] [-a arch] [-b bits] [-i file]\n"
			"          [-s addr] [-B blocksize] [-c cmd] [-e k=v] file|-|--|=\n");
	if (line != 1) printf (
		" --           Open radare2 on an empty file\n"
		" -            Equivalent of 'r2 malloc://512'\n"
		" =            Read file from stdin (use -i and -c to run cmds)\n"
		" -0           Print \\x00 after init and every command\n"
		" -a [arch]    set asm.arch\n"
		" -A           run 'aa' command to analyze all referenced code\n"
		" -b [bits]    set asm.bits\n"
		" -B [baddr]   set base address for PIE binaries\n"
		" -c 'cmd..'   execute radare command\n"
		" -C           file is host:port (alias for -c+=http://%%s/cmd/)\n"
		" -d           use 'file' as a program to debug\n"
		" -D [backend] enable debug mode (e cfg.debug=true)\n"
		" -e k=v       evaluate config var\n"
		" -f           block size = file size\n"
		" -h, -hh      show help message, -hh for long\n"
		" -i [file]    run script file\n"
		" -k [kernel]  set asm.os variable for asm and anal\n"
		" -l [lib]     load plugin file\n"
		" -L           list supported IO plugins\n"
		" -m [addr]    map file at given address\n"
		" -n, -nn      do not load RBin info (-nn only load bin structures)\n"
		" -N           do not load user settings and scripts\n"
		" -q           quiet mode (no prompt) and quit after -i\n"
		" -p [prj]     set project file\n"
		" -P [file]    apply rapatch file and quit\n"
		" -s [addr]    initial seek\n"
		" -S           start r2 in sandbox mode\n"
#if USE_THREADS
		" -t           load rabin2 info in thread\n"
#endif
		" -v, -V       show radare2 version (-V show lib versions)\n"
		" -w           open file in write mode\n"
		" -z, -zz      do not load strings or load them even in raw\n");
	if (line==2)
		printf (
		"Scripts:\n"
		" system   "R2_PREFIX"/share/radare2/radare2rc\n"
		" user     ~/.radare2rc ${RHOMEDIR}/radare2/radare2rc\n"
		" file     ${filename}.r2\n"
		"Plugins:\n"
		" plugins  "R2_PREFIX"/lib/radare2/last\n"
		" user     ~/.config/radare2/plugins\n"
		" LIBR_PLUGINS "R2_PREFIX"/lib/radare2/"R2_VERSION"\n"
		"Environment:\n"
		" RHOMEDIR     ~/.config/radare2\n" // TODO: rename to RHOME R2HOME?
		" RCFILE       ~/.radare2rc (user preferences, batch script)\n" // TOO GENERIC
		" MAGICPATH    "R_MAGIC_PATH"\n"
		" R_DEBUG      if defined, show error messages and crash signal\n"
		" VAPIDIR      path to extra vapi directory\n"
		);
	return 0;
}


static void list_io_plugins(RIO *io) {
	char str[4];
	struct list_head *pos;
	list_for_each_prev (pos, &io->io_list) {
		RIOList *il = list_entry (pos, RIOList, list);
		// read, write, debug, proxy
		str[0] = 'r';
		str[1] = il->plugin->write? 'w': '_';
		str[2] = il->plugin->isdbg? 'd': '_';
		str[3] = 0;
		printf ("%s  %-11s %s (%s)\n", str, il->plugin->name,
			il->plugin->desc, il->plugin->license);
	}
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
				if (th) r_th_lock_enter(th->user);
				nptr = strchr (ptr, '\n');
				if (nptr) *nptr = 0;
				r_core_cmd (&r, ptr, 0);
				if (nptr) ptr = nptr+1;
				if (th) r_th_lock_leave(th->user);
			} while (nptr);
		//r_core_cmd (&r, cmd, 0);
		r_str_free (rabin_cmd);
		rabin_cmd = NULL;
	}
	if (th) eprintf ("rabin2: done\n");
	return 0;
}
#endif

int main(int argc, char **argv, char **envp) {
#if USE_THREADS
	RThreadLock *lock = NULL;
	RThread *rabin_th = NULL;
#endif
	RListIter *iter;
	char *cmdn;
	RCoreFile *fh = NULL;
	const char *patchfile = NULL;
	const char *prj = NULL;
	//int threaded = R_FALSE;
	int debug = 0;
	int zflag = 0;
	int do_analysis = 0;
	int do_connect = 0;
	int fullfile = 0;
	int has_project = R_FALSE;
	int prefile = 0;
	int zerosep = 0;
	int help = 0;
	int run_anal = 1;
	int run_rc = 1;
 	int ret, i, c, perms = R_IO_READ;
	int sandbox = 0;
	ut64 baddr = 0;
	ut64 seek = UT64_MAX;
	char *pfile = NULL, *file = NULL;
	char *cmdfile[32];
	const char *debugbackend = "native";
	const char *asmarch = NULL;
	const char *asmos = NULL;
	const char *asmbits = NULL;
	ut64 mapaddr = 0LL;
	int quiet = R_FALSE;
	int is_gdb = R_FALSE;
	RList *cmds = r_list_new ();
	RList *evals = r_list_new ();
	int cmdfilei = 0;
	int va = 1; // set va = 0 to load physical offsets from rbin

	r_sys_set_environ (envp);

	if (r_sys_getenv ("R_DEBUG"))
		r_sys_crash_handler ("gdb --pid %d");

	if (argc<2) {
		r_list_free(cmds);
		r_list_free(evals);
		return main_help (1);
	}
	if (argc==2 && !strcmp (argv[1], "-p")) {
		char *path = r_str_home (R2_HOMEDIR"/projects/");
		DIR *d = r_sandbox_opendir (path);
		if (d) {
			for (;;) {
				struct dirent* de = readdir (d);
				if (!de) break;
				ret = strlen (de->d_name);
				if (!strcmp (".d", de->d_name+ret-2)) {
					// TODO:
					// do more checks to ensure it is a project
					// show project info (opened? file? ..?)
					printf ("%.*s\n", ret-2, de->d_name);
				}
			}
		}
		free (path);
		return 0;
	}
	r_core_init (&r);
	r_core_loadlibs (&r, R_CORE_LOADLIBS_ALL, NULL);

	// HACK TO PERMIT '#!/usr/bin/r2 - -i' hashbangs
	if (argc>1 && !strcmp (argv[1], "-")) {
		argv[1] = argv[0];
		prefile = 1;
		argc--;
		argv++;
	} else prefile = 0;

	while ((c = getopt (argc, argv, "0ACwfhm:e:nk:Ndqs:p:b:B:a:Lui:l:P:c:D:vVSz"
#if USE_THREADS
"t"
#endif
	))!=-1) {
		switch (c) {
			case '0':
				zerosep = R_TRUE;
				//r_config_set (r.config, "scr.color", "false");
				/* implicit -q */
				r_config_set (r.config, "scr.interactive", "false");
				r_config_set (r.config, "scr.prompt", "false");
				r_config_set (r.config, "scr.color", "false");
				quiet = R_TRUE;
				break;
			case 'a': asmarch = optarg; break;
			case 'z': zflag++; break;
			case 'A':
				do_analysis = R_TRUE;
				break;
			case 'b': asmbits = optarg; break;
			case 'B':
				baddr = r_num_math (r.num, optarg);
				va = 2;
				// hackaround. baddr=0: no laddr and -1 means baddr=0
				if (baddr==0)
					baddr = UT64_MAX;
				break;
			case 'c': r_list_append (cmds, optarg); break;
			case 'C':
				do_connect = R_TRUE;
				break;
#if DEBUGGER
			case 'd': debug = 1; break;
#else
			case 'd': eprintf ("Sorry. No compiler backend available.\n"); return 1;
#endif
			case 'D':
				debug = 2;
				debugbackend = optarg;
				break;
			case 'e': r_config_eval (r.config, optarg);
				  r_list_append (evals, optarg); break;
			case 'f': fullfile = 1; break;
			case 'h': help++; break;
			case 'i':
				if (cmdfilei+1 < (sizeof (cmdfile)/sizeof (*cmdfile)))
					cmdfile[cmdfilei++] = optarg;
				break;
			case 'k': asmos = optarg; break;
			case 'l': r_lib_open (r.lib, optarg); break;
			case 'L': list_io_plugins (r.io); return 0;
			case 'm': mapaddr = r_num_math (r.num, optarg); break;
			case 'n': run_anal --; break;
			case 'N': run_rc = 0; break;
			case 'p':
				if (*optarg == '-') {
					char *path, repath[128];
					snprintf (repath, sizeof (repath),
						R2_HOMEDIR"/projects/%s.d", optarg+1);
					path = r_str_home (repath);
					if (r_file_exists (path)) {
						if (r_file_rmrf (path) == R_FALSE) {
							eprintf ("Unable to recursively remove %s\n", path);
							free (path);
							return 1;
						}
						path [strlen (path)-2] = 0;
						if (r_file_rm (path) == R_FALSE) {
							eprintf ("Unable to remove %s\n", path);
							free (path);
							return 1;
						}
						free (path);
						return 0;
					}
					eprintf ("Can't find project '%s'\n", optarg+1);
					return 1;
				} else	r_config_set (r.config, "file.project", optarg);
				break;
			case 'P': patchfile = optarg; break;
			case 'q':
				r_config_set (r.config, "scr.interactive", "false");
				r_config_set (r.config, "scr.prompt", "false");
				quiet = R_TRUE;
				break;
			case 's': seek = r_num_math (r.num, optarg); break;
			case 'S': sandbox = 1; break;
#if USE_THREADS
			case 't':
				threaded = R_TRUE;
				break;
#endif
			case 'v': verify_version(0); return blob_version ("radare2");
			case 'V': return verify_version (1);
			case 'w': perms = R_IO_READ | R_IO_WRITE; break;
			default:
				r_list_free (evals);
				r_list_free (cmds);
				return 1;
		}
	}
	if (help>1) return main_help (2);
	else if (help) return main_help (0);

	// HACK TO PERMIT '#!/usr/bin/r2 - -i' hashbangs
	if (prefile) {
		optind = 1;
		argc = 2;
		argv[1] = "-";
	}

	//cverify_version (0);
	if (do_connect) {
		if (optind>= argc) {
			eprintf ("Missing URI for -C\n");
			return 1;
		}
		const char *uri = argv[optind];
		if (!strncmp (uri, "http://", 7))
			r_core_cmdf (&r, "=+%s", uri);
		else r_core_cmdf (&r, "=+http://%s/cmd/", argv[optind]);
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
			r_config_set_i (r.config, "io.va", 0);
			baddr = 0;
			break;
		case 2:
			r_config_set_i (r.config, "bin.laddr", baddr);
			break;
	}
// TODO: set io.va = 2 if -B
// -- means opening r2 without any file
	if (run_rc) {
		char *homerc = r_str_home (".radare2rc");
		if (homerc) {
			r_core_cmd_file (&r, homerc);
			free (homerc);
		}
		homerc = r_str_home ("/.config/radare2/radare2rc");
		if (homerc) {
			r_core_cmd_file (&r, homerc);
			free (homerc);
		}
		if (r_config_get_i (r.config, "file.analyze")) {
			r_core_cmd0 (&r, "aa");
		}
	}
	if (argv[optind] && !strcmp (argv[optind], "=")) {
		int sz;
		/* stdin/batch mode */
		ut8 *buf = (ut8 *)r_stdin_slurp (&sz);
		close (0);
		if (sz>0) {
			char path[1024];
			snprintf (path, sizeof (path)-1, "malloc://%d", sz);
			fh = r_core_file_open (&r, path, perms, mapaddr);
			if (fh) {
				r_io_write_at (r.io, 0, buf, sz);
				r_core_block_read (&r, 0);
				free (buf);
				// TODO: load rbin thing
			} else {
				eprintf ("Cannot open %s\n", path);
				return 1;
			}
		} else {
			eprintf ("Cannot slurp from stdin\n");
			return 1;
		}
	} else if (strcmp (argv[optind-1], "--")) {
		if (debug) {
			r_config_set (r.config, "search.in", "raw"); // implicit?
			r_config_set (r.config, "io.va", "false"); // implicit?
			r_config_set (r.config, "cfg.debug", "true");
			perms = R_IO_READ | R_IO_WRITE;
			if (optind>=argc) {
				eprintf ("No program given to -d\n");
				return 1;
			}
			if (debug == 2) {
				// autodetect backend with -D
				r_config_set (r.config, "dbg.backend", debugbackend);
				if (strcmp (debugbackend, "native")) {
					pfile = argv[optind++];
					perms = R_IO_READ; // XXX. should work with rw too
					debug = 1;
					fh = r_core_file_open (&r, pfile, perms, mapaddr);
/*
					if (fh) {
						r_core_bin_load (&r, pfile);
						r_debug_use (r.dbg, debugbackend);
					}
*/
				}
			} else {
				const char *f = argv[optind];
				char *ptr;
				is_gdb = (!memcmp (argv[optind], "gdb://", 6));
				if (!is_gdb) file = strdup ("dbg://");
				/* implicit ./ to make unix behave like windows */
				if (*f=='.' && f[1]=='/') {
					ptr = strdup (argv[optind]);
				} else if (*f!='/' && *f!='.' && r_file_exists (argv[optind])) {
					ptr = r_str_prefix (strdup (argv[optind]), "./");
				} else	ptr = r_file_path (argv[optind]);
				optind++;
				file = r_str_concat (file, ptr);
				if (optind <argc)
					file = r_str_concat (file, " ");
				while (optind < argc) {
					file = r_str_concat (file, argv[optind]);
					optind++;
					if (optind<argc)
						file = r_str_concat (file, " ");
				}
				{
					char *diskfile = strstr (file, "://");
					if (diskfile) {
						diskfile += 3;
					} else diskfile = file;
					fh = r_core_file_open (&r, file, perms, mapaddr);
					if (fh != NULL)
						r_debug_use (r.dbg, is_gdb? "gdb": debugbackend);
					/* load symbols when doing r2 -d ls */
					// NOTE: the baddr is redefined to support PIE/ASLR
					baddr = getBaddrFromDebugger (&r, diskfile);
					if (baddr) eprintf ("Using BADDR %llx\n", baddr);
					if (r_core_bin_load (&r, diskfile, baddr)) {
						RBinObject *obj = r_bin_get_object (r.bin);
						if (obj && obj->info)
							eprintf ("bits %d\n", obj->info->bits);
					}
				}
			}
		}

		if (!debug || debug==2) {
			if (optind<argc) {
				while (optind < argc) {
					pfile = argv[optind++];
					fh = r_core_file_open (&r, pfile, perms, mapaddr);
					if (perms & R_IO_WRITE) {
						if (!fh) {
							if (r_io_create (r.io, pfile, 0644, 0))
								fh = r_core_file_open (&r, pfile, perms, mapaddr);
							else eprintf ("r_io_create: Permission denied.\n");
						}
					}
					if (fh) {
						if (run_anal>0) {
#if USE_THREADS
							if (!rabin_th)
#endif
							{
								const char *filepath = NULL;
								if (debug) {
									// XXX: incorrect for PIE binaries
									filepath = file? strstr (file, "://"): NULL;
									filepath = filepath? filepath+3: pfile;
								}
								if (r.file && r.file->desc && r.file->desc->name)
									filepath = r.file->desc->name;

								/* Load rbin info from r2 dbg:// or r2 /bin/ls */
								/* the baddr should be set manually here */
								if (!r_core_bin_load (&r, filepath, baddr))
									r_config_set (r.config, "io.va", "false");
							}
						} else {
							if (run_anal<0) {
								// PoC -- must move -rk functionalitiy into rcore
								// this may be used with caution (r2 -nn $FILE)
								r_core_cmdf (&r, ".!rabin2 -rk '' '%s'", r.file->desc->name);
							}
						}
					}
				}
			} else {
				const char *prj = r_config_get (r.config, "file.project");
				if (prj && *prj) {
					pfile = r_core_project_info (&r, prj);
					if (pfile) fh = r_core_file_open (&r, pfile, perms, mapaddr);
					else	eprintf ("Cannot find project file\n");
				}
			}
		}
		if (!pfile) pfile = file;
		if (fh == NULL) {
			if (pfile && *pfile) {
				if (perms & R_IO_WRITE)
					eprintf ("Cannot open '%s' for writing.\n", pfile);
				else	eprintf ("Cannot open '%s'\n", pfile);
			} else	eprintf ("Missing file to open\n");
			return 1;
		}
		if (r.file == NULL) // no given file
			return 1;
		//if (!has_project && run_anal)
#if USE_THREADS
		if (run_anal>0 && threaded) {
			// XXX: if no rabin2 in path that may fail
			// TODO: pass -B 0 ? for pie bins?
			rabin_cmd = r_str_newf ("rabin2 -rSIeMzisR%s %s",
					(debug||r.io->va)?"":"p", r.file->desc->name);
			/* TODO: only load data if no project is used */
			lock = r_th_lock_new ();
			rabin_th = r_th_new (&rabin_delegate, lock, 0);
			// rabin_delegate (NULL);
		} // else eprintf ("Metadata loaded from 'file.project'\n");
#endif
		if (mapaddr)
			r_core_seek (&r, mapaddr, 1);

		r_list_foreach (evals, iter, cmdn) {
			r_config_eval (r.config, cmdn);
			r_cons_flush ();
		}

		has_project = r_core_project_open (&r, r_config_get (r.config, "file.project"));
#if 0
// Do not autodetect utf8 terminals to avoid problems on initial
// stdin buffer and some terminals that just hang (android/ios)
		if (!quiet && r_cons_is_utf8 ()) {
			r_config_set_i (r.config, "scr.utf8", R_TRUE);
		}
#endif
		if (asmarch) r_config_set (r.config, "asm.arch", asmarch);
		if (asmbits) r_config_set (r.config, "asm.bits", asmbits);
		if (asmos) r_config_set (r.config, "asm.os", asmos);

		(void)r_core_bin_update_arch_bits (&r);

		debug = r.file && r.file->desc && r.file->desc->plugin && \
			r.file->desc->plugin->isdbg;
		if (debug) {
			r_core_setup_debugger (&r, debugbackend);
		}

		if (!debug && r_flag_get (r.flags, "entry0"))
			r_core_cmd0 (&r, "s entry0");
		if (seek != UT64_MAX)
			r_core_seek (&r, seek, 1);

		if (fullfile) r_core_block_size (&r, r_io_desc_size (r.io, r.file->desc));

		r_core_seek (&r, r.offset, 1); // read current block

		/* check if file.sha1 has changed */
		if (!strstr (r.file->desc->uri, "://")) {
			const char *npath, *nsha1;
			char *path = strdup (r_config_get (r.config, "file.path"));
			char *sha1 = strdup (r_config_get (r.config, "file.sha1"));
			has_project = r_core_project_open (&r, r_config_get (r.config, "file.project"));
			if (has_project)
				r_config_set (r.config, "bin.strings", "false");
			if (r_core_hash_load (&r, r.file->desc->name) == R_FALSE)
				{} //eprintf ("WARNING: File hash not calculated\n");
			nsha1 = r_config_get (r.config, "file.sha1");
			npath = r_config_get (r.config, "file.path");
			if (sha1 && *sha1 && strcmp (sha1, nsha1))
				eprintf ("WARNING: file.sha1 change: %s => %s\n", sha1, nsha1);
			if (path && *path && strcmp (path, npath))
				eprintf ("WARNING: file.path change: %s => %s\n", path, npath);
			free (sha1);
			free (path);
		}
#if 1
		r_list_foreach (evals, iter, cmdn) {
			r_config_eval (r.config, cmdn);
			r_cons_flush ();
		}
		r_list_free (evals);
#endif
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
	if (do_analysis) {
		r_core_cmd0 (&r, "aa");
		r_cons_flush ();
	}
	/* run -i flags */
	cmdfile[cmdfilei] = 0;
	for (i=0; i<cmdfilei; i++) {
		if (!r_file_exists (cmdfile[i])) {
			eprintf ("Script '%s' not found.\n", cmdfile[i]);
			return 1;
		}
		ret = r_core_run_script (&r, cmdfile[i]);
		//ret = r_core_cmd_file (&r, cmdfile[i]);
		if (ret ==-2)
			eprintf ("Cannot open '%s'\n", cmdfile[i]);
		if (ret<0 || (ret==0 && quiet))
			return 0;
	}
/////
	r_list_foreach (cmds, iter, cmdn) {
		r_core_cmd0 (&r, cmdn);
		r_cons_flush ();
	}
	if ((cmdfile[0] || !r_list_empty (cmds)) && quiet)
		return 0;
	r_list_free (cmds);
/////
	if (r_config_get_i (r.config, "scr.prompt"))
		if (run_rc && r_config_get_i (r.config, "cfg.fortunes")) {
			r_core_cmd (&r, "fo", 0);
			r_cons_flush ();
		}
	if (sandbox)
		r_config_set (r.config, "cfg.sandbox", "true");
	if (quiet)
		r_config_set (r.config, "scr.wheel", "false");

	r.num->value = 0;
	if (patchfile) {
		char *data = r_file_slurp (patchfile, NULL);
		if (data) {
			r_core_patch (&r, data);
			r_core_seek (&r, 0, 1);
			free (data);
		} else eprintf ("Cannot open '%s'\n", patchfile);
	}
	if ((patchfile && !quiet) || !patchfile) {
		if (zerosep)
			r_cons_zero ();
		if (seek != UT64_MAX)
			r_core_seek (&r, seek, 1);

		// no flagspace selected by default the beginning
		r.flags->space_idx = -1;
		for (;;) {
			r.zerosep = zerosep;
#if USE_THREADS
			do {
				int err = r_core_prompt (&r, R_FALSE);
				if (err<1) {
					// handle ^D
					break;
				}
				if (lock) r_th_lock_enter (lock);
				/* -1 means invalid command, -2 means quit prompt loop */
				if ((ret = r_core_prompt_exec (&r))==-2)
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
			if (ret != -1 && r_config_get_i (r.config, "scr.interactive")) {
				if (debug) {
					if (r_cons_yesno ('y', "Do you want to quit? (Y/n)")) {
						if (r_cons_yesno ('y', "Do you want to kill the process? (Y/n)"))
							r_debug_kill (r.dbg, 0, R_FALSE, 9); // KILL
					} else continue;
				}
				prj = r_config_get (r.config, "file.project");
				if (prj && *prj && r_cons_yesno ('y', "Do you want to save the project? (Y/n)"))
					r_core_project_save (&r, prj);
			} else {
				// r_core_project_save (&r, prj);
				if (debug) {
					r_debug_kill (r.dbg, 0, R_FALSE, 9); // KILL
				}
			}
			break;
		}
	}
	// TODO: kill thread

	/* capture return value */
	ret = r.num->value;
	// not really needed, cause r_core_fini will close the file
	// and this fh may be come stale during the command
	// exectution.
	//r_core_file_close (&r, fh);
	r_core_fini (&r);
	r_cons_set_raw (0);
	free (file);
	return ret;
}
