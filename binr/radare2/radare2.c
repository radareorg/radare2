/* radare - LGPL - Copyright 2009-2012 - pancake */

#define USE_THREADS 1

#include <r_core.h>
#include <r_io.h>
#include <stdio.h>
#include <getopt.c>

#if USE_THREADS
#include <r_th.h>
static char *rabin_cmd = NULL;
static int threaded = 0;
#endif
static struct r_core_t r;

static int main_help(int line) {
	if (line<2)
		printf ("Usage: r2 [-dDwntLqv] [-P patch] [-p prj] [-a arch] [-b bits] [-i file]\n"
			"          [-s addr] [-B blocksize] [-c cmd] [-e k=v] [file]\n");
	if (line != 1) printf (
		" -a [arch]    set asm.arch eval var\n"
		" -b [bits]    set asm.bits eval var\n"
		" -B [size]    initial block size\n"
		" -c 'cmd..'   execute radare command\n"
		" -d           use 'file' as a program to debug\n"
		" -D [backend] enable debug mode (e cfg.debug=true)\n"
		" -e k=v       evaluate config var\n"
		" -f           block size = file size\n"
		" -i [file]    run script file\n"
		" -l [lib]     load plugin file\n"
		" -L           list supported IO plugins\n"
		" -n           disable analysis\n"
		" -N           disable user settings\n"
		" -q           quite mode (no prompt) and quit after -i\n"
		" -p [prj]     set project file\n"
		" -P [file]    apply rapatch file and quit\n"
		" -s [addr]    initial seek\n"
		" -m [addr]    map file at given address\n"
#if USE_THREADS
		" -t           load rabin2 info in thread\n"
#endif
		" -v           show radare2 version\n"
		" -w           open file in write mode\n"
		" -h, -hh      show help message, -hh for long\n");
	if (line==2)
		printf (
		"Files:\n"
		" RCFILE       ~/.radare2rc (user preferences, batch script)\n"
		" MAGICPATH    "R_MAGIC_PATH"\n"
		"Environment:\n"
		" R_DEBUG      if defined, show error messages and crash signal\n"
		" LIBR_PLUGINS path to plugins directory\n"
		" VAPIDIR      path to extra vapi directory\n"
		);
	return 0;
}

static int main_version() {
	printf ("radare2 "R2_VERSION" @ "R_SYS_OS"-"R_SYS_ENDIAN"-"R_SYS_ARCH"-%d build "R2_BIRTH"\n", R_SYS_BITS&8?64:32);
	return 0;
}

static void list_io_plugins(RIO *io) {
	struct list_head *pos;
	list_for_each_prev(pos, &io->io_list) {
		struct r_io_list_t *il = list_entry(pos, struct r_io_list_t, list);
		printf (" %-10s %s\n", il->plugin->name, il->plugin->desc);
	}
}

// Load the binary information from rabin2
// TODO: use thread to load this, split contents line, per line and use global lock
#if USE_THREADS
static int rabin_delegate(RThread *th) {
	if (rabin_cmd && r_file_exist (r.file->filename)) {
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

int main(int argc, char **argv) {
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
	int has_project = R_FALSE;
 	int ret, i, c, perms = R_IO_READ;
	int run_anal = 1;
	int run_rc = 1;
	int help = 0;
	int debug = 0;
	int fullfile = 0;
	ut32 bsize = 0;
	ut64 seek = 0;
	char file[4096];
	char *cmdfile[32];
	const char *debugbackend = "native";
	const char *asmarch = NULL;
	const char *asmbits = NULL;
	ut64 mapaddr = 0LL;
	int quite = R_FALSE;
	int is_gdb = R_FALSE;
	RList *cmds = r_list_new ();
	int cmdfilei = 0;
	
	if (r_sys_getenv ("R_DEBUG"))
		r_sys_crash_handler ("gdb --pid %d");

	if (argc<2)
		return main_help (1);
	r_core_init (&r);

	while ((c = getopt (argc, argv, "wfhm:e:nNdqvs:p:b:B:a:Lui:l:P:c:D:"
#if USE_THREADS
"t"
#endif
			))!=-1) {
		switch (c) {
#if USE_THREADS
		case 't':
			threaded = R_TRUE;
			break;
#endif
		case 'D':
			debug = 2;
			debugbackend = optarg;
			break;
		case 'm': mapaddr = r_num_math (r.num, optarg); break;
		case 'q':
			r_config_set (r.config, "scr.prompt", "false");
			quite = R_TRUE;
			break;
		case 'p': r_config_set (r.config, "file.project", optarg); break;
		case 'P': patchfile = optarg; break;
		case 'c': r_list_append (cmds, optarg); break;
		case 'i': cmdfile[cmdfilei++] = optarg; break;
		case 'l': r_lib_open (r.lib, optarg); break;
		case 'd': debug = 1; break;
		case 'e': r_config_eval (r.config, optarg); break;
		case 'H':
		case 'h': help++; break;
		case 'f': fullfile = 1; break;
		case 'n': run_anal = 0; break;
		case 'N': run_rc = 0; break;
		case 'v': return main_version ();
		case 'w': perms = R_IO_READ | R_IO_WRITE; break;
		case 'a': asmarch = optarg; break;
		case 'b': asmbits = optarg; break;
		case 'B': bsize = (ut32) r_num_math (r.num, optarg); break;
		case 's': seek = r_num_math (r.num, optarg); break;
		case 'L': list_io_plugins (r.io); return 0;
		default: return 1;
		}
	}
	if (help>1) return main_help (2);
	else if (help) return main_help (0);

	// DUP
	if (asmarch) r_config_set (r.config, "asm.arch", asmarch);
	if (asmbits) r_config_set (r.config, "asm.bits", asmbits);

	if (debug) {
		int filelen = 0;
		r_config_set (r.config, "io.va", "false"); // implicit?
		r_config_set (r.config, "cfg.debug", "true");
		if (optind>=argc) {
			eprintf ("No program given to -d\n");
			return 1;
		}
		if (debug == 2) {
			// autodetect backend with -D
			r_config_set (r.config, "dbg.backend", debugbackend);
		} else {
			is_gdb = (!memcmp (argv[optind], "gdb://", 6));
			if (is_gdb) *file = 0;
			else memcpy (file, "dbg://", 7);
			if (optind < argc) {
				char *ptr = r_file_path (argv[optind]);
				if (ptr) {
					strcat (file, ptr);
					free (ptr);
					optind++;
				}
			}
			while (optind < argc) {
				int largv = strlen (argv[optind]);
				if (filelen+largv+1>=sizeof (file)) {
					eprintf ("Too long arguments\n");
					return 1;
				}
				memcpy (file+filelen, argv[optind], largv);
				filelen += largv;
				if (filelen+6>=sizeof (file)) {
					eprintf ("Too long arguments\n");
					return 1;
				}
				memcpy (file+filelen, " ", 2);
				filelen += 2;
				if (++optind != argc) {
					memcpy (file+filelen, " ", 2);
					filelen += 2;
				}
			}

			fh = r_core_file_open (&r, file, perms, mapaddr);
			if (fh != NULL) {
				//const char *arch = r_config_get (r.config, "asm.arch");
				// TODO: move into if (debug) ..
				if (is_gdb) r_debug_use (r.dbg, "gdb");
				else r_debug_use (r.dbg, debugbackend);
			}
		}
	}

	if (!debug || debug==2) {
		if (optind<argc) {
			while (optind < argc) {
				const char *file = argv[optind++];
				fh = r_core_file_open (&r, file, perms, mapaddr);
				if (perms & R_IO_WRITE) {
					if (!fh) {
						r_io_create (r.io, file, 0644, 0);
						fh = r_core_file_open (&r, file, perms, mapaddr);
					}
				}
			}
		} else {
			const char *prj = r_config_get (r.config, "file.project");
			if (prj && *prj) {
				char *file = r_core_project_info (&r, prj);
				if (file) fh = r_core_file_open (&r, file, perms, mapaddr);
				else eprintf ("No file\n");
			}
		}
	}

	/* execute -c commands */
	if (fh == NULL) {
		if (perms & R_IO_WRITE)
			eprintf ("Cannot open file for writing.\n");
		else eprintf ("Cannot open file.\n");
		return 1;
	}
	if (r.file == NULL) // no given file
		return 1;
	//if (!has_project && run_anal) {
#if USE_THREADS
	if (run_anal) {
		if (threaded) {
			rabin_cmd = r_str_dup_printf ("rabin2 -rSIeMzisR%s %s",
					(debug||r.io->va)?"v":"", r.file->filename);
			/* TODO: only load data if no project is used */
			lock = r_th_lock_new ();
			rabin_th = r_th_new (&rabin_delegate, lock, 0);
		} //else rabin_delegate (NULL);
	} // else eprintf ("Metadata loaded from 'file.project'\n");
#endif

	has_project = r_core_project_open (&r, r_config_get (r.config, "file.project"));
	if (run_anal) {
#if USE_THREADS
		if (!rabin_th)	
#endif
			if (!r_core_bin_load (&r, NULL))
				r_config_set (r.config, "io.va", "false");
	}
	if (run_rc) {
		char *homerc = r_str_home (".radare2rc");
		if (homerc) {
			r_core_cmd_file (&r, homerc);
			free (homerc);
		}
	}
	if (asmarch) r_config_set (r.config, "asm.arch", asmarch);
	if (asmbits) r_config_set (r.config, "asm.bits", asmbits);

	if (debug) {
		int pid, *p = r.file->fd->data;
		if (!p) {
			eprintf ("Invalid debug io\n");
			return 1;
		}
		pid = *p; // 1st element in debugger's struct must be int
		r_core_cmd (&r, "e io.ffio=true", 0);
		if (is_gdb) r_core_cmd (&r, "dh gdb", 0);
		else r_core_cmdf (&r, "dh %s", debugbackend);
		r_core_cmdf (&r, "dpa %d", pid);
		r_core_cmdf (&r, "dp=%d", pid);
		r_core_cmd (&r, ".dr*", 0);
		/* honor dbg.bep */
		{
			const char *bep = r_config_get (r.config, "dbg.bep");
			if (bep) {
				// TODO: add support for init, fini, ..
				// TODO: maybe use "dcu %s".printf (bep);
				if (!strcmp (bep, "loader")) {
					/* do nothing here */
				} else
				if (!strcmp (bep, "main")) {
					r_core_cmd (&r, "dcu main", 0);
				} else
				if (!strcmp (bep, "entry")) {
					r_core_cmd (&r, "dcu entry0", 0);
				}
			}
		}
		r_core_cmd (&r, "sr pc", 0);
		r_config_set (r.config, "cmd.prompt", ".dr*");
		r_config_set (r.config, "cmd.vprompt", ".dr*");
	}

	if (seek)
		r_core_seek (&r, seek, 1);

	if (fullfile) r_core_block_size (&r, r.file->size);
	else if (bsize) r_core_block_size (&r, bsize);

	if (r_config_get_i (r.config, "scr.prompt"))
	if (run_rc && r_config_get_i (r.config, "cfg.fortunes")) {
		r_core_cmd (&r, "fo", 0);
		r_cons_flush ();
	}
	r_core_seek (&r, r.offset, 1); // read current block

	/* check if file.sha1 has changed */
	if (!strstr (r.file->uri, "://")) {
		const char *npath, *nsha1;
		char *path = strdup (r_config_get (r.config, "file.path"));
		char *sha1 = strdup (r_config_get (r.config, "file.sha1"));
		has_project = r_core_project_open (&r, r_config_get (r.config, "file.project"));
		if (has_project)
			r_config_set (r.config, "bin.strings", "false");
		if (r_core_hash_load (&r, r.file->filename) == R_FALSE)
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

	/* run -i and -c flags */
	cmdfile[cmdfilei] = 0;
	for (i=0; i<cmdfilei; i++) {
		int ret = r_core_cmd_file (&r, cmdfile[i]);
		if (ret==-1 || (ret==0 &&quite))
			return 0;
	}
	r_list_foreach (cmds, iter, cmdn) {
		r_core_cmd0 (&r, cmdn);
		r_cons_flush ();
	}
	if ((cmdfile[0] || !r_list_empty (cmds)) && quite)
		return 0;
	r_list_free (cmds);

	if (patchfile) {
		r_core_patch (&r, patchfile);
	} else
	for (;;) {
#if USE_THREADS
		do { 
			if (r_core_prompt (&r, R_FALSE)<1)
				break;
			if (lock) r_th_lock_enter (lock);
			if ((ret = r_core_prompt_exec (&r))==-1)
				eprintf ("Invalid command\n");
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

		if (debug) {
			if (r_cons_yesno ('y', "Do you want to quit? (Y/n)")) {
				if (r_cons_yesno ('y', "Do you want to kill the process? (Y/n)"))
					r_debug_kill (r.dbg, R_FALSE, 9); // KILL
			} else continue;
		}
		prj = r_config_get (r.config, "file.project");
		if (prj && *prj && r_cons_yesno ('y', "Do you want to save the project? (Y/n)"))
			r_core_project_save (&r, prj);
		break;
	}
	// TODO: kill thread

	/* capture return value */
	ret = r.num->value;
	r_core_file_close (&r, fh);
	return ret;
}
