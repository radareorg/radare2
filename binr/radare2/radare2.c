/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

#include <r_core.h>
//#include <r_th.h>
#include <r_io.h>
#include <stdio.h>
#include <getopt.h>

static struct r_core_t r;

static int main_help(int line) {
	printf ("Usage: radare2 [-dwnLuvV] [-p prj] [-s addr] [-b bsz] [-e k=v] [file]\n");
	if (!line) printf (
		" -d           use 'file' as a program to debug\n"
		" -w           open file in write mode\n"
		" -n           do not run ~/.radare2rc\n"
		" -v           nonverbose mode (no prompt)\n"
		" -f           block size = file size\n"
		" -p [prj]     set project file\n"
		" -s [addr]    initial seek\n"
		" -b [size]    initial block size\n"
		" -i [file]    run script file\n"
		" -V           show radare2 version\n"
		" -l [lib]     load plugin file\n"
		//" -t         load rabin2 info in thread\n"
		" -L           list supported IO plugins\n"
		" -u           unknown file size\n"
		" -e k=v       evaluate config var\n"
		"Environment:\n"
		" R_DEBUG      handle crash signal\n"
		" LIBR_PLUGINS path to plugins directory\n"
		" VAPIDIR      path to extra vapi directory\n"
		);
	return 0;
}

static int main_version() {
	printf ("radare2 "R2_VERSION" @ "R_SYS_OS"-"R_SYS_ENDIAN"-"R_SYS_ARCH"\n");
	return 0;
}

static int list_io_plugins(RIO *io) {
	struct list_head *pos;
	printf ("IO plugins:\n");
	list_for_each_prev(pos, &io->io_list) {
		struct r_io_list_t *il = list_entry(pos, struct r_io_list_t, list);
		printf("  %-10s %s\n", il->plugin->name, il->plugin->desc);
	}
	return 0;
}

// Load the binary information from rabin2
// TODO: use thread to load this, split contents line, per line and use global lock
#if 0
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
/*
	RThreadLock *lock = NULL;
	RThread *rabin_th = NULL;
*/
	RCoreFile *fh = NULL;
	//int threaded = R_FALSE;
	int has_project = R_FALSE;
 	int ret, c, perms = R_IO_READ;
	int run_rc = 1;
	int debug = 0;
	int fullfile = 0;
	ut32 bsize = 0;
	ut64 seek = 0;
	char file[1024];
	char *cmdfile = NULL;
	int is_gdb = R_FALSE;

	if (r_sys_getenv ("R_DEBUG"))
		r_sys_crash_handler ("gdb --pid %d");

	if (argc<2)
		return main_help (1);
	r_core_init (&r);

	while ((c = getopt (argc, argv, "wfhe:ndvVs:p:b:Lui:l:"))!=-1) {
		switch (c) {
#if 0
		case 't':
			threaded = R_TRUE;
			break;
#endif
		case 'v':
			r_config_set (r.config, "scr.prompt", "false");
			break;
		case 'p':
			r_config_set (r.config, "file.project", optarg);
			break;
		case 'i':
			cmdfile = optarg;
			break;
		case 'l':
			r_lib_open (r.lib, optarg);
			break;
		case 'd':
			debug = 1;
			break;
		case 'e':
			r_config_eval (r.config, optarg);
			break;
		case 'h':
			return main_help (0);
		case 'f':
			fullfile = 1;
			break;
		case 'n':
			run_rc = 0;
			break;
		case 'V':
			return main_version ();
		case 'w':
			perms = R_IO_READ | R_IO_WRITE;
			break;
		case 'b':
			bsize = (ut32) r_num_math (r.num, optarg);
			break;
		case 's':
			seek = r_num_math (r.num, optarg);
			break;
		case 'L':
			list_io_plugins (r.io);
			return 0;
		case 'u':
			eprintf ("TODO\n");
			break;
		default:
			return 1;
		}
	}

	if (debug) {
		r_config_set (r.config, "io.va", "false"); // implicit?
		r_config_set (r.config, "cfg.debug", "true");
		is_gdb = (!memcmp (argv[optind], "gdb://", 6));
		if (!is_gdb)
			strcpy (file, "dbg://");
		else *file = 0;
		if (optind < argc) {
			char *ptr = r_file_path (argv[optind]);
			if (ptr) {
				strcat (file, ptr);
				free (ptr);
				optind++;
			}
		}
		while (optind < argc) {
			strcat (file, argv[optind]);
			strcat (file, " ");
			if (++optind != argc)
				strcat (file, " ");
		}

		fh = r_core_file_open (&r, file, perms, 0LL);
		if (fh != NULL) {
			//const char *arch = r_config_get (r.config, "asm.arch");
			// TODO: move into if (debug) ..
			if (is_gdb) r_debug_use (r.dbg, "gdb");
			else r_debug_use (r.dbg, "native");
		}
	} else {
		if (optind<argc) {
			while (optind < argc)
				fh = r_core_file_open (&r, argv[optind++], perms, 0);
		} else {
			const char *prj = r_config_get (r.config, "file.project");
			if (prj && *prj) {
				char *file = r_core_project_info (&r, prj);
				if (file) fh = r_core_file_open (&r, file, perms, 0);
				else eprintf ("No file\n");
			}
		}
	}

	if (fh == NULL) {
		eprintf ("Cannot open file.\n");
		return 1;
	}
	if (r.file == NULL) // no given file
		return 1;
	//if (!has_project && run_rc) {
#if 0
	if (run_rc) {
		rabin_cmd = r_str_dup_printf ("rabin2 -rSIeMzisR%s %s",
			(debug||r.io->va)?"v":"", r.file->filename);
		if (threaded) {
			/* TODO: only load data if no project is used */
			lock = r_th_lock_new ();
			rabin_th = r_th_new (&rabin_delegate, lock, 0);
		} else rabin_delegate (NULL);
	} else eprintf ("Metadata loaded from 'file.project'\n");
#endif

	if (run_rc) {
		char *homerc = r_str_home (".radare2rc");
		r_core_bin_load (&r, NULL);
		if (homerc) {
			r_core_cmd_file (&r, homerc);
			free (homerc);
		}
	}

	if (debug) {
		int *p = r.file->fd->data;
		int pid = *p; // 1st element in debugger's struct must be int
		r_core_cmd (&r, "e io.ffio=true", 0);
		if (is_gdb) r_core_cmd (&r, "dh gdb", 0);
		else r_core_cmd (&r, "dh native", 0);
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

	if (run_rc && r_config_get_i (r.config, "cfg.fortunes")) {
		r_core_cmd (&r, "fo", 0);
		r_cons_flush ();
	}
	r_core_seek (&r, r.offset, 1); // read current block

	/* XXX: find better solution.. files > 10MB does not hash */
	#define SLURP_LIMIT (10*1024*1024)
	/* check if file.sha1 has changed */
	if (r.file->size < SLURP_LIMIT) // TODO: configure this in cfg.hashlimit // 
	if (!strstr (r.file->uri, "://")) {
		const char *npath, *nsha1;
		char *path = strdup (r_config_get (r.config, "file.path"));
		char *sha1 = strdup (r_config_get (r.config, "file.sha1"));
		char *cmd = r_str_dup_printf (".!rahash2 -r %s", r.file->filename);
		has_project = r_core_project_open (&r, r_config_get (r.config, "file.project"));
		r_core_cmd (&r, cmd, 0);
		nsha1 = r_config_get (r.config, "file.sha1");
		npath = r_config_get (r.config, "file.path");
		if (sha1 && *sha1 && strcmp (sha1, nsha1))
			eprintf ("WARNING: file.sha1 change: %s => %s\n", sha1, nsha1);
		if (path && *path && strcmp (path, npath))
			eprintf ("WARNING: file.path change: %s => %s\n", path, npath);
		r_str_free (cmd);
		free (sha1);
		free (path);
	}

	if (cmdfile)
		r_core_cmd_file (&r, cmdfile);

	for (;;) {
		do { 
			if (r_core_prompt (&r, R_FALSE)<1)
				break;
//			if (lock) r_th_lock_enter (lock);
			if ((ret = r_core_prompt_exec (&r))==-1)
				eprintf ("Invalid command\n");
/*			if (lock) r_th_lock_leave (lock);
			if (rabin_th && !r_th_wait_async (rabin_th)) {
				eprintf ("rabin thread end \n");
				r_th_free (rabin_th);
				r_th_lock_free (lock);
				lock = NULL;
				rabin_th = NULL;
			}
*/
		} while (ret != R_CORE_CMD_EXIT);

		if (debug) {
			if (r_cons_yesno ('y', "Do you want to quit? (Y/n)")) {
				if (r_cons_yesno ('y', "Do you want to kill the process? (Y/n)"))
					r_debug_kill (r.dbg, R_FALSE, 9); // KILL
			} else continue;
		}
		const char *prj = r_config_get (r.config, "file.project");
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
