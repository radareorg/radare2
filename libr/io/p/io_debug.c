/* radare - LGPL - Copyright 2007-2017 - pancake */

#include <errno.h>
#include <r_io.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_debug.h> /* only used for BSD PTRACE redefinitions */
#include <string.h>

#define USE_RARUN 0

#if __linux__ ||  __APPLE__ || __WINDOWS__ || __NetBSD__ || __KFBSD__ || __OpenBSD__
#define DEBUGGER_SUPPORTED 1
#else
#define DEBUGGER_SUPPORTED 0
#endif

#if DEBUGGER && DEBUGGER_SUPPORTED
#define MAGIC_EXIT 123

#include <signal.h>
#if __UNIX__
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#endif

#if __APPLE__
#if !__POWERPC__
#include <spawn.h>
#endif
#include <sys/types.h>
#include <sys/wait.h>
#include <mach/exception_types.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_traps.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach/vm_map.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#endif


static void trace_me ();

/*
 * Creates a new process and returns the result:
 * -1 : error
 *  0 : ok
 */
#if __WINDOWS__
#include <windows.h>
#include <tlhelp32.h>
#include <winbase.h>
#include <psapi.h>

typedef struct {
	HANDLE hnd;
	ut64 winbase;
} RIOW32;

typedef struct {
	int pid;
	int tid;
	ut64 winbase;
	PROCESS_INFORMATION pi;
} RIOW32Dbg;

static ut64 winbase;	//HACK
static int wintid;

static int setup_tokens() {
	HANDLE tok = NULL;
	TOKEN_PRIVILEGES tp;
	DWORD err = -1;

	if (!OpenProcessToken (GetCurrentProcess (), TOKEN_ADJUST_PRIVILEGES, &tok)) {
		goto err_enable;
	}
	tp.PrivilegeCount = 1;
	if (!LookupPrivilegeValue (NULL,  SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
		goto err_enable;
	}
	// tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
	tp.Privileges[0].Attributes = 0; //SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges (tok, 0, &tp, sizeof (tp), NULL, NULL)) {
		goto err_enable;
	}
	err = 0;
err_enable:
	if (tok) {
		CloseHandle (tok);
	}
	if (err) {
		r_sys_perror ("setup_tokens");
	}
	return err;
}

static int fork_and_ptraceme(RIO *io, int bits, const char *cmd) {
	PROCESS_INFORMATION pi;
	STARTUPINFO si = { 0 } ;
	DEBUG_EVENT de;
	int pid, tid;
	HANDLE th = INVALID_HANDLE_VALUE;
	if (!*cmd) {
		return -1;
	}
	setup_tokens ();
	char *_cmd = io->args ? r_str_appendf (strdup (cmd), " %s", io->args) :
		strdup (cmd);
	char **argv = r_str_argv (_cmd, NULL);
	// We need to build a command line with quoted argument and escaped quotes
	int cmd_len = 0;
	int i = 0;

	si.cb = sizeof (si);
	while (argv[i]) {
		char *current = argv[i];
		int quote_count = 0;
		while ((current = strchr (current, '"'))) {
			quote_count ++;
		}
		cmd_len += strlen (argv[i]);
		cmd_len += quote_count; // The quotes will add one backslash each
		cmd_len += 2; // Add two enclosing quotes;
		i++;
	}
	cmd_len += i-1; // Add argc-1 spaces

	char *cmdline = malloc ((cmd_len + 1) * sizeof (char));
	int cmd_i = 0; // Next character to write in cmdline
	i = 0;
	while (argv[i]) {
		if (i != 0) {
			cmdline[cmd_i++] = ' ';
		}
		cmdline[cmd_i++] = '"';

		int arg_i = 0; // Index of current character in orginal argument
		while (argv[i][arg_i]) {
			char c = argv[i][arg_i];
			if (c == '"') {
				cmdline[cmd_i++] = '\\';
			}
			cmdline[cmd_i++] = c;
			arg_i++;
		}

		cmdline[cmd_i++] = '"';
		i++;
	}
	cmdline[cmd_i] = '\0';

	LPTSTR appname_ = r_sys_conv_utf8_to_utf16 (argv[0]);
	LPTSTR cmdline_ = r_sys_conv_utf8_to_utf16 (cmdline);
	if (!CreateProcess (appname_, cmdline_, NULL, NULL, FALSE,
						 CREATE_NEW_CONSOLE | DEBUG_ONLY_THIS_PROCESS,
						 NULL, NULL, &si, &pi)) {
		r_sys_perror ("fork_and_ptraceme/CreateProcess");
		free (appname_);
		free (cmdline_);
		return -1;
	}
	free (appname_);
	free (cmdline_);
	free (cmdline);
	r_str_argv_free (argv);
	/* get process id and thread id */
	pid = pi.dwProcessId;
	tid = pi.dwThreadId;

	/* catch create process event */
	if (!WaitForDebugEvent (&de, 10000)) goto err_fork;

	/* check if is a create process debug event */
	if (de.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT) {
		eprintf ("exception code 0x%04x\n", (ut32)de.dwDebugEventCode);
		goto err_fork;
	}

	if (th != INVALID_HANDLE_VALUE) {
		CloseHandle (th);
	}
	eprintf ("Spawned new process with pid %d, tid = %d\n", pid, tid);
	winbase = (ut64)de.u.CreateProcessInfo.lpBaseOfImage;
	wintid = tid;
	return pid;

err_fork:
	eprintf ("ERRFORK\n");
	TerminateProcess (pi.hProcess, 1);
	if (th != INVALID_HANDLE_VALUE) CloseHandle (th);
	return -1;
}
#else // windows

#if (__APPLE__ && __POWERPC__) || !__APPLE__
#if __APPLE__ || __BSD__
static void inferior_abort_handler(int pid) {
	eprintf ("Inferior received signal SIGABRT. Executing BKPT.\n");
}
#endif

// UNUSED
static void trace_me () {
#if __APPLE__
	signal (SIGTRAP, SIG_IGN); //NEED BY STEP
#endif
#if __APPLE__ || __BSD__
	/* we can probably remove this #if..as long as PT_TRACE_ME is redefined for OSX in r_debug.h */
	signal (SIGABRT, inferior_abort_handler);
	if (ptrace (PT_TRACE_ME, 0, 0, 0) != 0) {
		r_sys_perror ("ptrace-traceme");
	}
#else
	if (ptrace (PTRACE_TRACEME, 0, NULL, NULL) != 0) {
		r_sys_perror ("ptrace-traceme");
		exit (MAGIC_EXIT);
	}
#endif
}
#endif

void handle_posix_error(int err) {
	switch (err) {
	case 0:
		// eprintf ("Success\n");
		break;
	case 22:
		eprintf ("posix_spawnp: Invalid argument\n");
		break;
	case 86:
		eprintf ("Unsupported architecture. Please specify -b 32\n");
		break;
	default:
		eprintf ("posix_spawnp: unknown error %d\n", err);
		perror ("posix_spawnp");
		break;
	}
}

static RRunProfile* _get_run_profile(RIO *io, int bits, char **argv) {
	char *expr = NULL;
	int i;
	RRunProfile *rp = r_run_new (NULL);
	if (!rp) {
		return NULL;
	}
	for (i = 0; argv[i]; i++) {
		rp->_args[i] = argv[i];
	}
	rp->_args[i] = NULL;
	if (!argv[0]) {
		r_run_free (rp);
		return NULL;
	}
	rp->_program = strdup (argv[0]);

	rp->_dodebug = true;
	if (io->runprofile && *io->runprofile) {
		if (!r_run_parsefile (rp, io->runprofile)) {
			eprintf ("Can't find profile '%s'\n", io->runprofile);
			r_run_free (rp);
			return NULL;
		}
		if (strstr (io->runprofile, R_SYS_DIR ".rarun2.")) {
			(void)r_file_rm (io->runprofile);
		}
	}
	if (bits == 64) {
		r_run_parseline (rp, expr=strdup ("bits=64"));
	} else if (bits == 32) {
		r_run_parseline (rp, expr=strdup ("bits=32"));
	}
	free (expr);
	if (r_run_config_env (rp)) {
		eprintf ("Can't config the environment.\n");
		r_run_free (rp);
		return NULL;
	}
	return rp;
}

#if __APPLE__ && !__POWERPC__

static void handle_redirection(char *path, int flag, posix_spawn_file_actions_t *fileActions, int fd) {
	int mode = S_IRUSR | S_IWUSR;
	posix_spawn_file_actions_addopen (fileActions, fd, path, flag, mode);
}

static void handle_posix_redirection(RRunProfile *rp, posix_spawn_file_actions_t *fileActions) {
	int flag = 0;
	if (rp->_stdin) {
		flag |= O_RDONLY;
		handle_redirection (rp->_stdin, flag, fileActions, STDIN_FILENO);
	}
	if (rp->_stdout) {
		flag |= O_WRONLY;
		handle_redirection (rp->_stdout, flag, fileActions, STDOUT_FILENO);
	}
	if (rp->_stderr) {
		flag |= O_WRONLY;
		handle_redirection (rp->_stderr, flag, fileActions, STDERR_FILENO);
	}
}

// __UNIX__ (not windows)
static int fork_and_ptraceme_for_mac(RIO *io, int bits, const char *cmd) {
	bool runprofile = io->runprofile && *(io->runprofile);
	pid_t p = -1;
	char **argv;
	posix_spawn_file_actions_t fileActions;
	ut32 ps_flags = POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK;
	sigset_t no_signals;
	sigset_t all_signals;
	size_t copied = 1;
	cpu_type_t cpu = CPU_TYPE_ANY;
	posix_spawnattr_t attr = {0};
	posix_spawnattr_init (&attr);

	sigemptyset (&no_signals);
	sigfillset (&all_signals);
	posix_spawnattr_setsigmask (&attr, &no_signals);
	posix_spawnattr_setsigdefault (&attr, &all_signals);

	posix_spawn_file_actions_init (&fileActions);
	posix_spawn_file_actions_addinherit_np (&fileActions, STDIN_FILENO);
	posix_spawn_file_actions_addinherit_np (&fileActions, STDOUT_FILENO);
	posix_spawn_file_actions_addinherit_np (&fileActions, STDERR_FILENO);

	ps_flags |= POSIX_SPAWN_CLOEXEC_DEFAULT;
	ps_flags |= POSIX_SPAWN_START_SUSPENDED;
#define _POSIX_SPAWN_DISABLE_ASLR 0x0100
	if (!runprofile) {
		int ret, useASLR = io->aslr;
		char *_cmd = io->args
			? r_str_appendf (strdup (cmd), " %s", io->args)
			: strdup (cmd);
		argv = r_str_argv (_cmd, NULL);
		if (!argv) {
			free (_cmd);
			return -1;
		}
		if (!*argv) {
			r_str_argv_free (argv);
			free (_cmd);
			eprintf ("Invalid execvp\n");
			return -1;
		}
		if (useASLR != -1) {
			if (!useASLR) {
				ps_flags |= _POSIX_SPAWN_DISABLE_ASLR;
			}
		}
		(void)posix_spawnattr_setflags (&attr, ps_flags);
#if __x86_64__
		if (bits == 32) {
			cpu = CPU_TYPE_I386;
			// cpu |= CPU_ARCH_ABI64;
		}
#endif
		posix_spawnattr_setbinpref_np (&attr, 1, &cpu, &copied);
		{
			char *dst = r_file_readlink (argv[0]);
			if (dst) {
				argv[0] = dst;
			}
		}
		// XXX: this is a workaround to fix spawning programs with spaces in path
		if (strstr (argv[0], "\\ ")) {
			argv[0] = r_str_replace (argv[0], "\\ ", " ", true);
		}

		ret = posix_spawnp (&p, argv[0], &fileActions, &attr, argv, NULL);
		handle_posix_error (ret);
		posix_spawn_file_actions_destroy (&fileActions);
		r_str_argv_free (argv);
		free (_cmd);
		return p;
	}
	int ret;
	argv = r_str_argv (cmd, NULL);
	if (!argv) {
		posix_spawn_file_actions_destroy (&fileActions);
		return -1;
	}
	RRunProfile *rp = _get_run_profile (io, bits, argv);
	if (!rp) {
		r_str_argv_free (argv);
		posix_spawn_file_actions_destroy (&fileActions);
		return -1;
	}
	handle_posix_redirection (rp, &fileActions);
	if (rp->_args[0]) {
		if (!rp->_aslr) {
			ps_flags |= _POSIX_SPAWN_DISABLE_ASLR;
		}
#if __x86_64__
		if (rp->_bits == 32) {
			cpu = CPU_TYPE_I386;
		}
#endif
		(void)posix_spawnattr_setflags (&attr, ps_flags);
		posix_spawnattr_setbinpref_np (&attr, 1, &cpu, &copied);
		ret = posix_spawnp (&p, rp->_args[0], &fileActions, &attr, rp->_args, NULL);
		handle_posix_error (ret);
	}
	r_str_argv_free (argv);
	r_run_free (rp);
	posix_spawn_file_actions_destroy (&fileActions);
	return p; // -1 ?
}
#endif

static char *get_and_escape_path (char *str)
{
	char *path_bin = strdup (str);
	char *final = NULL;

	if (path_bin) {
		char *p = (char*) r_str_lchr (str, '/');
		char *pp = (char*) r_str_tok (p, ' ', -1);
		char *args;

		if (!pp) {
			// There is nothing more to parse
			free (path_bin);
			return str;
		}

		path_bin[pp - str] = '\0';
		if (strstr (path_bin, "\\ ")) {
		        path_bin = r_str_replace (path_bin, "\\ ", " ", true);
		}
		args = path_bin + (pp - str) + 1;

		char *path_bin_escaped = r_str_arg_escape (path_bin);
		int len = strlen (path_bin_escaped);

		path_bin_escaped[len] = ' ';
		path_bin_escaped[len + 1] = '\0';

		final = r_str_append (path_bin_escaped, args);
		free (path_bin);
       }

       return final;
}

static int fork_and_ptraceme(RIO *io, int bits, const char *cmd) {
#if __APPLE__ && !__POWERPC__
	return fork_and_ptraceme_for_mac(io, bits, cmd);
#else
	int ret, status, child_pid;
	bool runprofile = io->runprofile && *(io->runprofile);
	char **argv;
	child_pid = r_sys_fork ();
	switch (child_pid) {
	case -1:
		perror ("fork_and_ptraceme");
		break;
	case 0:
		if (runprofile) {
			argv = r_str_argv (cmd, NULL);
			if (!argv) {
				exit(1);
			}
			RRunProfile *rp = _get_run_profile (io, bits, argv);
			if (!rp) {
				r_str_argv_free (argv);
				exit (1);
			}
			trace_me ();
			r_run_start (rp);
			r_run_free (rp);
			r_str_argv_free (argv);
			exit (1);
		} else {
			char *_cmd = io->args ?
				r_str_appendf (strdup (cmd), " %s", io->args) :
				strdup (cmd);
			char *path_escaped = get_and_escape_path (_cmd);
			trace_me ();
			argv = r_str_argv (path_escaped, NULL);
			if (argv && strstr (argv[0], "\\ ")) {
				argv[0] = r_str_replace (argv[0], "\\ ", " ", true);
			}
			if (!argv) {
				free (path_escaped);
				free (_cmd);
				return -1;
			}
			if (argv && *argv) {
				int i;
				for (i = 3; i < 1024; i++) {
					(void)close (i);
				}
				if (execvp (argv[0], argv) == -1) {
					eprintf ("Could not execvp: %s\n", strerror (errno));
					exit (MAGIC_EXIT);
				}
			} else {
				eprintf ("Invalid execvp\n");
			}
			r_str_argv_free (argv);
			free (path_escaped);
			free (_cmd);
		}
		perror ("fork_and_attach: execv");
		//printf(stderr, "[%d] %s execv failed.\n", getpid(), ps.filename);
		exit (MAGIC_EXIT); /* error */
		return 0; // invalid pid // if exit is overriden.. :)
	default:
		/* XXX: clean this dirty code */
		do {
			ret = wait (&status);
			if (ret == -1) return -1;
			if (ret != child_pid) {
				eprintf ("Wait event received by "
					"different pid %d\n", ret);
			}
		} while (ret != child_pid);
		if (WIFSTOPPED (status)) {
			eprintf ("Process with PID %d started...\n", (int)child_pid);
		}
		if (WEXITSTATUS (status) == MAGIC_EXIT) {
			child_pid = -1;
		}
		// XXX kill (pid, SIGSTOP);
		break;
	}
	return child_pid;
#endif
}
#endif

static bool __plugin_open(RIO *io, const char *file, bool many) {
	if (!strncmp (file, "waitfor://", 10)) {
		return true;
	}
	if (!strncmp (file, "pidof://", 8)) {
		return true;
	}
	return (!strncmp (file, "dbg://", 6) && file[6]);
}

#include <r_core.h>
static int get_pid_of(RIO *io, const char *procname) {
	RCore *c = io->user;
	if (c && c->dbg && c->dbg->h) {
		RListIter *iter;
		RDebugPid *proc;
		RDebug *d = c->dbg;
		RList *pids = d->h->pids (d, 0);
		r_list_foreach (pids, iter, proc) {
			if (strstr (proc->path, procname)) {
				eprintf ("Matching PID %d %s\n", proc->pid, proc->path);
				return proc->pid;
			}
		}
	} else {
		eprintf ("Cannot enumerate processes\n");
	}
	return -1;
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	RIOPlugin *_plugin;
	RIODesc *ret = NULL;
	char uri[128];
	if (!strncmp (file, "waitfor://", 10)) {
		const char *procname = file + 10;
		eprintf ("Waiting for %s\n", procname);
		while (true) {
			int target_pid = get_pid_of (io, procname);
			if (target_pid != -1) {
				snprintf (uri, sizeof (uri), "dbg://%d", target_pid);
				file = uri;
				break;
			}
			r_sys_usleep (100);
		}
	} else if (!strncmp (file, "pidof://", 8)) {
		const char *procname = file + 8;
		int target_pid = get_pid_of (io, procname);
		if (target_pid == -1) {
			eprintf ("Cannot find matching process for %s\n", file);
			return NULL;
		}
		snprintf (uri, sizeof (uri), "dbg://%d", target_pid);
		file = uri;
	}
	if (__plugin_open (io, file, 0)) {
		const char *pidfile = file + 6;
		char *endptr;
		int pid = (int)strtol (pidfile, &endptr, 10);
		if (endptr == pidfile || pid < 0) {
			pid = -1;
		}
		if (pid == -1) {
			pid = fork_and_ptraceme (io, io->bits, file + 6);
			if (pid == -1) {
				return NULL;
			}
#if __WINDOWS__
			sprintf (uri, "w32dbg://%d", pid);
			_plugin = r_io_plugin_resolve (io, (const char *)uri, false);
			if (!_plugin || !_plugin->open) {
				return NULL;
			}
			if ((ret = _plugin->open (io, uri, rw, mode))) {
				RIOW32Dbg *w32 = (RIOW32Dbg *)ret->data;
				w32->winbase = winbase;
				w32->tid = wintid;
			}

#elif __APPLE__
			sprintf (uri, "smach://%d", pid);		//s is for spawn
			_plugin = r_io_plugin_resolve (io, (const char *)uri + 1, false);
			if (!_plugin || !_plugin->open || !_plugin->close) {
				return NULL;
			}
			ret = _plugin->open (io, uri, rw, mode);
#else
			// TODO: use io_procpid here? faster or what?
			sprintf (uri, "ptrace://%d", pid);
			_plugin = r_io_plugin_resolve (io, (const char *)uri, false);
			if (!_plugin || !_plugin->open) {
				return NULL;
			}
			ret = _plugin->open (io, uri, rw, mode);
#endif
		} else {
			sprintf (uri, "attach://%d", pid);
			_plugin = r_io_plugin_resolve (io, (const char *)uri, false);
			if (!_plugin || !_plugin->open) {
				return NULL;
			}
			ret = _plugin->open (io, uri, rw, mode);
		}
		if (ret) {
			ret->plugin = _plugin;
			ret->referer = strdup (file);		//kill this
		}
	}
	return ret;
}

static int __close (RIODesc *desc) {
	int ret = -2;
	eprintf ("something went wrong\n");
	if (desc) {
		eprintf ("trying to close %d with io_debug\n", desc->fd);
		ret = -1;
	}
	r_sys_backtrace ();
	return ret;
}

RIOPlugin r_io_plugin_debug = {
	.name = "debug",
	.desc = "Native debugger (dbg:///bin/ls dbg://1388 pidof:// waitfor://)",
	.license = "LGPL3",
	.author = "pancake",
	.version = "0.2.0",
	.open = __open,
	.close = __close,
	.check = __plugin_open,
	.isdbg = true,
};
#else
RIOPlugin r_io_plugin_debug = {
	.name = "debug",
	.desc = "Debug a program or pid. (NOT SUPPORTED FOR THIS PLATFORM)",
};
#endif

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_debug,
	.version = R2_VERSION
};
#endif
