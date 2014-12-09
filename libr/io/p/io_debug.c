/* radare - LGPL - Copyright 2007-2014 - pancake */

#include <r_io.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_debug.h> /* only used for BSD PTRACE redefinitions */

#define USE_RARUN 0

static void my_io_redirect (RIO *io, const char *ref, const char *file) {
	free (io->referer);
	io->referer = ref? strdup (ref): NULL;
	free (io->redirect);
	io->redirect = file? strdup (file): NULL;
}

#if __linux__ ||  __APPLE__ || __WINDOWS__ || \
	__NetBSD__ || __KFBSD__ || __OpenBSD__
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
#include <spawn.h>
#include <sys/ptrace.h>
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

#if __APPLE__ || __BSD__
static void inferior_abort_handler(int pid) {
        eprintf ("Inferior received signal SIGABRT. Executing BKPT.\n");
}
#endif

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

static int setup_tokens() {
        HANDLE tok;
        TOKEN_PRIVILEGES tp; 
        DWORD err;

        tok = NULL;
        err = -1; 

        if (!OpenProcessToken (GetCurrentProcess (), TOKEN_ADJUST_PRIVILEGES, &tok))
                goto err_enable;

        tp.PrivilegeCount = 1;
        if (!LookupPrivilegeValue (NULL,  SE_DEBUG_NAME, &tp.Privileges[0].Luid))
                goto err_enable;

        //tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
        tp.Privileges[0].Attributes = 0; //SE_PRIVILEGE_ENABLED;
        if (!AdjustTokenPrivileges (tok, 0, &tp, sizeof (tp), NULL, NULL)) 
                goto err_enable;
        err = 0;
err_enable:
        if (tok != NULL)
                CloseHandle (tok);
        if (err)
		r_sys_perror ("setup_tokens");
        return err;
}

static int fork_and_ptraceme(RIO *io, int bits, const char *cmd) {
	PROCESS_INFORMATION pi;
        STARTUPINFO si = { sizeof (si) };
        DEBUG_EVENT de;
	int pid, tid;
	HANDLE th = INVALID_HANDLE_VALUE;
	if (!*cmd)
		return -1;
	setup_tokens ();
        /* TODO: with args */
        if (!CreateProcess (cmd, NULL,
                        NULL, NULL, FALSE,
                        CREATE_NEW_CONSOLE | DEBUG_ONLY_THIS_PROCESS,
                        NULL, NULL, &si, &pi)) {
                r_sys_perror ("CreateProcess");
                return -1;
        }

        /* get process id and thread id */
        pid = pi.dwProcessId;
        tid = pi.dwThreadId;

#if 0
        /* load thread list */
	{
		HANDLE h;
		THREADENTRY32 te32;
		HANDLE WINAPI (*win32_openthread)(DWORD, BOOL, DWORD) = NULL;
		win32_openthread = (HANDLE WINAPI (*)(DWORD, BOOL, DWORD))
			GetProcAddress (GetModuleHandle ("kernel32"), "OpenThread");

		th = CreateToolhelp32Snapshot (TH32CS_SNAPTHREAD, pid);
		if (th == INVALID_HANDLE_VALUE || !Thread32First(th, &te32))
			r_sys_perror ("CreateToolhelp32Snapshot");

		do {
			if (te32.th32OwnerProcessID == pid) {
				h = win32_openthread (THREAD_ALL_ACCESS, 0, te32.th32ThreadID);
				if (h == NULL) r_sys_perror ("OpenThread");
				else eprintf ("HANDLE=%p\n", h);
			}
		} while (Thread32Next (th, &te32));
	}
#endif

#if 0
	// Access denied here :?
	if (ContinueDebugEvent (pid, tid, DBG_CONTINUE) == 0) {
		r_sys_perror ("ContinueDebugEvent");
		goto err_fork;
	}
#endif

        /* catch create process event */
        if (!WaitForDebugEvent (&de, 10000))
                goto err_fork;

        /* check if is a create process debug event */
        if (de.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT) {
                eprintf ("exception code 0x%04x\n", (ut32)de.dwDebugEventCode);
                goto err_fork;
        }

	if (th != INVALID_HANDLE_VALUE)
		CloseHandle (th);

	eprintf ("PID=%d\n", pid);
	eprintf ("TID=%d\n", tid);
        return pid;

err_fork:
	eprintf ("ERRFORK\n");
        TerminateProcess (pi.hProcess, 1);
	if (th != INVALID_HANDLE_VALUE)
		CloseHandle (th);
        return -1;
}
#else // windows

// __UNIX__ (not windows)
static int fork_and_ptraceme(RIO *io, int bits, const char *cmd) {
	char **argv;
	int ret, status, pid = fork ();
	switch (pid) {
	case -1:
		perror ("fork_and_ptraceme");
		break;
	case 0:
#if __APPLE__
		signal (SIGTRAP, SIG_IGN); //NEED BY STEP 
#endif
#if __APPLE__ || __BSD__
/* we can probably remove this #if..as long as PT_TRACE_ME is redefined for OSX in r_debug.h */
		signal (SIGABRT, inferior_abort_handler);
		if (ptrace (PT_TRACE_ME, 0, 0, 0) != 0) {
#else
		if (ptrace (PTRACE_TRACEME, 0, NULL, NULL) != 0) {
#endif
			r_sys_perror ("ptrace-traceme");
			exit (MAGIC_EXIT);
		}
		if (io->runprofile && *(io->runprofile)) {
			char *expr = NULL;
			int i;
			RRunProfile *rp = r_run_new (NULL);
			argv = r_str_argv (cmd, NULL);
			for (i=0; argv[i]; i++) {
				rp->_args[i] = argv[i];
			}
			rp->_args[i] = NULL;
			rp->_program = argv[0];
			if (io->runprofile && *io->runprofile) {
				if (!r_run_parsefile (rp, io->runprofile)) {
					eprintf ("Can't find profile '%s'\n", io->runprofile);
					exit (MAGIC_EXIT);
				}
			}
			if (bits==64)
				r_run_parseline (rp, expr=strdup ("bits=64"));
			else if (bits==32)
				r_run_parseline (rp, expr=strdup ("bits=32"));
			free (expr);
			r_run_start (rp);
			r_run_free (rp);
			// double free wtf
			//	r_str_argv_free (argv);
			exit (1);
		} else {
			// TODO: Add support to redirect filedescriptors
			// TODO: Configure process environment
			argv = r_str_argv (cmd, NULL);

#if __APPLE__
			 {
#define _POSIX_SPAWN_DISABLE_ASLR 0x0100
				ut32 ps_flags = POSIX_SPAWN_SETEXEC;
				posix_spawnattr_t attr = {0};
				size_t copied = 1;
				cpu_type_t cpu;
				pid_t p = -1;
				int ret;

				int useASLR = 1;
				posix_spawnattr_init (&attr);
				if (useASLR != -1) {
					if (useASLR) {
						// enable aslr if not enabled? really?
					} else {
						ps_flags |= _POSIX_SPAWN_DISABLE_ASLR;
					}
				}
				(void)posix_spawnattr_setflags (&attr, ps_flags);
#if __i386__ || __x86_64__
				cpu = CPU_TYPE_I386;
				if (bits == 64)
					cpu |= CPU_ARCH_ABI64;
#else
				cpu = CPU_TYPE_ANY;
#endif
				posix_spawnattr_setbinpref_np (&attr, 1, &cpu, &copied);
				ret = posix_spawnp (&p, argv[0], NULL, &attr, argv, NULL);
				switch (ret) {
				case 0:
					eprintf ("Success\n");
					break;
				case 22:
					eprintf ("posix_spawnp: Invalid argument\n");
					break;
				case 86:
					eprintf ("Unsupported architecture\n");
					break;
				default:
					eprintf ("posix_spawnp: unknown error %d\n", ret);
					perror ("posix_spawnp");
					break;
				}
				/* only required if no SETEXEC called
				   if (p != -1)
				   wait (p);
				 */
				exit (MAGIC_EXIT); /* error */
			 }
#else
			execvp (argv[0], argv);
#endif
		}
		perror ("fork_and_attach: execv");
		//printf(stderr, "[%d] %s execv failed.\n", getpid(), ps.filename);
		exit (MAGIC_EXIT); /* error */
		return 0; // invalid pid // if exit is overriden.. :)
	default:
		/* XXX: clean this dirty code */
                ret = wait (&status);
		if (ret != pid)
			eprintf ("Wait event received by different pid %d\n", ret);
                if (WIFSTOPPED (status))
                        eprintf ("Process with PID %d started...\n", (int)pid);
		if (WEXITSTATUS (status) == MAGIC_EXIT)
			pid = -1;
		// XXX kill (pid, SIGSTOP);
		break;
	}
	eprintf ("PID = %d\n", pid);
	return pid;
}
#endif

static int __plugin_open(RIO *io, const char *file, ut8 many) {
	if (!strncmp (file, "dbg://", 6) && file[6])
		return R_TRUE;
	return R_FALSE;
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	char uri[128];
	if (__plugin_open (io, file,  0)) {
		int pid = atoi (file+6);
		if (pid == 0) {
			pid = fork_and_ptraceme (io, io->bits, file+6);
			if (pid==-1)
				return NULL;
#if __WINDOWS__
			sprintf (uri, "w32dbg://%d", pid);
#elif __APPLE__
			sprintf (uri, "mach://%d", pid);
#else
			// TODO: use io_procpid here? faster or what?
			sprintf (uri, "ptrace://%d", pid);
#endif
			my_io_redirect (io, file, uri);
		} else {
			sprintf (uri, "attach://%d", pid);
			my_io_redirect (io, file, uri);
		}
		return NULL;
	}
	my_io_redirect (io, file, NULL);
	return NULL;
}

RIOPlugin r_io_plugin_debug = {
        //void *plugin;
	.name = "debug",
        .desc = "Debug a program or pid. dbg:///bin/ls, dbg://1388",
	.license = "LGPL3",
        .open = __open,
        .plugin_open = __plugin_open,
	.lseek = NULL,
	.system = NULL,
	.isdbg = R_TRUE,
        //void *widget;
/*
        struct debug_t *debug;
        ut32 (*write)(int fd, const ut8 *buf, ut32 count);
	int fds[R_IO_NFDS];
*/
};
#else // DEBUGGER
struct r_io_plugin_t r_io_plugin_debug = {
	.name = "debug",
        .desc = "Debug a program or pid. (NOT SUPPORTED FOR THIS PLATFORM)",
	.debug = (void *)(size_t)1,
};
#endif // DEBUGGER

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_debug
};
#endif
