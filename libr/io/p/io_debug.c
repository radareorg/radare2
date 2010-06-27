/* radare - LGPL - Copyright 2007-2010 pancake<nopcode.org> */

#include <r_io.h>
#include <r_lib.h>
#include <r_util.h>

#if __linux__ || __NetBSD__ || __FreeBSD__ || __OpenBSD__ || __APPLE__ || __WINDOWS__

#define MAGIC_EXIT 31337

#include <signal.h>
#if __UNIX__
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#endif

static void inferior_abort_handler(int pid) {
        eprintf ("Inferior received signal SIGABRT. Executing BKPT.\n");
}

#if __APPLE__
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

static int fork_and_ptraceme(const char *cmd) {
	PROCESS_INFORMATION pi;
        STARTUPINFO si = { sizeof (si) };
        DEBUG_EVENT de;
	int pid, tid;
	HANDLE h, th = INVALID_HANDLE_VALUE;

	setup_tokens ();
        /* TODO: with args */
        if( !CreateProcess (cmd, NULL,
                        NULL, NULL, FALSE,
                        CREATE_NEW_CONSOLE | DEBUG_ONLY_THIS_PROCESS,
                        NULL, NULL, &si, &pi ) ) {
                r_sys_perror ("CreateProcess");
                return -1;
        }

        /* get process id and thread id */
        pid = pi.dwProcessId;
        tid = pi.dwThreadId;

        /* load thread list */
	{
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
                eprintf ("exception code %d\n",
                                de.dwDebugEventCode);
                goto err_fork;
        }

	if (th != INVALID_HANDLE_VALUE)
		CloseHandle (th);

	eprintf ("PID=%d\n", pid);
	eprintf ("TID=%d\n", tid);
        return pid;

err_fork:
        TerminateProcess (pi.hProcess, 1);
	if (th != INVALID_HANDLE_VALUE)
		CloseHandle (th);
        return -1;
}
#else

static int __waitpid(int pid) {
	int st = 0;
	if (waitpid (pid, &st, 0) == -1)
		return R_FALSE;
	if (WIFEXITED (st)) {
	//if ((WEXITSTATUS(wait_val)) != 0) {
		perror ("==> Process has exited\n");
		//debug_exit();
		return -1;
	}
	return R_TRUE;
}

static int fork_and_ptraceme(const char *cmd) {
	char **argv;
	int status, pid = -1;

	pid = vfork ();
	switch (pid) {
	case -1:
		perror ("fork_and_ptraceme");
		break;
	case 0:
#if __APPLE__
		signal (SIGTRAP, SIG_IGN); // SINO NO FUNCIONA EL STEP
		signal (SIGABRT, inferior_abort_handler);
		if (ptrace (PT_TRACE_ME, 0, 0, 0) != 0) {
#else
		if (ptrace (PTRACE_TRACEME, 0, NULL, NULL) != 0) {
#endif
			eprintf ("ptrace-traceme failed\n");
			exit (MAGIC_EXIT);
		}
		// TODO: Add support to redirect filedescriptors
		// TODO: Configure process environment
		argv = r_str_argv (cmd, NULL);
		execvp (argv[0], argv);
		r_str_argv_free (argv);

		perror ("fork_and_attach: execv");
		//printf(stderr, "[%d] %s execv failed.\n", getpid(), ps.filename);
		exit (MAGIC_EXIT); /* error */
		return 0; // invalid pid // if exit is overriden.. :)
	default:
		/* XXX: clean this dirty code */
                wait (&status);
                if (WIFSTOPPED (status))
                        eprintf ("Process with PID %d started...\n", (int)pid);
		// XXX
		//kill (pid, SIGSTOP);
		break;
	}
	printf ("PID = %d\n", pid);
	return pid;
}
#endif

static int __plugin_open(struct r_io_t *io, const char *file) {
	if (!memcmp (file, "dbg://", 6))
		return R_TRUE;
	return R_FALSE;
}

static int __open(struct r_io_t *io, const char *file, int rw, int mode) {
	char uri[1024];
	if (__plugin_open (io, file)) {
		int pid = atoi (file+6);
		if (pid == 0) {
			pid = fork_and_ptraceme(file+6);
			if (pid==-1)
				return -1;
#if __WINDOWS__
			sprintf (uri, "w32dbg://%d", pid);
#elif __APPLE__
			sprintf (uri, "mach://%d", pid);
#else
			sprintf (uri, "ptrace://%d", pid);
#endif
			eprintf ("io_redirect: %s\n", uri);
			return r_io_redirect (io, uri);
		} else {
			sprintf (uri, "attach://%d", pid);
			r_io_redirect (io, uri);
			return -1;
		}
	}
	r_io_redirect (io, NULL);
	return -1;
}

static int __init(struct r_io_t *io) {
	eprintf ("dbg init\n");
	return R_TRUE;
}

struct r_io_plugin_t r_io_plugin_debug = {
        //void *plugin;
	.name = "debug",
        .desc = "Debug a program or pid. dbg:///bin/ls, dbg://1388",
        .open = __open,
        .plugin_open = __plugin_open,
	.lseek = NULL,
	.system = NULL,
	.debug = (void *)1,
	.init = __init,
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
	.debug = (void *)1,
};
#endif // DEBUGGER

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_debug
};
#endif
