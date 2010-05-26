/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_userconf.h>

#include <r_io.h>
#include <r_lib.h>
#include <r_cons.h>

#if __APPLE__
//#define USE_PTRACE 0
// EXPERIMENTAL
#define EXCEPTION_PORT 0

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
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#define MACH_ERROR_STRING(ret) \
	(mach_error_string (ret) ? mach_error_string (ret) : "(unknown)")

#undef R_IO_NFDS
#define R_IO_NFDS 2
extern int errno;
static int fds[3];

static task_t pid_to_task(int pid) {
        static task_t old_pid  = -1;
        static task_t old_task = -1;
        task_t task = 0;
        int err;

        /* xlr8! */
        if (old_task!= -1) //old_pid != -1 && old_pid == pid)
                return old_task;

        err = task_for_pid(mach_task_self(), (pid_t)pid, &task);
        if ((err != KERN_SUCCESS) || !MACH_PORT_VALID(task)) {
                fprintf(stderr, "Failed to get task %d for pid %d.\n", (int)task, (int)pid);
                eprintf ("Reason: 0x%x: %s\n", err, MACH_ERROR_STRING(err));
                eprintf ("You probably need to add user to procmod group.\n"
                                " Or chmod g+s radare && chown root:procmod radare\n");
                fprintf(stderr, "FMI: http://developer.apple.com/documentation/Darwin/Reference/ManPages/man8/taskgated.8.html\n");
                return -1;
        }
        old_pid = pid;
        old_task = task;

        return task;
}

static int __read(RIO *io, int pid, void *buff, int len) {
        unsigned int size = 0;
        int err = vm_read_overwrite (pid_to_task (pid),
		(unsigned int)io->off, len, (pointer_t)buff, &size);
        if (err == -1) {
                eprintf ("Cannot read\n");
                return -1;
        }
        return (int)size;
}

static int ptrace_write_at(int tid, const void *buff, int len, ut64 addr) {
        kern_return_t err;
        // XXX SHOULD RESTORE PERMS LATER!!!
        err = vm_protect (pid_to_task (tid), addr+(addr%4096), 4096, 0,
		VM_PROT_READ | VM_PROT_WRITE);
        if (err != KERN_SUCCESS)
                eprintf ("cant change page perms to rw\n");

        err = vm_write( pid_to_task(tid),
                (vm_address_t)(unsigned int)addr, // XXX not for 64 bits
                (pointer_t)buff, (mach_msg_type_number_t)len);
        if (err != KERN_SUCCESS)
                eprintf ("cant write on memory\n");

        vm_protect (pid_to_task (tid), addr+(addr%4096), 4096, 0,
		VM_PROT_READ | VM_PROT_EXECUTE);
        if (err != KERN_SUCCESS) {
        	eprintf ("Oops (0x%"PFMT64x") error (%s)\n", addr,
			MACH_ERROR_STRING (err));
                eprintf ("cant change page perms to rx\n");
	}
	return len;
}

static int __write(struct r_io_t *io, int pid, const ut8 *buf, int len) {
	return ptrace_write_at (pid, buf, len, io->off);
}

static int __plugin_open(struct r_io_t *io, const char *file) {
	if (!memcmp (file, "mach://", 7))
		return R_TRUE;
	return R_FALSE;
}

static task_t inferior_task = 0;
static int task = 0;

// s/inferior_task/port/
static int debug_attach(int pid) {
        inferior_task = pid_to_task (pid);
        if (inferior_task == -1)
                return -1;

        task = inferior_task; // ugly global asignation
        eprintf ("; pid = %d\ntask= %d\n", pid, inferior_task);
#if 0
	// TODO : move this code into debug
        if (task_threads (task, &inferior_threads, &inferior_thread_count)
			!= KERN_SUCCESS) {
                eprintf ("Failed to get list of task's threads.\n");
                return -1;
        }
        eprintf ("Thread count: %d\n", inferior_thread_count);
#endif

#if SUSPEND
	if (task_suspend (this->port) != KERN_SUCCESS) {
		eprintf ("cannot suspend task\n");
		return -1; // R_FALSE
	}
#endif
	/* is this required for arm ? */
#if EXCEPTION_PORT
        if (mach_port_allocate (mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
			&exception_port) != KERN_SUCCESS) {
                eprintf ("Failed to create exception port.\n");
                return -1;
        }
        if (mach_port_insert_right(mach_task_self(), exception_port,
			exception_port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
                eprintf ("Failed to acquire insertion rights on the port.\n");
                return -1;
        }
        if (task_set_exception_ports(inferior_task, EXC_MASK_ALL, exception_port,
			EXCEPTION_DEFAULT, THREAD_STATE_NONE) != KERN_SUCCESS) {
                eprintf ("Failed to set the inferior's exception ports.\n");
                return -1;
        }
#endif
        return 0;
}

static int __open(struct r_io_t *io, const char *file, int rw, int mode) {
	int ret = -1;
	if (__plugin_open (io, file)) {
		int pid = atoi(file+7);
		if (pid>0) {
			ret = debug_attach (pid);
			if (ret == -1) {
				switch (errno) {
				case EPERM:
					ret = pid;
					eprintf ("Operation not permitted\n");
					break;
				case EINVAL:
					perror ("ptrace: Cannot attach");
					eprintf ("ERRNO: %d (EINVAL)\n", errno);
					break;
				}
			} ret = pid;
		} else ret = pid;
	}
	fds[0] = ret;
	return ret;
}

static ut64 __lseek(struct r_io_t *io, int fildes, ut64 offset, int whence) {
	return offset;
}

static int __close(struct r_io_t *io, int pid) {
	return ptrace (PT_DETACH, pid, 0, 0);
}

static int __system(struct r_io_t *io, int fd, const char *cmd) {
	//printf("ptrace io command (%s)\n", cmd);
	/* XXX ugly hack for testing purposes */
	if (!strcmp (cmd, "pid")) {
		int pid = atoi (cmd+4);
		if (pid != 0)
			io->fd = pid;
		//printf("PID=%d\n", io->fd);
		return io->fd;
	} else eprintf ("Try: '|pid'\n");
	return R_TRUE;
}

static int __init(struct r_io_t *io) {
	eprintf ("mach init\n");
	return R_TRUE;
}

// TODO: rename ptrace to io_mach .. err io.ptrace ??
struct r_io_plugin_t r_io_plugin_mach = {
        //void *plugin;
	.name = "mach",
        .desc = "mach debug io",
        .open = __open,
        .close = __close,
	.read = __read,
        .plugin_open = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.init = __init,
	.write = __write,
	// .debug ?
};

#else

struct r_io_plugin_t r_io_plugin_mach = {
	.name = "io.ptrace",
        .desc = "ptrace io (NOT SUPPORTED FOR THIS PLATFORM)",
};

#endif

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_mach
};
#endif
