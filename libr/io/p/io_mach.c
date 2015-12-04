/* radare - LGPL - Copyright 2009-2015 - pancake */

#include <r_userconf.h>

#include <r_io.h>
#include <r_lib.h>
#include <r_cons.h>

#if __APPLE__ && DEBUGGER

#define EXCEPTION_PORT 0

#include <mach/exception_types.h>
//no available for ios #include <mach/mach_vm.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_traps.h>
#include <mach/processor_set.h>
#include <mach/mach_error.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach/vm_map.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/wait.h>
#include <errno.h>

#define MACH_ERROR_STRING(ret) \
	(mach_error_string (ret) ? mach_error_string (ret) : "(unknown)")

typedef struct {
	int pid;
	task_t task;
} RIOMach;
#define RIOMACH_PID(x) (x ? ((RIOMach*)(x))->pid : -1)
#define RIOMACH_TASK(x) (x ? ((RIOMach*)(x))->task : -1)

#undef R_IO_NFDS
#define R_IO_NFDS 2
extern int errno;

static task_t task_for_pid_workaround(int Pid) {
	host_t myhost = mach_host_self();
	mach_port_t psDefault = 0;
	mach_port_t psDefault_control = 0;
	task_array_t tasks = NULL;
	mach_msg_type_number_t numTasks = 0;
	kern_return_t kr = -1;
	int i;
	if (Pid == -1) return -1;

	kr = processor_set_default (myhost, &psDefault);
	if (kr != KERN_SUCCESS) {
		return -1;
	}
	kr = host_processor_set_priv (myhost, psDefault, &psDefault_control);
	if (kr != KERN_SUCCESS) {
		eprintf ("host_processor_set_priv failed with error 0x%x\n", kr);
		//mach_error ("host_processor_set_priv",kr);
		return -1;
	}

	numTasks = 0;
	kr = processor_set_tasks (psDefault_control, &tasks, &numTasks);
	if (kr != KERN_SUCCESS) {
		eprintf ("processor_set_tasks failed with error %x\n", kr);
		return -1;
	}
	if (Pid == 0) {
		/* kernel task */
		return tasks[0];
	}
	for (i = 0; i < numTasks; i++) {
		int pid;
		pid_for_task (i, &pid);
		if (pid == Pid) {
			return (tasks[i]);
		}
	}
	return -1;
}

static task_t pid_to_task(int pid) {
	task_t task = -1;
	int err = task_for_pid (mach_task_self (), (pid_t)pid, &task);
	if ((err != KERN_SUCCESS) || !MACH_PORT_VALID (task)) {
		task = task_for_pid_workaround (pid);
		if (task == -1) {
			eprintf ("Failed to get task %d for pid %d.\n", (int)task, (int)pid);
			eprintf ("Missing priviledges? 0x%x: %s\n", err, MACH_ERROR_STRING (err));
#if 0
			eprintf ("You probably need to add user to procmod group.\n"
					" Or chmod g+s radare && chown root:procmod radare\n");
			eprintf ("FMI: http://developer.apple.com/documentation/Darwin/Reference/ManPages/man8/taskgated.8.html\n");
#endif
			return -1;
		}
	}
	return task;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len) {
	vm_size_t size = 0;
	int blen, err, copied = 0;
	int blocksize = 32;
	if (RIOMACH_PID (fd->data) == 0) {
		if (io->off<4096)
			return len;
	}
	memset (buf, 0xff, len);
	while (copied<len) {
		blen = R_MIN ((len-copied), blocksize);
		//blen = len;
		err = vm_read_overwrite (RIOMACH_TASK (fd->data),
			(ut64)io->off+copied, blen, (pointer_t)buf+copied, &size);
		switch (err) {
		case KERN_PROTECTION_FAILURE:
			//eprintf ("r_io_mach_read: kern protection failure.\n");
			break;
		case KERN_INVALID_ADDRESS:
			if (blocksize == 1) {
				memset (buf+copied, 0xff, len-copied);
				return size+copied;
			}
			blocksize = 1;
			blen = 1;
			buf[copied] = 0xff;
			//eprintf("invaddr %d\n",len);
			break;
		}
		if (err == -1) {
			//eprintf ("Cannot read\n");
			return -1;
		}
		if (size==0) {
			if (blocksize == 1) {
				memset (buf+copied, 0xff, len-copied);
				return len; //size+copied;
			}
			blocksize = 1;
			blen = 1;
			buf[copied] = 0xff;
		}
		//if (size != blen) { return size+copied; }
		copied += blen;
	}
	return len; //(int)size;
}

static vm_address_t tsk_getpagebase(ut64 addr) {
	vm_address_t a = addr;
	a >>= 12;
	a <<= 12;
	return a;
}

static int tsk_getperm(task_t task, vm_address_t addr) {
	vm_size_t pagesize = 1;
	int _basic64[VM_REGION_BASIC_INFO_COUNT_64];
	vm_region_basic_info_64_t basic64 = (vm_region_basic_info_64_t)_basic64;
	mach_msg_type_number_t infocnt = VM_REGION_BASIC_INFO_COUNT_64;
	mach_port_t objname;
	kern_return_t rc;

	rc = vm_region_64 (task, &addr, &pagesize, VM_REGION_BASIC_INFO,
		(vm_region_info_t)basic64, &infocnt, &objname);
	if (rc == KERN_SUCCESS) {
		return basic64[0].protection;
	}
	return 0;
}

static int tsk_pagesize(RIO *io, int len) {
#if __arm__ || __arm64__ || __aarch64__
	int is_arm64 = (io && io->bits == 64);
	int pagesize = is_arm64? 16384: 4096;
#else
	int pagesize = getpagesize();
#endif
	if (pagesize<1) pagesize = 4096;
	if (len > pagesize) {
		pagesize *= (1 + (len / pagesize));
	}
	return pagesize;
}

static bool tsk_setperm(RIO *io, task_t task, vm_address_t addr, int len, int perm) {
	mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT;
	vm_region_flavor_t flavor = VM_REGION_BASIC_INFO;
	vm_address_t region = (vm_address_t)addr;
	vm_region_basic_info_data_t info;
	vm_size_t region_size = tsk_pagesize(io, len);
#if 1
	task_t t;
	vm_region_64 (task, &region, &region_size, flavor, (vm_region_info_t)&info,
			(mach_msg_type_number_t*)&info_count, (mach_port_t*)&t);
#endif
	return vm_protect (task, region, region_size, FALSE, perm) == KERN_SUCCESS;
}

static bool tsk_write(task_t task, vm_address_t addr, const ut8 *buf, int len) {
	mach_msg_type_number_t _len = len;
	vm_offset_t _buf = (vm_offset_t)buf;
	return vm_write (task, addr, _buf, _len) == KERN_SUCCESS;
}

static int mach_write_at(RIO *io, RIOMach *riom, const void *buf, int len, ut64 addr) {
	vm_address_t vaddr = addr;
	vm_address_t pageaddr;
	vm_size_t pagesize;
	int operms = 0;
	task_t task;

	if (!riom || len <1) {
		return 0;
	}
	task = riom->task;

	pageaddr = tsk_getpagebase (addr);
	pagesize = tsk_pagesize (io, len);

	if (tsk_write (task, vaddr, buf, len)) {
		return len;
	}
	operms = tsk_getperm (task, pageaddr);
	if (!tsk_setperm (io, task, pageaddr, pagesize, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY)) {
		perror ("setperm");
		eprintf ("io.mach: cant set page perms for %d bytes at 0x%08"
			PFMT64x"\n", (int)pagesize, (ut64)pageaddr);
		//return -1;
	}
	if (!tsk_write (task, vaddr, buf, len)) {
		perror ("write");
		eprintf ("io.mach: cant write on memory\n");
		len = -1;
	}
	if (operms) {
		if (!tsk_setperm (io, task, pageaddr, pagesize, operms)) {
			eprintf ("io.mach: cant restore page perms\n");
			return -1;
		}
	}
	return len;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	return mach_write_at (io, (RIOMach*)fd->data, buf, len, io->off);
}

static int __plugin_open(RIO *io, const char *file, ut8 many) {
	return (!strncmp (file, "attach://", 9) \
		|| !strncmp (file, "mach://", 7));
}

// s/inferior_task/port/
static int debug_attach(int pid) {
	task_t task = pid_to_task (pid);
	if (task == -1) {
		return -1;
	}
	eprintf ("pid: %d\ntask: %d\n", pid, task);
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
		return -1; // false
	}
#endif
	/* is this required for arm ? */
#if EXCEPTION_PORT
	int exception_port;
	if (mach_port_allocate (mach_task_self (), MACH_PORT_RIGHT_RECEIVE,
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
	return task;
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	RIODesc *ret = NULL;
	RIOMach *riom;
	const char *pidfile;
	char *pidpath, *endptr;
	int pid;
	task_t task;
	if (!__plugin_open (io, file, 0))
		return NULL;
	pidfile = file+(file[0]=='a'?9:7);
	pid = (int)strtol (pidfile, &endptr, 10);
	if (endptr == pidfile || pid < 0)
		return NULL;

	task = debug_attach (pid);
	if ((int)task == -1) {
		if (pid>0 && io->referer && !strncmp (io->referer, "dbg://", 6)) {
			eprintf ("Child killed\n");
			kill (pid, 9);
		}
		switch (errno) {
		case EPERM:
			eprintf ("Operation not permitted\n");
			break;
		case EINVAL:
			perror ("ptrace: Cannot attach");
			eprintf ("ERRNO: %d (EINVAL)\n", errno);
			break;
		default:
			eprintf ("unknown error in debug_attach\n");
			break;
		}
		return NULL;
	}
	riom = R_NEW0 (RIOMach);
	riom->pid = pid;
	riom->task = task;
	// sleep 1s to get proper path (program name instead of ls) (racy)
	if (pid == 0) {
		pidpath = strdup ("kernel");
	} else {
		pidpath = r_sys_pid_to_path (pid);
	}
	ret = r_io_desc_new (&r_io_plugin_mach, riom->pid,
		pidpath, rw | R_IO_EXEC, mode, riom);
	free (pidpath);
	return ret;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case 0: // abs
		io->off = offset;
		break;
	case 1: // cur
		io->off += (int)offset;
		break;
	case 2: // end
		io->off = UT64_MAX;
		break;
	}
	return io->off;
}

static int __close(RIODesc *fd) {
	int pid = RIOMACH_PID (fd->data);
	R_FREE (fd->data);
	return ptrace (PT_DETACH, pid, 0, 0);
}

static int __system(RIO *io, RIODesc *fd, const char *cmd) {
	RIOMach *riom = (RIOMach*)fd->data;
	//printf("ptrace io command (%s)\n", cmd);
	/* XXX ugly hack for testing purposes */
	if (!strncmp (cmd, "perm", 4)) {
		int perm = r_str_rwx (cmd+4);
		if (perm) {
			int pagesize = tsk_pagesize(io, 1);
			tsk_setperm (io, riom->task, io->off, pagesize, perm);
		} else {
			eprintf ("Usage: =!perm [rwx]\n");
		}
		return 0;
	}
	if (!strncmp (cmd, "pid", 3)) {
		const char *pidstr = cmd + 4;
		int pid = -1;
		if (!cmd[3]) {
			int pid = RIOMACH_PID (fd->data);
			eprintf ("%d\n", pid);
			return 0;
		}
		if (!strcmp (pidstr, "0")) {
			pid = 0;
		} else {
			pid = atoi (cmd+4);
			if (!pid) pid = -1;
		}
		if (pid != -1) {
			task_t task = pid_to_task (pid);
			if (task != -1) {
				eprintf ("PID=%d\n", pid);
				riom->pid = pid;
				riom->task = task;
				return 0;
			}
		}
		eprintf ("io_mach_system: Invalid pid %d\n", pid);
	} else eprintf ("Try: '=!pid' or '=!perm'\n");
	return 1;
}

// TODO: rename ptrace to io_mach .. err io.ptrace ??
RIOPlugin r_io_plugin_mach = {
	.name = "mach",
	.desc = "mach debugger io plugin (mach://pid)",
	.license = "LGPL",
	.open = __open,
	.close = __close,
	.read = __read,
	.plugin_open = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.write = __write,
	.isdbg = true
};

#else
RIOPlugin r_io_plugin_mach = {
	.name = "mach",
	.desc = "mach debug io (unsupported in this platform)",
	.license = "LGPL"
};
#endif

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_mach,
	.version = R2_VERSION
};
#endif
