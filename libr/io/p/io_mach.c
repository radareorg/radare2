/* radare - LGPL - Copyright 2009-2014 - pancake */

#include <r_userconf.h>

#include <r_io.h>
#include <r_lib.h>
#include <r_cons.h>

#if __APPLE__ && DEBUGGER

#define EXCEPTION_PORT 0

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <mach/exception_types.h>
#include <mach/mach_vm.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_traps.h>
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
#include <sys/wait.h>
#include <errno.h>

#define MACH_ERROR_STRING(ret) \
	(mach_error_string (ret) ? mach_error_string (ret) : "(unknown)")

typedef struct {
	int pid;
	task_t task;
} RIOMach;
#define RIOMACH_PID(x) (x?((RIOMach*)(x))->pid:-1)
#define RIOMACH_TASK(x) (x?((RIOMach*)(x))->task:-1)

#undef R_IO_NFDS
#define R_IO_NFDS 2
extern int errno;

static task_t pid_to_task(int pid) {
        task_t task = 0;
        int err = task_for_pid (mach_task_self (), (pid_t)pid, &task);
        if ((err != KERN_SUCCESS) || !MACH_PORT_VALID (task)) {
                eprintf ("Failed to get task %d for pid %d.\n", (int)task, (int)pid);
                eprintf ("Reason: 0x%x: %s\n", err, MACH_ERROR_STRING (err));
                eprintf ("You probably need to add user to procmod group.\n"
                                " Or chmod g+s radare && chown root:procmod radare\n");
                eprintf ("FMI: http://developer.apple.com/documentation/Darwin/Reference/ManPages/man8/taskgated.8.html\n");
                return -1;
        }
        return task;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len) {
	vm_size_t size = 0;
	int blen, err, copied = 0;
	int blocksize = 16;
	while (copied<len) {
		blen = R_MIN ((len-copied), blocksize);
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
				return size+copied;
			}
			blocksize = 1;
			blen = 1;
			buf[copied] = 0xff;
		}
		//if (size != blen) { return size+copied; }
		copied += blen;
	}
        return (int)size;
}

static int mach_write_at(RIOMach *riom, const void *buff, int len, ut64 addr) {
	task_t task = riom->task;
#if 0
/* get paVM_PROT_EXECUTEge perms */
        kern_return_t err;
	int ret, _basic64[VM_REGION_BASIC_INFO_COUNT_64];
	vm_region_basic_info_64_t basic64 = (vm_region_basic_info_64_t)_basic64;
	mach_msg_type_number_t	infocnt;
const int pagesize = 4096;
vm_offset_t addrbase;
	mach_port_t	objname;
	vm_size_t size = pagesize;

eprintf ("   0x%llx\n", addr);
	infocnt = VM_REGION_BASIC_INFO_COUNT_64;
addrbase = addr;
size = len;
	// intentionally use VM_REGION_BASIC_INFO and get up-converted
	ret = vm_region_64 (task, &addrbase, &size, VM_REGION_BASIC_INFO_64,
					 (vm_region_info_t)basic64, &infocnt, &objname);
eprintf ("+ PERMS (%x) %llx\n", basic64->protection, addr);
	if (ret == -1) {
		eprintf ("Cant get vm region info\n");
	}

#endif
/* get page perms */

        // XXX SHOULD RESTORE PERMS LATER!!!
        if (vm_protect (task, addr, len, 0, VM_PROT_COPY | VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE) != KERN_SUCCESS)
		//if (mach_vm_protect (task, addr, len, 0, VM_PROT_READ | VM_PROT_WRITE) != KERN_SUCCESS)
			if (vm_protect (task, addr, len, 0, VM_PROT_WRITE) != KERN_SUCCESS)
				eprintf ("cant change page perms to rw at 0x%"PFMT64x" with len= %d\n", addr, len);
        if (vm_write (task, (vm_address_t)addr,
                	(vm_offset_t)buff, (mach_msg_type_number_t)len) != KERN_SUCCESS)
                eprintf ("cant write on memory\n");
	//if (vm_read_overwrite(task, addr, 4, buff, &sz)) { eprintf ("cannot overwrite\n"); }

#if 0
eprintf ("addrbase: %x\n", addrbase);
eprintf ("change prems to %x\n", basic64->protection);
int prot = 0;
if (basic64->protection & 1) prot |= VM_PROT_EXECUTE;
if (basic64->protection & 2) prot |= VM_PROT_WRITE;
if (basic64->protection & 4) prot |= VM_PROT_READ;
printf ("%d vs %d\n", prot, basic64->protection);
int prot = VM_PROT_READ | VM_PROT_EXECUTE;
        if (vm_protect (task, addr, len, 0, prot) != KERN_SUCCESS) { //basic64->protection) != KERN_SUCCESS) {
        	eprintf ("Oops (0x%"PFMT64x") error (%s)\n", addr,
			MACH_ERROR_STRING (err));
                eprintf ("cant change page perms to rx\n");
	}
#endif
	return len;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	return mach_write_at ((RIOMach*)fd->data, buf, len, io->off);
}

static int __plugin_open(RIO *io, const char *file, ut8 many) {
	return (!strncmp (file, "attach://", 9) \
		|| !strncmp (file, "mach://", 7));
}

//static task_t inferior_task = 0;
//static int task = 0;

// s/inferior_task/port/
static int debug_attach(int pid) {
        task_t task = pid_to_task (pid);
        if (task == -1)
                return -1;
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
		return -1; // R_FALSE
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
	char *pidpath;
	int pid;
	task_t task;
	if (!__plugin_open (io, file, 0))
		return NULL;
 	pid = atoi (file+(file[0]=='a'?9:7));
	if (pid<1)
		return NULL;
	task = debug_attach (pid);
	if ((int)task == -1) {
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
	pidpath = r_sys_pid_to_path (pid);
	ret = r_io_desc_new (&r_io_plugin_mach, riom->pid,
		pidpath, rw | R_IO_EXEC, mode, riom);
	free (pidpath);
	return ret;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	io->off = offset;
	return offset;
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
	if (!strcmp (cmd, "pid")) {
		if (!cmd[3]) {
			int pid = RIOMACH_PID (fd->data);
			eprintf ("%d\n", pid);
			return 0;
		}
		int pid = atoi (cmd+4);
		if (pid != 0) {
			task_t task = pid_to_task (pid);
			if (task != -1) {
				eprintf ("PID=%d\n", pid);
				riom->pid = pid;
				riom->task = task;
				return 0;
			}
		}
		eprintf ("io_mach_system: Invalid pid %d\n", pid);
		return 1;
	} else eprintf ("Try: '=!pid'\n");
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
	.isdbg = R_TRUE
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
	.data = &r_io_plugin_mach
};
#endif
