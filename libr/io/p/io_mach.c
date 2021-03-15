/* radare - LGPL - Copyright 2009-2017 - pancake */

#include <r_userconf.h>

#include <r_io.h>
#include <r_lib.h>
#include <r_cons.h>

#if __APPLE__ && DEBUGGER

static int __get_pid (RIODesc *desc);
#define EXCEPTION_PORT 0

// NOTE: mach/mach_vm is not available for iOS
#include <mach/exception_types.h>
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

#define R_MACH_MAGIC r_str_hash ("mach")

typedef struct r_io_mach_data_t {
	ut32 magic;
	int pid;
	int tid;
	void *data;
} RIOMachData;

typedef struct {
	task_t task;
} RIOMach;
/*
#define RIOMACH_PID(x) (x ? ((RIOMach*)(x))->pid : -1)
#define RIOMACH_TASK(x) (x ? ((RIOMach*)(x))->task : -1)
*/

int RIOMACH_TASK(RIOMachData *x) {
	// TODO
	return -1;
}

#undef R_IO_NFDS
#define R_IO_NFDS 2
extern int errno;

static task_t task_for_pid_workaround(int pid) {
	host_t myhost = mach_host_self();
	mach_port_t psDefault = 0;
	mach_port_t psDefault_control = 0;
	task_array_t tasks = NULL;
	mach_msg_type_number_t numTasks = 0;
	kern_return_t kr = -1;
	int i;

	if (pid == -1) {
		return MACH_PORT_NULL;
	}
	kr = processor_set_default (myhost, &psDefault);
	if (kr != KERN_SUCCESS) {
		return MACH_PORT_NULL;
	}
	kr = host_processor_set_priv (myhost, psDefault, &psDefault_control);
	if (kr != KERN_SUCCESS) {
//		eprintf ("host_processor_set_priv failed with error 0x%x\n", kr);
		//mach_error ("host_processor_set_priv",kr);
		return MACH_PORT_NULL;
	}
	numTasks = 0;
	kr = processor_set_tasks (psDefault_control, &tasks, &numTasks);
	if (kr != KERN_SUCCESS) {
//		eprintf ("processor_set_tasks failed with error %x\n", kr);
		return MACH_PORT_NULL;
	}
	if (pid == 0) {
		/* kernel task */
		return tasks[0];
	}
	for (i = 0; i < numTasks; i++) {
		int pid2 = -1;
		pid_for_task (i, &pid2);
		if (pid == pid2) {
			return tasks[i];
		}
	}
	return MACH_PORT_NULL;
}

static task_t task_for_pid_ios9pangu(int pid) {
	task_t task = MACH_PORT_NULL;
	host_get_special_port (mach_host_self (), HOST_LOCAL_NODE, 4, &task);
	return task;
}

static task_t pid_to_task(RIODesc *fd, int pid) {
	task_t task = 0;
	static task_t old_task = 0;
	static int old_pid = -1;
	kern_return_t kr;

	RIOMachData *iodd = fd? (RIOMachData *)fd->data: NULL;
	RIOMach *riom = NULL;
	if (iodd) {
		riom = iodd->data;
		if (riom && riom->task) {
			old_task = riom->task;
			riom->task = 0;
			old_pid = iodd->pid;
		}
	}
	if (old_task != 0) {
		if (old_pid == pid) {
			return old_task;
		}
		//we changed the process pid so deallocate a ref from the old_task
		//since we are going to get a new task
		kr = mach_port_deallocate (mach_task_self (), old_task);
		if (kr != KERN_SUCCESS) {
			eprintf ("pid_to_task: fail to deallocate port\n");
			return 0;
		}
	}
	int err = task_for_pid (mach_task_self (), (pid_t)pid, &task);
	if ((err != KERN_SUCCESS) || !MACH_PORT_VALID (task)) {
		task = task_for_pid_workaround (pid);
		if (task == MACH_PORT_NULL) {
			task = task_for_pid_ios9pangu (pid);
			if (task != MACH_PORT_NULL) {
				//eprintf ("Failed to get task %d for pid %d.\n", (int)task, (int)pid);
				//eprintf ("Missing priviledges? 0x%x: %s\n", err, MACH_ERROR_STRING (err));
				return -1;
			}
		}
	}
	old_task = task;
	old_pid = pid;
	return task;
}

static bool task_is_dead(RIODesc *fd, int pid) {
	unsigned int count = 0;
	kern_return_t kr = mach_port_get_refs (mach_task_self (),
		pid_to_task (fd, pid), MACH_PORT_RIGHT_SEND, &count);
	return (kr != KERN_SUCCESS || !count);
}

static ut64 the_lower = UT64_MAX;

static ut64 getNextValid(RIO *io, RIODesc *fd, ut64 addr) {
	struct vm_region_submap_info_64 info;
	vm_address_t address = MACH_VM_MIN_ADDRESS;
	vm_size_t size = (vm_size_t) 0;
	vm_size_t osize = (vm_size_t) 0;
	natural_t depth = 0;
	kern_return_t kr;
	int tid = __get_pid (fd);
	task_t task = pid_to_task (fd, tid);
	ut64 lower = addr;
#if __arm64__ || __aarch64__
	size = osize = 16384; // acording to frida
#else
	size = osize = 4096;
#endif
	if (the_lower != UT64_MAX) {
		return R_MAX (addr, the_lower);
	}

	for (;;) {
		mach_msg_type_number_t info_count;
		info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
		memset (&info, 0, sizeof (info));
		kr = vm_region_recurse_64 (task, &address, &size,
			&depth, (vm_region_recurse_info_t) &info, &info_count);
		if (kr != KERN_SUCCESS) {
			break;
		}
		if (lower == addr) {
			lower = address;
		}
		if (info.is_submap) {
			depth++;
			continue;
		}
		if (addr >= address && addr < address + size) {
			return addr;
		}
		if (address < lower) {
			lower = address;
		}
		if (size < 1) {
			size = osize; // fuck
		}
		address += size;
		size = 0;
	}
	the_lower = lower;
	return lower;
}

static int __read(RIO *io, RIODesc *desc, ut8 *buf, int len) {
	vm_size_t size = 0;
	int blen, err, copied = 0;
	int blocksize = 32;
	RIOMachData *dd = (RIOMachData *)desc->data;
	if (!io || !desc || !buf || !dd) {
		return -1;
	}
	if (dd ->magic != r_str_hash ("mach")) {
		return -1;
	}
	memset (buf, 0xff, len);
	int pid = __get_pid (desc);
	task_t task = pid_to_task (desc, pid);
	if (task_is_dead (desc, pid)) {
		return -1;
	}
	if (pid == 0) {
		if (io->off < 4096) {
			return len;
		}
	}
	copied = getNextValid (io, desc, io->off) - io->off;
	if (copied < 0) {
		copied = 0;
	}
	while (copied < len) {
		blen = R_MIN ((len - copied), blocksize);
		//blen = len;
		err = vm_read_overwrite (task,
			(ut64)io->off + copied, blen,
			(pointer_t)buf + copied, &size);
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
			break;
		}
		if (err == -1 || size < 1) {
			return -1;
		}
		if (size == 0) {
			if (blocksize == 1) {
				memset (buf + copied, 0xff, len - copied);
				return len;
			}
			blocksize = 1;
			blen = 1;
			buf[copied] = 0xff;
		}
		copied += blen;
	}
	return len;
}

static int tsk_getperm(RIO *io, task_t task, vm_address_t addr) {
	kern_return_t kr;
	mach_port_t object;
	vm_size_t vmsize;
	mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
	vm_region_flavor_t flavor = VM_REGION_BASIC_INFO_64;
	vm_region_basic_info_data_64_t info;
	kr = vm_region_64 (task, &addr, &vmsize, flavor, (vm_region_info_t)&info, &info_count, &object);
	return (kr != KERN_SUCCESS ? 0 : info.protection);
}

static int tsk_pagesize(RIODesc *desc) {
	int tid = __get_pid (desc);
	task_t task = pid_to_task (desc, tid);
	static vm_size_t pagesize = 0;
	return pagesize
		? pagesize
		: (host_page_size (task, &pagesize) == KERN_SUCCESS)
			? pagesize : 4096;
}

static vm_address_t tsk_getpagebase(RIODesc *desc, ut64 addr) {
	vm_address_t pagesize = tsk_pagesize (desc);
	return (addr & ~(pagesize - 1));
}

static bool tsk_setperm(RIO *io, task_t task, vm_address_t addr, int len, int perm) {
	kern_return_t kr;
	kr = vm_protect (task, addr, len, 0, perm);
	if (kr != KERN_SUCCESS) {
		perror ("tsk_setperm");
		return false;
	}
	return true;
}

static bool tsk_write(task_t task, vm_address_t addr, const ut8 *buf, int len) {
	kern_return_t kr = vm_write (task, addr, (vm_offset_t)buf, (mach_msg_type_number_t)len);
	if (kr != KERN_SUCCESS) {
		return false;
	}
	return true;
}

static int mach_write_at(RIO *io, RIODesc *desc, const void *buf, int len, ut64 addr) {
	vm_address_t vaddr = addr;
	vm_address_t pageaddr;
	vm_size_t pagesize;
	vm_size_t total_size;
	int operms = 0;
	int pid = __get_pid (desc);
	if (!desc || pid < 0) {
		return 0;
	}
	task_t task = pid_to_task (desc, pid);

	if (len < 1 || task_is_dead (desc, task)) {
		return 0;
	}
	pageaddr = tsk_getpagebase (desc, addr);
	pagesize = tsk_pagesize (desc);
	total_size = (len > pagesize)
		? pagesize * (1 + (len / pagesize))
		: pagesize;
	if (tsk_write (task, vaddr, buf, len)) {
		return len;
	}
	operms = tsk_getperm (io, task, pageaddr);
	if (!tsk_setperm (io, task, pageaddr, total_size, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY)) {
		eprintf ("io.mach: Cannot set page perms for %d byte(s) at 0x%08"
			PFMT64x"\n", (int)pagesize, (ut64)pageaddr);
		return -1;
	}
	if (!tsk_write (task, vaddr, buf, len)) {
		eprintf ("io.mach: Cannot write on memory\n");
		len = -1;
	}
	if (operms) {
		if (!tsk_setperm (io, task, pageaddr, total_size, operms)) {
			eprintf ("io.mach: Cannot restore page perms\n");
			return -1;
		}
	}
	return len;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	return mach_write_at (io, fd, buf, len, io->off);
}

static bool __plugin_open(RIO *io, const char *file, bool many) {
	return (!strncmp (file, "attach://", 9) || !strncmp (file, "mach://", 7));
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	RIODesc *ret = NULL;
	RIOMach *riom = NULL;
	const char *pidfile;
	char *pidpath, *endptr;
	int pid;
	task_t task;
	if (!__plugin_open (io, file, false) && !__plugin_open (io, (const char *)&file[1], false)) {
		return NULL;
	}
	pidfile = file + (file[0] == 'a' ? 9 : (file[0] == 's' ? 8 : 7));
	pid = (int)strtol (pidfile, &endptr, 10);
	if (endptr == pidfile || pid < 0) {
		return NULL;
	}
	task = pid_to_task (NULL, pid);
	if (task == -1) {
		return NULL;
	}
	if (!task) {
		if (pid > 0 && !strncmp (file, "smach://", 8)) {
			kill (pid, SIGKILL);
			eprintf ("Child killed\n");
		}
#if 0
		/* this is broken, referer gets set in the riodesc after this function returns the riodesc
		 * the pid > 0 check  doesn't seem to be reasonable to me too
		 * what was this intended to check anyway ? */
		if (pid > 0 && io->referer && !strncmp (io->referer, "dbg://", 6)) {
			eprintf ("Child killed\n");
			kill (pid, SIGKILL);
		}
#endif
		switch (errno) {
		case EPERM:
			eprintf ("Operation not permitted\n");
			break;
		case EINVAL:
			perror ("ptrace: Cannot attach");
			eprintf ("Possibly unsigned r2. Please see doc/macos.md\n");
			eprintf ("ERRNO: %d (EINVAL)\n", errno);
			break;
		default:
			eprintf ("unknown error in debug_attach\n");
			break;
		}
		return NULL;
	}
	RIOMachData *iodd = R_NEW0 (RIOMachData);
	if (iodd) {
		iodd->pid = pid;
		iodd->tid = pid;
		iodd->data = NULL;
	}
	riom = R_NEW0 (RIOMach);
	if (!riom) {
		R_FREE (iodd);
		return NULL;
	}
	riom->task = task;
	iodd->magic = r_str_hash ("mach");
	iodd->data = riom;
	// sleep 1s to get proper path (program name instead of ls) (racy)
	pidpath = pid
		? r_sys_pid_to_path (pid)
		: strdup ("kernel");
	if (!strncmp (file, "smach://", 8)) {
		ret = r_io_desc_new (io, &r_io_plugin_mach, &file[1],
			       rw | R_PERM_X, mode, iodd);
	} else {
		ret = r_io_desc_new (io, &r_io_plugin_mach, file,
			       rw | R_PERM_X, mode, iodd);
	}
	ret->name = pidpath;
	return ret;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case R_IO_SEEK_SET:
		io->off = offset;
		break;
	case R_IO_SEEK_CUR:
		io->off += offset;
		break;
	case R_IO_SEEK_END:
		io->off = ST64_MAX;
	}
	return io->off;
}

static int __close(RIODesc *fd) {
	if (!fd) {
		return false;
	}
	RIOMachData *iodd = fd->data;
	kern_return_t kr;
	if (!iodd) {
		return false;
	}
	if (iodd->magic != R_MACH_MAGIC) {
		return false;
	}
	task_t task = pid_to_task (fd, iodd->pid);
	kr = mach_port_deallocate (mach_task_self (), task);
	if (kr != KERN_SUCCESS) {
		perror ("__close io_mach");
	}
	R_FREE (fd->data);
	return kr == KERN_SUCCESS;
}

static char *__system(RIO *io, RIODesc *fd, const char *cmd) {
	if (!io || !fd || !cmd || !fd->data) {
		return NULL;
	}
	RIOMachData *iodd = fd->data;
	if (iodd->magic != R_MACH_MAGIC) {
		return NULL;
	}

	task_t task = pid_to_task (fd, iodd->tid);
	/* XXX ugly hack for testing purposes */
	if (!strcmp (cmd, "")) {
		return NULL;
	}
	if (!strncmp (cmd, "perm", 4)) {
		int perm = r_str_rwx (cmd + 4);
		if (perm) {
			int pagesize = tsk_pagesize (fd);
			tsk_setperm (io, task, io->off, pagesize, perm);
		} else {
			eprintf ("Usage: =!perm [rwx]\n");
		}
		return NULL;
	}
	if (!strncmp (cmd, "pid", 3)) {
		RIOMachData *iodd = fd->data;
		RIOMach *riom = iodd->data;
		const char *pidstr = cmd + 3;
		int pid = -1;
		if (*pidstr) {
			pid = __get_pid (fd);
			//return NULL;
		} else {
			eprintf ("%d\n", iodd->pid);
			return NULL;
		}
		if (!strcmp (pidstr, "0")) {
			pid = 0;
		} else {
			pid = atoi (pidstr);
			if (!pid) {
				pid = -1;
			}
		}
		if (pid != -1) {
			task_t task = pid_to_task (fd, pid);
			if (task != -1) {
				riom->task = task;
				iodd->pid = pid;
				iodd->tid = pid;
				return NULL;
			}
		}
		eprintf ("io_mach_system: Invalid pid %d\n", pid);
	} else {
		eprintf ("Try: '=!pid' or '=!perm'\n");
	}
	return NULL;
}

static int __get_pid (RIODesc *desc) {
	// dupe for ? r_io_desc_get_pid (desc);
	if (!desc || !desc->data) {
		return -1;
	}
	RIOMachData *iodd = desc->data;
	if (iodd) {
		if (iodd->magic != R_MACH_MAGIC) {
			return -1;
		}
		return iodd->pid;
	}
	return -1;
}

// TODO: rename ptrace to io_mach .. err io.ptrace ??
RIOPlugin r_io_plugin_mach = {
	.name = "mach",
	.desc = "Attach to mach debugger instance",
	.license = "LGPL",
	.uris = "attach://,mach://,smach://",
	.open = __open,
	.close = __close,
	.read = __read,
	.getpid = __get_pid,
	.gettid = __get_pid,
	.check = __plugin_open,
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

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_mach,
	.version = R2_VERSION
};
#endif
