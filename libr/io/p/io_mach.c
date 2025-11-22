/* radare - LGPL - Copyright 2009-2025 - pancake */

#include <r_userconf.h>

#include <r_io.h>
#include <r_lib.h>
#include <r_cons.h>
#include <r_core.h>

#if __APPLE__ && DEBUGGER

#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#include <mach/exception_types.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>
#include <mach/processor_set.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/vm_map.h>

static int __get_pid(RIODesc *desc);
#if APPLE_SDK_IPHONEOS
// missing includes
#else

#define EXCEPTION_PORT 0

// NOTE: mach/mach_vm is not available for iOS
#include <mach/mach_traps.h>
#include <mach/mach_error.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/ptrace.h>
#endif
#include <mach/task.h>
#include <mach/task_info.h>
#if defined(__x86_64__)
#include <mach/i386/thread_status.h>
#elif defined(__arm64__) || defined(__aarch64__)
#include <mach/arm/thread_status.h>
#endif

#define MACH_ERROR_STRING(ret) \
	(mach_error_string (ret)? mach_error_string (ret): "(unknown)")

#define R_MACH_MAGIC 0x5066a4c2

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
#define RIOMACH_PID(x) (x? ((RIOMach*) (x))->pid: -1)
#define RIOMACH_TASK(x) (x? ((RIOMach*) (x))->task: -1)
 */

int RIOMACH_TASK(RIOMachData *x) {
	// TODO
	return -1;
}

#undef R_IO_NFDS
#define R_IO_NFDS 2
extern int errno;

static task_t task_for_pid_workaround(int pid) {
	host_t myhost = mach_host_self ();
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
		R_LOG_DEBUG ("host_processor_set_priv failed with error 0x%x", kr);
		// mach_error ("host_processor_set_priv",kr);
		return MACH_PORT_NULL;
	}
	numTasks = 0;
	kr = processor_set_tasks (psDefault_control, &tasks, &numTasks);
	if (kr != KERN_SUCCESS) {
		R_LOG_DEBUG ("processor_set_tasks failed with error %x", kr);
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
	static R_TH_LOCAL task_t old_task = 0;
	static R_TH_LOCAL int old_pid = -1;
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
		// we changed the process pid so deallocate a ref from the old_task
		// since we are going to get a new task
		kr = mach_port_deallocate (mach_task_self (), old_task);
		if (kr != KERN_SUCCESS) {
			R_LOG_ERROR ("pid_to_task: fail to deallocate port");
			return 0;
		}
	}
	int err = task_for_pid (mach_task_self (), (pid_t)pid, &task);
	if ((err != KERN_SUCCESS) || !MACH_PORT_VALID (task)) {
		task = task_for_pid_workaround (pid);
		if (task == MACH_PORT_NULL) {
			task = task_for_pid_ios9pangu (pid);
			if (task != MACH_PORT_NULL) {
				// R_LOG_ERROR ("Failed to get task %d for pid %d", (int)task, (int)pid);
				// R_LOG_ERROR ("Missing priviledges? 0x%x: %s", err, MACH_ERROR_STRING (err));
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

static R_TH_LOCAL ut64 the_lower = UT64_MAX;

static ut64 getNextValid(RIO *io, RIODesc *fd, ut64 addr) {
	struct vm_region_submap_info_64 info;
	vm_address_t address = MACH_VM_MIN_ADDRESS;
	vm_size_t size = (vm_size_t)0;
	vm_size_t osize = (vm_size_t)0;
	natural_t depth = 0;
	kern_return_t kr;
	int tid = __get_pid (fd);
	task_t task = pid_to_task (fd, tid);
	ut64 lower = addr;
#if __arm64__ || __aarch64__ || __arm64e__
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
			&depth, (vm_region_recurse_info_t)&info, &info_count);
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
	if (dd->magic != R_MACH_MAGIC) {
		return -1;
	}
	memset (buf, io->Oxff, len);
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
		// blen = len;
		err = vm_read_overwrite (task,
			(ut64)io->off + copied, blen,
			(pointer_t)buf + copied, &size);
		switch (err) {
		case KERN_PROTECTION_FAILURE:
			R_LOG_DEBUG ("r_io_mach_read: kern protection failure");
			break;
		case KERN_INVALID_ADDRESS:
			if (blocksize == 1) {
				memset (buf + copied, io->Oxff, len - copied);
				return size + copied;
			}
			blocksize = 1;
			blen = 1;
			buf[copied] = io->Oxff;
			break;
		}
		if (err == -1 || size < 1) {
			return -1;
		}
		if (size == 0) {
			if (blocksize == 1) {
				memset (buf + copied, io->Oxff, len - copied);
				return len;
			}
			blocksize = 1;
			blen = 1;
			buf[copied] = io->Oxff;
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
	return (kr != KERN_SUCCESS? 0: info.protection);
}

static int tsk_pagesize(RIODesc *desc) {
	int tid = __get_pid (desc);
	task_t task = pid_to_task (desc, tid);
	static R_TH_LOCAL vm_size_t pagesize = 0;
	return pagesize
		? pagesize
		: (host_page_size (task, &pagesize) == KERN_SUCCESS)
		? pagesize
		: 4096;
}

static vm_address_t tsk_getpagebase(RIODesc *desc, ut64 addr) {
	vm_address_t pagesize = tsk_pagesize (desc);
	return (addr & ~ (pagesize - 1));
}

static bool tsk_setperm(RIO *io, task_t task, vm_address_t addr, int len, int perm) {
	kern_return_t kr;
	kr = vm_protect (task, addr, len, 0, perm);
	if (kr != KERN_SUCCESS) {
		r_sys_perror ("tsk_setperm");
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
		? pagesize *(1 + (len / pagesize))
		: pagesize;
	if (tsk_write (task, vaddr, buf, len)) {
		return len;
	}
	operms = tsk_getperm (io, task, pageaddr);
	if (!tsk_setperm (io, task, pageaddr, total_size, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY)) {
		R_LOG_ERROR ("io.mach: Cannot set page perms for %d byte(s) at 0x%08" PFMT64x, (int)pagesize, (ut64)pageaddr);
		return -1;
	}
	if (!tsk_write (task, vaddr, buf, len)) {
		R_LOG_ERROR ("io.mach: Cannot write on memory");
		len = -1;
	}
	if (operms) {
		if (!tsk_setperm (io, task, pageaddr, total_size, operms)) {
			R_LOG_ERROR ("io.mach: Cannot restore page perms");
			return -1;
		}
	}
	return len;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	return mach_write_at (io, fd, buf, len, io->off);
}

static bool __plugin_open(RIO *io, const char *file, bool many) {
	return r_str_startswith (file, "attach://") || r_str_startswith (file, "mach://");
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
	if (!r_sandbox_check (R_SANDBOX_GRAIN_EXEC)) {
		return NULL;
	}
	pidfile = file + (file[0] == 'a'? 9: (file[0] == 's'? 8: 7));
	pid = (int)strtol (pidfile, &endptr, 10);
	if (endptr == pidfile || pid < 0) {
		return NULL;
	}
	task = pid_to_task (NULL, pid);
	if (task == -1) {
		return NULL;
	}
	if (!task) {
		if (pid > 0 && r_str_startswith (file, "smach://")) {
			kill (pid, SIGKILL);
		}
#if 0
		/* this is broken, referer gets set in the riodesc after this function returns the riodesc
		 * the pid > 0 check  doesn't seem to be reasonable to me too
		 * what was this intended to check anyway? */
		if (pid > 0 && io->referer && !strncmp (io->referer, "dbg://", 6)) {
			R_LOG_INFO ("Child killed");
			kill (pid, SIGKILL);
		}
#endif
		switch (errno) {
		case EPERM:
			R_LOG_ERROR ("Operation not permitted");
			break;
		case EINVAL:
			r_sys_perror ("ptrace: Cannot attach");
			R_LOG_INFO ("Possibly unsigned r2. Please see doc/macos.md");
			break;
		default:
			R_LOG_ERROR ("unknown error in debug_attach");
			break;
		}
		return NULL;
	}
	RIOMachData *iodd = R_NEW0 (RIOMachData);
	iodd->pid = pid;
	iodd->tid = pid;
	iodd->data = NULL;
	riom = R_NEW0 (RIOMach);
	riom->task = task;
	iodd->magic = R_MACH_MAGIC;
	iodd->data = riom;
	// sleep 1s to get proper path (program name instead of ls) (racy)
	pidpath = pid? r_sys_pid_to_path (pid): strdup ("kernel");
	if (r_str_startswith (file, "smach://")) {
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
		io->off = UT64_MAX;
		break;
	}
	return io->off;
}

static bool __close(RIODesc *fd) {
	if (!fd) {
		return false;
	}
	RIOMachData *iodd = fd->data;
	if (!iodd) {
		return false;
	}
	if (iodd->magic != R_MACH_MAGIC) {
		return false;
	}
	task_t task = pid_to_task (fd, iodd->pid);
	kern_return_t kr = mach_port_deallocate (mach_task_self (), task);
	if (kr != KERN_SUCCESS) {
		r_sys_perror ("__close io_mach");
	}
	R_FREE (fd->data);
	return kr == KERN_SUCCESS;
}

static char *mach_get_tls(RIO *io, RIODesc *fd, int tid) {
	task_t task = pid_to_task (fd, tid);
	if (!task) {
		R_LOG_ERROR ("Cannot get task");
		return NULL;
	}
	thread_array_t threads = NULL;
	mach_msg_type_number_t thread_count = 0;
	kern_return_t kr = task_threads (task, &threads, &thread_count);
	if (kr != KERN_SUCCESS) {
		R_LOG_ERROR ("Cannot get threads: %s", MACH_ERROR_STRING (kr));
		return NULL;
	}
	if (thread_count == 0) {
		R_LOG_ERROR ("No threads found");
		return NULL;
	}
	// Use the first thread (assuming single-threaded or main thread)
	thread_t thread = threads[0];
	ut64 tls_addr = 0;
	ut64 tlb_addr = 0;

#if defined(__x86_64__)
	x86_thread_state64_t state;
	mach_msg_type_number_t count = x86_THREAD_STATE64_COUNT;
	kr = thread_get_state (thread, x86_THREAD_STATE64, (thread_state_t)&state, &count);
	if (kr == KERN_SUCCESS) {
		tls_addr = state.__fs;
	} else {
		R_LOG_ERROR ("Cannot get thread state: %s", MACH_ERROR_STRING (kr));
	}
#elif defined(__arm64__) || defined(__aarch64__)
	struct thread_identifier_info info;
	mach_msg_type_number_t count = THREAD_IDENTIFIER_INFO_COUNT;
	kr = thread_info (thread, THREAD_IDENTIFIER_INFO, (thread_info_t)&info, &count);
	if (kr == KERN_SUCCESS) {
		tlb_addr = info.thread_handle;
	} else {
		R_LOG_ERROR ("Cannot get thread state: %s", MACH_ERROR_STRING (kr));
	}

	arm_thread_state64_t state;
	count = ARM_THREAD_STATE64_COUNT;
	kr = thread_get_state (thread, ARM_THREAD_STATE64, (thread_state_t)&state, &count);
	if (kr == KERN_SUCCESS) {
		tls_addr = state.__tpidr_el0;
	} else {
		R_LOG_ERROR ("Cannot get thread state: %s", MACH_ERROR_STRING (kr));
	}
#else
	R_LOG_ERROR ("TLS retrieval not implemented for this architecture");
#endif

	// Clean up
	vm_deallocate (mach_task_self (), (vm_address_t)threads, thread_count * sizeof (thread_t));

	if (tls_addr || tlb_addr) {
		return r_str_newf ("f tls=0x%" PFMT64x "\nf tlb=0x%"PFMT64x"\n", tls_addr, tlb_addr);
	}
	return NULL;
}

static char *__system(RIO *io, RIODesc *fd, const char *cmd) {
	R_RETURN_VAL_IF_FAIL (io && fd, NULL);
	if (!cmd || !fd->data) {
		return NULL;
	}
	RIOMachData *iodd = fd->data;
	if (iodd->magic != R_MACH_MAGIC) {
		return NULL;
	}
	if (!strcmp (cmd, "")) {
		return NULL;
	}
	if (r_str_startswith (cmd, "perm")) {
		int perm = r_str_rwx (cmd + 4);
		if (perm >= 0) {
			int pagesize = tsk_pagesize (fd);
			task_t task = pid_to_task (fd, iodd->tid);
			tsk_setperm (io, task, io->off, pagesize, perm);
		} else {
			R_LOG_ERROR ("Usage: :perm [rwx]");
		}
		return NULL;
	}
	if (r_str_startswith (cmd, "tls")) {
		int tid = r_num_get (NULL, cmd + 3);
		if (tid < 1) {
			tid = iodd->tid;
		}
		char *tls_output = mach_get_tls (io, fd, tid);
		if (tls_output) {
			io->cb_printf ("%s", tls_output);
			free (tls_output);
		} else {
			R_LOG_ERROR ("Cannot find the tls for tid=%d", tid);
		}
	} else if (r_str_startswith (cmd, "pid")) {
		RIOMachData *iodd = fd->data;
		RIOMach *riom = iodd->data;
		const char *pidstr = r_str_trim_head_ro (cmd + 3);
		if (R_STR_ISEMPTY (pidstr)) {
			io->cb_printf ("%d\n", iodd->pid);
			return NULL;
		}
		int pid = __get_pid (fd);
		if (!strcmp (pidstr, "0")) {
			pid = 0;
		} else {
			pid = atoi (pidstr);
			if (pid < 1) {
				pid = -1;
			}
		}
		if (pid >= 0) {
			task_t task = pid_to_task (fd, pid);
			if (task != -1) {
				riom->task = task;
				iodd->pid = pid;
				iodd->tid = pid;
				return NULL;
			}
		}
		R_LOG_ERROR ("Invalid pid %d", pid);
	} else {
		eprintf ("Try: ':pid', ':tls' or ':perm'\n");
	}
	return NULL;
}

static int __get_pid(RIODesc *desc) {
	// dupe for? r_io_desc_get_pid (desc);
	if (desc) {
		RIOMachData *iodd = desc->data;
		if (iodd) {
			if (iodd->magic != R_MACH_MAGIC) {
				return -1;
			}
			return iodd->pid;
		}
	}
	return -1;
}

RIOPlugin r_io_plugin_mach = {
	.meta = {
		.name = "mach",
		.author = "pancake",
		.desc = "Attach to mach debugger instance",
		.license = "LGPL-3.0-only",
	},
	.uris = "attach://,mach://,smach://",
	.open = __open,
	.close = __close,
	.read = __read,
	.getpid = __get_pid,
	.gettid = __get_pid,
	.check = __plugin_open,
	.seek = __lseek,
	.system = __system,
	.write = __write,
	.isdbg = true
};

#else
RIOPlugin r_io_plugin_mach = {
	.meta = {
		.name = "mach",
		.author = "pancake",
		.desc = "mach debug io (unsupported in this platform)",
		.license = "LGPL-3.0-only" },
};
#endif

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_mach,
	.version = R2_VERSION
};
#endif
