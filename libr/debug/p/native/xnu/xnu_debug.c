/* radare - LGPL - Copyright 2015 - pancake */

#if TARGET_OS_IPHONE
#define XNU_USE_PTRACE 0
#else
#define XNU_USE_PTRACE 1
#endif

#if 1
#undef XNU_USE_PTRACE
#define XNU_USE_PTRACE 1
#define XNU_USE_EXCTHR 0
#endif


// ------------------------------------

#include <r_debug.h>
#include <r_asm.h>
#include <r_reg.h>
#include <r_lib.h>
#include <r_anal.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>
#include "xnu_debug.h"
#include "xnu_threads.c"

#if XNU_USE_EXCTHR
#include "xnu_excthreads.c"
#endif

#include "trap_x86.c"
#include "trap_arm.c"

static thread_t getcurthread (RDebug *dbg, task_t *task) {
	thread_array_t threads = NULL;
	unsigned int n_threads = 0;
	task_t t = pid_to_task (dbg->pid);
	if (task) *task = t;
	if (task_threads (t, &threads, &n_threads))
		return -1;
	if (n_threads < 1)
		return -1;
	if (n_threads > 1)
		eprintf ("THREADS: %d\n", n_threads);
	return threads[0];
}

static bool hwstep_enable(RDebug *dbg, bool enable) {
	return xnu_native_hwstep_enable (dbg, enable);
}

static task_t task_for_pid_workaround(int Pid) {
	host_t myhost = mach_host_self();
	mach_port_t psDefault = 0;
	mach_port_t psDefault_control = 0;
	task_array_t tasks = NULL;
	mach_msg_type_number_t numTasks = 0;
	kern_return_t kr;
	int i;
	if (Pid == -1) return -1;

	kr = processor_set_default (myhost, &psDefault);
	if (kr != KERN_SUCCESS) return -1;

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

	/* kernel task */
	if (Pid == 0) return tasks[0];

	for (i = 0; i < numTasks; i++) {
		int pid;
		pid_for_task (i, &pid);
		if (pid == Pid) return (tasks[i]);
	}
	return -1;
}

bool xnu_step(RDebug *dbg) {
	int ret = false;
#if __arm__ || __arm64__ || __aarch64__
	// op-not-permitted ret = ptrace (PT_STEP, dbg->pid, (caddr_t)1, 0); //SIGINT
	task_t task;
	hwstep_enable (dbg, true);
	task = pid_to_task (dbg->pid);
	if (task<1) {
		perror ("pid_to_task");
		eprintf ("step failed on task %d for pid %d\n", task, dbg->tid);
	}
	if (task_resume (task) != KERN_SUCCESS) {
		perror ("thread_resume");
	} else {
		ret = true;
		waitpid (dbg->pid, NULL, 0);
	}
#if 0
	if (thread_resume (dbg->tid) == KERN_SUCCESS) {
		ret = true;
	} else perror ("thread_resume");
#endif
	hwstep_enable (dbg, false);
//	eprintf ("thu %d\n", ptrace (PT_THUPDATE, dbg->pid, (void*)0, 0));
#else
#if XNU_USE_PTRACE
	ret = ptrace (PT_STEP, dbg->pid, (caddr_t)1, 0) == 0; //SIGINT
	if (!ret) {
		perror ("ptrace-step");
		eprintf ("mach-error: %d, %s\n", ret, MACH_ERROR_STRING (ret));
	}
#else
#if 0
	task_t task;
	thread_t th = getcurthread (dbg, &task);
	task_resume (task);
#endif
	task_t task = pid_to_task (dbg->pid);
	if (task<1) {
		perror ("pid_to_task");
		eprintf ("step failed on task %d for pid %d\n", task, dbg->tid);
	}
	hwstep_enable (dbg, true);
	if (task_resume (task) != KERN_SUCCESS) {
		perror ("thread_resume");
	} else {
		ret = true;
		waitpid (dbg->pid, NULL, 0);
	}
#if 0
	if (thread_resume (dbg->tid) == KERN_SUCCESS) {
		ret = true;
	} else perror ("thread_resume");
	int rc = ptrace (PT_THUPDATE, dbg->pid, thport, );
	if (rc) perror ("PT_THUPDATE");
#endif
	hwstep_enable (dbg, false);
#endif
#endif
	return ret;
}

int xnu_attach(RDebug *dbg, int pid) {
//this should be necessary
#if XNU_USE_PTRACE
	//XXX it seems that PT_ATTACH will be deprecated
	//but using PT_ATTACHEXC throw errors
	if (ptrace (PT_ATTACH, pid, 0, 0) == -1) {
		perror ("ptrace (PT_ATTACH)");
		return -1;
	}
	int rc = ptrace (PT_ATTACHEXC, pid, 0, 0);
	if (rc) perror ("PT_THUPDATE");
	// TODO: move into attach
#if XNU_USE_EXCTHR
	xnu_create_exception_thread(dbg);
#endif
#endif
	return pid;
}

int xnu_dettach(int pid) {
	return ptrace (PT_DETACH, pid, NULL, 0);
}

int xnu_continue(RDebug *dbg, int pid, int tid, int sig) {
#if __arm__ || __arm64__ || __aarch64__
	task_t task;
	thread_t th = getcurthread (dbg, &task);
	task_resume (task);
	thread_resume (th);
	//return xnu_dettach (pid);
	return true;
#else
	void *data = (void*)(size_t)((sig != -1) ? sig : dbg->reason.signum);
	task_resume (pid_to_task (pid));
	return ptrace (PT_CONTINUE, pid, (void*)(size_t)1,
			(int)(size_t)data) == 0;
#endif
}

const char *xnu_reg_profile(RDebug *dbg) {
#if __i386__ || __x86_64__
	if (dbg->bits & R_SYS_BITS_32) {
#		include "reg/darwin-x86.h"
	} else if (dbg->bits == R_SYS_BITS_64) {
#		include "reg/darwin-x64.h"
	} else {
		eprintf ("invalid bit size\n");
		return NULL;
	}
#elif __POWERPC__
#	include "reg/darwin-ppc.h"
#elif __APPLE__ && (__aarch64__ || __arm64__ || __arm__)
	if (dbg->bits == R_SYS_BITS_64) {
#		include "reg/darwin-arm64.h"
	} else {
#		include "reg/darwin-arm.h"
	}
#else
#error "Unsupported Apple architecture"
#endif
}

static xnu_thread_t* get_xnu_thread(RDebug *dbg, int tid) {
	task_t task;
	RListIter *it = NULL;
	if (!dbg) return false;
	if (!xnu_update_thread_list (dbg)) {
		eprintf ("Failed to update thread_list xnu_reg_write\n");
		return NULL;
	}
	//TODO get the current thread
	it = r_list_find (dbg->threads, (const void *)(size_t)&tid,
		(RListComparator)&thread_find);
	if (it) return (xnu_thread_t *)it->data;
	tid = dbg->tid = getcurthread (dbg, &task);
	it = r_list_find (dbg->threads, (const void *)(size_t)&tid,
		(RListComparator)&thread_find);
	if (it) return (xnu_thread_t *)it->data;
	eprintf ("Thread not found xnu_reg_write\n");
	return NULL;
}

int xnu_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
	int ret;
	xnu_thread_t *th = get_xnu_thread (dbg, dbg->tid);
	switch (type) {
	case R_REG_TYPE_DRX:
		memcpy (&th->drx, buf, R_MIN (size, sizeof (th->drx)));
		ret = xnu_thread_set_drx (dbg, th);
		break;
	default:
		//th->gpr has a header and the state we should copy on the state only
		memcpy (&th->gpr.uts, buf, R_MIN (size, sizeof (th->gpr.uts)));
		ret = xnu_thread_set_gpr (dbg, th);
		break;
	}
	return ret;
}

int xnu_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	bool ret;
	xnu_thread_t *th = get_xnu_thread (dbg, dbg->tid);
	switch (type) {
	case R_REG_TYPE_SEG:
	case R_REG_TYPE_FLG:
	case R_REG_TYPE_GPR:
		ret = xnu_thread_get_gpr (dbg, th);
		break;
	case R_REG_TYPE_DRX:
		ret = xnu_thread_get_drx (dbg, th);
		break;
	default:
		return 0;
	}
	if (!ret) {
		perror ("xnu_reg_read");
		return 0;
	}
	if (th->state) {
		int rsz = R_MIN (th->state_size, size);
		memcpy (buf, th->state, rsz);
		return rsz;
	}
	return 0;
}

RDebugMap *xnu_map_alloc(RDebug *dbg, ut64 addr, int size) {
	kern_return_t ret;
	ut8 *base = (ut8 *)addr;
	bool anywhere = !VM_FLAGS_ANYWHERE;

	if (addr == -1) anywhere = VM_FLAGS_ANYWHERE;

	ret = vm_allocate (pid_to_task (dbg->tid),
			(vm_address_t*)&base,
			(vm_size_t)size,
			anywhere);

	if (ret != KERN_SUCCESS) {
		printf("vm_allocate failed\n");
		return NULL;
	}
	r_debug_map_sync (dbg); // update process memory maps
	return r_debug_map_get (dbg, (ut64)base);
}

int xnu_map_dealloc (RDebug *dbg, ut64 addr, int size) {
	int ret = vm_deallocate (pid_to_task (dbg->tid),
		(vm_address_t)addr, (vm_size_t)size);
	if (ret != KERN_SUCCESS) {
		perror ("vm_deallocate");
		return false;
	}
	return true;
}

RDebugInfo *xnu_info (RDebug *dbg, const char *arg) {
	RDebugInfo *rdi = R_NEW0 (RDebugInfo);
	if (!rdi) return NULL;
	rdi->status = R_DBG_PROC_SLEEP; // TODO: Fix this
	rdi->pid = dbg->pid;
	rdi->tid = dbg->tid;
	rdi->uid = -1;// TODO
	rdi->gid = -1;// TODO
	return rdi;
}

/*
static void xnu_free_threads_ports (RDebugPid *p) {
	kern_return_t kr;
	if (!p) return;
	free (p->path);
	if (p->pid != old_pid) {
		kr = mach_port_deallocate (old_pid, p->pid);
		if (kr != KERN_SUCCESS) {
			eprintf ("error mach_port_deallocate in "
				"xnu_free_threads ports\n");
		}
	}
}
*/
RList *xnu_thread_list (RDebug *dbg, int pid, RList *list) {
#if __arm__ || __arm64__ || __aarch_64__
	#define CPU_PC (dbg->bits == R_SYS_BITS_64) ? \
		state.ts_64.__pc : state.ts_32.__pc
#elif __POWERPC__
	#define CPU_PC state.srr0
#elif __x86_64__ || __i386__
	#define CPU_PC (dbg->bits == R_SYS_BITS_64) ? \
		state.uts.ts64.__rip : state.uts.ts32.__eip
#endif
	RListIter *iter;
	xnu_thread_t *thread;
	R_REG_T state;
	xnu_update_thread_list (dbg);
	list->free = (RListFree)&r_debug_pid_free;
	r_list_foreach (dbg->threads, iter, thread) {
		if (!xnu_thread_get_gpr (dbg, thread)) {
			eprintf ("Failed to get gpr registers xnu_thread_list\n");
			continue;
		}
		thread->state_size = sizeof (thread->gpr);
		memcpy (&state, &thread->gpr, sizeof (R_REG_T));
		r_list_append (list, r_debug_pid_new (thread->name,
			thread->tid, 's', CPU_PC));
	}
	return list;
}

#if 0
static vm_prot_t unix_prot_to_darwin(int prot) {
        return ((prot & 1 << 4) ? VM_PROT_READ : 0 |
                (prot & 1 << 2) ? VM_PROT_WRITE : 0 |
                (prot & 1 << 1) ? VM_PROT_EXECUTE : 0);
}
#endif

int xnu_map_protect (RDebug *dbg, ut64 addr, int size, int perms) {
	int ret;
	// TODO: align pointers
	ret = vm_protect (pid_to_task (dbg->tid),
			(vm_address_t)addr,
			(vm_size_t)size,
			(boolean_t)0, /* maximum protection */
			VM_PROT_COPY|perms); //unix_prot_to_darwin (perms));
	if (ret != KERN_SUCCESS) {
		printf("vm_protect failed\n");
		return false;
	}
	return true;
}

task_t pid_to_task (int pid) {
	static task_t old_task = -1;
	static task_t old_pid = -1;
	task_t task = -1;
	int err;

	/* xlr8! */
	if (old_task != -1 && old_pid == pid)
		return old_task;

	err = task_for_pid (mach_task_self (), (pid_t)pid, &task);
	if ((err != KERN_SUCCESS) || !MACH_PORT_VALID (task)) {
		task = task_for_pid_workaround (pid);
		if (task == -1) {
			eprintf ("Failed to get task %d for pid %d.\n",
				(int)task, (int)pid);
			eprintf ("Reason: 0x%x: %s\n", err,
				(char *)MACH_ERROR_STRING (err));
			eprintf ("You probably need to run as root or sign "
				"the binary.\n Read doc/ios.md || doc/osx.md\n"
				" make -C binr/radare2 ios-sign || osx-sign\n");
			return -1;
		}
	}
	old_pid = pid;
	old_task = task;
	return task;
}

RDebugPid *xnu_get_pid (int pid) {
	int psnamelen, foo, nargs, mib[3];
	size_t size, argmax = 4096;
	char *curr_arg, *start_args, *iter_args, *end_args;
	char *procargs = NULL;
	char psname[4096];
#if 0
	/* Get the maximum process arguments size. */
	mib[0] = CTL_KERN;
	mib[1] = KERN_ARGMAX;
	size = sizeof(argmax);
	if (sysctl (mib, 2, &argmax, &size, NULL, 0) == -1) {
		eprintf ("sysctl() error on getting argmax\n");
		return NULL;
	}
#endif
	/* Allocate space for the arguments. */
	procargs = (char *)malloc (argmax);
	if (procargs == NULL) {
		eprintf ("getcmdargs(): insufficient memory for procargs %d\n",
			(int)(size_t)argmax);
		return NULL;
	}

	/*
	 * Make a sysctl() call to get the raw argument space of the process.
	 */
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROCARGS2;
	mib[2] = pid;

	size = argmax;
	procargs[0] = 0;
	if (sysctl (mib, 3, procargs, &size, NULL, 0) == -1) {
		if (EINVAL == errno) { // invalid == access denied for some reason
			//eprintf("EINVAL returned fetching argument space\n");
			free (procargs);
			return NULL;
		}
		eprintf ("sysctl(): unspecified sysctl error - %i\n", errno);
		free (procargs);
		return NULL;
	}

	// copy the number of argument to nargs
	memcpy (&nargs, procargs, sizeof(nargs));
	iter_args =  procargs + sizeof(nargs);
	end_args = &procargs[size-30]; // end of the argument space
	if (iter_args >= end_args) {
		eprintf ("getcmdargs(): argument length mismatch");
		free (procargs);
		return NULL;
	}

	//TODO: save the environment variables to envlist as well
	// Skip over the exec_path and '\0' characters.
	// XXX: fix parsing
#if 0
	while (iter_args < end_args && *iter_args != '\0') { iter_args++; }
	while (iter_args < end_args && *iter_args == '\0') { iter_args++; }
#endif
	if (iter_args == end_args) {
		free (procargs);
		return NULL;
	}
	/* Iterate through the '\0'-terminated strings and add each string
	 * to the Python List arglist as a Python string.
	 * Stop when nargs strings have been extracted.  That should be all
	 * the arguments.  The rest of the strings will be environment
	 * strings for the command.
	 */
	curr_arg = iter_args;
	start_args = iter_args; //reset start position to beginning of cmdline
	foo = 1;
	*psname = 0;
	psnamelen = 0;
	while (iter_args < end_args && nargs > 0) {
		if (*iter_args++ == '\0') {
			int alen = strlen (curr_arg);
			if (foo) {
				memcpy (psname, curr_arg, alen+1);
				foo = 0;
			} else {
				psname[psnamelen] = ' ';
				memcpy (psname+psnamelen+1, curr_arg, alen+1);
			}
			psnamelen += alen;
			//printf("arg[%i]: %s\n", iter_args, curr_arg);
			/* Fetch next argument */
			curr_arg = iter_args;
			nargs--;
		}
	}
#if 1
	/*
	 * curr_arg position should be further than the start of the argspace
	 * and number of arguments should be 0 after iterating above. Otherwise
	 * we had an empty argument space or a missing terminating \0 etc.
	 */
	if (curr_arg == start_args || nargs > 0) {
		psname[0] = 0;
//		eprintf ("getcmdargs(): argument parsing failed");
		free (procargs);
		return NULL;
	}
#endif
	return r_debug_pid_new (psname, pid, 's', 0); // XXX 's' ??, 0?? must set correct values
}

kern_return_t mach_vm_region_recurse (
	vm_map_t target_task,
	mach_vm_address_t *address,
	mach_vm_size_t *size,
	natural_t *nesting_depth,
	vm_region_recurse_info_t info,
	mach_msg_type_number_t *infoCnt
);

static const char * unparse_inheritance (vm_inherit_t i) {
	switch (i) {
	case VM_INHERIT_SHARE: return "share";
	case VM_INHERIT_COPY: return "copy";
	case VM_INHERIT_NONE: return "none";
	default: return "???";
	}
}

#ifndef KERNEL_LOWER
#define ADDR "%8x"
#define HEADER_SIZE 0x1000
#define IMAGE_OFFSET 0x201000
#define KERNEL_LOWER 0x80000000
#endif

//it's not used (yet)
vm_address_t get_kernel_base(task_t ___task) {
	kern_return_t ret;
	task_t task;
	vm_region_submap_info_data_64_t info;
	ut64 size;
	mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
	unsigned int depth = 0;
	ut64 addr = KERNEL_LOWER;         // lowest possible kernel base address
	int count;

	ret = task_for_pid (mach_task_self(), 0, &task);
	if (ret != KERN_SUCCESS) return 0;
	ut64 naddr;
	eprintf ("%d vs %d\n", task, ___task);
	for (count=128; count; count--) {
		// get next memory region
		naddr = addr;
		ret = vm_region_recurse_64 (task, (vm_address_t*)&naddr,
					   (vm_size_t*)&size, &depth,
					   (vm_region_info_t)&info, &info_count);
		if (ret != KERN_SUCCESS) break;
		if (size<1) break;
		if (addr == naddr) {
			addr += size;
			continue;
		}
		eprintf ("0x%08"PFMT64x" size 0x%08"PFMT64x" perm 0x%x\n",
			(ut64)addr, (ut64)size, info.max_protection);
		// the kernel maps over a GB of RAM at the address where it maps
		// itself so we use that fact to detect it's position
		if (size > 1024 * 1024 * 1024) {
			return addr + IMAGE_OFFSET;
		}
		addr += size;
	}
	return (vm_address_t)0;
}

extern int proc_regionfilename(int pid, uint64_t address,
			      void * buffer, uint32_t buffersize);

#define MAX_MACH_HEADER_SIZE (64 * 1024)
#define DYLD_INFO_COUNT 5
#define DYLD_INFO_LEGACY_COUNT 1
#define DYLD_INFO_32_COUNT 3
#define DYLD_INFO_64_COUNT 5
#define DYLD_IMAGE_INFO_32_SIZE 12
#define DYLD_IMAGE_INFO_64_SIZE 24

typedef struct {
	ut32 version;
	ut32 info_array_count;
	ut32 info_array;
} DyldAllImageInfos32;
typedef struct {
	ut32 image_load_address;
	ut32 image_file_path;
	ut32 image_file_mod_date;
} DyldImageInfo32;
typedef struct {
	ut32 version;
	ut32 info_array_count;
	ut64 info_array;
} DyldAllImageInfos64;
typedef struct {
	ut64 image_load_address;
	ut64 image_file_path;
	ut64 image_file_mod_date;
} DyldImageInfo64;

#if 0
static int xnu_get_bits (RDebug *dbg) {
	struct task_dyld_info info;
	mach_msg_type_number_t count;
	kern_return_t kr;
	count = TASK_DYLD_INFO_COUNT;
	task_t task = pid_to_task (dbg->tid);

	kr = task_info (task, TASK_DYLD_INFO, (task_info_t) &info, &count);
	if (kr != KERN_SUCCESS) return 0;

	if (info.all_image_info_format == TASK_DYLD_ALL_IMAGE_INFO_64) {
		return 64;
	}
	return 32; // 16 for ARM?
}
#endif

// TODO: Implement mach0 size.. maybe copypasta from rbin?
static int mach0_size (RDebug *dbg, ut64 addr) {
	return 4096;
#if 0
	int size = 4096;
	ut8 header[MAX_MACH_HEADER_SIZE];

	dbg->iob.read_at (dbg->iob.io, addr, header, sizeof (header));
	p = first_command;
	for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++) {
		const struct load_command * lc = (struct load_command *) p;
		if (lc->cmd == GUM_LC_SEGMENT) {
			gum_segment_command_t * sc = (gum_segment_command_t *) lc;
			size += sc->vmsize;
		}

		p += lc->cmdsize;
	}
	return size;
#endif
}

static void xnu_map_free(RDebugMap *map) {
	if (!map) return;
	free (map->name);
	free (map->file);
	free (map);
}

static RList *xnu_dbg_modules(RDebug *dbg) {
	struct task_dyld_info info;
	mach_msg_type_number_t count;
	kern_return_t kr;
	int size, info_array_count, info_array_size, i;
	ut64 info_array_address;
	void *info_array = NULL;
	//void *header_data = NULL;
	char file_path[MAXPATHLEN];
	count = TASK_DYLD_INFO_COUNT;
	task_t task = pid_to_task (dbg->tid);
	ut64 addr, file_path_address;
	RDebugMap *mr = NULL;
	RList *list = NULL;

	kr = task_info (task, TASK_DYLD_INFO, (task_info_t) &info, &count);
	if (kr != KERN_SUCCESS)
		return NULL;

	if (info.all_image_info_format == TASK_DYLD_ALL_IMAGE_INFO_64) {
		DyldAllImageInfos64 all_infos;
		dbg->iob.read_at (dbg->iob.io, info.all_image_info_addr,
			(ut8*)&all_infos, sizeof (DyldAllImageInfos64));
		info_array_count = all_infos.info_array_count;
		info_array_size = info_array_count * DYLD_IMAGE_INFO_64_SIZE;
		info_array_address = all_infos.info_array;
	} else {
		DyldAllImageInfos32 all_info;
		dbg->iob.read_at (dbg->iob.io, info.all_image_info_addr,
			(ut8*)&all_info, sizeof (DyldAllImageInfos32));
		info_array_count = all_info.info_array_count;
		info_array_size = info_array_count * DYLD_IMAGE_INFO_32_SIZE;
		info_array_address = all_info.info_array;
	}

	if (info_array_address == 0) return NULL;

	info_array = malloc (info_array_size);
	if (!info_array) {
		eprintf ("Cannot allocate info_array_size %d\n",
			info_array_size);
		return NULL;
	}

	dbg->iob.read_at (dbg->iob.io, info_array_address,
			info_array, info_array_size);

	list = r_list_new ();
	if (!list) {
		free (info_array);
		return NULL;
	}
	list->free = (RListFree)xnu_map_free;
	for (i=0; i < info_array_count; i++) {
		if (info.all_image_info_format == TASK_DYLD_ALL_IMAGE_INFO_64) {
			DyldImageInfo64 * info = info_array + \
						(i * DYLD_IMAGE_INFO_64_SIZE);
			addr = info->image_load_address;
			file_path_address = info->image_file_path;
		} else {
			DyldImageInfo32 * info = info_array + \
						(i * DYLD_IMAGE_INFO_32_SIZE);
			addr = info->image_load_address;
			file_path_address = info->image_file_path;
		}
		dbg->iob.read_at (dbg->iob.io, file_path_address,
				(ut8*)file_path, MAXPATHLEN);
		//eprintf ("--> %d 0x%08"PFMT64x" %s\n", i, addr, file_path);
		size = mach0_size (dbg, addr);
		mr = r_debug_map_new (file_path, addr, addr + size, 7, 0);
		if (mr == NULL) {
			free (info_array);
			eprintf ("Cannot create r_debug_map_new\n");
			break;
		}
		mr->file = strdup (file_path);
		r_list_append (list, mr);
	}
	free (info_array);
	return list;
}

RList *xnu_dbg_maps(RDebug *dbg, int only_modules) {
	//bool contiguous = false;
	//ut32 oldprot = UT32_MAX;
	//ut32 oldmaxprot = UT32_MAX;
	char buf[1024];
	char module_name[MAXPATHLEN];
	mach_vm_address_t address = MACH_VM_MIN_ADDRESS;
	mach_vm_size_t size = (mach_vm_size_t) 0;
	mach_vm_size_t osize = (mach_vm_size_t) 0;
	natural_t depth = 0;
	int tid = dbg->pid;
	task_t task = pid_to_task (tid);
	RDebugMap *mr = NULL;
	RList *list = NULL;
	int i = 0;
	if (only_modules) return xnu_dbg_modules (dbg);

#if __arm64__ || __aarch64__
	size = osize = 16384; // acording to frida
#else
	size = osize = 4096;
#endif
#if 0
	if (dbg->pid == 0) {
		vm_address_t base = get_kernel_base (task);
		eprintf ("Kernel Base Address: 0x%"PFMT64x"\n", (ut64)base);
		return NULL;
	}
#endif
	list = r_list_new ();
	if (!list) return NULL;
	list->free = (RListFree)xnu_map_free;
	kern_return_t kr;
	for (;;) {
		struct vm_region_submap_info_64 info;
		mach_msg_type_number_t info_count;

		info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
		memset (&info, 0, sizeof (info));
		kr = mach_vm_region_recurse (task, &address, &size, &depth,
					(vm_region_recurse_info_t) &info,
					&info_count);

		if (kr != KERN_SUCCESS) break;
		if (info.is_submap) {
			depth++;
			continue;
		}
		{
			module_name[0] = 0;
			int ret = proc_regionfilename (tid, address,
				module_name, sizeof(module_name));
			module_name[ret] = 0;
		}
#if 0
		oldprot = info.protection;
		oldmaxprot = info.max_protection;
// contiguous pages seems to hide some map names
		if (mr) {
			if (address == mr->addr + mr->size) {
				if (oldmaxprot == info.max_protection) {
					contiguous = false;
				} else if (oldprot != UT32_MAX && oldprot == info.protection) {
					/* expand region */
					mr->size += size;
					contiguous = true;
				} else {
					contiguous = false;
				}
			} else {
				contiguous = false;
			}
		} else contiguous = false;
		//if (info.max_protection == oldprot && !contiguous)
#endif
		if (true) {
			#define xwr2rwx(x) ((x&1)<<2) | (x&2) | ((x&4)>>2)
			char maxperm[32];
			char depthstr[32];
			if (depth>0) {
				snprintf (depthstr, sizeof (depthstr), "_%d", depth);
			} else depthstr[0] = 0;

			if (info.max_protection != info.protection) {
				strcpy (maxperm, r_str_rwx_i (xwr2rwx (
					info.max_protection)));
			} else {
				maxperm[0] = 0;
			}
			// XXX: if its shared, it cannot be read?
			snprintf (buf, sizeof (buf), "%02x_%s%s%s%s%s%s%s%s",
				//r_str_rwx_i (xwr2rwx (info.max_protection)), i,
				i, unparse_inheritance (info.inheritance),
				info.user_tag? "_user": "",
				info.is_submap? "_sub": "",
				"", // info.inheritance? " inherit": "",
				info.is_submap ? "_submap": "",
				module_name, maxperm, depthstr);
				//info.shared ? "shar" : "priv",
				//info.reserved ? "reserved" : "not-reserved",
				//""); //module_name);
			mr = r_debug_map_new (buf, address, address+size,
					xwr2rwx (info.protection), 0);
			if (mr == NULL) {
				eprintf ("Cannot create r_debug_map_new\n");
				break;
			}
			if (*module_name) {
				mr->file = strdup (module_name);
			}
			i++;
			r_list_append (list, mr);
		}
		if (size < 1) {
			eprintf ("EFUCK\n");
			size = osize; // fuck
		}
		address += size;
		size = 0;
	}
	return list;
}
