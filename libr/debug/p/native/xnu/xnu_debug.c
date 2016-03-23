/* radare - LGPL - Copyright 2015-2016 - pancake, alvaro_fe */

#include <r_userconf.h>
#if DEBUGGER

#if XNU_USE_PTRACE
#define XNU_USE_EXCTHR 0
#else
#define XNU_USE_EXCTHR 1
#endif
// ------------------------------------

#include <r_debug.h>
#include <r_asm.h>
#include <r_reg.h>
#include <r_lib.h>
#include <r_anal.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>

static task_t task_dbg = 0;
#include "xnu_debug.h"
#include "xnu_threads.c"
#if XNU_USE_EXCTHR
#include "xnu_excthreads.c"
#endif

static thread_t getcurthread (RDebug *dbg) {
	thread_array_t threads = NULL;
	unsigned int n_threads = 0;
	task_t t = pid_to_task (dbg->pid);
	if (!t)
		return -1;
	if (task_threads (t, &threads, &n_threads))
		return -1;
	if (n_threads < 1)
		return -1;
	if (n_threads > 1)
		eprintf ("THREADS: %d\n", n_threads);
	return threads[0];
}


static xnu_thread_t* get_xnu_thread(RDebug *dbg, int tid) {
	RListIter *it = NULL;
	if (!dbg)
		return NULL;
	if (tid < 0)
		return NULL;
	if (!xnu_update_thread_list (dbg)) {
		eprintf ("Failed to update thread_list xnu_reg_write\n");
		return NULL;
	}
	//TODO get the current thread
	it = r_list_find (dbg->threads, (const void *)(size_t)&tid,
			  (RListComparator)&thread_find);
	if (it)
		return (xnu_thread_t *)it->data;
	tid = getcurthread (dbg);
	it = r_list_find (dbg->threads, (const void *)(size_t)&tid,
			  (RListComparator)&thread_find);
	if (it)
		return (xnu_thread_t *)it->data;
	eprintf ("Thread not found get_xnu_thread\n");
	return NULL;
}

static task_t task_for_pid_workaround(int Pid) {
	host_t myhost = mach_host_self();
	mach_port_t psDefault = 0;
	mach_port_t psDefault_control = 0;
	task_array_t tasks = NULL;
	mach_msg_type_number_t numTasks = 0;
	kern_return_t kr;
	int i;
	if (Pid == -1)
		return 0;

	kr = processor_set_default (myhost, &psDefault);
	if (kr != KERN_SUCCESS)
		return 0;

	kr = host_processor_set_priv (myhost, psDefault, &psDefault_control);
	if (kr != KERN_SUCCESS) {
		eprintf ("host_processor_set_priv failed with error 0x%x\n", kr);
		//mach_error ("host_processor_set_priv",kr);
		return 0;
	}

	numTasks = 0;
	kr = processor_set_tasks (psDefault_control, &tasks, &numTasks);
	if (kr != KERN_SUCCESS) {
		eprintf ("processor_set_tasks failed with error %x\n", kr);
		return 0;
	}

	/* kernel task */
	if (Pid == 0)
		return tasks[0];

	for (i = 0; i < numTasks; i++) {
		int pid;
		pid_for_task (i, &pid);
		if (pid == Pid)
			return (tasks[i]);
	}
	return 0;
}

static task_t task_for_pid_ios9pangu(int pid) {
	task_t task = MACH_PORT_NULL;
	host_get_special_port (mach_host_self (), HOST_LOCAL_NODE, 4, &task);
	return task;
}

int xnu_wait(RDebug *dbg, int pid) {
#if XNU_USE_PTRACE
	return R_DEBUG_REASON_UNKNOWN;
#else
	return __xnu_wait (dbg, pid);
#endif
}

bool xnu_step(RDebug *dbg) {
#if XNU_USE_PTRACE
	int ret = ptrace (PT_STEP, dbg->pid, (caddr_t)1, 0) == 0; //SIGINT
	if (!ret) {
		perror ("ptrace-step");
		eprintf ("mach-error: %d, %s\n", ret, MACH_ERROR_STRING (ret));
	}
	return ret;

#else
	int ret = 0;
	//we must find a way to get the current thread not just the first one
	task_t task = pid_to_task (dbg->pid);
	if (!task) {
		eprintf ("step failed on task %d for pid %d\n", task, dbg->tid);
		return false;
	}
	xnu_thread_t *th = get_xnu_thread (dbg, getcurthread (dbg));
	if (!th)
		return false;
	ret = set_trace_bit (dbg, th);
	if (!ret) {
		eprintf ("xnu_step modificy_trace_bit error\n");
		return false;
	}
	th->stepping = true;
	task_resume (task);
	return ret;
#endif
}

int xnu_attach(RDebug *dbg, int pid) {
#if XNU_USE_PTRACE
        if (ptrace (PT_ATTACH, pid, 0, 0) == -1) {
                perror ("ptrace (PT_ATTACH)");
                return -1;
        }
	return pid;
#else
	dbg->pid = pid;
	if (!xnu_create_exception_thread (dbg)) {
		eprintf ("error setting up exception thread\n");
		return -1;
	}
	return pid;
#endif
}

int xnu_detach(RDebug *dbg, int pid) {
#if XNU_USE_PTRACE
	return ptrace (PT_DETACH, pid, NULL, 0);
#else
	kern_return_t kr;
	//do the cleanup necessary
	//XXX check for errors and ref counts
	(void)xnu_restore_exception_ports (pid);
	kr = mach_port_deallocate (mach_task_self (), task_dbg);
	if (kr != KERN_SUCCESS) {
		eprintf ("failed to deallocate port %s-%d\n",
			__FILE__, __LINE__);
		return false;
	}
	//we mark the task as not longer available since we deallocated the ref
	task_dbg = 0;
	r_list_free (dbg->threads);
	return true;
#endif
}

int xnu_continue(RDebug *dbg, int pid, int tid, int sig) {
#if XNU_USE_PTRACE
	void *data = (void*)(size_t)((sig != -1) ? sig : dbg->reason.signum);
	task_resume (pid_to_task (pid));
	return ptrace (PT_CONTINUE, pid, (void*)(size_t)1,
			(int)(size_t)data) == 0;
#else
	task_t task = pid_to_task (pid);
	kern_return_t kr;
	if (!task)
		return false;
	//TODO free refs count threads
	xnu_thread_t *th  = get_xnu_thread (dbg, getcurthread (dbg));
	if (!th) {
		eprintf ("failed to get thread in xnu_continue\n");
		return false;
	}
	//disable trace bit if enable
	if (th->stepping) {
		if (!clear_trace_bit (dbg, th)) {
			eprintf ("error clearing trace bit in xnu_continue\n");
			return false;
		}
	}
	kr = task_resume (task);
	if (kr != KERN_SUCCESS)
		eprintf ("Failed to resume task xnu_continue\n");
	return true;
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

//r_debug_select
//using getcurthread has some drawbacks. You lose the ability to select
//the thread you want to write or read from. but how that feature
//is not implemented yet i don't care so much
int xnu_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
	bool ret;
	xnu_thread_t *th = get_xnu_thread (dbg, getcurthread (dbg));
	if (!th)
		return 0;
	switch (type) {
	case R_REG_TYPE_DRX:
#if __x86_64__ || __i386__
		memcpy (&th->drx, buf, R_MIN (size, sizeof (th->drx)));

#elif __arm || __arm64 || __aarch64
#if defined (ARM_DEBUG_STATE32) && (defined (__arm64__) || defined (__aarch64__))
	memcpy (&th->debug.drx32, buf, R_MIN (size, sizeof (th->debug.drx32)));
#else
	memcpy (&th->debug.drx, buf, R_MIN (size, sizeof (th->debug.drx)));
#endif
#endif
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
	xnu_thread_t *th = get_xnu_thread (dbg, getcurthread (dbg));
	if (!th)
		return 0;
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
	xnu_thread_t *th = get_xnu_thread (dbg, dbg->tid);
	bool anywhere = !VM_FLAGS_ANYWHERE;
	if (!th)
		return NULL;
	if (addr == -1)
		anywhere = VM_FLAGS_ANYWHERE;
	ret = vm_allocate (th->port, (vm_address_t *)&base,
			  (vm_size_t)size, anywhere);
	if (ret != KERN_SUCCESS) {
		printf("vm_allocate failed\n");
		return NULL;
	}
	r_debug_map_sync (dbg); // update process memory maps
	return r_debug_map_get (dbg, (ut64)base);
}

int xnu_map_dealloc (RDebug *dbg, ut64 addr, int size) {
	xnu_thread_t *th = get_xnu_thread (dbg, dbg->tid);
	if (!th)
		return false;
	int ret = vm_deallocate (th->port,
		(vm_address_t)addr, (vm_size_t)size);
	if (ret != KERN_SUCCESS) {
		perror ("vm_deallocate");
		return false;
	}
	return true;
}

static int xnu_get_kinfo_proc (int pid, struct kinfo_proc *kp) {
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };
	int len = 4;

	mib[3] = pid;
	if (sysctl (mib, len, kp, &len, NULL, 0) == -1) {
    	perror ("sysctl");
    	return -1;
  	} else {
    	return 0;
  	}

}

RDebugInfo *xnu_info (RDebug *dbg, const char *arg) {
	RDebugInfo *rdi = R_NEW0 (RDebugInfo);
	if (!rdi) return NULL;
	struct kinfo_proc *kp; // XXX This need to be freed?

	xnu_get_kinfo_proc(dbg->pid, kp);

	rdi->status = R_DBG_PROC_SLEEP; // TODO: Fix this
	rdi->pid = dbg->pid;
	rdi->tid = dbg->tid;
	rdi->uid = kp->kp_eproc.e_ucred.cr_uid;
	rdi->gid = kp->kp_eproc.e_ucred.cr_gid;
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
			thread->port, 's', CPU_PC));
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

int xnu_dealloc_threads (RList *threads) {
	RListIter *iter, *iter2;
	xnu_thread_t *thread;
	mach_msg_type_number_t thread_count;
	thread_array_t thread_list;
	kern_return_t kr = KERN_SUCCESS;

	kr = task_threads (task_dbg, &thread_list, &thread_count);
	if (kr != KERN_SUCCESS) {
		perror ("task_threads");
	} else {
		r_list_foreach_safe (threads, iter, iter2, thread) {
			mach_port_deallocate (mach_task_self (), thread->port);
		}
		vm_deallocate (mach_task_self (), (vm_address_t)thread_list,
			thread_count * sizeof (thread_act_t));
	}
}

int xnu_map_protect (RDebug *dbg, ut64 addr, int size, int perms) {
	int ret;
	// TODO: align pointers
	xnu_thread_t *th = get_xnu_thread (dbg, dbg->tid);
	if (!th)
		return false;
	ret = vm_protect (th->port, (vm_address_t)addr,
			 (vm_size_t)size, (boolean_t)0,
			 VM_PROT_COPY | perms);
	if (ret != KERN_SUCCESS) {
		printf("vm_protect failed\n");
		return false;
	}
	return true;
}

task_t pid_to_task (int pid) {
	static int old_pid = -1;
	kern_return_t kr;
	task_t task = -1;
	int err;

	/* it means that we are done with the task*/
	if (task_dbg != 0 && old_pid == pid) {
		return task_dbg;
	} else if (task_dbg != 0 && old_pid != pid) {
		//we changed the process pid so deallocate a ref from the old_task
		//since we are going to get a new task
		kr = mach_port_deallocate (mach_task_self (), task_dbg);
		if (kr != KERN_SUCCESS) {
			eprintf ("fail to deallocate port %s:%d\n", __FILE__, __LINE__);
			return 0;
		}

	}
	err = task_for_pid (mach_task_self (), (pid_t)pid, &task);
	if ((err != KERN_SUCCESS) || !MACH_PORT_VALID (task)) {
		task = task_for_pid_workaround (pid);
		if (task == 0) {
			task = task_for_pid_ios9pangu (pid);
			if (task != MACH_PORT_NULL) {
				if (pid != -1) {
					eprintf ("Failed to get task %d for pid %d.\n",
							(int)task, (int)pid);
					eprintf ("Reason: 0x%x: %s\n", err,
							(char *)MACH_ERROR_STRING (err));
				}
				eprintf ("You probably need to run as root or sign "
					"the binary.\n Read doc/ios.md || doc/osx.md\n"
					" make -C binr/radare2 ios-sign || osx-sign\n");
				return 0;
			}
		}
	}
	old_pid = pid;
	task_dbg = task;
	return task;
}

int xnu_get_vmmap_entries_for_pid (pid_t pid) {
	task_t task = pid_to_task (pid);
	kern_return_t kr = KERN_SUCCESS;
	vm_address_t address = 0;
	vm_size_t size = 0;
	int n = 1;

	for(;;) {
		mach_msg_type_number_t count;
		struct vm_region_submap_info_64 info;
		ut32 nesting_depth;

		count = VM_REGION_SUBMAP_INFO_COUNT_64;
		kr = vm_region_recurse_64 (task, &address, &size, &nesting_depth,
									(vm_region_info_64_t)&info, &count);

		if (kr == KERN_INVALID_ADDRESS) break;
		else if (kr) mach_error ("vm_region:", kr); break;

		if (info.is_submap) nesting_depth++;
		else address += size; n++;
	}

	return n;
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
	if (ret != KERN_SUCCESS)
		return 0;
	ut64 naddr;
	eprintf ("%d vs %d\n", task, ___task);
	for (count = 128; count; count--) {
		// get next memory region
		naddr = addr;
		ret = vm_region_recurse_64 (task, (vm_address_t*)&naddr,
					   (vm_size_t*)&size, &depth,
					   (vm_region_info_t)&info, &info_count);
		if (ret != KERN_SUCCESS)
			break;
		if (size < 1)
			break;
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
	ret = mach_port_deallocate (mach_task_self (), 0);
	if (ret != KERN_SUCCESS)
		eprintf ("leaking kernel port %s-%d\n", __FILE__, __LINE__);
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


// TODO: Implement mach0 size.. maybe copypasta from rbin?
static int mach0_size (RDebug *dbg, ut64 addr) {
	return 4096;
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
	if (!task)
		return NULL;

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
	if (!task)
		return NULL;
	if (only_modules)
		return xnu_dbg_modules (dbg);

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
			int ret = proc_regionfilename (tid, address, module_name,
						     sizeof (module_name));
			module_name[ret] = 0;
		}
		if (true) {
			#define xwr2rwx(x) ((x&1)<<2) | (x&2) | ((x&4)>>2)
			char maxperm[32];
			char depthstr[32];
			if (depth>0)
				snprintf (depthstr, sizeof (depthstr), "_%d", depth);
			else
				depthstr[0] = 0;

			if (info.max_protection != info.protection)
				strcpy (maxperm, r_str_rwx_i (xwr2rwx (
					info.max_protection)));
			else
				maxperm[0] = 0;
			// XXX: if its shared, it cannot be read?
			snprintf (buf, sizeof (buf), "%02x_%s%s%s%s%s%s%s%s",
				i, unparse_inheritance (info.inheritance),
				info.user_tag? "_user": "",
				info.is_submap? "_sub": "",
				"", info.is_submap ? "_submap": "",
				module_name, maxperm, depthstr);
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

#endif
