/* radare2 - LGPL - Copyright 2015-2019 - pancake, alvaro_fe */

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
#include <string.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>
#include <mach/mach_vm.h>
#include <mach/thread_status.h>
#include <mach/vm_statistics.h>

static task_t task_dbg = 0;
#include "xnu_debug.h"
#include "xnu_threads.c"
#if XNU_USE_EXCTHR
#include "xnu_excthreads.c"
#endif

extern int proc_regionfilename(int pid, uint64_t address, void * buffer, uint32_t buffersize);

#define MAX_MACH_HEADER_SIZE (64 * 1024)
#define DYLD_INFO_COUNT 5
#define DYLD_INFO_LEGACY_COUNT 1
#define DYLD_INFO_32_COUNT 3
#define DYLD_INFO_64_COUNT 5
#define DYLD_IMAGE_INFO_32_SIZE 12
#define DYLD_IMAGE_INFO_64_SIZE 24
#define DEBUG_MAP_TAG_ID 239 /* anonymous page id monitorable (e.g. vmmap) */

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

/* XXX: right now it just returns the first thread, not the one selected in dbg->tid */
static thread_t getcurthread (RDebug *dbg) {
	thread_t th;
	thread_array_t threads = NULL;
	unsigned int n_threads = 0;
	task_t t = pid_to_task (dbg->pid);
	if (!t) {
		return -1;
	}
	if (task_threads (t, &threads, &n_threads) != KERN_SUCCESS) {
		return -1;
	}
	if (n_threads > 0) {
		memcpy (&th, threads, sizeof (th));
	} else {
		th = -1;
	}
	vm_deallocate (t, (vm_address_t)threads, n_threads * sizeof (thread_act_t));
	return th;
}

static xnu_thread_t* get_xnu_thread(RDebug *dbg, int tid) {
	if (!dbg || tid < 0) {
		return NULL;
	}
	if (!xnu_update_thread_list (dbg)) {
		eprintf ("Failed to update thread_list xnu_udpate_thread_list\n");
		return NULL;
	}
	//TODO get the current thread
	RListIter *it = r_list_find (dbg->threads, (const void *)(size_t)&tid,
			  (RListComparator)&thread_find);
	if (!it) {
		tid = getcurthread (dbg);
		it = r_list_find (dbg->threads, (const void *)(size_t)&tid,
			  (RListComparator)&thread_find);
		if (!it) {
			eprintf ("Thread not found get_xnu_thread\n");
			return NULL;
		}
	}
	return (xnu_thread_t *)it->data;
}

static task_t task_for_pid_workaround(int Pid) {
	host_t myhost = mach_host_self();
	mach_port_t psDefault = 0;
	mach_port_t psDefault_control = 0;
	task_array_t tasks = NULL;
	mach_msg_type_number_t numTasks = 0;
	int i;
	if (Pid == -1) {
		return 0;
	}
	kern_return_t kr = processor_set_default (myhost, &psDefault);
	if (kr != KERN_SUCCESS) {
		return 0;
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
	/* kernel task */
	task_t task = -1;
	if (Pid == 0) {
		task = tasks[0];
	} else {
		for (i = 0; i < numTasks; i++) {
			pid_t pid = 0;
			pid_for_task (i, &pid);
			if (pid == Pid) {
				task = tasks[i];
				break;
			}
		}
	}
	vm_deallocate (myhost, (vm_address_t)tasks, numTasks * sizeof (task_t));
	return task;
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
	int ret = r_debug_ptrace (dbg, PT_STEP, dbg->pid, (caddr_t)1, 0) == 0; //SIGINT
	if (!ret) {
		perror ("ptrace-step");
		eprintf ("mach-error: %d, %s\n", ret, MACH_ERROR_STRING (ret));
	}
	return ret;
#else
	//we must find a way to get the current thread not just the first one
	task_t task = pid_to_task (dbg->pid);
	if (!task) {
		eprintf ("step failed on task %d for pid %d\n", task, dbg->tid);
		return false;
	}
	xnu_thread_t *th = get_xnu_thread (dbg, getcurthread (dbg));
	if (!th) {
		return false;
	}
	int ret = set_trace_bit (dbg, th);
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
  #if PT_ATTACHEXC
	if (r_debug_ptrace (dbg, PT_ATTACHEXC, pid, 0, 0) == -1) {
  #else
	if (r_debug_ptrace (dbg, PT_ATTACH, pid, 0, 0) == -1) {
  #endif
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
	xnu_stop (dbg, pid);
	return pid;
#endif
}

int xnu_detach(RDebug *dbg, int pid) {
#if XNU_USE_PTRACE
	return r_debug_ptrace (dbg, PT_DETACH, pid, NULL, 0);
#else
	kern_return_t kr;
	//do the cleanup necessary
	//XXX check for errors and ref counts
	(void)xnu_restore_exception_ports (pid);
	kr = mach_port_deallocate (mach_task_self (), task_dbg);
	if (kr != KERN_SUCCESS) {
		eprintf ("xnu_detach: failed to deallocate port\n");
		return false;
	}
	//we mark the task as not longer available since we deallocated the ref
	task_dbg = 0;
	r_list_free (dbg->threads);
	dbg->threads = NULL;
	return true;
#endif
}

static int task_suspend_count(task_t task) {
	kern_return_t kr;
	struct task_basic_info info;
	mach_msg_type_number_t count = TASK_BASIC_INFO_COUNT;
	kr = task_info (task, TASK_BASIC_INFO, (task_info_t) &info, &count);
	if (kr != KERN_SUCCESS) {
		eprintf ("failed to get task info\n");
		return -1;
	}
	return info.suspend_count;
}

int xnu_stop(RDebug *dbg, int pid) {
#if XNU_USE_PTRACE
	eprintf ("xnu_stop: not implemented\n");
	return false;
#else
	task_t task = pid_to_task (pid);
	if (!task) {
		return false;
	}

	int suspend_count = task_suspend_count (task);
	if (suspend_count == -1) {
		return false;
	}
	if (suspend_count == 1) {
		// Hopefully _we_ suspended it.
		return true;
	}
	if (suspend_count > 1) {
		// This is unexpected.
		return false;
	}

	kern_return_t kr = task_suspend (task);
	if (kr != KERN_SUCCESS) {
		eprintf ("failed to suspend task\n");
		return false;
	}

	suspend_count = task_suspend_count (task);
	if (suspend_count != 1) {
		// This is unexpected.
		return false;
	}
	return true;
#endif
}

int xnu_continue(RDebug *dbg, int pid, int tid, int sig) {
#if XNU_USE_PTRACE
	void *data = (void*)(size_t)((sig != -1) ? sig : dbg->reason.signum);
	task_resume (pid_to_task (pid));
	return r_debug_ptrace (dbg, PT_CONTINUE, pid, (void*)(size_t)1,
			(int)(size_t)data) == 0;
#else
	task_t task = pid_to_task (pid);
	if (!task) {
		return false;
	}
	//TODO free refs count threads
	xnu_thread_t *th = get_xnu_thread (dbg, getcurthread (dbg));
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
	kern_return_t kr = task_resume (task);
	if (kr != KERN_SUCCESS) {
		eprintf ("xnu_continue: Warning: Failed to resume task\n");
	}
	return true;
#endif
}

char *xnu_reg_profile(RDebug *dbg) {
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
	if (!th) {
		return 0;
	}
	switch (type) {
	case R_REG_TYPE_DRX:
#if __x86_64__
		memcpy (&th->drx.uds.ds32, buf, R_MIN (size, sizeof (th->drx)));
#elif __i386__
		memcpy (&th->drx.uds.ds64, buf, R_MIN (size, sizeof (th->drx)));
#elif __arm64 || __aarch64
		if (dbg->bits == R_SYS_BITS_64) {
			memcpy (&th->debug.drx64, buf, R_MIN (size, sizeof (th->debug.drx64)));
		} else {
			memcpy (&th->debug.drx32, buf, R_MIN (size, sizeof (th->debug.drx32)));
		}
#elif __arm || __armv7 || __arm__ || __armv7__
		memcpy (&th->debug.drx, buf, R_MIN (size, sizeof (th->debug.drx)));
#endif
		ret = xnu_thread_set_drx (dbg, th);
		break;
	default:
		//th->gpr has a header and the state we should copy on the state only
#if __POWERPC__
#warning TODO powerpc support here
#else
		memcpy (&th->gpr.uts, buf, R_MIN (size, sizeof (th->gpr.uts)));
#endif
		ret = xnu_thread_set_gpr (dbg, th);
		break;
	}
	return ret;
}

int xnu_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	xnu_thread_t *th = get_xnu_thread (dbg, getcurthread (dbg));
	if (!th) {
		return 0;
	}
	switch (type) {
	case R_REG_TYPE_SEG:
	case R_REG_TYPE_FLG:
	case R_REG_TYPE_GPR:
		if (!xnu_thread_get_gpr (dbg, th)) {
			return 0;
		}
		break;
	case R_REG_TYPE_DRX:
		if (!xnu_thread_get_drx (dbg, th)) {
			return 0;
		}
		break;
	default:
		return 0;
	}
	if (th->state) {
		int rsz = R_MIN (th->state_size, size);
		if (rsz > 0) {
			memcpy (buf, th->state, rsz);
			return rsz;
		}
	}
	return 0;
}

RDebugMap *xnu_map_alloc(RDebug *dbg, ut64 addr, int size) {
	kern_return_t ret;
	ut8 *base = (ut8 *)addr;
	xnu_thread_t *th = get_xnu_thread (dbg, dbg->tid);
	bool anywhere = !VM_FLAGS_ANYWHERE;
	if (!th) {
		return NULL;
	}
	if (addr == -1) {
		anywhere = VM_FLAGS_ANYWHERE;
	}
	ret = vm_allocate (th->port, (vm_address_t *)&base,
			  (vm_size_t)size,
			  anywhere | VM_MAKE_TAG(DEBUG_MAP_TAG_ID));
	if (ret != KERN_SUCCESS) {
		eprintf ("vm_allocate failed\n");
		return NULL;
	}
	r_debug_map_sync (dbg); // update process memory maps
	return r_debug_map_get (dbg, (ut64)base);
}

int xnu_map_dealloc (RDebug *dbg, ut64 addr, int size) {
	xnu_thread_t *th = get_xnu_thread (dbg, dbg->tid);
	if (!th) {
		return false;
	}
	int ret = vm_deallocate (th->port, (vm_address_t)addr, (vm_size_t)size);
	if (ret != KERN_SUCCESS) {
		perror ("vm_deallocate");
		return false;
	}
	return true;
}

static int xnu_get_kinfo_proc (int pid, struct kinfo_proc *kp) {
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };
	int len = 4;
	size_t kpl = sizeof (struct kinfo_proc);

	mib[3] = pid;
	if (sysctl (mib, len, kp, &kpl, NULL, 0) == -1) {
		perror ("sysctl");
		return -1;
  	}
  	if (kpl < 1) {
		return -1;
	}
	return 0;
}

RDebugInfo *xnu_info (RDebug *dbg, const char *arg) {
	struct kinfo_proc kp; // XXX This need to be freed?
	int kinfo_proc_error = 0;
	RDebugInfo *rdi = R_NEW0 (RDebugInfo);
	if (!rdi) return NULL;

	kinfo_proc_error = xnu_get_kinfo_proc(dbg->pid, &kp);

	if (kinfo_proc_error) {
		eprintf ("Error while querying the process info to sysctl\n");
		return NULL;
	}
	rdi->status = R_DBG_PROC_SLEEP; // TODO: Fix this w/o libproc ?
	rdi->pid = dbg->pid;
	rdi->tid = dbg->tid;
	rdi->uid = kp.kp_eproc.e_ucred.cr_uid;
	rdi->gid = kp.kp_eproc.e_ucred.cr_gid;
#ifdef HAS_LIBPROC
	struct proc_bsdinfo proc;
	rdi->status = 0;
	char file_path[MAXPATHLEN] = {0};
	int file_path_len;
	file_path_len = proc_pidpath (rdi->pid, file_path, sizeof (file_path));
	if (file_path_len > 0) {
		file_path[file_path_len] = 0;
		rdi->exe = strdup (file_path);
	}
	if (proc_pidinfo (rdi->pid, PROC_PIDTBSDINFO, 0,
		&proc, PROC_PIDTBSDINFO_SIZE) == PROC_PIDTBSDINFO_SIZE) {
		if ((proc.pbi_flags & PROC_FLAG_TRACED) != 0) {
			rdi->status = R_DBG_PROC_RUN;
		}
		if ((proc.pbi_flags & PROC_FLAG_INEXIT) != 0) {
			rdi->status = R_DBG_PROC_STOP;
		}
	}
#endif
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
			thread->port, getuid (), 's', CPU_PC));
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
	task_t task = pid_to_task (dbg->tid);
#define xwr2rwx(x) ((x&1)<<2) | (x&2) | ((x&4)>>2)
	int xnu_perms = xwr2rwx (perms);
	ret = mach_vm_protect (task, (vm_address_t)addr, (vm_size_t)size, (boolean_t)0, xnu_perms); //VM_PROT_COPY | perms);
	if (ret != KERN_SUCCESS) {
		perror ("vm_protect");
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
	}
	if (task_dbg != 0 && old_pid != pid) {
		//we changed the process pid so deallocate a ref from the old_task
		//since we are going to get a new task
		kr = mach_port_deallocate (mach_task_self (), task_dbg);
		if (kr != KERN_SUCCESS) {
			eprintf ("pid_to_task: fail to deallocate port\n");
			/* ignore on purpose to not break process reload: ood */
			//return 0;
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
					"the binary.\n Read doc/ios.md || doc/macos.md\n"
					" make -C binr/radare2 ios-sign || macos-sign\n");
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

	for (;;) {
		mach_msg_type_number_t count;
		struct vm_region_submap_info_64 info;
		ut32 nesting_depth;

		count = VM_REGION_SUBMAP_INFO_COUNT_64;
		kr = vm_region_recurse_64 (task, &address, &size, &nesting_depth,
			(vm_region_info_64_t)&info, &count);
		if (kr == KERN_INVALID_ADDRESS) {
			break;
		}
		if (kr) {
			mach_error ("vm_region:", kr);
			break;
		}
		if (info.is_submap) {
			nesting_depth++;
		} else {
			address += size; 
			n++;
		}
	}

	return n;
}

#define xwr2rwx(x) ((x&1)<<2) | (x&2) | ((x&4)>>2)
#define COMMAND_SIZE(segment_count,segment_command_sz,\
	thread_count,tstate_size)\
	segment_count * segment_command_sz + thread_count * \
	sizeof (struct thread_command) + tstate_size * thread_count

static void get_mach_header_sizes(size_t *mach_header_sz, 
									size_t *segment_command_sz) {
#if __ppc64__ || __x86_64__
	*mach_header_sz = sizeof(struct mach_header_64);
	*segment_command_sz = sizeof(struct segment_command_64);
#elif __i386__ || __ppc__ || __POWERPC__
	*mach_header_sz = sizeof(struct mach_header);
	*segment_command_sz = sizeof(struct segment_command);
#else
#endif
// XXX: What about arm?
}

// XXX: This function could use less function calls, but works.
static cpu_type_t xnu_get_cpu_type (pid_t pid) {
	int mib[CTL_MAXNAME];
	size_t len = CTL_MAXNAME;
	cpu_type_t cpu_type;
	size_t cpu_type_len = sizeof (cpu_type_t);

	if (sysctlnametomib ("sysctl.proc_cputype", mib, &len) == -1) {
		perror ("sysctlnametomib");
		return -1;
	}
	mib[len++] = pid;
	if (sysctl (mib, len, &cpu_type, &cpu_type_len, NULL, 0) == -1) {
		perror ("sysctl");
		return -1;
	}
	if (cpu_type_len > 0) return cpu_type;
	return -1;
}

static cpu_subtype_t xnu_get_cpu_subtype () {
	size_t size;
	cpu_subtype_t subtype;

	size = sizeof (cpu_subtype_t);
	sysctlbyname ("hw.cpusubtype", &subtype, &size, NULL, 0);

	return subtype;
}

static void xnu_build_corefile_header (vm_offset_t header,
	int segment_count, int thread_count, int command_size, pid_t pid) {
#if __ppc64__ || __x86_64__
	struct mach_header_64 *mh64;
	mh64 = (struct mach_header_64 *)header;
	mh64->magic = MH_MAGIC_64;
	mh64->cputype = xnu_get_cpu_type (pid);
	mh64->cpusubtype = xnu_get_cpu_subtype (); 
	mh64->filetype = MH_CORE;
	mh64->ncmds = segment_count + thread_count;
	mh64->sizeofcmds = command_size;
	mh64->reserved = 0; // 8-byte alignment 
#elif __i386__ || __ppc__ || __POWERPC__
	struct mach_header *mh;
	mh = (struct mach_header *)header;
	mh->magic = MH_MAGIC;
	mh->cputype = xnu_get_cpu_type (pid);
	mh->cpusubtype = xnu_get_cpu_subtype ();
	mh->filetype = MH_CORE;
	mh->ncmds = segment_count + thread_count;
	mh->sizeofcmds = command_size;
#endif
}

static int xnu_dealloc_threads (RList *threads) {
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
	return kr;
}

/* XXX This is temporal. Later it will write in a RBuffer. */
/* XXX Apart from writing to the file, it also creates the commands, */
/* XXX which follow the header. */
/* XXX Maybe this function needs refactoring, but I haven't come up with */
/* XXX a better way to do it yet. */
static int xnu_write_mem_maps_to_buffer (RBuffer *buffer, RList *mem_maps, int start_offset,
	vm_offset_t header, int header_end, int segment_command_sz, int *hoffset_out) {
	RListIter *iter, *iter2;
	RDebugMap *curr_map;
	int foffset = 0; //start_offset;
	int hoffset = header_end;
	kern_return_t kr = KERN_SUCCESS;
	int error = 0;
	ssize_t rc = 0;

#define CAST_DOWN(type, addr) (((type)((uintptr_t)(addr))))
#if __ppc64__ || __x86_64__
	struct segment_command_64 *sc64;
#elif __i386__ || __ppc__ || __POWERPC__
	struct segment_command *sc;
#endif
	r_list_foreach_safe (mem_maps, iter, iter2, curr_map) {
		eprintf ("Writing section from 0x%"PFMT64x" to 0x%"PFMT64x" (%"PFMT64d")\n", 
			curr_map->addr, curr_map->addr_end, curr_map->size);

		vm_map_offset_t vmoffset = curr_map->addr;
#if __ppc64__ || __x86_64__
		sc64 = (struct segment_command_64 *)(header + hoffset);
		sc64->cmd = LC_SEGMENT_64;
		sc64->cmdsize = sizeof (struct segment_command_64);
		sc64->segname[0] = 0; // XXX curr_map->name OR curr_map->file ???
		sc64->vmaddr = curr_map->addr;
		sc64->vmsize = curr_map->size;
		sc64->maxprot = xwr2rwx (curr_map->user);
		sc64->initprot = xwr2rwx (curr_map->perm);
		sc64->nsects = 0;
#elif __i386__ || __ppc__
		sc = (struct segment_command*)(header + hoffset);
		sc->cmd = LC_SEGMENT;
		sc->cmdsize = sizeof (struct segment_command);
		sc->segname[0] = 0;
		sc->vmaddr = CAST_DOWN (vm_offset_t, curr_map->addr); // XXX: Is this needed?
		sc->vmsize = CAST_DOWN (vm_size_t, curr_map->size);
		sc->fileoff = CAST_DOWN (ut32, foffset);
		sc->filesize = CAST_DOWN (ut32, curr_map->size);
		sc->maxprot = xwr2rwx (curr_map->user);
		sc->initprot = xwr2rwx (curr_map->perm);
		sc->nsects = 0;
#endif
		if ((curr_map->perm & VM_PROT_READ) == 0) {
			mach_vm_protect (task_dbg, curr_map->addr, curr_map->size, FALSE,
				curr_map->perm | VM_PROT_READ);
		}

		/* Acording to osxbook, the check should be like this: */
#if 0
		if ((maxprot & VM_PROT_READ) == VM_PROT_READ &&
			(vbr.user_tag != VM_MEMORY_IOKIT)) {
#endif
		if ((curr_map->perm & VM_PROT_READ) == VM_PROT_READ) {
			vm_map_size_t tmp_size = curr_map->size;
			off_t xfer_foffset = foffset;

			while (tmp_size > 0) {
				vm_map_size_t xfer_size = tmp_size;
				vm_offset_t local_address;
				mach_msg_type_number_t local_size;

				if (xfer_size > INT_MAX) xfer_size = INT_MAX;
				kr = mach_vm_read (task_dbg, vmoffset, xfer_size,
					&local_address, &local_size);

				if ((kr != KERN_SUCCESS) || (xfer_size != local_size)) {
					eprintf ("Failed to read target memory\n"); // XXX: Improve this message?
					eprintf ("[DEBUG] kr = %d\n", kr);
					eprintf ("[DEBUG] KERN_SUCCESS = %d\n", KERN_SUCCESS);
					eprintf ("[DEBUG] xfer_size = %"PFMT64d"\n", (ut64)xfer_size);
					eprintf ("[DEBUG] local_size = %d\n", local_size);
					if (kr > 1) error = -1; // XXX: INVALID_ADDRESS is not a bug right know
					goto cleanup;
				}
#if __ppc64__ || __x86_64__ || __aarch64__ || __arm64__
				rc = r_buf_append_bytes (buffer, (const ut8*)local_address, xfer_size);
// #elif __i386__ || __ppc__ || __arm__
#else
				rc = r_buf_append_bytes (buffer, (void *)CAST_DOWN (ut32, local_address),
					CAST_DOWN (ut32, xfer_size));
#endif
				if (!rc) {
					error = errno;
					eprintf ("Failed to write in the destination\n");
					goto cleanup;
				}

				tmp_size -= xfer_size;
				xfer_foffset += xfer_size;
			}
		}

		hoffset += segment_command_sz;
		foffset += curr_map->size;
		vmoffset += curr_map->size;
	}

cleanup:
	*hoffset_out = hoffset;
	return error;
}

static int xnu_get_thread_status (register thread_t thread, int flavor, 
	thread_state_t tstate, mach_msg_type_number_t *count) {
	return thread_get_state (thread, flavor, tstate, count);
}

static void xnu_collect_thread_state (thread_t port, void *tirp) {
	coredump_thread_state_flavor_t *flavors;
	tir_t *tir = (tir_t *)tirp;
	struct thread_command *tc;
	vm_offset_t header;
	ut64 hoffset;
	int i;

	header = tir->header;
	hoffset = tir->hoffset;
	flavors = tir->flavors;
	eprintf ("[DEBUG] tc location: 0x%" PFMT64x "\n", hoffset);

	tc = (struct thread_command *)(header + hoffset);
	tc->cmd = LC_THREAD;
	tc->cmdsize = sizeof (struct thread_command) + tir->tstate_size;
	hoffset += sizeof (struct thread_command);

	for (i = 0; i < coredump_nflavors; i++) {
		eprintf ("[DEBUG] %d/%d\n", i+1, coredump_nflavors);
		*(coredump_thread_state_flavor_t *)(header + hoffset) = flavors[i];
		hoffset += sizeof (coredump_thread_state_flavor_t);
		xnu_get_thread_status (port, flavors[i].flavor,
			(thread_state_t)(header + hoffset), &flavors[i].count);
		hoffset += flavors[i].count * sizeof (int);
	}
	tir->hoffset = hoffset;
}

#define CORE_ALL_SECT 0

#include <sys/sysctl.h>

static uid_t uidFromPid(pid_t pid) {
	uid_t uid = -1;

	struct kinfo_proc process;
	size_t procBufferSize = sizeof (process);

	// Compose search path for sysctl. Here you can specify PID directly.
	int path[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
	const int pathLenth = (sizeof (path) / sizeof (int));
	int sysctlResult = sysctl (path, pathLenth, &process, &procBufferSize, NULL, 0);
	// If sysctl did not fail and process with PID available - take UID.
	if ((sysctlResult == 0) && (procBufferSize != 0)) {
		uid = process.kp_eproc.e_ucred.cr_uid;
	}
	return uid;
}

bool xnu_generate_corefile (RDebug *dbg, RBuffer *dest) {
	int error = 0, i;
	int tstate_size;
	int segment_count;
	int command_size;
	int header_size;
	size_t mach_header_sz;
	size_t segment_command_sz;
	size_t padding_sz;
	int hoffset;

	RBuffer *mem_maps_buffer;
	vm_offset_t header;
	ut8 *padding = NULL;
	RListIter *iter, *iter2;
	RList *threads_list;
	xnu_thread_t *thread;
	task_t task = pid_to_task (dbg->pid);
	coredump_thread_state_flavor_t flavors[MAX_TSTATE_FLAVORS];
	tir_t tir;

	mem_maps_buffer = r_buf_new ();

	get_mach_header_sizes (&mach_header_sz, &segment_command_sz);
	(void)task_suspend(task);
	threads_list = xnu_thread_list (dbg, dbg->pid, r_list_new ());
	xnu_dealloc_threads (threads_list);

	segment_count = xnu_get_vmmap_entries_for_pid (dbg->pid);

	memcpy (thread_flavor_array, &flavors, sizeof (thread_flavor_array));
	tstate_size = 0;

	for (i = 0; i < coredump_nflavors; i++) {
		tstate_size += sizeof (coredump_thread_state_flavor_t) +
			(flavors[i].count * sizeof(int));
	}

	command_size = COMMAND_SIZE (segment_count,segment_command_sz, 
		r_list_length (threads_list), tstate_size);
	header_size = command_size + mach_header_sz; // XXX: Add here the round_page() ?
	header = (vm_offset_t)calloc (1, header_size);
	xnu_build_corefile_header (header, segment_count,
		r_list_length (threads_list), command_size, dbg->pid);

	if (!dbg->maps) {
		perror ("There are not loaded maps");
	}
	if (xnu_write_mem_maps_to_buffer (mem_maps_buffer, dbg->maps, round_page (header_size),
		header, mach_header_sz, segment_command_sz, &hoffset) < 0) {
		eprintf ("There was an error while writing the memory maps");
		error = false;
		goto cleanup;
	}

	tir.header = header;
	tir.hoffset = hoffset;
	tir.flavors = flavors;
	tir.tstate_size = tstate_size;

	r_list_foreach_safe (threads_list, iter, iter2, thread) {
		xnu_collect_thread_state (thread->port, &tir);
	}
	xnu_dealloc_threads (threads_list);

	r_buf_append_bytes (dest, (const ut8*)header, header_size);
	padding_sz = round_page (header_size) - header_size;
	padding = (ut8*)calloc (1, padding_sz);
	r_buf_append_bytes (dest, (const ut8*)padding, padding_sz);
	r_buf_append_buf (dest, mem_maps_buffer);

cleanup:
	//if (corefile_fd > 0) close (corefile_fd);
	r_buf_free (mem_maps_buffer);
	free ((void *)header);
	free ((void *)padding);
	r_list_free (threads_list);
	return !error;
}

RDebugPid *xnu_get_pid (int pid) {
	int psnamelen, foo, nargs, mib[3], uid;
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
	uid = uidFromPid (pid);

	/* Allocate space for the arguments. */
	procargs = (char *)malloc (argmax);
	if (!procargs) {
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
	memcpy (&nargs, procargs, sizeof (nargs));
	iter_args = procargs + sizeof (nargs);
	end_args = &procargs[size - 30]; // end of the argument space
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
				memcpy (psname + psnamelen + 1, curr_arg, alen + 1);
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
	return r_debug_pid_new (psname, pid, uid, 's', 0); // XXX 's' ??, 0?? must set correct values
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
	mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
	vm_region_submap_info_data_64_t info;
	ut64 naddr, addr = KERNEL_LOWER; // lowest possible kernel base address
	unsigned int depth = 0;
	kern_return_t ret;
	task_t task;
	ut64 size;
	int count;

	ret = task_for_pid (mach_task_self(), 0, &task);
	if (ret != KERN_SUCCESS) {
		return 0;
	}
	// eprintf ("%d vs %d\n", task, ___task);
	for (count = 128; count; count--) {
		// get next memory region
		naddr = addr;
		ret = vm_region_recurse_64 (task, (vm_address_t*)&naddr,
					   (vm_size_t*)&size, &depth,
					   (vm_region_info_t)&info, &info_count);
		if (ret != KERN_SUCCESS) {
			break;
		}
		if (size < 1) {
			break;
		}
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
	if (ret != KERN_SUCCESS) {
		eprintf ("get_kernel_base: leaking kernel port\n");
	}
	return (vm_address_t)0;
}

// TODO: Implement mach0 size.. maybe copypasta from rbin?
static int mach0_size (RDebug *dbg, ut64 addr) {
	return 4096;
}

static void xnu_map_free(RDebugMap *map) {
	if (map) {
		free (map->name);
		free (map->file);
		free (map);
	}
}

static RList *xnu_dbg_modules(RDebug *dbg) {
#if __POWERPC__
#warning TODO: xnu_dbg_modules not supported
	return NULL;
#else
	struct task_dyld_info info;
	mach_msg_type_number_t count;
	kern_return_t kr;
	int size, info_array_count, info_array_size, i;
	ut64 info_array_address;
	void *info_array = NULL;
	//void *header_data = NULL;
	char file_path[MAXPATHLEN] = {0};
	count = TASK_DYLD_INFO_COUNT;
	task_t task = pid_to_task (dbg->tid);
	ut64 addr, file_path_address;
	RDebugMap *mr = NULL;
	RList *list = NULL;
	if (!task) {
		return NULL;
	}

	kr = task_info (task, TASK_DYLD_INFO, (task_info_t) &info, &count);
	if (kr != KERN_SUCCESS) {
		r_list_free (list);
		return NULL;
	}

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

	if (info_array_address == 0) {
		return NULL;
	}
	info_array_size = R_ABS (info_array_size);
	info_array = calloc (1, info_array_size);
	if (!info_array) {
		eprintf ("Cannot allocate info_array_size %d\n",
			info_array_size);
		return NULL;
	}

	dbg->iob.read_at (dbg->iob.io, info_array_address, info_array, info_array_size);

	list = r_list_newf ((RListFree)xnu_map_free);
	if (!list) {
		free (info_array);
		return NULL;
	}
	for (i = 0; i < info_array_count; i++) {
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
		memset (file_path, 0, MAXPATHLEN);
		dbg->iob.read_at (dbg->iob.io, file_path_address,
				(ut8*)file_path, MAXPATHLEN - 1);
		//eprintf ("--> %d 0x%08"PFMT64x" %s\n", i, addr, file_path);
		size = mach0_size (dbg, addr);
		mr = r_debug_map_new (file_path, addr, addr + size, 7, 7);
		if (!mr) {
			eprintf ("Cannot create r_debug_map_new\n");
			break;
		}
		mr->file = strdup (file_path);
		mr->shared = true;
		r_list_append (list, mr);
	}
	free (info_array);
	return list;
#endif
}

static RDebugMap *moduleAt(RList *list, ut64 addr) {
	RListIter *iter;
	RDebugMap *map;
	r_list_foreach (list, iter, map) {
		if (R_BETWEEN (map->addr, addr, map->addr_end)) {
			return map;
		}
	}
	return NULL;
}

static int cmp (const void *_a, const void *_b) {
	const RDebugMap *a = _a;
	const RDebugMap *b = _b;
	if (a->addr > b->addr) {
		return 1;
	}
	if (a->addr < b->addr) {
		return -1;
	}
	return 0;
}

static RDebugMap *r_debug_map_clone (RDebugMap *m) {
	RDebugMap *map = R_NEWCOPY (RDebugMap, m);
	// memcpy (map, m, sizeof (RDebugMap));
	if (m->name) {
		map->name = strdup (m->name);
	}
	if (m->file) {
		map->file = strdup (m->file);
	}
	return map;
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
	int i = 0;

	if (!task) {
		return NULL;
	}
	RList *modules = xnu_dbg_modules (dbg);
	if (only_modules) {
		return modules;
	}
#if __arm64__ || __aarch64__
	size = osize = 16384;
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
	RList *list = r_list_new ();
	if (!list) {
		return NULL;
	}
	list->free = (RListFree)xnu_map_free;
	for (;;) {
		struct vm_region_submap_info_64 info = {0};
		mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
		kern_return_t kr = mach_vm_region_recurse (task, &address, &size, &depth,
					(vm_region_recurse_info_t) &info, &info_count);
		if (kr != KERN_SUCCESS) {
			break;
		}
		if (info.is_submap) {
			depth++;
			continue;
		}
		module_name[0] = 0;
#ifndef __POWERPC__
		{
			int ret = proc_regionfilename (tid, address, module_name,
							 sizeof (module_name));
			module_name[ret] = 0;
		}
#endif
		if (true) {
			char maxperm[32];
			char depthstr[32];
			if (depth > 0) {
				snprintf (depthstr, sizeof (depthstr), "_%d", depth);
			} else {
				depthstr[0] = 0;
			}

			if (info.max_protection != info.protection) {
				strcpy (maxperm, r_str_rwx_i (xwr2rwx (
					info.max_protection)));
			} else {
				maxperm[0] = 0;
			}
			// XXX: if its shared, it cannot be read?
			snprintf (buf, sizeof (buf), "%02x_%s%s%s%s%s%s%s%s",
				i, unparse_inheritance (info.inheritance),
				info.user_tag? "_user": "",
				info.is_submap? "_sub": "",
				"", info.is_submap ? "_submap": "",
				module_name, maxperm, depthstr);
			if (!(mr = r_debug_map_new (buf, address, address + size, xwr2rwx (info.protection), xwr2rwx (info.max_protection)))) {
				eprintf ("Cannot create r_debug_map_new\n");
				break;
			}
			RDebugMap *rdm = moduleAt (modules, address);
			if (rdm) {
				mr->file = strdup (rdm->name);
			} else {
				if (*module_name) {
					mr->file = strdup (module_name);
				}
			}
			if (mr->file) {
				if (!strcmp (mr->file, mr->file)) {
					mr->name[0] = 0;
					const char *slash = r_str_lchr (mr->file, '/');
					if (slash) {
						strcpy (mr->name, slash + 1);
					}
				}
			}
			i++;
			mr->shared = false;
			r_list_append (list, mr);
		}
		if (size < 1) {
			eprintf ("size error\n");
			size = osize;
		}
		address += size;
		size = 0;
	}
	RListIter *iter;
	RDebugMap *m;
	r_list_foreach (modules, iter, m) {
		RDebugMap *m2 = r_debug_map_clone (m);
		if (m2->name && m2->file) {
			if (!strcmp (m2->name, m2->file)) {
				m2->name[0] = 0;
				const char *slash = r_str_lchr (m2->file, '/');
				if (slash) {
					strcpy (m2->name, slash + 1);
				}
			}
		}
		r_list_append (list, m2);	
	}
	r_list_sort (list, cmp);
 	r_list_free (modules);
	return list;
}

#endif
