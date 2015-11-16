/* radare - LGPL - Copyright 2009-2015 - pancake */

//TODO much work remains to be done
#include "xnu_debug.h"
#include "xnu_threads.h"

static void xnu_thread_free(xnu_thread_t *thread) {
	if (!thread) return;
	free (thread->name);
	free (thread);
}

static int xnu_thread_set_drx(RDebug *dbg, xnu_thread_t *thread) {
	R_DEBUG_REG_T *regs;
	if (!thread) {
		thread->count = 0;
		return false;
	}
	regs = (R_DEBUG_REG_T*)&thread->drx;
#if __i386__ || __x86_64__
	if (dbg->bits == R_SYS_BITS_64) {
		thread->flavor = regs->dsh.flavor = x86_DEBUG_STATE64;
		thread->count = R_DEBUG_STATE_SZ; //R_MIN (thread->count, sizeof(regs->uds.ds64));
	} else {
		thread->flavor = regs->dsh.flavor = x86_DEBUG_STATE32;
		thread->count = R_DEBUG_STATE_SZ; //R_MIN (thread->count, sizeof(regs->uds.ds32));
	}
#elif __arm || __arm64 || __aarch64
	if (dbg->bits == R_SYS_BITS_64) {
		thread->flavor = regs->dsh.flavor = ARM_DEBUG_STATE64;
		thread->count = R_MIN (thread->count, sizeof(regs->uds.ds64));
	} else {
		thread->flavor = regs->dsh.flavor = ARM_DEBUG_STATE32;
		thread->count = R_MIN (thread->count, sizeof(regs->uds.ds64));
	}
#elif __POWERPC__
#ifndef PPC_DEBUG_STATE32
#define PPC_DEBUG_STATE32 1
#endif
	thread->flavor = PPC_DEBUG_STATE32;
	thread->count = R_MIN (thread->count, sizeof(regs->uds.ds32));
#else
	regs->dsh.flavor = 0;
	thread->count = 0;
#endif
	memcpy (&regs->uds, thread->state, thread->count);
	thread->flavor = regs->dsh.flavor;
	kern_return_t rc = thread_set_state (thread->tid, thread->flavor,
		(thread_state_t)thread->state, thread->count);
	if (rc != KERN_SUCCESS) {
		perror ("thread_set_state");
		thread->count = false;
		return false;
	}
	return true;
}

static int xnu_thread_set_gpr(RDebug *dbg, xnu_thread_t *thread) {
	kern_return_t rc;
	R_REG_T *regs;
	if (!dbg || !thread) {
		thread->count = 0;
		return false;
	}
	thread->state = regs = (R_REG_T*)&thread->gpr;
	thread->state_size = sizeof (thread->gpr);
#if __i386__ || __x86_64__
	//thread->flavor is used in a switch+case but in regs->tsh.flavor we specify
	thread->flavor = x86_THREAD_STATE;
	thread->count = x86_THREAD_STATE_COUNT;
	if (dbg->bits == R_SYS_BITS_64) {
		regs->tsh.flavor = x86_THREAD_STATE64;
		regs->tsh.count = x86_THREAD_STATE64_COUNT;
		//thread->count = R_MIN (thread->count, sizeof (regs->uts.ts64));
	} else {
		regs->tsh.flavor = x86_THREAD_STATE32;
		regs->tsh.count = x86_THREAD_STATE32_COUNT;
		//thread->count = R_MIN (thread->count, sizeof (regs->uts.ts32));
		//memcpy (&regs->uts, thread->state, thread->state_size);
	}
#elif __arm || __arm64 || __aarch64
	if (dbg->bits == R_SYS_BITS_64) {
		thread->flavor = regs->ash.flavor = ARM_THREAD_STATE64;
		thread->count = R_MIN (thread->count, sizeof (regs->ts_64));
	} else {
		thread->flavor = regs->ash.flavor = ARM_THREAD_STATE32;
		thread->count = R_MIN (thread->count, sizeof (regs->ts_32));
	}
#endif
	rc = thread_set_state (thread->tid, thread->flavor,
		(thread_state_t)thread->state, thread->count);
	if (rc != KERN_SUCCESS) {
		perror ("xnu_thread_set_state");
		thread->count = 0;
		return false;
	}
	return true;
}

static bool xnu_thread_get_gpr(RDebug *dbg, xnu_thread_t *thread) {
	kern_return_t rc;
	R_REG_T *regs;
	if (!dbg || !thread) {
		thread->count = 0;
		return false;
	}
	regs = thread->state = (R_REG_T*)&thread->gpr;
	if (!regs) {
		eprintf ("no gpr ptr set\n");
		return false;
	}
	thread->state_size = sizeof (thread->gpr);
#if __arm || __arm64 || __aarch64
	thread->flavor = regs->ash.flavor = ARM_UNIFIED_THREAD_STATE;
	thread->count = regs->ash.count = R_DEBUG_STATE_SZ;
#elif __x86_64__ || __i386__
	if (dbg->bits == R_SYS_BITS_64) {
		thread->flavor = regs->tsh.flavor = x86_THREAD_STATE;
		thread->count = regs->tsh.count = x86_THREAD_STATE_COUNT;
	} else {
		thread->flavor = regs->tsh.flavor = i386_THREAD_STATE;
		thread->count = regs->tsh.count = i386_THREAD_STATE_COUNT;
	}
#endif
	rc = thread_get_state (thread->tid, thread->flavor,
		(thread_state_t)thread->state, &thread->count);
	if (rc != KERN_SUCCESS) {
		thread->count = 0;
		eprintf ("Failed to get gpr registers\n");
		return false;
	}
	return true;
}

static bool xnu_thread_get_drx(RDebug *dbg, xnu_thread_t *thread) {
	R_DEBUG_REG_T *regs;
	if (!thread) {
		thread->count = 0;
		return false;
	}
	thread->state = regs = (R_DEBUG_REG_T*)&thread->drx;
	thread->state_size = sizeof (thread->drx);
#if __x86_64__ || __i386__
	thread->flavor = regs->dsh.flavor = x86_DEBUG_STATE;
	thread->count = regs->dsh.count = R_DEBUG_STATE_SZ;
	// XXX thread->state = regs->uds;
#elif __arm || __arm64 || __aarch64
	thread->flavor = regs->dsh.flavor = ARM_UNIFIED_THREAD_STATE;
	thread->count = regs->dsh.count;
	thread->state = regs->uds;
#endif
	kern_return_t rc = thread_get_state (thread->tid, thread->flavor, thread->state, &thread->count);
	if (rc != KERN_SUCCESS) {
		thread->count = 0;
		perror ("xnu_thread_get_drx");
		return false;
	}
	return true;
}

static bool xnu_fill_info_thread(RDebug *dbg, xnu_thread_t *thread) {
	mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
	struct proc_threadinfo proc_threadinfo;
	thread_identifier_info_data_t identifier_info;
	int ret_proc;
	kern_return_t kr = thread_info (thread->tid, THREAD_BASIC_INFO,
		(thread_info_t)&thread->basic_info, &count);
	if (kr != KERN_SUCCESS) {
		eprintf ("Fail to get thread_basic_info\n");
		return false;
	}
        count = THREAD_IDENTIFIER_INFO_COUNT;
        kr = thread_info (thread->tid, THREAD_IDENTIFIER_INFO,
			(thread_info_t)&identifier_info, &count);
	if (kr != KERN_SUCCESS) {
		eprintf ("Fail to get thread_identifier_info\n");
		return false;
	}
#if TARGET_OS_IPHONE
	// TODO proc_pidinfo here
	thread->name = strdup ("unknown");
#else
	ret_proc = proc_pidinfo (dbg->pid, PROC_PIDTHREADINFO,
				identifier_info.thread_handle,
				&proc_threadinfo, PROC_PIDTHREADINFO_SIZE);
	if (ret_proc && proc_threadinfo.pth_name[0]) {
		thread->name = strdup (proc_threadinfo.pth_name);
	} else {
		thread->name = strdup ("unknown");
	}
#endif
	return true;
}

static xnu_thread_t *xnu_get_thread_with_info(RDebug *dbg, thread_t tid) {
	xnu_thread_t *thread = R_NEW0 (xnu_thread_t);
	if (!thread) return NULL;
	thread->tid = tid;
	if (!xnu_fill_info_thread (dbg, thread))
		thread->name = strdup ("unknown");
	return thread;
}

static int xnu_update_thread_info(RDebug *dbg, xnu_thread_t *thread) {
	if (!xnu_fill_info_thread (dbg, thread)) {
		free (thread->name);
		thread->name = strdup ("unknown");
	}
	return true;
}

static int thread_find(thread_t *tid, xnu_thread_t *a) {
	if (a && tid && (a->tid == *tid))
		return 0; // match
	return 1;
}

static int xnu_update_thread_list(RDebug *dbg){
	thread_array_t thread_list = NULL;
	unsigned int thread_count = 0;
	xnu_thread_t *thread;
	kern_return_t kr;
	int i;

	// XXX: dbg->threads
	if (!dbg->threads) {
		dbg->threads = r_list_newf ((RListFree)&xnu_thread_free);
		if (!dbg->threads) {
			eprintf ("Impossible to create the list dbg->threads"
				" in xnu_update_thread_list\n");
			return false;
		}
	}
	//ok we have the list that will hold our thread, now is time to get them
	kr = task_threads (pid_to_task (dbg->pid), &thread_list, &thread_count);
	if (kr != KERN_SUCCESS) {
		eprintf ("Failed to get list of task's threads\n");
		return false;
	}
	if (r_list_empty (dbg->threads)) {
		//it's the first time write all threads inside the list
		for (i = 0; i < thread_count; i++) {
			thread = xnu_get_thread_with_info (dbg, thread_list[i]);
//			kr = mach_port_deallocate (mach_task_self (), thread_list[i]);
			if (!thread) {
				eprintf ("Failed to fill_thread\n");
				continue;
			}
#if 0
			if (kr != KERN_SUCCESS) {
				eprintf ("Failed to deallocate port\n");
				xnu_thread_free (thread);
				continue;
			}
#endif
			if (!r_list_append (dbg->threads, thread)) {
				eprintf ("Failed to add thread to list\n");
				xnu_thread_free (thread);
			}
		}
	} else {
		RListIter *iter, *iter2;
		//first pass to get rid of those threads that are not longer alive
		r_list_foreach_safe (dbg->threads, iter, iter2, thread) {
			bool flag = true; // this flag will denote when delete a thread
			for (i = 0; i < thread_count; i++) {
				if (thread->tid == thread_list[i]) {
					flag = false;
					break;
				}
			}
			//it is not longer alive so remove from the list
			if (flag) r_list_delete (dbg->threads, iter);
			//otherwise update the info
			else xnu_update_thread_info (dbg, thread);
		}
		//ok now we have to insert those threads that we don't have
		for (i = 0; i < thread_count; i++) {
			xnu_thread_t *t;
			iter = r_list_find (dbg->threads, &thread_list[i],
					(RListComparator)&thread_find);
#if 0
			kr = mach_port_deallocate (mach_task_self (), thread_list[i]);
			if (kr != KERN_SUCCESS) {
				eprintf ("Failed to deallocate port\n");
				continue;
			}
#endif
			//it means is already in our list
			if (iter) continue;
			//otherwise insert it
			t = xnu_get_thread_with_info (dbg, thread_list[i]);
			r_list_append (dbg->threads, t);
		}
	}
#if 0
	//once that is over we need to free the buffer
	kr = vm_deallocate (mach_task_self (), (mach_vm_address_t)thread_list,
				thread_count * sizeof (thread_t));
	if (kr != KERN_SUCCESS) {
		eprintf ("error: vm_deallocate xnu_update_thread_list\n");
		return false;
	}
#endif
	return true;
}
