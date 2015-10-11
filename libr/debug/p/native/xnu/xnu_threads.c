/* radare - LGPL - Copyright 2009-2015 - pancake */

typedef struct xnu_thread {
	thread_t tid; // mach_port of the thread id
	char *name;   // name of the thread
	thread_basic_info_data_t basic_info; // need this?
	int stepping; // thread is stepping or not
} xnu_thread_t;

static void xnu_thread_free (xnu_thread_t *thread) {
	if (!thread) return;
	free (thread->name);
	free (thread);
}

static int xnu_fill_info_thread(RDebug *dbg, xnu_thread_t *thread) {
#if TARGET_OS_IPHONE
#warning not implement yet for iOS
	eprintf ("Cannot get thread info on iOS\n");
	return false;
#else
	mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
	struct proc_threadinfo proc_threadinfo;
	thread_identifier_info_data_t identifier_info;
	kern_return_t kr;
	int ret_proc;

	kr = thread_info (thread->tid, THREAD_BASIC_INFO,
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
	ret_proc = proc_pidinfo (dbg->pid, PROC_PIDTHREADINFO,
				identifier_info.thread_handle,
				&proc_threadinfo, PROC_PIDTHREADINFO_SIZE);
	if (ret_proc && proc_threadinfo.pth_name[0]) {
		thread->name = strdup (proc_threadinfo.pth_name);
	} else {
		thread->name = strdup ("unknown");
	}
	return true;
#endif
}

static xnu_thread_t *xnu_get_thread_with_info (RDebug *dbg, thread_t tid){
	xnu_thread_t *thread = NULL;
	int ret;
	thread = R_NEW0 (xnu_thread_t);
	if (!thread) return NULL;
	thread->tid = tid;
	ret = xnu_fill_info_thread (dbg, thread);
	if (ret == false) {
		thread->name = strdup ("unknown");
	}
	return thread;
}

static int xnu_update_thread_info(RDebug *dbg, xnu_thread_t *thread) {
	int ret;
	free (thread->name);
	ret = xnu_fill_info_thread (dbg, thread);
	if (ret == false) {
		thread->name = strdup ("unknown");
	}
	return true;

}

static int thread_find(xnu_thread_t *a, thread_t *tid) {
	if (a) return a->tid == *tid;
	return false;
}

static int xnu_update_thread_list(RDebug *dbg){
	xnu_thread_t *thread;
	thread_array_t thread_list;
	kern_return_t kr;
	unsigned int thread_count;
	int i;

	if (dbg->threads == NULL) {
		//we need to create the list to hold threads
		//this function will be called the first time
		//after attached to the child process (review the logic)
		dbg->threads  = r_list_new();
		if (!dbg->threads) {
			eprintf ("Impossible to create the list dbg->threads"
				" in xnu_update_thread_list\n");
			return false;
		}
		dbg->threads->free = (RListFree)&xnu_thread_free;
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
			kr = mach_port_deallocate (mach_task_self (), thread_list[i]);
			if (!thread) {
				eprintf ("Failed to fill_thread\n");
				continue;
			}
			if (kr != KERN_SUCCESS) {
				eprintf ("Failed to deallocate port\n");
				xnu_thread_free (thread);
				continue;
			}
			if (!r_list_append (dbg->threads, thread)) {
				eprintf ("Failed to add thread to list\n");
				xnu_thread_free (thread);

			}
		}
	} else {
		//we need to update our list. So we need to iterate over
		//thread_list and see which threads we have. If some thread
		//is gone we need to get rid of it from our list. The rest
		//will be added.
		RListIter *iter = NULL;
		//first pass to get rid of those threads that are not longer alive
		r_list_foreach (dbg->threads, iter, thread) {
			int flag = 1; // this flag will denote when delete a thread
			for (i = 0; i < thread_count; i++) {
				if (thread->tid == thread_list[i]) {
					flag = 0;
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
			kr = mach_port_deallocate (mach_task_self (),
						thread_list[i]);
			if (kr != KERN_SUCCESS) {
				eprintf ("Failed to deallocate port\n");
				continue;
			}
			//it means is already in our list
			if (iter) continue;
			//otherwise insert it
			t = xnu_get_thread_with_info (dbg, thread_list[i]);
			r_list_append (dbg->threads, t);
		}
	}

	//once that is over we need to free the buffer
	kr = vm_deallocate (mach_task_self (), (mach_vm_address_t)thread_list,
				thread_count * sizeof(thread_t));
	if (kr != KERN_SUCCESS) {
		eprintf ("error: vm_deallocate xnu_update_thread_list\n");
		return false;
	}
	return true;
}
