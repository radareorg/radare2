/* radare - LGPL - Copyright 2009-2023 - pancake */

#include <r_th.h>
#include <r_util.h>

#if __APPLE__
// Here to avoid polluting mach types macro redefinitions...
#include <mach/thread_act.h>
#include <mach/thread_policy.h>
#endif

#if __sun
#include <sys/pset.h>
#endif

#if __HAIKU__
#include <kernel/scheduler.h>
#endif

#if HAVE_PTHREAD
// 1MB per thread. otherwise running analysis can segfault
// this is pthread-specific for now, and will be good if we can have control
// on this at some point, via api or dynamically depending on the task.
#define THREAD_STACK_SIZE (1024 * 1024)
#endif

#if R2__WINDOWS__
static DWORD WINAPI _r_th_launcher(void *_th) {
#else
static void *_r_th_launcher(void *_th) {
#endif
	int ret = 0;
	bool repeat = true;
	RThread *th = _th;
	do {
		r_th_lock_enter (th->lock);
		bool is_ready = th->ready;
		r_th_lock_leave (th->lock);
		
		while (!is_ready) {
			// spinlock
#ifdef	__GNUC__
			__asm__ volatile ("nop");
#else
	//		r_sys_usleep (1);
#endif
			r_th_lock_enter (th->lock);
			if (th->breaked) {
				th->running = false;
				r_th_lock_leave (th->lock);
				return 0;
			}
			is_ready = th->ready;
			r_th_lock_leave (th->lock);
		}
		r_th_lock_enter (th->lock);
		if (th->delay) {
			r_sys_sleep (th->delay);
			th->delay = 0;
		}
		ret = th->fun (th);
		switch (ret) {
		case R_TH_STOP:
			repeat = false;
		case R_TH_PAUSE:
			r_th_lock_enter (th->lock);
			th->ready = false;
			r_th_lock_leave (th->lock);
		case R_TH_REPEAT:
			r_th_lock_leave (th->lock);
			break;
		case R_TH_FREED:
		default:
			r_th_lock_enter (th->lock);
			th->ready = false;
			th->running = false;
			r_th_lock_leave (th->lock);
#if HAVE_PTHREAD
			pthread_exit (&ret);
#endif
			r_th_lock_leave (th->lock);
			return 0;
		}
	} while (repeat && !th->breaked);
	
	r_th_lock_enter (th->lock);
	th->running = false;
	r_th_lock_leave (th->lock);
#if HAVE_PTHREAD
	pthread_exit (&ret);
#endif
	return 0;
}

R_API bool r_th_is_running(RThread *th) {
	r_th_lock_enter (th->lock);
	bool res = th->running;
	r_th_lock_leave (th->lock);
	return res;
}

R_API void r_th_set_running(RThread *th, bool b) {
	r_th_lock_enter (th->lock);
	th->running = b;
	r_th_lock_leave (th->lock);
}

R_API int r_th_push_task(RThread *th, void *user) {
	int ret = true;
	th->user = user;
	r_th_lock_leave (th->lock);
	return ret;
}

R_API R_TH_TID r_th_self(void) {
#if HAVE_PTHREAD
	return pthread_self ();
#elif R2__WINDOWS__
	return GetCurrentThread ();
#else
#pragma message("Not implemented on this platform")
	return (R_TH_TID)-1;
#endif
}

R_API bool r_th_setname(RThread *th, const char *name) {
#if defined(HAVE_PTHREAD_NP) && HAVE_PTHREAD_NP
#if __linux__ || __sun
	if (pthread_setname_np (th->tid, name) != 0) {
		R_LOG_ERROR ("Failed to set thread name");
		return false;
	}
#elif __APPLE__
	if (pthread_setname_np (name) != 0) {
		R_LOG_ERROR ("Failed to set thread name");
		return false;
	}
#elif __FreeBSD__ || __OpenBSD__ || __DragonFly__ || __sun
	pthread_set_name_np (th->tid, name);
#elif __NetBSD__
	if (pthread_setname_np (th->tid, "%s", (void *)name) != 0) {
		R_LOG_ERROR ("Failed to set thread name");
		return false;
	}
#elif __HAIKU__
	if (rename_thread ((thread_id)th->tid, name) != B_OK) {
		R_LOG_ERROR ("Failed to set thread name");
		return false;
	}
#else
#pragma message("warning r_th_setname not implemented")
#endif
#endif
	return true;
}

R_API bool r_th_getname(RThread *th, char *name, size_t len) {
#if defined(HAVE_PTHREAD_NP) && HAVE_PTHREAD_NP
#if __linux__ || __NetBSD__ || __APPLE__ || __sun
	if (pthread_getname_np (th->tid, name, len) != 0) {
		R_LOG_ERROR ("Failed to get thread name");
		return false;
	}
#elif (__FreeBSD__ &&  __FreeBSD_version >= 1200000) || __DragonFly__  || (__OpenBSD__ && OpenBSD >= 201905)
	pthread_get_name_np (th->tid, name, len);
#elif defined(__HAIKU__)
	thread_info ti;
	size_t flen = len < B_OS_NAME_LENGTH ? len : B_OS_NAME_LENGTH;

	if (get_thread_info ((thread_id)th->tid, &ti) != B_OK) {
		R_LOG_ERROR ("Failed to get thread name");
		return false;
	}

	r_str_ncpy (name, ti.name, flen);
#else
#pragma message("warning r_th_getname not implemented")
#endif
#endif
	return true;
}

#if 0
// disabled because its not really useful and hard to compile
R_API bool r_th_setaffinity(RThread *th, int cpuid) {
#if !WANT_THREADS || defined(__wasi__) || defined(_WASI_EMULATED_SIGNAL)
	return true;
#elif __linux__
#if defined(__GLIBC__) && defined (__GLIBC_MINOR__) && (__GLIBC__ <= 2) && (__GLIBC_MINOR__ <= 2)
	// Old versions of GNU libc don't have this feature
#pragma message("warning r_th_setaffinity not implemented")
#else
	cpu_set_t c;
	CPU_ZERO(&c);
	CPU_SET(cpuid, &c);
#if 0
	if (sched_setaffinity (th->tid, sizeof (c), &c) != 0) {
		R_LOG_ERROR ("Failed to set cpu affinity");
		return false;
	}
#endif
#endif
#elif __FreeBSD__ || __DragonFly__
	cpuset_t c;
	CPU_ZERO(&c);
	CPU_SET(cpuid, &c);

	if (pthread_setaffinity_np (th->tid, sizeof (c), &c) != 0) {
		R_LOG_ERROR ("Failed to set cpu affinity");
		return false;
	}
#elif __NetBSD__
	cpuset_t *c;
	c = cpuset_create ();

	if (pthread_setaffinity_np (th->tid, cpuset_size(c), c) != 0) {
		cpuset_destroy (c);
		R_LOG_ERROR ("Failed to set cpu affinity");
		return false;
	}

	cpuset_destroy (c);
#elif __APPLE__
	thread_affinity_policy_data_t c = {cpuid};
	if (thread_policy_set (pthread_mach_thread_np (th->tid),
		THREAD_AFFINITY_POLICY, (thread_policy_t)&c, 1) != KERN_SUCCESS) {
		R_LOG_ERROR ("Failed to set cpu affinity");
		return false;
	}
#elif R2__WINDOWS__
	if (SetThreadAffinityMask (th->tid, (DWORD_PTR)1 << cpuid) == 0) {
		R_LOG_ERROR ("Failed to set cpu affinity");
		return false;
	}
#elif __sun
	psetid_t c;

	pset_create (&c);
	pset_assign (c, cpuid, NULL);

	if (pset_bind (c, P_PID, r_sys_getpid (), NULL)) {
		pset_destroy (c);
		R_LOG_ERROR ("Failed to set cpu affinity");
		return false;
	}

	pset_destroy (c);
#else
#pragma message("warning r_th_setaffinity not implemented")
#endif
	return true;
}
#endif

R_API RThread *r_th_new(RThreadFunction fun, void *user, ut32 delay) {
	RThread *th = R_NEW0 (RThread);
	th->lock = r_th_lock_new (true);
	th->running = false;
	th->fun = fun;
	th->user = user;
	th->delay = delay;
	th->breaked = false;
	th->ready = false;
#if HAVE_PTHREAD
	pthread_attr_t *pattr = NULL;
	pthread_attr_t attr;
	int rc = pthread_attr_init(&attr);
	if (rc != -1) {
		rc = pthread_attr_setstacksize (&attr, THREAD_STACK_SIZE);
		if (rc != -1) {
			pattr = &attr;
		}
	}
	pthread_create (&th->tid, pattr, _r_th_launcher, th);
#elif R2__WINDOWS__
	th->tid = CreateThread (NULL, 0, _r_th_launcher, th, 0, 0);
#endif
	th->running = true;
	return th;
}

R_API void r_th_break(RThread *th) {
	th->breaked = true;
}

R_API bool r_th_kill(RThread *th, bool force) {
	if (!th || !th->tid) {
		return false;
	}
	// First set breaked flag to signal thread to stop
	th->breaked = true;
	
	// If force is true, kill the thread immediately
	if (force) {
#if HAVE_PTHREAD
#ifdef __ANDROID__
		pthread_kill (th->tid, 9);
#else
		pthread_cancel (th->tid);
#endif
#elif R2__WINDOWS__
		TerminateThread (th->tid, -1);
#endif
	}
	
	// Wait for thread to finish
	r_th_wait (th);
	return false;
}

// enable should be bool and th->ready must be protected with locks
R_API bool r_th_start(RThread *th) {
	R_RETURN_VAL_IF_FAIL (th, false);
	r_th_lock_enter (th->lock);
	if (!th->running) {
		// thread already exited, cannot launch
		r_th_lock_leave (th->lock);
		return false;
	}
	if (th->ready) {
		//thread is currently running and has launched user function
		r_th_lock_leave (th->lock);
		return true;
	}
	th->ready = true;
	r_th_lock_leave (th->lock);
	return true;
}

R_API int r_th_wait(struct r_th_t *th) {
	int ret = false;
	if (th) {
#if HAVE_PTHREAD
		void *thret;
		ret = pthread_join (th->tid, &thret);
#elif R2__WINDOWS__
		ret = WaitForSingleObject (th->tid, INFINITE);
#endif
	}
	return ret;
}

R_API int r_th_wait_async(struct r_th_t *th) {
	return th->running;
}

R_API void *r_th_free(struct r_th_t *th) {
	if (!th) {
		return NULL;
	}
#if R2__WINDOWS__
	CloseHandle (th->tid);
#endif
	r_th_lock_free (th->lock);
	free (th);
	return NULL;
}

R_API void *r_th_kill_free(struct r_th_t *th) {
	if (!th) {
		return NULL;
	}
	r_th_kill (th, true);
	r_th_free (th);
	return NULL;
}

#if 0

// Thread Pipes
typedef struct r_th_pipe_t {
	RList *msglist;
	RThread *th;
	//RThreadLock *lock;
} RThreadPipe;

r_th_pipe_new();

#endif