/* radare - LGPL - Copyright 2009-2022 - pancake */

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

#if __WINDOWS__
static DWORD WINAPI _r_th_launcher(void *_th) {
#else
static void *_r_th_launcher(void *_th) {
#endif
	int ret;
	RThread *th = _th;
	th->ready = true;
	if (th->delay > 0) {
		r_sys_sleep (th->delay);
	} else if (th->delay < 0) {
		r_th_lock_wait (th->lock);
	}
	r_th_lock_enter (th->lock);
	do {
		r_th_set_running (th, true);
		ret = th->fun (th);
		if (ret < 0) {
			th->ready = false;
			r_th_lock_leave (th->lock);
			return 0;
		}
		r_th_set_running (th, false);
	} while (ret);
	th->ready = false;
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
#elif __WINDOWS__
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

	if (sched_setaffinity (th->tid, sizeof (c), &c) != 0) {
		R_LOG_ERROR ("Failed to set cpu affinity");
		return false;
	}
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
#elif __WINDOWS__
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

R_API RThread *r_th_new(RThreadFunction fun, void *user, int delay) {
	RThread *th = R_NEW0 (RThread);
	if (th) {
		th->lock = r_th_lock_new (true);
		th->running = false;
		th->fun = fun;
		th->user = user;
		th->delay = delay;
		th->breaked = false;
		th->ready = false;
#if HAVE_PTHREAD
		pthread_create (&th->tid, NULL, _r_th_launcher, th);
#elif __WINDOWS__
		th->tid = CreateThread (NULL, 0, _r_th_launcher, th, 0, 0);
#endif
	}
	return th;
}

R_API void r_th_break(RThread *th) {
	th->breaked = true;
}

R_API bool r_th_kill(RThread *th, bool force) {
	if (!th || !th->tid) {
		return false;
	}
	th->breaked = true;
	r_th_break (th);
	r_th_wait (th);
#if HAVE_PTHREAD
#ifdef __ANDROID__
	pthread_kill (th->tid, 9);
#else
	pthread_cancel (th->tid);
#endif
#elif __WINDOWS__
	TerminateThread (th->tid, -1);
#endif
	return 0;
}

// enable should be bool and th->ready must be protected with locks
R_API bool r_th_start(RThread *th, int enable) {
	bool ret = true;
	enable = false; /// R2_580. remove the enable bit imho
	if (enable) {
		R_LOG_WARN ("r_th_start.enable should be removed");
		if (!r_th_is_running (th)) {
			// start thread
			while (!th->ready) {
				/* spinlock */
			}
			r_th_lock_leave (th->lock);
		}
	} else {
		if (r_th_is_running (th)) {
			// stop thread
			//r_th_kill (th, 0);
			r_th_lock_enter (th->lock); // deadlock?
		}
	}
	r_th_set_running (th, enable);
	return ret;
}

R_API int r_th_wait(struct r_th_t *th) {
	int ret = false;
	if (th) {
#if HAVE_PTHREAD
		void *thret;
		ret = pthread_join (th->tid, &thret);
#elif __WINDOWS__
		ret = WaitForSingleObject (th->tid, INFINITE);
#endif
		r_th_set_running (th, false);
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
#if __WINDOWS__
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

