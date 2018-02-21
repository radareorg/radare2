/* radare - LGPL - Copyright 2009-2018 - pancake */

#include <r_th.h>

#if __WINDOWS__ && !defined(__CYGWIN__)
static DWORD WINAPI _r_th_launcher(void *_th) {
#else
static void *_r_th_launcher(void *_th) {
#endif
	int ret;
	RThread *th = _th;
	th->ready = true;
#if __UNIX__
	if (th->delay > 0) {
		sleep (th->delay);
	} else if (th->delay < 0) {
		r_th_lock_wait (th->lock);
	}
#else
	if (th->delay < 0) {
		r_th_lock_wait (th->lock);
	}
#endif
	do {
		// CID 1378280:  API usage errors  (LOCK)
		// "r_th_lock_leave" unlocks "th->lock->lock" while it is unlocked.
		r_th_lock_leave (th->lock);
		th->running = true;
		ret = th->fun (th);
		th->running = false;
		r_th_lock_enter (th->lock);
	} while (ret);
#if HAVE_PTHREAD
	pthread_exit (&ret);
#endif
	return 0;
}

R_API int r_th_push_task(struct r_th_t *th, void *user) {
	int ret = true;
	th->user = user;
	r_th_lock_leave (th->lock);
	return ret;
}

R_API RThread *r_th_new(R_TH_FUNCTION(fun), void *user, int delay) {
	RThread *th = R_NEW0 (RThread);
	if (th) {
		th->lock = r_th_lock_new (false);
		th->running = false;
		th->fun = fun;	
		th->user = user;
		th->delay = delay;
		th->breaked = false;
		th->ready = false;
#if HAVE_PTHREAD
		pthread_create (&th->tid, NULL, _r_th_launcher, th);
#elif __WINDOWS__ && !defined(__CYGWIN__)
		th->tid = CreateThread (NULL, 0, _r_th_launcher, th, 0, 0);
#endif
	}
	return th;
}

R_API void r_th_break(RThread *th) {
	th->breaked = true;
}

R_API bool r_th_kill(RThread *th, bool force) {
	if (!th) {
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
#elif __WINDOWS__ && !defined(__CYGWIN__)
	TerminateThread (th->tid, -1);
#endif
	return 0;
}

R_API bool r_th_start(RThread *th, int enable) {
	bool ret = true;
	if (enable) {
		if (!th->running) {
			// start thread
			while (!th->ready) {
				/* spinlock */
			}
			r_th_lock_leave (th->lock);
		}
	} else {
		if (th->running) {
			// stop thread
			r_th_kill (th, 0);
			r_th_lock_enter (th->lock); // deadlock?
		}
	}
	th->running = enable;
	return ret;
}

R_API int r_th_wait(struct r_th_t *th) {
	int ret = false;
	void *thret;
	if (th) {
#if HAVE_PTHREAD
		ret = pthread_join (th->tid, &thret);
#elif __WINDOWS__ && !defined(__CYGWIN__)
		ret = WaitForSingleObject (th->tid, INFINITE);
#endif
		th->running = false;
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
	r_th_kill (th, true);
#if __WINDOWS__ && !defined(__CYGWIN__)
	CloseHandle (th->tid);
#endif
	r_th_lock_free (th->lock);
	free (th);
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

