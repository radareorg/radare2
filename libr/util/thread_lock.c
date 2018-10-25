/* radare - LGPL - Copyright 2009-2017 - pancake */

#include <r_th.h>

/* locks/mutex/sems */

R_API RThreadLock *r_th_lock_new(bool recursive) {
	RThreadLock *thl = R_NEW0 (RThreadLock);
	if (thl) {
		// TODO: thl->refs is inconsistently guarded by mutexes and could race
		thl->refs = 0;
#if HAVE_PTHREAD
		if (recursive) {
			pthread_mutexattr_t attr;
			pthread_mutexattr_init (&attr);
#if !defined(__GLIBC__) || __USE_UNIX98__
			pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE);
#else
			pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE_NP);
#endif
			pthread_mutex_init (&thl->lock, &attr);
		} else {
			pthread_mutex_init (&thl->lock, NULL);
		}
#elif __WINDOWS__ && !defined(__CYGWIN__)
		// TODO: obey `recursive` (currently it is always recursive)
		InitializeCriticalSection (&thl->lock);
#endif
	}
	return thl;
}

R_API int r_th_lock_wait(RThreadLock *thl) {
	r_th_lock_enter (thl); // locks here
	r_th_lock_leave (thl); // releases previous mutex
	return 0;
}

R_API int r_th_lock_enter(RThreadLock *thl) {
#if HAVE_PTHREAD
	pthread_mutex_lock (&thl->lock);
#elif __WINDOWS__ && !defined(__CYGWIN__)
	EnterCriticalSection (&thl->lock);
#endif
	return ++thl->refs;
}

R_API int r_th_lock_leave(RThreadLock *thl) {
#if HAVE_PTHREAD
	pthread_mutex_unlock (&thl->lock);
#elif __WINDOWS__ && !defined(__CYGWIN__)
	LeaveCriticalSection (&thl->lock);
#endif
	if (thl->refs > 0) {
		thl->refs--;
	}
	return thl->refs;
}

R_API int r_th_lock_check(RThreadLock *thl) {
	return thl->refs;
}

R_API void *r_th_lock_free(RThreadLock *thl) {
	if (thl) {
#if HAVE_PTHREAD
		pthread_mutex_destroy (&thl->lock);
#elif __WINDOWS__ && !defined(__CYGWIN__)
		DeleteCriticalSection (&thl->lock);
#endif
		free (thl);
	}
	return NULL;
}
