/* radare - LGPL - Copyright 2009-2017 - pancake */

#include <r_th.h>

/* locks/mutex/sems */

R_API RThreadLock *r_th_lock_new(bool recursive) {
	RThreadLock *thl = R_NEW0 (RThreadLock);
	if (thl) {
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
#elif __WINDOWS__
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
	return pthread_mutex_lock (&thl->lock);
#elif __WINDOWS__
	EnterCriticalSection (&thl->lock);
	return 0;
#endif
}

R_API int r_th_lock_tryenter(RThreadLock *thl) {
#if HAVE_PTHREAD
	return !pthread_mutex_trylock (&thl->lock);
#elif __WINDOWS__
	return TryEnterCriticalSection (&thl->lock);
#endif
}

R_API int r_th_lock_leave(RThreadLock *thl) {
#if HAVE_PTHREAD
	return pthread_mutex_unlock (&thl->lock);
#elif __WINDOWS__
	LeaveCriticalSection (&thl->lock);
	return 0;
#endif
}

R_API void *r_th_lock_free(RThreadLock *thl) {
	if (thl) {
#if HAVE_PTHREAD
		pthread_mutex_destroy (&thl->lock);
#elif __WINDOWS__
		DeleteCriticalSection (&thl->lock);
#endif
		free (thl);
	}
	return NULL;
}
