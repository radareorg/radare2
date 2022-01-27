/* radare - LGPL - Copyright 2009-2022 - pancake */

#include <r_th.h>

/* locks/mutex/sems */

static bool lock_init(RThreadLock *thl, bool recursive) {
#if HAVE_PTHREAD
	if (recursive) {
		pthread_mutexattr_t attr;
		pthread_mutexattr_init (&attr);
#if !defined(__GLIBC__) || __USE_UNIX98__
		pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE);
#else
		pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE_NP);
#endif /* !defined(__GLIBC__) || __USE_UNIX98__ */
		pthread_mutex_init (&thl->lock, &attr);
	} else {
		pthread_mutexattr_t attr;
		pthread_mutexattr_init (&attr);
		pthread_mutex_init (&thl->lock, &attr);
	}
#elif __WINDOWS__
	// TODO: obey `recursive` (currently it is always recursive)
	InitializeCriticalSection (&thl->lock);
#else
#warning Unsupported mutex
	return false;
#endif /* HAVE_PTHREAD */
	return true;
}

R_API RThreadLock *r_th_lock_new(bool recursive) {
	RThreadLock *thl = R_NEW0 (RThreadLock);
	if (!thl) {
		return NULL;
	}

	if (!lock_init (thl, recursive)) {
		return NULL;
	}

	thl->type = R_TH_LOCK_TYPE_HEAP;
	thl->active = 1;
#ifdef HAVE_STDATOMIC_H
	thl->activating = 0;
#endif
	return thl;
}

R_API int r_th_lock_wait(RThreadLock *thl) {
	r_th_lock_enter (thl); // locks here
	r_th_lock_leave (thl); // releases previous mutex
	return 0;
}

// TODO: return bool
R_API int r_th_lock_enter(RThreadLock *thl) {
	if (!thl) {
		return -1;
	}

	// initialize static locks on acquisition
	if (thl->type == R_TH_LOCK_TYPE_STATIC) {
#ifdef HAVE_STDATOMIC_H
		while (atomic_exchange_explicit (&thl->activating, true, memory_order_acquire))
			;
#endif /* HAVE_STDATOMIC_H */

		if (!thl->active) {
			lock_init (thl, false);
			thl->active = 1;
		}

#ifdef HAVE_STDATOMIC_H
		atomic_store_explicit (&thl->activating, false, memory_order_release);
#endif /* HAVE_STDATOMIC_H */
	}
#if HAVE_PTHREAD
	return pthread_mutex_lock (&thl->lock);
#elif __WINDOWS__
	EnterCriticalSection (&thl->lock);
	return 0;
#else
	return 0;
#endif
}

R_API int r_th_lock_tryenter(RThreadLock *thl) {
	if (!thl) {
		return -1;
	}
#if HAVE_PTHREAD
	return !pthread_mutex_trylock (&thl->lock);
#elif __WINDOWS__
	return TryEnterCriticalSection (&thl->lock);
#else
	return 0;
#endif
}

R_API int r_th_lock_leave(RThreadLock *thl) {
	if (!thl) {
		return -1;
	}
#if HAVE_PTHREAD
	return pthread_mutex_unlock (&thl->lock);
#elif __WINDOWS__
	LeaveCriticalSection (&thl->lock);
	return 0;
#else
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
		if (thl->type == R_TH_LOCK_TYPE_HEAP) {
			free (thl);
		}
	}
	return NULL;
}
