/* radare - LGPL - Copyright 2009-2022 - pancake, keegan */

#define R_LOG_DISABLE 1

#include <r_th.h>
#include <r_util/r_assert.h>
#include <r_util/r_log.h>

/* locks/mutex/sems */
static bool _lock_init(RThreadLock *thl, bool recursive) {
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
		pthread_mutexattr_t attr;
		pthread_mutexattr_init (&attr);
		pthread_mutex_init (&thl->lock, &attr);
	}
#elif R2__WINDOWS__
	// TODO: obey `recursive` (currently it is always recursive)
	InitializeCriticalSection (&thl->lock);
#else
#warning Unsupported mutex
	return false;
#endif /* HAVE_PTHREAD */
	return true;
}

R_API bool r_atomic_exchange(volatile R_ATOMIC_BOOL *data, bool v) {
#if HAVE_STDATOMIC_H
	return atomic_exchange_explicit (data, v, memory_order_acquire);
#elif __GNUC__ && !__TINYC__ && !(__APPLE__ && __ppc__)
	int orig = 0;
	int conv = (int)v;
	// Use __atomic_exchange for gcc for consistency across platforms
	__atomic_exchange (data, &conv, &orig, __ATOMIC_ACQUIRE);
	return (bool)orig;
#elif _MSC_VER
	int conv = (int)v;
	return (bool)InterlockedExchange (data, conv);
#else
	// Fallback with basic non-atomic implementation
	// Note this is NOT thread-safe
	bool orig = *data;
	*data = v;
	return orig;
#endif
}

R_API void r_atomic_store(volatile R_ATOMIC_BOOL *data, bool v) {
#if HAVE_STDATOMIC_H
	atomic_store_explicit (data, v, memory_order_release);
#elif __GNUC__ && !__TINYC__ && !(__APPLE__ && __ppc__)
	int conv = (int)v;
	// Use __atomic_store for gcc for consistency across platforms
	__atomic_store (data, &conv, __ATOMIC_RELEASE);
#elif _MSC_VER
	int conv = (int)v;
	// This is a busy-wait loop which isn't ideal but ensures store happens
	while (InterlockedExchange (data, conv) != conv)
		;
#else
	// Fallback with basic non-atomic implementation
	// Note this is NOT thread-safe
	*data = v;
#endif
}

R_API RThreadLock *r_th_lock_new(bool recursive) {
	R_LOG_DEBUG ("r_th_lock_new");
	RThreadLock *thl = R_NEW0 (RThreadLock);
	if (thl) {
		if (_lock_init (thl, recursive)) {
			thl->type = R_TH_LOCK_TYPE_HEAP;
			thl->active = true;
			thl->activating = false;
		} else {
			R_FREE (thl);
		}
	}
	return thl;
}

R_API bool r_th_lock_wait(RThreadLock *thl) {
	R_RETURN_VAL_IF_FAIL (thl, false);
	R_LOG_DEBUG ("r_th_lock_wait");
	r_th_lock_enter (thl); // locks here
	r_th_lock_leave (thl); // releases previous mutex
	return true;
}

#if WANT_THREADS
R_API bool r_th_lock_enter(RThreadLock *thl) {
	if (!thl) {
		return false;
	}
//	R_RETURN_VAL_IF_FAIL (thl, false);
	R_LOG_DEBUG ("r_th_lock_enter");

	// initialize static locks on acquisition
	if (thl->type == R_TH_LOCK_TYPE_STATIC) {
		while (r_atomic_exchange (&thl->activating, true)) {
			// spinning
		}
		if (!thl->active) {
			_lock_init (thl, false);
			thl->active = true;
		}
		// finish spinning
		r_atomic_store (&thl->activating, false);
	}
#if HAVE_PTHREAD
	return pthread_mutex_lock (&thl->lock) == 0;
#elif R2__WINDOWS__
	EnterCriticalSection (&thl->lock);
	return true;
#else
	return true;
#endif
}
R_API bool r_th_lock_tryenter(RThreadLock *thl) {
	R_RETURN_VAL_IF_FAIL (thl, false);
	R_LOG_DEBUG ("r_th_lock_tryenter");
#if HAVE_PTHREAD
	return pthread_mutex_trylock (&thl->lock) == 0;
#elif R2__WINDOWS__
	return TryEnterCriticalSection (&thl->lock);
#else
	return false;
#endif
}

R_API bool r_th_lock_leave(RThreadLock *thl) {
	if (!thl) {
		return false;
	}
	//R_RETURN_VAL_IF_FAIL (thl, false);
	R_LOG_DEBUG ("r_th_lock_leave");
#if HAVE_PTHREAD
	return pthread_mutex_unlock (&thl->lock) == 0;
#elif R2__WINDOWS__
	LeaveCriticalSection (&thl->lock);
	return true;
#else
	return false;
#endif
}
#else
R_API bool r_th_lock_enter(RThreadLock *thl) {
	return false;
}
R_API bool r_th_lock_tryenter(RThreadLock *thl) {
	return false;
}
R_API bool r_th_lock_leave(RThreadLock *thl) {
	return false;
}
#endif

R_API void *r_th_lock_free(RThreadLock *thl) {
	R_LOG_DEBUG ("r_th_lock_free");
	if (thl) {
#if HAVE_PTHREAD
		pthread_mutex_destroy (&thl->lock);
#elif R2__WINDOWS__
		DeleteCriticalSection (&thl->lock);
#endif
		if (thl->type == R_TH_LOCK_TYPE_HEAP) {
			free (thl);
		}
	}
	return NULL;
}