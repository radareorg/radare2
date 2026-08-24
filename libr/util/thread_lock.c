/* radare - LGPL - Copyright 2009-2022 - pancake, keegan */

#define R_LOG_DISABLE 1

#include <r_th.h>
#include <r_util/r_assert.h>
#include <r_util/r_log.h>

#if R2__WINDOWS__
enum {
	W32_SRW_ENTER,
	W32_SRW_TRYENTER,
	W32_SRW_LEAVE,
};

static bool w32_srw_init(RThreadLock *lock) {
	R_STATIC_ASSERT (sizeof (lock->lock.srw) <= sizeof (CRITICAL_SECTION));
	HANDLE lib = GetModuleHandleA ("kernel32.dll");
	FARPROC init = GetProcAddress (lib, "InitializeSRWLock");
	FARPROC *api = lock->lock.srw.api;
	api[W32_SRW_ENTER] = GetProcAddress (lib, "AcquireSRWLockExclusive");
	api[W32_SRW_TRYENTER] = GetProcAddress (lib, "TryAcquireSRWLockExclusive");
	api[W32_SRW_LEAVE] = GetProcAddress (lib, "ReleaseSRWLockExclusive");
	if (!init || !api[W32_SRW_ENTER] || !api[W32_SRW_TRYENTER] || !api[W32_SRW_LEAVE]) {
		return false;
	}
	((void (WINAPI *)(PVOID))init) (&lock->lock.srw.lock);
	return true;
}
#endif

/* locks/mutex/sems */
static bool _lock_init(RThreadLock *thl, bool recursive) {
#if HAVE_PTHREAD
	pthread_mutexattr_t attr;
	if (pthread_mutexattr_init (&attr) != 0) {
		return false;
	}
	if (recursive) {
#if !defined(__GLIBC__) || __USE_UNIX98__
		if (pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE) != 0) {
			pthread_mutexattr_destroy (&attr);
			return false;
		}
#else
		if (pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE_NP) != 0) {
			pthread_mutexattr_destroy (&attr);
			return false;
		}
#endif
	}
	int rc = pthread_mutex_init (&thl->lock, &attr);
	pthread_mutexattr_destroy (&attr);
	if (rc != 0) {
		return false;
	}
#elif R2__WINDOWS__
	if (!recursive && w32_srw_init (thl)) {
		thl->type = (RThreadLockType)(thl->type | R_TH_LOCK_TYPE_SRW);
	} else {
		InitializeCriticalSection (&thl->lock.cs);
	}
#else
#if !R2_UEFI
#warning Unsupported mutex
#endif
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
	if (_lock_init (thl, recursive)) {
		thl->type = (RThreadLockType)(thl->type | R_TH_LOCK_TYPE_HEAP);
		thl->active = true;
	} else {
		R_FREE (thl);
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
	if (!(thl->type & R_TH_LOCK_TYPE_HEAP)) {
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
	if (thl->type & R_TH_LOCK_TYPE_SRW) {
		((void (WINAPI *)(PVOID))thl->lock.srw.api[W32_SRW_ENTER]) (&thl->lock.srw.lock);
	} else {
		EnterCriticalSection (&thl->lock.cs);
	}
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
	if (thl->type & R_TH_LOCK_TYPE_SRW) {
		return ((BYTE (WINAPI *)(PVOID))thl->lock.srw.api[W32_SRW_TRYENTER]) (&thl->lock.srw.lock) != 0;
	}
	return TryEnterCriticalSection (&thl->lock.cs);
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
	if (thl->type & R_TH_LOCK_TYPE_SRW) {
		((void (WINAPI *)(PVOID))thl->lock.srw.api[W32_SRW_LEAVE]) (&thl->lock.srw.lock);
	} else {
		LeaveCriticalSection (&thl->lock.cs);
	}
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
		if (!(thl->type & R_TH_LOCK_TYPE_SRW)) {
			DeleteCriticalSection (&thl->lock.cs);
		}
#endif
		if (thl->type & R_TH_LOCK_TYPE_HEAP) {
			free (thl);
		}
	}
	return NULL;
}
