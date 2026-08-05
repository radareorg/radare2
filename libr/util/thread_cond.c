/* radare - LGPL - Copyright 2009-2026 - pancake, thestr4ng3r */

#include <r_th.h>
#include <r_util/r_time.h>

#if R2__WINDOWS__
// Use legacy primitives when native condition variables are unavailable.
typedef struct {
	CONDITION_VARIABLE cond;
	CRITICAL_SECTION waiters_lock;
	RList *waiters;
	FARPROC wait_srw;
	bool native;
} W32Cond;

typedef struct w32_cond_waiter_t {
	HANDLE event;
} W32CondWaiter;

static W32Cond *cond_data(RThreadCond *cond) {
	return (W32Cond *)cond->cond.Ptr;
}

static bool cond_wait(W32Cond *cond, RThreadLock *lock, DWORD timeout) {
	if (cond->native) {
		if (lock->type & R_TH_LOCK_TYPE_SRW) {
			return ((BOOL (WINAPI *)(PCONDITION_VARIABLE, PVOID, DWORD, ULONG))
				cond->wait_srw) (&cond->cond, &lock->lock.srw.lock, timeout, 0);
		}
		return r_w32_SleepConditionVariableCS (&cond->cond, &lock->lock.cs, timeout);
	}
	W32CondWaiter *waiter = R_NEW0 (W32CondWaiter);
	waiter->event = CreateEvent (NULL, FALSE, FALSE, NULL);
	if (!waiter->event) {
		free (waiter);
		return false;
	}
	EnterCriticalSection (&cond->waiters_lock);
	r_list_append (cond->waiters, waiter);
	LeaveCriticalSection (&cond->waiters_lock);

	r_th_lock_leave (lock);
	const DWORD result = WaitForSingleObject (waiter->event, timeout);

	EnterCriticalSection (&cond->waiters_lock);
	r_list_delete_data (cond->waiters, waiter);
	LeaveCriticalSection (&cond->waiters_lock);
	r_th_lock_enter (lock);
	CloseHandle (waiter->event);
	free (waiter);
	return result == WAIT_OBJECT_0;
}

static void cond_signal(W32Cond *cond, bool all) {
	if (cond->native) {
		if (all) {
			r_w32_WakeAllConditionVariable (&cond->cond);
		} else {
			r_w32_WakeConditionVariable (&cond->cond);
		}
		return;
	}
	EnterCriticalSection (&cond->waiters_lock);
	W32CondWaiter *waiter = NULL;
	while ((waiter = r_list_pop_head (cond->waiters))) {
		SetEvent (waiter->event);
		if (!all) {
			break;
		}
	}
	LeaveCriticalSection (&cond->waiters_lock);
}
#endif

R_API RThreadCond *r_th_cond_new(void) {
	RThreadCond *cond = R_NEW0 (RThreadCond);
#if HAVE_PTHREAD
	if (pthread_cond_init (&cond->cond, NULL) != 0) {
		free (cond);
		return NULL;
	}
#elif R2__WINDOWS__
	W32Cond *wcond = R_NEW0 (W32Cond);
	wcond->wait_srw = GetProcAddress (GetModuleHandleA ("kernel32.dll"), "SleepConditionVariableSRW");
	wcond->native = wcond->wait_srw && r_w32_InitializeConditionVariable (&wcond->cond);
	if (!wcond->native) {
		wcond->waiters = r_list_new ();
		InitializeCriticalSection (&wcond->waiters_lock);
	}
	cond->cond.Ptr = wcond;
#endif
	return cond;
}

R_API void r_th_cond_signal(RThreadCond *cond) {
#if HAVE_PTHREAD
	pthread_cond_signal (&cond->cond);
#elif R2__WINDOWS__
	cond_signal (cond_data (cond), false);
#endif
}

R_API void r_th_cond_signal_all(RThreadCond *cond) {
#if HAVE_PTHREAD
	pthread_cond_broadcast (&cond->cond);
#elif R2__WINDOWS__
	cond_signal (cond_data (cond), true);
#endif
}

// Waits until the condition is signaled; a timeout_ms of 0 or UT64_MAX waits forever.
// Returns false only when the timeout expires before the condition is signaled.
R_API bool r_th_cond_wait(RThreadCond *cond, RThreadLock *lock, ut64 timeout_ms) {
	if (timeout_ms == 0 || timeout_ms == UT64_MAX) {
#if HAVE_PTHREAD
		pthread_cond_wait (&cond->cond, &lock->lock);
#elif R2__WINDOWS__
		cond_wait (cond_data (cond), lock, INFINITE);
#endif
		return true;
	}
#if HAVE_PTHREAD
	const ut64 deadline_us = r_time_now () + (timeout_ms * 1000);
	struct timespec ts = {
		.tv_sec = (time_t) (deadline_us / 1000000),
		.tv_nsec = (long) ((deadline_us % 1000000) * 1000)
	};
	return pthread_cond_timedwait (&cond->cond, &lock->lock, &ts) == 0;
#elif R2__WINDOWS__
	const DWORD timeout = timeout_ms < INFINITE ? (DWORD)timeout_ms : INFINITE - 1;
	return cond_wait (cond_data (cond), lock, timeout);
#else
	return true;
#endif
}

R_API void r_th_cond_free(RThreadCond *cond) {
	if (!cond) {
		return;
	}
#if HAVE_PTHREAD
	pthread_cond_destroy (&cond->cond);
#elif R2__WINDOWS__
	W32Cond *wcond = cond_data (cond);
	if (!wcond->native) {
		DeleteCriticalSection (&wcond->waiters_lock);
		r_list_free (wcond->waiters);
	}
	free (wcond);
#endif
	free (cond);
}
