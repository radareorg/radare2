/* radare - LGPL - Copyright 2009-2021 - thestr4ng3r */

#include <r_th.h>
#include <r_util/r_time.h>

// XXX the windows implementation requires windows 2008 or higher

R_API RThreadCond *r_th_cond_new(void) {
	RThreadCond *cond = R_NEW0 (RThreadCond);
	if (!cond) {
		return NULL;
	}
#if HAVE_PTHREAD
	if (pthread_cond_init (&cond->cond, NULL) != 0) {
		free (cond);
		return NULL;
	}
#elif R2__WINDOWS__
	r_w32_InitializeConditionVariable (&cond->cond);
#endif
	return cond;
}

R_API void r_th_cond_signal(RThreadCond *cond) {
#if HAVE_PTHREAD
	pthread_cond_signal (&cond->cond);
#elif R2__WINDOWS__
	r_w32_WakeConditionVariable (&cond->cond);
#endif
}

R_API void r_th_cond_signal_all(RThreadCond *cond) {
#if HAVE_PTHREAD
	pthread_cond_broadcast (&cond->cond);
#elif R2__WINDOWS__
	r_w32_WakeAllConditionVariable (&cond->cond);
#endif
}

// Waits until the condition is signaled; a timeout_ms of 0 or UT64_MAX waits forever.
// Returns false only when the timeout expires before the condition is signaled.
R_API bool r_th_cond_wait(RThreadCond *cond, RThreadLock *lock, ut64 timeout_ms) {
	if (timeout_ms == 0 || timeout_ms == UT64_MAX) {
#if HAVE_PTHREAD
		pthread_cond_wait (&cond->cond, &lock->lock);
#elif R2__WINDOWS__
		r_w32_SleepConditionVariableCS (&cond->cond, &lock->lock, INFINITE);
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
	return r_w32_SleepConditionVariableCS (&cond->cond, &lock->lock, (DWORD)timeout_ms);
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
	// Windows condition variables don't require explicit destruction
	// They are automatically cleaned up when no longer in use
#endif
	free (cond);
}