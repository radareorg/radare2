/* radare - LGPL - Copyright 2009-2021 - thestr4ng3r */

#include <r_th.h>

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

R_API void r_th_cond_wait(RThreadCond *cond, RThreadLock *lock) {
#if HAVE_PTHREAD
	pthread_cond_wait (&cond->cond, &lock->lock);
#elif R2__WINDOWS__
	r_w32_SleepConditionVariableCS (&cond->cond, &lock->lock, INFINITE);
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