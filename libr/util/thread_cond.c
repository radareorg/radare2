/* radare - LGPL - Copyright 2009-2018 - thestr4ng3r */

#include <r_th.h>

R_API RThreadCond *r_th_cond_new() {
	RThreadCond *cond = R_NEW0 (RThreadCond);
	if (!cond) {
		return NULL;
	}
#if HAVE_PTHREAD
	if (pthread_cond_init (&cond->cond, NULL) != 0) {
		free (cond);
		return NULL;
	}
#elif __WINDOWS__
	InitializeConditionVariable (&cond->cond);
#endif
	return cond;
}

R_API void r_th_cond_signal(RThreadCond *cond) {
#if HAVE_PTHREAD
	pthread_cond_signal (&cond->cond);
#elif __WINDOWS__
	WakeConditionVariable (&cond->cond);
#endif
}

R_API void r_th_cond_signal_all(RThreadCond *cond) {
#if HAVE_PTHREAD
	pthread_cond_broadcast (&cond->cond);
#elif __WINDOWS__
	WakeAllConditionVariable (&cond->cond);
#endif
}

R_API void r_th_cond_wait(RThreadCond *cond, RThreadLock *lock) {
#if HAVE_PTHREAD
	pthread_cond_wait (&cond->cond, &lock->lock);
#elif __WINDOWS__
	SleepConditionVariableCS (&cond->cond, &lock->lock, INFINITE);
#endif
}

R_API void r_th_cond_free(RThreadCond *cond) {
	if (!cond) {
		return;
	}
#if HAVE_PTHREAD
	pthread_cond_destroy (&cond->cond);
#endif
	free (cond);
}
