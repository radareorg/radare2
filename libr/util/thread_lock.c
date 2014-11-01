/* radare - LGPL - Copyright 2009-2014 - pancake */

#include <r_th.h>

/* locks/mutex/sems */

R_API RThreadLock *r_th_lock_new() {
	RThreadLock *thl = R_NEW(RThreadLock);
	if (thl) {
		thl->refs = 0;
#if HAVE_PTHREAD
		pthread_mutex_init (&thl->lock, NULL);
#elif __WIN32__
		//thl->lock = CreateSemaphore(NULL, 0, 1, NULL);
		InitializeCriticalSection(&thl->lock);
#endif
	}
	return thl;
}

R_API int r_th_lock_wait(RThreadLock *thl) {
#if HAVE_PTHREAD
	r_th_lock_enter (thl);
	r_th_lock_enter (thl); // locks here
	r_th_lock_leave (thl); // releases previous mutex
#elif __WIN32__
	WaitForSingleObject (thl->lock, INFINITE);
#else
	while (r_th_lock_check ());
#endif
	return 0;
}

R_API int r_th_lock_enter(RThreadLock *thl) {
#if HAVE_PTHREAD
	pthread_mutex_lock(&thl->lock);
#elif __WIN32__
	EnterCriticalSection (&thl->lock);
#endif
	return ++thl->refs;
}

R_API int r_th_lock_leave(RThreadLock *thl) {
#if HAVE_PTHREAD
	pthread_mutex_unlock (&thl->lock);
#elif __WIN32__
	LeaveCriticalSection (&thl->lock);
	//ReleaseSemaphore (thl->lock, 1, NULL);
#endif
	if (thl->refs>0)
		thl->refs--;
	return thl->refs;
}

R_API int r_th_lock_check(RThreadLock *thl) {
//w32 // TryEnterCriticalSection(&thl->lock);
	return thl->refs;
}

R_API void *r_th_lock_free(RThreadLock *thl) {
	if (thl) {
#if HAVE_PTHREAD
		pthread_mutex_destroy (&thl->lock);
#elif __WIN32__
		DeleteCriticalSection (&thl->lock);
		CloseHandle (thl->lock);
#endif
		free (thl);
	}
	return NULL;
}
