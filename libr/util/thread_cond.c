/* radare - LGPL - Copyright 2009-2021 - thestr4ng3r */

#include <r_th.h>

// XXX the windows implementation requires windows 2008 or higher

#if __WINDOWS__
static FARPROC (*icv)(PCONDITION_VARIABLE) = NULL;
static BOOL (*scvcs)(
  PCONDITION_VARIABLE ConditionVariable,
  PCRITICAL_SECTION   CriticalSection,
  DWORD               dwMilliseconds
);
static void (*wcv)(PCONDITION_VARIABLE);
static void (*wacv)(PCONDITION_VARIABLE);
static bool init_done = false;
static bool init(void) {
	if (init_done) {
		return true;
	}
	init_done = true;
	void *lib = GetModuleHandle (TEXT ("kernel32"));
	icv = (FARPROC (*) (PCONDITION_VARIABLE)) GetProcAddress(lib, "InitializeConditionVariable");
	scvcs = (BOOL (*) (PCONDITION_VARIABLE, PCRITICAL_SECTION, DWORD)) GetProcAddress (lib, "SleepConditionVariableCS");
	wcv = (void(*) (PCONDITION_VARIABLE)) GetProcAddress (lib, "WakeConditionVariable");
	wacv = (void(*) (PCONDITION_VARIABLE)) GetProcAddress (lib, "WakeAllConditionVariable");
	return true;
}
#endif

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
#elif __WINDOWS__
	if (init () && icv) {
		icv (&cond->cond);
	}
#endif
	return cond;
}

R_API void r_th_cond_signal(RThreadCond *cond) {
#if HAVE_PTHREAD
	pthread_cond_signal (&cond->cond);
#elif __WINDOWS__
	if (init () && wcv) {
		wcv (&cond->cond);
	}
#endif
}

R_API void r_th_cond_signal_all(RThreadCond *cond) {
#if HAVE_PTHREAD
	pthread_cond_broadcast (&cond->cond);
#elif __WINDOWS__
	if (init () && wacv) {
		wacv (&cond->cond);
	}
#endif
}

R_API void r_th_cond_wait(RThreadCond *cond, RThreadLock *lock) {
#if HAVE_PTHREAD
	pthread_cond_wait (&cond->cond, &lock->lock);
#elif __WINDOWS__
	if (init () && scvcs) {
		scvcs (&cond->cond, &lock->lock, INFINITE);
	}
#endif
}

R_API void r_th_cond_free(RThreadCond *cond) {
	if (!cond) {
		return;
	}
#if HAVE_PTHREAD
	pthread_cond_destroy (&cond->cond);
#elif __WINDOWS__
#endif
	free (cond);
}
