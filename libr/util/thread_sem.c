/* radare2 - LGPL - Copyright 2018 - thestr4ng3r */

#include <r_th.h>

R_API RThreadSemaphore *r_th_sem_new(unsigned int initial) {
	RThreadSemaphore *sem = R_NEW (RThreadSemaphore);
	if (!sem) {
		return NULL;
	}
#if HAVE_PTHREAD
	if (sem_init (&sem->sem, 0, initial) != 0) {
		free (sem);
		return NULL;
	}
#elif __WINDOWS__ && !defined(__CYGWIN__)
	sem->sem = CreateSemaphore (NULL, (LONG)initial, ST32_MAX, NULL);
	if (!sem->sem) {
		free (sem);
		return NULL;
	}
#endif
	return sem;
}

R_API void r_th_sem_free(RThreadSemaphore *sem) {
	if (!sem) {
		return;
	}
#if HAVE_PTHREAD
	sem_destroy (&sem->sem);
#elif __WINDOWS__ && !defined(__CYGWIN__)
	CloseHandle (sem->sem);
#endif
	free (sem);
}

R_API void r_th_sem_post(RThreadSemaphore *sem) {
#if HAVE_PTHREAD
	sem_post (&sem->sem);
#elif __WINDOWS__ && !defined(__CYGWIN__)
	ReleaseSemaphore (sem->sem, 1, NULL);
#endif
}

R_API void r_th_sem_wait(RThreadSemaphore *sem) {
#if HAVE_PTHREAD
	sem_wait (&sem->sem);
#elif __WINDOWS__ && !defined(__CYGWIN__)
	WaitForSingleObject (sem->sem, INFINITE);
#endif
}