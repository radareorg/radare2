/* radare2 - LGPL - Copyright 2018 - thestr4ng3r */

#include <r_th.h>

#ifdef __APPLE__
#define R_SEM_NAMED_ONLY 1
#define R_SEM_NAME_LEN_MAX 31
#else
#define R_SEM_NAMED_ONLY 0
#endif

#if R_SEM_NAMED_ONLY
#include <uuid/uuid.h>
#include <limits.h>
#endif

R_API RThreadSemaphore *r_th_sem_new(unsigned int initial) {
	RThreadSemaphore *sem = R_NEW (RThreadSemaphore);
	if (!sem) {
		return NULL;
	}
#if HAVE_PTHREAD
#  if R_SEM_NAMED_ONLY
	uuid_t uuid;
	uuid_generate (uuid);
	char name[38];
	name[0] = '/';
	uuid_unparse (uuid, name + 1);
	if (strlen (name) > R_SEM_NAME_LEN_MAX-1) {
	    name[R_SEM_NAME_LEN_MAX-1] = '\0';
	}
	sem->sem = sem_open (name, O_CREAT | O_EXCL, S_IRUSR | S_IWUSR, initial);
	if (sem->sem == SEM_FAILED) {
		free (sem);
		return NULL;
	}
#  else
	sem->sem = malloc (sizeof (sem_t));
	if (!sem->sem) {
		free (sem);
		return NULL;
	}
	if (sem_init (sem->sem, 0, initial) != 0) {
		free (sem->sem);
		free (sem);
		return NULL;
	}
#  endif
#elif __WINDOWS__
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
	if (sem->sem) {
#  if R_SEM_NAMED_ONLY
		sem_close (sem->sem);
#  else
		sem_destroy (sem->sem);
		free (sem->sem);
#  endif
	}
#elif __WINDOWS__
	CloseHandle (sem->sem);
#endif
	free (sem);
}

R_API void r_th_sem_post(RThreadSemaphore *sem) {
#if HAVE_PTHREAD
	sem_post (sem->sem);
#elif __WINDOWS__
	ReleaseSemaphore (sem->sem, 1, NULL);
#endif
}

R_API void r_th_sem_wait(RThreadSemaphore *sem) {
#if HAVE_PTHREAD
	sem_wait (sem->sem);
#elif __WINDOWS__
	WaitForSingleObject (sem->sem, INFINITE);
#endif
}
