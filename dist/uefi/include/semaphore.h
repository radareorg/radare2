/* radare2 uefi libc - LGPL - Copyright 2026 - pancake */

#ifndef _SEMAPHORE_H
#define _SEMAPHORE_H

#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	int __v;
} sem_t;

#define SEM_FAILED ((sem_t *)0)

int sem_init(sem_t *sem, int pshared, unsigned int value);
int sem_destroy(sem_t *sem);
int sem_wait(sem_t *sem);
int sem_trywait(sem_t *sem);
int sem_timedwait(sem_t *sem, const struct timespec *abs_timeout);
int sem_post(sem_t *sem);
int sem_getvalue(sem_t *sem, int *sval);
sem_t *sem_open(const char *name, int oflag, ...);
int sem_close(sem_t *sem);
int sem_unlink(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* _SEMAPHORE_H */
