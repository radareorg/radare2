#ifndef R_TH_H
#define R_TH_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "r_types.h"
#include "r_userconf.h"

#include <stdio.h>
#include <stdlib.h>

#ifndef WANT_THREADS
#define WANT_THREADS 1
#endif

#ifdef __GNUC__
# define HAVE_TH_LOCAL 1
# define R_TH_LOCAL __thread

#elif _MSC_VER
# define HAVE_TH_LOCAL 1
# define R_TH_LOCAL __declspec( thread )

#elif __STDC_VERSION__ >= 201112L
# define HAVE_TH_LOCAL 1
# define R_TH_LOCAL _Thread_local

#else
# define HAVE_TH_LOCAL 0
# define R_TH_LOCAL
#endif

#if __STDC_VERSION__ >= 201112L && !defined (_MSC_VER)
# define HAVE_STDATOMIC_H 1
# include <stdatomic.h>
#endif

#if WANT_THREADS

#if __WINDOWS__
#undef HAVE_PTHREAD
#define HAVE_PTHREAD 0
#define R_TH_TID HANDLE
#define R_TH_LOCK_T CRITICAL_SECTION
#define R_TH_COND_T CONDITION_VARIABLE
#define R_TH_SEM_T HANDLE

#else

#undef HAVE_PTHREAD
#define HAVE_PTHREAD 1

#define __GNU
#include <semaphore.h>
#include <pthread.h>
#if __linux__
#include <sched.h>
#endif
#if __linux__ && __GLIBC_MINOR < 12
#define HAVE_PTHREAD_NP 0
#else
#define HAVE_PTHREAD_NP 1
#endif
#if __APPLE__
#include <pthread.h>
#endif
#if __FreeBSD__ || __OpenBSD__ || __DragonFly__
#if __FreeBSD__
#include <sys/cpuset.h>
#endif
#include <pthread_np.h>
#endif
#define R_TH_TID pthread_t
#define R_TH_LOCK_T pthread_mutex_t
#define R_TH_COND_T pthread_cond_t
#define R_TH_SEM_T sem_t *

#endif

#else

#define R_TH_SEM_T int
#define R_TH_LOCK_T int
#define R_TH_COND_T int
#define R_TH_TID int

#endif

#ifdef __cplusplus
extern "C" {
#endif
typedef enum { R_TH_FREED = -1, R_TH_STOP = 0, R_TH_REPEAT = 1 } RThreadFunctionRet;

struct r_th_t;

typedef RThreadFunctionRet (*RThreadFunction)(struct r_th_t *);

typedef struct r_th_sem_t {
	R_TH_SEM_T sem;
} RThreadSemaphore;

typedef enum r_th_lock_type_t {
	R_TH_LOCK_TYPE_STATIC = 0,
	R_TH_LOCK_TYPE_HEAP,
} RThreadLockType;

typedef struct r_th_lock_t {
#ifdef HAVE_STDATOMIC_H
	atomic_bool activating;
#endif
	struct {
		ut8 active : 1;
		RThreadLockType type : 7;
	};
	R_TH_LOCK_T lock;
} RThreadLock;

#define R_THREAD_LOCK_INIT {0}

typedef struct r_th_cond_t {
	R_TH_COND_T cond;
} RThreadCond;

typedef struct r_th_t {
	R_TH_TID tid;
	RThreadLock *lock;
	RThreadFunction fun;
	void *user;    // user pointer
	bool running;
	int breaked;   // thread aims to be interrupted
	int delay;     // delay the startup of the thread N seconds
	int ready;     // thread is properly setup
} RThread;

typedef struct r_th_pool_t {
	int size;
	RThread **threads;
} RThreadPool;

#ifdef R_API
R_API RThread *r_th_new(RThreadFunction fun, void *user, int delay);
R_API bool r_th_start(RThread *th, int enable);
R_API int r_th_wait(RThread *th);
R_API int r_th_wait_async(RThread *th);
R_API void r_th_break(RThread *th);
R_API void *r_th_free(RThread *th);
R_API void r_th_set_running(RThread *th, bool b);
R_API bool r_th_is_running(RThread *th);
R_API void *r_th_kill_free(RThread *th);
R_API bool r_th_kill(RThread *th, bool force);
R_API R_TH_TID r_th_self(void);
R_API bool r_th_setname(RThread *th, const char *name);
R_API bool r_th_getname(RThread *th, char *name, size_t len);
R_API bool r_th_setaffinity(RThread *th, int cpuid);

R_API RThreadSemaphore *r_th_sem_new(unsigned int initial);
R_API void r_th_sem_free(RThreadSemaphore *sem);
R_API void r_th_sem_post(RThreadSemaphore *sem);
R_API void r_th_sem_wait(RThreadSemaphore *sem);

R_API RThreadLock *r_th_lock_new(bool recursive);
R_API int r_th_lock_wait(RThreadLock *th);
R_API int r_th_lock_tryenter(RThreadLock *thl);
R_API int r_th_lock_enter(RThreadLock *thl);
R_API int r_th_lock_leave(RThreadLock *thl);
R_API void *r_th_lock_free(RThreadLock *thl);

R_API RThreadCond *r_th_cond_new(void);
R_API void r_th_cond_signal(RThreadCond *cond);
R_API void r_th_cond_signal_all(RThreadCond *cond);
R_API void r_th_cond_wait(RThreadCond *cond, RThreadLock *lock);
R_API void r_th_cond_free(RThreadCond *cond);

#endif

#ifdef __cplusplus
}
#endif

#endif
