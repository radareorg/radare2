#ifndef _INCLUDE_R_TH_H_
#define _INCLUDE_R_TH_H_

#include "r_types.h"

#define HAVE_PTHREAD 1

#if __WINDOWS__

#include <windows.h>

#define R_TH_TID HANDLE
#define R_TH_LOCK_T CRITICAL_SECTION

#elif HAVE_PTHREAD
#define __GNU
#include <pthread.h>
#define R_TH_TID pthread_t
#define R_TH_LOCK_T pthread_mutex_t

#else
#error Threading library only supported for ptrace and w32
#endif

#define R_TH_FUNCTION(x) int (*x)(struct r_th_t *)

typedef struct r_th_lock_t {
	int refs;
	R_TH_LOCK_T lock;
} RThreadLock;

typedef struct r_th_t {
	R_TH_TID tid;
	struct r_th_lock_t lock;
	R_TH_FUNCTION(fun);
	void *user;    // user pointer
	int running;
	int breaked;   // thread aims to be interruped
	int delay;     // delay the startup of the thread N seconds
	int ready;     // thread is properly setup
} RThread;

typedef struct r_th_pool_t {
	int size;
	struct r_th_t **threads;
} RThreadPool;

#ifdef R_API
R_API struct r_th_t *r_th_new(R_TH_FUNCTION(fun), void *user, int delay);
R_API int r_th_init(struct r_th_t *th, R_TH_FUNCTION(fun), void *user, int delay);
R_API int r_th_start(struct r_th_t *th, int enable);
R_API int r_th_wait(struct r_th_t *th);
R_API int r_th_wait_async(struct r_th_t *th);
R_API void r_th_break(struct r_th_t *th);
R_API int r_th_wait(struct r_th_t *th);
R_API void *r_th_free(struct r_th_t *th);

R_API int r_th_lock_init(struct r_th_lock_t *thl);
R_API struct r_th_lock_t *r_th_lock_new();
R_API int r_th_lock_wait(struct r_th_lock_t *th);
R_API int r_th_lock_check(struct r_th_lock_t *thl);
R_API int r_th_lock_enter(struct r_th_lock_t *thl);
R_API int r_th_lock_leave(struct r_th_lock_t *thl);
R_API void *r_th_lock_free(struct r_th_lock_t *thl);
#endif

#endif
