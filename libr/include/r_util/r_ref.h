#ifndef R2_UTIL_REF_H
#define R2_UTIL_REF_H

// reference counter
#define USE_THREADSAFE_REFS 0
#define USE_DEBUG_REFS 0
#define USE_DEBUG_REFS_MAX 100

#if USE_THREADSAFE_REFS
#include <r_th.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if USE_THREADSAFE_REFS

#define R_REF_NAME ref
#define R_REF_TYPE RRef R_REF_NAME;


typedef struct {
	int count;
	void (*free)(void*);
	// void *lock;
	RThreadLock *lock;
} RRef;

#define r_ref_init(x,y) {\
	(x)->R_REF_NAME.lock = r_th_lock_new (false);\
	(x)->ref.count = 1;\
	(x)->ref.free = (void *)(y);\
}

#define r_ref_count(x) (x)->R_REF_NAME.count

static inline void *r_ref_(void *p, RRef *ref) {
	if (ref) {
		r_th_lock_enter (ref->lock);
		ref->count++;
		r_th_lock_leave (ref->lock);
	}
	return p;
}
#define r_ref(x) r_ref_((x), (x)?&(x)->R_REF_NAME: NULL)

static inline void *r_unref_(void *p, RRef *ref) {
	if (!p || !ref) {
		return NULL;
	}
	r_th_lock_enter (ref->lock);
	ref->count--;
	if (ref->count == 0 && ref->free) {
		ref->free (p);
	}
	r_th_lock_leave (ref->lock);
	return p;
}
#define r_unref(x) r_unref_(x, (x)?&(x)->R_REF_NAME: NULL)
// #define r_ref_set(x,y) do { if ((x) != (y) && (x) != NULL) { r_unref(x); (x)=r_ref((y)); } while(0)
// #define r_ref_set(x,y) do { void *a = (x); (x)=r_ref((y)); r_unref (a); } while(0)
// #define r_ref_set(x,y) do { void *a = (x); (x)=r_ref((y)); } while(0)
#define r_ref_set(x,y) do { void *a = r_ref((y)); r_unref(x); x=y; } while(0)

#else
typedef int RRef;
#define R_REF_NAME refcount
#define R_REF_TYPE RRef R_REF_NAME; void (*free)(void*)
#define r_ref_count(x) (x)->R_REF_NAME

// TODO: detect integer overflow
#if USE_DEBUG_REFS
#define r_ref(x) do { eprintf ("REF %p %d\n", (x), (x)->R_REF_NAME); r_sys_backtrace (); if (USE_DEBUG_REFS_MAX) { (x)->R_REF_NAME > USE_DEBUG_REFS_MAX) { kill(getpid(), SIGINT); } } (x)->R_REF_NAME++; } while (0)
#define r_unref(x) { eprintf ("UNREF %p %d\n", (x), ((x)?(x)->R_REF_NAME: 0)); if ((x) != NULL && (x)->R_REF_NAME > 0 && !--((x)->R_REF_NAME)) { eprintf ("unref.free %p\n", (x)); if ((x)->free) { (x)->free(x); } (x) = NULL; } }
#else
#define r_ref(x) do { (x)->R_REF_NAME++; } while (0)
#define r_unref(x) { if ((x) != NULL && (x)->R_REF_NAME > 0 && !--((x)->R_REF_NAME)) { if ((x)->free) { (x)->free(x); } (x) = NULL; } }
#endif
#define r_ref_ptr(x) ((x)->R_REF_NAME++, (x));
#define r_ref_init(x,y) (x)->R_REF_NAME = 1; (x)->free = (void *)(y)
// #define r_ref_set(x,y) do { if ((x) != (y) && (x) != NULL) { r_unref(x); } (x)=(y); (y)->R_REF_NAME++; } while(0)
#define r_ref_set(x,y) do { r_ref((y)); r_unref((x)); (x) = (y); } while(0)

#endif

#ifdef __cplusplus
}
#endif

#endif
