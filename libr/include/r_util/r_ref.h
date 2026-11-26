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
#define r_ref(x) r_ref_((x), (x)?&(x)->R_REF_NAME: NULL), (x)

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
#define r_ref(x) ((x)->R_REF_NAME++, (x))
#define r_unref(x) { if ((x) != NULL && (x)->R_REF_NAME > 0 && !--((x)->R_REF_NAME)) { if ((x)->free) { (x)->free(x); } (x) = NULL; } }
#endif
#define r_ref_ptr(x) ((x)->R_REF_NAME++, (x));
#define r_ref_init(x,y) (x)->R_REF_NAME = 1; (x)->free = (void *)(y)
// #define r_ref_set(x,y) do { if ((x) != (y) && (x) != NULL) { r_unref(x); } (x)=(y); (y)->R_REF_NAME++; } while(0)
#define r_ref_set(x,y) do { r_ref((y)); r_unref((x)); (x) = (y); } while(0)

#endif

// Where R_REF_TYPE lives inside an object, so refcounting works through void *
typedef struct {
	size_t count; // offset of R_REF_NAME, SZT_MAX for plain pointers
	size_t free; // offset of the free callback
} RRefLayout;

#define R_REF_LAYOUT_NONE ((RRefLayout){ SZT_MAX, 0 })

#if USE_THREADSAFE_REFS
#define R_REF_LAYOUT(type) ((RRefLayout){ r_offsetof (type, R_REF_NAME), 0 })

static inline void *r_ref_erased(void *p, RRefLayout layout) {
	return (p && layout.count != SZT_MAX)? r_ref_ (p, (RRef *)((ut8 *)p + layout.count)): p;
}

static inline void r_unref_erased(void *p, RRefLayout layout) {
	if (p && layout.count != SZT_MAX) {
		r_unref_ (p, (RRef *)((ut8 *)p + layout.count));
	}
}
#else
#define R_REF_LAYOUT(type) ((RRefLayout){ r_offsetof (type, R_REF_NAME), r_offsetof (type, free) })

static inline void *r_ref_erased(void *p, RRefLayout layout) {
	if (p && layout.count != SZT_MAX) {
		(*(RRef *)((ut8 *)p + layout.count))++;
	}
	return p;
}

static inline void r_unref_erased(void *p, RRefLayout layout) {
	if (!p || layout.count == SZT_MAX) {
		return;
	}
	RRef *count = (RRef *)((ut8 *)p + layout.count);
	if (*count > 0 && !--*count) {
		void (*free_cb)(void *) = *(void (**)(void *))((ut8 *)p + layout.free);
		if (free_cb) {
			free_cb (p);
		}
	}
}
#endif

#ifdef __cplusplus
}
#endif

#endif
