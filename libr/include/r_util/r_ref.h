
// reference counter
#define USE_THREADSAFE_REFS 0
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
	r_th_lock_enter (ref->lock);
	ref->count++;
	r_th_lock_leave (ref->lock);
	return p;
}
#define r_ref(x) r_ref_((x), &(x)->R_REF_NAME)

static inline void *r_unref_(void *p, RRef *ref) {
	if (!p || !ref) {
		return NULL;
	}
	r_th_lock_enter (ref->lock);
	ref->count--;
	if (ref->count == 0) {
		ref->free (p);
	}
	r_th_lock_leave (ref->lock);
	return p;
}
#define r_unref(x) r_unref_(x, (x)?&(x)->R_REF_NAME: NULL)
#define r_ref_set(x,y) do { if ((x) != (y) && (x) != NULL) { r_unref(x); } (x)=(y); (y)->ref.count++; } while(0)

#else
typedef int RRef;
#define R_REF_NAME refcount
#define R_REF_TYPE RRef R_REF_NAME; void (*free)(void*)
#define r_ref_count(x) (x)->R_REF_NAME

#define r_ref(x) ((x)->R_REF_NAME++, (x));
#define r_ref_init(x,y) (x)->R_REF_NAME = 1;(x)->free = (void *)(y)
// #define r_unref(x) { assert (x->R_REF_NAME > 0); if (!--(x->R_REF_NAME)) { x->free(x); } }
#define r_unref(x) { if ((x) != NULL && (x)->R_REF_NAME > 0 && !--((x)->R_REF_NAME)) { (x)->free(x); (x) = NULL; } }
#define r_ref_set(x,y) do { if ((x) != (y) && (x) != NULL) { r_unref(x); } (x)=(y); (y)->R_REF_NAME++; } while(0)

#endif

#ifdef __cplusplus
}
#endif
