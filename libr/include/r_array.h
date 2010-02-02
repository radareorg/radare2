#ifndef _INCLUDE_ITER_H_
#define _INCLUDE_ITER_H_ 1

#define R_ITER_CPP 0
#define r_array_t void**
#define RArray void**

#define r_array_iterator(x) x
#define r_array_get(x) *(x++)
#define r_array_free(x) x
#define r_array_cur(x) *x
#define r_array_arrayator(x) x
#define r_array_next(x) (*x!=0)
#define r_array_rewind(x) (x=r_array_first(x))

#ifdef R_API
#if R_ITER_CPP
// TODO: Fully test/implement r_array in CPP macros if possible
#define r_array_set(x,y,z) x[y]=z
#define r_array_get_n(x,y) x+y
#define r_array_prev(x) (--it==*it)?0:it
#define r_array_delete(x) for(;*x;x++)*x=*(x+1)
R_API void **r_array_new(int n);
R_API RArray r_array_init(RArray ptr, int n);
R_API void **r_array_first(void **it);
R_API void r_array_foreach(void **it, int (*callback)(void *, void *), void *user);
R_API void **r_array_free(void **ptr);
#else
#define r_array_arrayator(x) x
R_API void **r_array_new(int n);
R_API void r_array_set(void **ptr, int idx, void *data);
//R_API void *r_array_cur(void **ptr);
//R_API void **r_array_get(void **it);
R_API void **r_array_get_n(void **ptr, int idx);
R_API void **r_array_prev(void **it);
R_API void r_array_delete(void **it);
//R_API int r_array_next(void **it);
R_API void **r_array_first(void **it);
R_API void r_array_foreach(void **it, int (*callback)(void *, void *), void *user);
//R_API void **r_array_free(void *ptr);
#endif
#endif

#endif
