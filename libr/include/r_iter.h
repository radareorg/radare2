#ifndef _INCLUDE_ITER_H_
#define _INCLUDE_ITER_H_ 1

#define R_ITER_CPP 0
#define r_iter_t void**

#define r_iter_get(x) *(x++)
#define r_iter_free(x) x
#define r_iter_cur(x) *x
#define r_iter_iterator(x) x
#define r_iter_next(x) (*x!=0)
#define r_iter_rewind(x) (x=r_iter_first(x)+1)

#ifdef R_API
#if R_ITER_CPP
// TODO: Fully test/implement r_iter in CPP macros if possible
#define r_iter_set(x,y,z) x[y]=z
#define r_iter_get_n(x,y) x+y
#define r_iter_prev(x) (--it==*it)?0:it
#define r_iter_delete(x) for(;*x;x++)*x=*(x+1)
R_API void **r_iter_new(int n);
R_API void **r_iter_init(void **ptr, int n);
R_API void **r_iter_first(void **it);
R_API void r_iter_foreach(void **it, int (*callback)(void *, void *), void *user);
R_API void **r_iter_free(void **ptr);
#else
#define r_iter_iterator(x) x
R_API void **r_iter_new(int n);
R_API void r_iter_set(void **ptr, int idx, void *data);
//R_API void *r_iter_cur(void **ptr);
//R_API void **r_iter_get(void **it);
R_API void **r_iter_get_n(void **ptr, int idx);
R_API void **r_iter_prev(void **it);
R_API void r_iter_delete(void **it);
//R_API int r_iter_next(void **it);
R_API void **r_iter_first(void **it);
R_API void r_iter_foreach(void **it, int (*callback)(void *, void *), void *user);
//R_API void **r_iter_free(void *ptr);
#endif
#endif

#endif
