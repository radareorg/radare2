#ifndef R_STACK_H
#define R_STACK_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*RStackFree)(void *ptr);

typedef struct r_stack_t {
	void **elems;
	int n_elems;
	int top;
	RStackFree free;
} RStack;

R_API RStack *r_stack_new(ut32 n);
R_API void r_stack_free(RStack *s);
R_API bool r_stack_is_empty(RStack *s);
R_API RStack *r_stack_newf(ut32 n, RStackFree f);
R_API bool r_stack_push(RStack *s, void *el);
R_API void *r_stack_pop(RStack *s);
R_API size_t r_stack_size(RStack *s);
R_API void *r_stack_peek(RStack *s);

#ifdef __cplusplus
}
#endif

#endif //  R_STACK_H
