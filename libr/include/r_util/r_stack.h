#ifndef R_STACK_H
#define R_STACK_H

typedef struct r_stack_t {
	void **elems;
	unsigned int n_elems;
	int top;
} RStack;

R_API RStack *r_stack_new(unsigned int n);
R_API void r_stack_free(RStack *s);
R_API int r_stack_push(RStack *s, void *el);
R_API void *r_stack_pop(RStack *s);
R_API int r_stack_is_empty(RStack *s);
R_API unsigned int r_stack_size(RStack *s);
#endif //  R_STACK_H
