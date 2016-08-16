/* radare - LGPL - Copyright 2007-2015 - ret2libc */

#include <r_util.h>

R_API RStack *r_stack_new(unsigned int n) {
	RStack *s = R_NEW0 (RStack);
	if (!s) return NULL;
	s->elems = R_NEWS0 (void *, n);
	if (!s->elems) {
		free (s);
		return NULL;
	}

	s->n_elems = n;
	s->top = -1;
	return s;
}

R_API void r_stack_free(RStack *s) {
	free (s->elems);
	free (s);
}

R_API int r_stack_push(RStack *s, void *el) {
	if (s->top == s->n_elems - 1) {
		/* reallocate the stack */
		s->n_elems *= 2;
		s->elems = realloc (s->elems, s->n_elems * sizeof (void *));
		if (!s->elems)
			return false;
	}

	s->top++;
	s->elems[s->top] = el;
	return true;
}

R_API void *r_stack_pop(RStack *s) {
	void *res;
	if (s->top == -1)
		return NULL;

	res = s->elems[s->top];
	s->top--;
	return res;
}

R_API int r_stack_is_empty(RStack *s) {
	return s->top == -1;
}

R_API ut32 r_stack_size(RStack *s) {
	return (ut32)(s->top + 1);
}

R_API void *r_stack_peek(RStack *s) {
	void *res;
	if (s->top != -1) {
		res = s->elems[s->top];
		return res;
	}
	return NULL;
}
