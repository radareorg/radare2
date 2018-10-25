/* radare - LGPL - Copyright 2007-2015 - ret2libc */

#include <r_util.h>

R_API RStack *r_stack_new(ut32 n) {
	RStack *s = R_NEW0 (RStack);
	if (!s) {
		return NULL;
	}
	s->elems = R_NEWS0 (void *, n);
	if (!s->elems) {
		free (s);
		return NULL;
	}
	s->n_elems = n;
	s->top = -1;
	return s;
}

R_API RStack *r_stack_newf(ut32 n, RStackFree f) {
	RStack *s = r_stack_new (n);
	if (s) {
		s->free = f;
	}
	return s;
}

R_API void r_stack_free(RStack *s) {
	if (s) {
		if (s->free) {
			int i;
			for (i = 0; i <= s->top; i++) {
				s->free (s->elems[i]);
			}
		}
		free (s->elems);
		free (s);
	}
}

R_API int r_stack_push(RStack *s, void *el) {
	if (s->top == s->n_elems - 1) {
		/* reallocate the stack */
		s->n_elems *= 2;
		s->elems = realloc (s->elems, s->n_elems * sizeof (void *));
		if (!s->elems) {
			return false;
		}
	}

	s->top++;
	s->elems[s->top] = el;
	return true;
}


//the caller should be take care of the object returned
R_API void *r_stack_pop(RStack *s) {
	void *res;
	if (s->top == -1) {
		return NULL;
	}
	res = s->elems[s->top];
	s->top--;
	return res;
}

R_API bool r_stack_is_empty(RStack *s) {
	return s->top == -1;
}

R_API unsigned int r_stack_size(RStack *s) {
	return (unsigned int)(s->top + 1);
}

R_API void *r_stack_peek(RStack *s) {
	void *res;
	if (!r_stack_is_empty (s)) {
		res = s->elems[s->top];
		return res;
	}
	return NULL;
}
