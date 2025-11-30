/* radare - LGPL - Copyright 2007-2022 - pancake, ret2libc */

#include <r_util.h>

R_API RStack *r_stack_new(ut32 n) {
	R_RETURN_VAL_IF_FAIL (n > 0 && n < ST32_MAX, NULL);
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
	R_RETURN_VAL_IF_FAIL (n > 0 && n < ST32_MAX && f, NULL);
	RStack *s = r_stack_new (n);
	if (s) {
		s->free = f;
	}
	return s;
}

R_API void r_stack_free(RStack *s) {
	if (s) {
		if (s->free && s->top > -1) {
			int i;
			for (i = 0; i <= s->top; i++) {
				s->free (s->elems[i]);
			}
		}
		free (s->elems);
		free (s);
	}
}

R_API bool r_stack_push(RStack *s, void *el) {
	R_RETURN_VAL_IF_FAIL (s && el, false);
	if (s->top + 1 >= ST32_MAX) {
		// avoid integer overflow
		return false;
	}
	if (s->top >= s->n_elems - 1) {
		int n_elems = (s->n_elems + 4) * 2;
		if (n_elems <= s->n_elems) {
			return false;
		}
		void **elems = realloc (s->elems, n_elems * sizeof (void *));
		if (!elems) {
			return false;
		}
		s->n_elems = n_elems;
		s->elems = elems;
	}
	s->top++;
	s->elems[s->top] = el;
	return true;
}

R_API void *r_stack_pop(RStack *s) {
	R_RETURN_VAL_IF_FAIL (s, NULL);
	if (s->top == -1) {
		return NULL;
	}
	void *res = s->elems[s->top];
	s->top--;
	return res;
}

R_API bool r_stack_is_empty(RStack *s) {
	R_RETURN_VAL_IF_FAIL (s, false);
	return s->top == -1;
}

R_API size_t r_stack_size(RStack *s) {
	R_RETURN_VAL_IF_FAIL (s && s->top >= -1, 0);
	return (size_t) (s->top + 1);
}

R_API void *r_stack_peek(RStack *s) {
	R_RETURN_VAL_IF_FAIL (s, NULL);
	return (s->top >= 0)? s->elems[s->top]: NULL;
}
