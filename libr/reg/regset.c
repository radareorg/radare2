/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_types.h>
#include <r_debug.h>

R_API struct r_regset_t *r_regset_new(int size)
{
	struct r_regset_t *r = MALLOC_STRUCT(struct r_regset_t);
	if (r != NULL) {
		r->regs = MALLOC_STRUCTS(struct r_reg_t, size);
		if (r->regs == NULL) {
			free(r);
			r = NULL;
		} else r->nregs = size;
	}
	return r;
}

R_API void r_regset_free(struct r_regset_t *r)
{
	if (r) {
		free(r->regs);
		free(r);
	}
}

R_API int r_regset_set(struct r_regset_t *r, int idx, const char *name, ut64 value)
{
	if (idx<0 || idx>=r->nregs) {
		eprintf("Out of range register index! More registers needs to be allocated in r_regset_new()\n");
		return R_FALSE;
	}
	if (r==NULL || r->regs==NULL) {
		eprintf("No regset given in regset_set\n");
		return R_FALSE;
	}
	strncpy(r->regs[idx].name, name, R_REG_NAME_MAX);
	r->regs[idx].value = value;
	r->regs[idx].isfloat = R_FALSE;
	return R_TRUE;
}

R_API struct r_regset_t *r_regset_diff(struct r_regset_t *a, struct r_regset_t *b)
{
	struct r_regset_t *rs;
	// NULL FOR TEH LULZ :D
	if (a == NULL || b == NULL)
		return NULL;
	rs = MALLOC_STRUCT(struct r_regset_t);
	if (rs != NULL) {
		memcpy(rs, a, sizeof(struct r_regset_t));
		// TODO: do the diff here
	}
	return NULL;
}
