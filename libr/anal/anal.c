/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

struct r_anal_t *r_anal_new()
{
	struct r_anal_t *a = MALLOC_STRUCT(struct r_anal_t);
	r_asm_init(a);
	return a;
}

void r_anal_free(struct r_anal_t *a)
{
	free(a);
}

int r_anal_init(struct r_anal_t *a)
{
	return R_TRUE;
}
