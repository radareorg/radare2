/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_anal.h>
#include <r_util.h>

int r_anal_init(struct r_anal_t *anal)
{
	anal->user = NULL;
	r_anal_set_bits(anal, 32);
	r_anal_set_big_endian(anal, R_FALSE);
	INIT_LIST_HEAD(&anal->anals);
	return R_TRUE;
}

void r_anal_set_user_ptr(struct r_anal_t *anal, void *user)
{
	anal->user = user;
}

int r_anal_add(struct r_anal_t *anal, struct r_anal_handle_t *foo)
{
	if (foo->init)
		foo->init(anal->user);
	list_add_tail(&(foo->list), &(anal->anals));
	return R_TRUE;
}

int r_anal_list(struct r_anal_t *anal)
{
	struct list_head *pos;
	list_for_each_prev(pos, &anal->anals) {
		struct r_anal_handle_t *h = list_entry(pos, struct r_anal_handle_t, list);
		printf(" %s: %s\n", h->name, h->desc);
	}
	return R_FALSE;
}

int r_anal_set(struct r_anal_t *anal, const char *name)
{
	struct list_head *pos;
	list_for_each_prev(pos, &anal->anals) {
		struct r_anal_handle_t *h = list_entry(pos, struct r_anal_handle_t, list);
		if (!memcmp(h->name, name, strlen(h->name))) {
			anal->cur = h;
			return R_TRUE;
		}
	}
	return R_FALSE;
}

int r_anal_aop(struct r_anal_t *anal)
{ 
	if (anal->cur && anal->cur->aop)
		return anal->cur->aop(anal->user);
	return R_FALSE;
}

int r_anal_set_bits(struct r_anal_t *anal, int bits)
{
	switch (bits) {
	case 16:
	case 32:
	case 64:
		anal->bits = bits;
		return R_TRUE;
	default:
		return R_FALSE;
	}
}

int r_anal_set_big_endian(struct r_anal_t *anal, int boolean)
{
	anal->big_endian = boolean;
	return R_TRUE;
}
