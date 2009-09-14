/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_reg.h>
#include "../config.h"

// TODO: all this shit is pure stub!1 move into r_lib or so!!11eleven!
static struct r_reg_handle_t *reg_static_plugins[] = 
	{ R_REG_STATIC_PLUGINS };

R_API int r_reg_handle_init(struct r_reg_t *reg)
{
	int i;
	INIT_LIST_HEAD(&reg->handlers);
	for(i=0;reg_static_plugins[i];i++)
		r_reg_handle_add (reg, reg_static_plugins[i]);
	return R_TRUE;
}

R_API int r_reg_handle_set(struct r_reg_t *reg, const char *str)
{
	struct list_head *pos;
	list_for_each_prev(pos, &reg->handlers) {
		struct r_reg_handle_t *h = list_entry(pos, struct r_reg_handle_t, list);
		if (!strcmp(str, h->name)) {
			reg->h = h;
			return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API int r_reg_handle_add(struct r_reg_t *reg, struct r_reg_handle_t *foo)
{
	list_add_tail(&(foo->list), &(reg->handlers));
	return R_TRUE;
}

// TODO: deprecate
R_API int r_reg_handle_list(struct r_reg_t *reg)
{
	int count = 0;
	struct list_head *pos;
	list_for_each_prev(pos, &reg->handlers) {
		struct r_reg_handle_t *h = list_entry(pos, struct r_reg_handle_t, list);
		printf("%d %s %s\n", count, h->name, ((h==reg->h)?"*":""));
		count++;
	}
	return R_FALSE;
}
