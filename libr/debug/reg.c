/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_debug.h>
#include <r_reg.h>

R_API int r_debug_reg_sync(struct r_debug_t *dbg, int type, int write)
{
	int ret = R_FALSE;
	if (write) {
		// TODO must implement
		//if (dbg && dbg->h && dbg->h->reg_write)
		//	dbg->h->reg_write(dbg->pid, dbg->regs);
	} else {
		/* read registers from debugger backend to dbg->regs */
		if (dbg && dbg->h && dbg->h->reg_read) {
			int size = 4096;
			ut8 buf[4096]; // XXX hacky!
			size = dbg->h->reg_read(dbg, type, buf, size);
			r_reg_set_bytes(dbg->reg, type, buf, size);
			ret = R_TRUE;
		}
	}
	return ret;
}

R_API int r_debug_reg_list(struct r_debug_t *dbg, int type, int size, int rad)
{
	int n = 0;
	struct list_head *pos, *head = r_reg_get_list(dbg->reg, type);
//printf("list type=%d size=%d\n", type, size);
	list_for_each(pos, head) {
		struct r_reg_item_t *item = list_entry(pos, struct r_reg_item_t, list);
//printf("--> t=%d\n", item->type);
		if (type != -1 && type != item->type)
			continue;
		if (size != 0 && size != item->size)
			continue;
		if (rad) dbg->printf("f %s @ 0x%08llx\n", item->name, r_reg_get_value(dbg->reg, item));
		else dbg->printf("%s = 0x%08llx\n", item->name, r_reg_get_value(dbg->reg, item));
		n++;
	}
	return n;
}
