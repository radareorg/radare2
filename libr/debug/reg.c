/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_debug.h>
#include <r_reg.h>

R_API int r_debug_reg_sync(struct r_debug_t *dbg, int type, int write)
{
	int size, ret = R_FALSE;
	if (write) {
		if (dbg && dbg->h && dbg->h->reg_write) {
			ut8 *buf = r_reg_get_bytes (dbg->reg, type, &size);
			if (!dbg->h->reg_write (dbg->pid, type, buf, sizeof (buf)))
				eprintf ("r_debug_reg: error reading registers\n");
		} else eprintf ("r_debug_reg: cannot set registers\n");
	} else {
		/* read registers from debugger backend to dbg->regs */
		if (dbg && dbg->h && dbg->h->reg_read) {
			ut8 buf[4096]; // XXX hacky!
			size = dbg->h->reg_read (dbg, type, buf, sizeof (buf));
			if (size == R_FALSE)
				eprintf ("r_debug_reg: error reading registers\n");
			ret = r_reg_set_bytes (dbg->reg, type, buf, size);
		} else eprintf ("r_debug_reg: cannot read registers\n");
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
		if (rad) dbg->printf("f %s @ 0x%08llx\n",
			item->name, r_reg_get_value(dbg->reg, item));
		else dbg->printf("%s = 0x%08llx\n",
			item->name, r_reg_get_value(dbg->reg, item));
		n++;
	}
	return n;
}
