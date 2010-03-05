/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_debug.h>
#include <r_reg.h>

R_API int r_debug_reg_sync(struct r_debug_t *dbg, int type, int write) {
	ut8 buf[4096]; // XXX hacky!
	int size, ret = R_FALSE;
	if (write) {
		if (dbg && dbg->h && dbg->h->reg_write) {
			ut8 *buf = r_reg_get_bytes (dbg->reg, type, &size);
			if (!dbg->h->reg_write (dbg->pid, type, buf, sizeof (buf)))
				eprintf ("r_debug_reg: error writing registers\n");
		} else eprintf ("r_debug_reg: cannot set registers\n");
	} else {
		/* read registers from debugger backend to dbg->regs */
		if (dbg && dbg->h && dbg->h->reg_read) {
			size = dbg->h->reg_read (dbg, type, buf, sizeof (buf));
			if (size == 0)
				eprintf ("r_debug_reg: error reading registers pid=%d\n", dbg->pid);
			ret = r_reg_set_bytes (dbg->reg, type, buf, size);
		} else eprintf ("r_debug_reg: cannot read registers\n");
	}
	return ret;
}

R_API int r_debug_reg_list(struct r_debug_t *dbg, int type, int size, int rad) {
	int cols, n = 0;
	struct list_head *pos, *head = r_reg_get_list(dbg->reg, type);
	const char *fmt, *fmt2;
	if (dbg->h && dbg->h->bits & R_SYS_BITS_64) {
		fmt = "%s = 0x%016llx%s";
		fmt2 = "%4s 0x%016llx%s";
		cols = 3;
	} else {
		fmt = "%s = 0x%08llx%s";
		fmt2 = "%4s 0x%08llx%s";
		cols = 4;
	}
	list_for_each (pos, head) {
		struct r_reg_item_t *item = list_entry (pos, struct r_reg_item_t, list);
		if (type != -1 && type != item->type)
			continue;
		if (size != 0 && size != item->size)
			continue;
		if (rad==1)
			dbg->printf ("f %s @ 0x%llx\n", item->name,
				r_reg_get_value (dbg->reg, item));
		else if (rad==2)
			dbg->printf (fmt2, item->name, r_reg_get_value (dbg->reg, item),
				((n+1)%cols)?"   ":"\n");
		else dbg->printf (fmt, item->name, r_reg_get_value (dbg->reg, item));
		n++;
	}
	if (n>0 && rad==2 && (!((n+1)%cols)))
		dbg->printf ("\n");
	return n;
}

R_API int r_debug_reg_set(struct r_debug_t *dbg, const char *name, ut64 num) {
	RRegisterItem *ri;
	int role = r_reg_get_name_idx (name);
	if (role != -1)
		name = r_reg_get_name (dbg->reg, role);
	ri = r_reg_get (dbg->reg, name, R_REG_TYPE_GPR);
	if (ri) {
		r_reg_set_value (dbg->reg, ri, num);
		r_debug_reg_sync (dbg, R_REG_TYPE_GPR, R_TRUE);
	}
	return (ri!=NULL);
}

R_API ut64 r_debug_reg_get(struct r_debug_t *dbg, const char *name) {
	RRegisterItem *ri = NULL;
	ut64 ret = 0LL;
	int role = r_reg_get_name_idx (name);
	if (role != -1) {
		name = r_reg_get_name (dbg->reg, role);
		if (name == NULL && *name == '\0') {
			eprintf ("Cannot resolve name for register role '%s'.\n", name);
		}
	}
	ri = r_reg_get (dbg->reg, name, R_REG_TYPE_GPR);
	if (ri) {
		r_debug_reg_sync (dbg, R_REG_TYPE_GPR, R_FALSE);
		ret = r_reg_get_value (dbg->reg, ri);
	}
	return ret;
}
