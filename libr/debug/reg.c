/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_debug.h>
#include <r_reg.h>

R_API int r_debug_reg_sync(struct r_debug_t *dbg, int type, int write) {
	ut8 buf[4096]; // XXX hacky!
	int size, ret = R_FALSE;
	if (!dbg || !dbg->reg)
		return R_FALSE;
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
	int diff, cols, n = 0;
	RList *head; //struct list_head *pos, *head;
	RListIter *iter;
	RRegItem *item;
	const char *fmt, *fmt2;

	if (!dbg || !dbg->reg)
		return R_FALSE;
	head = r_reg_get_list(dbg->reg, type);
	if (dbg->h && dbg->h->bits & R_SYS_BITS_64) {
		fmt = "%s = 0x%016"PFMT64x"%s";
		fmt2 = "%4s 0x%016"PFMT64x"%s";
		cols = 3;
	} else {
		fmt = "%s = 0x%08"PFMT64x"%s";
		fmt2 = "%4s 0x%08"PFMT64x"%s";
		cols = 4;
	}
	r_list_foreach (head, iter, item) {
		ut64 value;
		if (type != -1 && type != item->type)
			continue;
		if (size != 0 && size != item->size)
			continue;
		value = r_reg_get_value (dbg->reg, item);
		diff = r_reg_cmp (dbg->reg, item);
		if (diff) // TODO: use inverse colors
			dbg->printf ("*");
		if (rad==1)
			dbg->printf ("f %s @ 0x%"PFMT64x"\n", item->name, value);
		else if (rad==2)
			dbg->printf (fmt2, item->name, value, ((n+1)%cols)?"   ":"\n");
		else dbg->printf (fmt, item->name, value, "\n");
		n++;
	}
	if (n>0 && rad==2 && (!((n+1)%cols)))
		dbg->printf ("\n");
	return n;
}

R_API int r_debug_reg_set(struct r_debug_t *dbg, const char *name, ut64 num) {
	RRegItem *ri;
	int role = r_reg_get_name_idx (name);
	if (!dbg || !dbg->reg)
		return R_FALSE;
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
	RRegItem *ri = NULL;
	ut64 ret = 0LL;
	int role = r_reg_get_name_idx (name);
	if (!dbg || !dbg->reg)
		return R_FALSE;
	if (role != -1) {
		name = r_reg_get_name (dbg->reg, role);
		if (name == NULL || *name == '\0') {
			eprintf ("Cannot resolve name for register role '%s'.\n", name);
			return 0LL;
		}
	}
	ri = r_reg_get (dbg->reg, name, R_REG_TYPE_GPR);
	if (ri) {
		r_debug_reg_sync (dbg, R_REG_TYPE_GPR, R_FALSE);
		ret = r_reg_get_value (dbg->reg, ri);
	}
	return ret;
}
