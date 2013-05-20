/* radare - LGPL - Copyright 2009-2013 - pancake */

#include <r_debug.h>
#include <r_cons.h>
#include <r_reg.h>

R_API int r_debug_reg_sync(RDebug *dbg, int type, int write) {
	ut8 buf[4096]; // XXX hacky!
	int size, ret = R_FALSE;
	if (!dbg || !dbg->reg || dbg->pid == -1)
		return R_FALSE;
	if (write) {
		if (dbg && dbg->h && dbg->h->reg_write) {
			ut8 *buf = r_reg_get_bytes (dbg->reg, type, &size);
			if (!dbg->h->reg_write (dbg, type, buf, sizeof (buf)))
				eprintf ("r_debug_reg: error writing registers\n");
		} //else eprintf ("r_debug_reg: cannot set registers\n");
	} else {
		/* read registers from debugger backend to dbg->regs */
		if (dbg && dbg->h && dbg->h->reg_read) {
			size = dbg->h->reg_read (dbg, type, buf, sizeof (buf));
			if (size == 0) {
				eprintf ("r_debug_reg: error reading registers pid=%d\n", dbg->pid);
			} else {
				ret = r_reg_set_bytes (dbg->reg, type, buf, size);
			}
		} //else eprintf ("r_debug_reg: cannot read registers\n");
	}
	return ret;
}

R_API int r_debug_reg_list(RDebug *dbg, int type, int size, int rad) {
	ut64 diff;
	int cols, n = 0;
	RList *head; //struct list_head *pos, *head;
	RListIter *iter;
	RRegItem *item;
	const char *fmt, *fmt2;

	if (!dbg || !dbg->reg)
		return R_FALSE;
	head = r_reg_get_list (dbg->reg, type);
	//if (dbg->h && dbg->h->bits & R_SYS_BITS_64) {
	if (dbg->bits & R_SYS_BITS_64) {
		fmt = "%s = 0x%016"PFMT64x"%s";
		fmt2 = "%4s 0x%016"PFMT64x"%s";
		cols = 3;
	} else {
		fmt = "%s = 0x%08"PFMT64x"%s";
		fmt2 = "%4s 0x%08"PFMT64x"%s";
		cols = 4;
	}
	if (rad=='j')
		dbg->printf ("{");
	if (head)
	r_list_foreach (head, iter, item) {
		ut64 value;
		if (type != -1 && type != item->type)
			continue;
		if (size != 0 && size != item->size)
			continue;
		value = r_reg_get_value (dbg->reg, item);
		diff = (ut64)r_reg_cmp (dbg->reg, item);
		switch (rad) {
		case 'j':
			dbg->printf ("%s\"%s\":%"PFMT64d,
				n?",":"",item->name, value);
			break;
		case 1:
		case '*':
			dbg->printf ("f %s 1 0x%"PFMT64x"\n", item->name, value);
			break;
		case 'd':
		case 2:
			if (diff) // TODO: DO NOT COLORIZE ALWAYS ..do debug knows about console?? use inverse colors
				dbg->printf (Color_BWHITE); //INVERT); //Color_BWHITE);
			if (item->flags) {
				char *str = r_reg_get_bvalue (dbg->reg, item);
				dbg->printf ("%s = %s%s", item->name, str, ((n+1)%cols)?"   ":"\n");
				free (str);
			} else dbg->printf (fmt2, item->name, value, ((n+1)%cols)?"   ":"\n");
			if (diff) // TODO: use inverse colors
				//dbg->printf (Color_INVERT_RESET); //Color_RESET);
				dbg->printf (Color_RESET); //Color_RESET);
			break;
		case 3:
			if (diff) {
				char woot[32];
				snprintf (woot, sizeof (woot), " was 0x%08"PFMT64x"\n", diff);
				dbg->printf (fmt, item->name, value, woot);
			}
			break;
		default:
			dbg->printf (fmt, item->name, value, "\n");
			break;
		}
		n++;
	}
	if (rad=='j') dbg->printf ("}\n");
	else if (n>0 && rad==2 && ((n%cols)))
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
	const char *pname = name;
	if (!dbg || !dbg->reg)
		return R_FALSE;
	if (role != -1) {
		name = r_reg_get_name (dbg->reg, role);
		if (name == NULL || *name == '\0') {
			eprintf ("No debug register profile defined for '%s'.\n", pname);
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
