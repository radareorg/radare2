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
	int i, delta, from, to, cols, n = 0;
	const char *fmt, *fmt2, *kwhites;
	RListIter *iter;
	RRegItem *item;
	RList *head;
	ut64 diff;

	if (!dbg || !dbg->reg)
		return R_FALSE;
	//if (dbg->h && dbg->h->bits & R_SYS_BITS_64) {
	if (dbg->bits & R_SYS_BITS_64) {
		fmt = "%s = 0x%08"PFMT64x"%s";
		fmt2 = "%4s 0x%08"PFMT64x"%s";
		cols = 3;
		kwhites = "         ";
	} else {
		fmt = " %s = 0x%08"PFMT64x"%s";
		fmt2 = " %3s 0x%08"PFMT64x"%s";
		cols = 4;
		kwhites = "    ";
	}
	if (rad=='j')
		dbg->printf ("{");
	if (type == -1) {
		from = 0;
		to = R_REG_TYPE_LAST;
	} else {
		from = type;
		to = from +1;
	}
	for (i=from; i<to; i++) {
		head = r_reg_get_list (dbg->reg, i);
		if (!head) continue;
		r_list_foreach (head, iter, item) {
			ut64 value;
			if (type != -1) {
				if (type != item->type)
					continue;
				if (size != 0 && size != item->size)
					continue;
			}
			value = r_reg_get_value (dbg->reg, item);
			r_reg_arena_swap (dbg->reg, R_FALSE);
			diff = r_reg_get_value (dbg->reg, item);
			r_reg_arena_swap (dbg->reg, R_FALSE);
			delta = value-diff;

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
				 {
					char whites[16];
					strcpy (whites, kwhites); 
					if (delta) // TODO: DO NOT COLORIZE ALWAYS ..do debug knows about console?? use inverse colors
						dbg->printf (Color_BWHITE);
					if (item->flags) {
						char *str = r_reg_get_bvalue (dbg->reg, item);
						int len = strlen (str);
						strcpy (whites, "        ");
						if (len>9)len=9;
						else len = 9-len;
						whites[len] = 0;
						dbg->printf (" %s = %s%s", item->name,
							str, ((n+1)%cols)? whites: "\n");
						free (str);
					} else {
						char content[128];
						int len;

						snprintf (content, sizeof(content), fmt2, item->name, value, "");
						len = strlen (content);
						len -= 4;

						if (len>10) {
							len -= 10;
							if (len>9)len=9;
							else len = 9-len;
							whites[len] = 0;
						}
						dbg->printf (fmt2, item->name, value,
							((n+1)%cols)? whites: "\n");

					}
					if (delta) // TODO: only in color mode ON
						dbg->printf (Color_RESET);
				 }
				break;
			case 3:
				if (delta) {
					char woot[64];
					snprintf (woot, sizeof (woot),
						" was 0x%08"PFMT64x" delta %d\n", diff, delta);
					dbg->printf (fmt, item->name, value, woot);
				}
				break;
			default:
				dbg->printf (fmt, item->name, value, "\n");
				break;
			}
			n++;
		}
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
