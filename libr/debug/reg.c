/* radare - LGPL - Copyright 2009-2014 - pancake */

#include <r_debug.h>
#include <r_cons.h>
#include <r_reg.h>

R_API int r_debug_reg_sync(RDebug *dbg, int type, int write) {
	int i, size;
	if (!dbg || !dbg->reg || !dbg->h)
		return R_FALSE;

	// Theres no point in syncing a dead target
	if (r_debug_is_dead (dbg))
		return R_FALSE;

	// Check if the functions needed are available
	if (write && !dbg->h->reg_write)
		return R_FALSE;
	if (!write && !dbg->h->reg_read)
		return R_FALSE;

	// Sync all the types sequentially if asked
	i = (type == R_REG_TYPE_ALL) ? R_REG_TYPE_GPR : type;

	do {
		if (write) {
			ut8 *buf = r_reg_get_bytes (dbg->reg, i, &size);
			if (!buf || !dbg->h->reg_write (dbg, i, buf, size)) {
				if (i==0)
					eprintf ("r_debug_reg: error writing registers %d to %d\n", i, dbg->pid);
				return R_FALSE;
			}
		} else {
			//int bufsize = R_MAX (1024, dbg->reg->size*2); // i know. its hacky
			int bufsize = dbg->reg->size;
			ut8 *buf = malloc (bufsize);
			size = dbg->h->reg_read (dbg, i, buf, dbg->reg->size);
			if (size < 0) {
				eprintf ("r_debug_reg: error reading registers\n");
				return R_FALSE;
			}
			if (size)
				r_reg_set_bytes (dbg->reg, i, buf, R_MIN(size, bufsize));
			free (buf);
		}
		// DO NOT BREAK R_REG_TYPE_ALL PLEASE
		//   break;

		// Continue the syncronization or just stop if it was asked only for a single type of regs 
	} while ((type==R_REG_TYPE_ALL) && (i++ < R_REG_TYPE_LAST));
	return R_TRUE;
}

R_API int r_debug_reg_list(RDebug *dbg, int type, int size, int rad, const char *use_color) {
	int i, delta, from, to, cols, n = 0;
	const char *fmt1, *fmt2, *fmt3;
	RListIter *iter;
	RRegItem *item;
	RList *head;
	ut64 diff;

	if (!dbg || !dbg->reg)
		return R_FALSE;
	if (!(dbg->reg->bits & size)) {
		// TODO: verify if 32bit exists, otherwise use 64 or 8?
		size = 32;
	}

	if (dbg->bits & R_SYS_BITS_64) {
		fmt1 = "%4s %#18"PFMT64x;
		fmt2 = "%6s = %#18"PFMT64x" was %#18"PFMT64x" delta %d\n";
		fmt3 = "%6s = %#18"PFMT64x"\n";
		cols = 3;
	} else {
		fmt1 = "%4s %#10"PFMT64x;
		fmt2 = "%6s = %#10"PFMT64x" was %#10"PFMT64x" delta %d\n";
		fmt3 = "%6s = %#10"PFMT64x"\n";
		cols = 4;
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
				if (n)
					dbg->printf (",");
				dbg->printf ("\"%s\":%"PFMT64d, item->name, value);
				break;
			case '-':
				dbg->printf ("f-%s\n", item->name);
				break;
			case 1:
			case '*':
				dbg->printf ("f %s 1 0x%"PFMT64x"\n", item->name, value);
				break;
			case 'd':
			case 2:
				// make columns
				if (n == 0);
				else if (n % cols == 0)
					dbg->printf ("\n");
				else
					dbg->printf ("  |  ");

				// set color
				if (delta && use_color)
					dbg->printf (use_color);

				// print register
				if (item->flags) {
					char *str;
					str = r_reg_get_bvalue (dbg->reg, item);
					dbg->printf ("%s = %s", item->name, str);
					free(str);
				} else {
					dbg->printf (fmt1, item->name, value);
				}

				// reset color
				if (delta && use_color)
					dbg->printf (Color_RESET);
				break;
			case 3:
				if (delta)
					dbg->printf (fmt2, item->name, value, diff, delta);
				break;
			default:
				if (delta && use_color)
					dbg->printf (use_color);
				dbg->printf (fmt3, item->name, value);
				if (delta && use_color)
					dbg->printf (Color_RESET);
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

R_API ut64 r_debug_reg_get(RDebug *dbg, const char *name) {
	// ignores errors
	return r_debug_reg_get_err(dbg, name, NULL);
}

R_API ut64 r_debug_reg_get_err(RDebug *dbg, const char *name, int *err) {
	RRegItem *ri = NULL;
	ut64 ret = 0LL;
	int role = r_reg_get_name_idx (name);
	const char *pname = name;
	if (err) *err = 0;
	if (!dbg || !dbg->reg) {
		if (err) *err = 1;
		return UT64_MAX;
	}
	if (role != -1) {
		name = r_reg_get_name (dbg->reg, role);
		if (name == NULL || *name == '\0') {
			eprintf ("No debug register profile defined for '%s'.\n", pname);
			if (err) *err = 1;
			return UT64_MAX;
		}
	}
	ri = r_reg_get (dbg->reg, name, R_REG_TYPE_GPR);
	if (ri) {
		r_debug_reg_sync (dbg, R_REG_TYPE_GPR, R_FALSE);
		ret = r_reg_get_value (dbg->reg, ri);
	}
	return ret;
}
