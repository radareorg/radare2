/* radare - LGPL - Copyright 2009-2016 - pancake */

#include <r_core.h> // just to get the RPrint instance
#include <r_debug.h>
#include <r_cons.h>
#include <r_reg.h>

R_API int r_debug_reg_sync(RDebug *dbg, int type, int write) {
	int i, size;
	if (!dbg || !dbg->reg || !dbg->h)
		return false;
	// Theres no point in syncing a dead target
	if (r_debug_is_dead (dbg))
		return false;
	// Check if the functions needed are available
	if (write && !dbg->h->reg_write)
		return false;
	if (!write && !dbg->h->reg_read)
		return false;
	// Sync all the types sequentially if asked
	i = (type == R_REG_TYPE_ALL)? R_REG_TYPE_GPR: type;
	do {
		if (write) {
			ut8 *buf = r_reg_get_bytes (dbg->reg, i, &size);
			if (!buf || !dbg->h->reg_write (dbg, i, buf, size)) {
				if (i == 0)
					eprintf ("r_debug_reg: error writing "
						"registers %d to %d\n", i, dbg->tid);
				return false;
			}
		} else {
			// int bufsize = R_MAX (1024, dbg->reg->size*2); // i know. its hacky
			int bufsize = dbg->reg->size;
			//int bufsize = dbg->reg->regset[i].arena->size;
			if (bufsize > 0) {
				ut8 *buf = calloc (1, bufsize);
				if (!buf) {
					return false;
				}
				//we have already checked dbg->h and dbg->h->reg_read above
				size = dbg->h->reg_read (dbg, i, buf, bufsize);
				// we need to check against zero because reg_read can return false
				if (size > 0) {
					r_reg_set_bytes (dbg->reg, i, buf, size); //R_MIN (size, bufsize));
			//		free (buf);
			//		return true;
				}
				free (buf);
			}
		}
		// DO NOT BREAK R_REG_TYPE_ALL PLEASE
		//   break;
		// Continue the syncronization or just stop if it was asked only for a single type of regs
		i++;
	} while ((type == R_REG_TYPE_ALL) && (i < R_REG_TYPE_LAST));
	return true;
}

R_API int r_debug_reg_list(RDebug *dbg, int type, int size, int rad, const char *use_color) {
	int i, delta, from, to, cols, n = 0;
	const char *fmt, *fmt2, *kwhites;
	RPrint *pr = NULL;
	int colwidth = 20;
	RListIter *iter;
	RRegItem *item;
	RList *head;
	ut64 diff;

	if (!dbg || !dbg->reg) {
		return false;
	}

	if (dbg->corebind.core) {
		pr = ((RCore*)dbg->corebind.core)->print;
	}

	if (!(dbg->reg->bits & size)) {
		// TODO: verify if 32bit exists, otherwise use 64 or 8?
		size = 32;
	}
	if (dbg->bits & R_SYS_BITS_64) {
		fmt = "%s = 0x%08"PFMT64x"%s";
		fmt2 = "%s%4s%s 0x%08"PFMT64x"%s";
		kwhites = "         ";
		colwidth = dbg->regcols? 20: 25;
		cols = 3;
	} else {
		fmt = "%s = 0x%08"PFMT64x"%s";
		fmt2 = "%s%4s%s 0x%08"PFMT64x"%s";
		kwhites = "    ";
		colwidth = 20;
		cols = 4;
	}
	if (dbg->regcols) {
		cols = dbg->regcols;
	}
	if (rad == 'j') {
		dbg->cb_printf ("{");
	}
	if (type == -1) {
		from = 0;
		to = R_REG_TYPE_LAST;
	} else {
		from = type;
		to = from + 1;
	}

	to = R_MAX (to, R_REG_TYPE_FLG + 1);

	int itmidx = -1;
	dbg->creg = NULL;
	for (i = from; i < to; i++) {
		head = r_reg_get_list (dbg->reg, i);
		if (!head) {
			continue;
		}
		r_list_foreach (head, iter, item) {
			ut64 value;
#if 0
			bool is_arm = dbg->arch && strstr (dbg->arch, "arm");

			/* the thumb flag in the cpsr register shouldnt forbid us to switch between arm or thumb */
			/* this code must run only after a step maybe ... need some discussion, disabling for now */
			if (is_arm && (rad == 1 || rad == '*') && item->size == 1) {
				if (!strcmp (item->name, "tf")) {
					bool is_thumb = r_reg_get_value (dbg->reg, item);
					int new_bits = is_thumb? 16: 32;
					if (dbg->anal->bits != new_bits)
						dbg->cb_printf ("e asm.bits=%d\n", new_bits);
				}
				continue;
			}
#endif
			if (type != -1) {
				if (type != item->type && R_REG_TYPE_FLG != item->type) continue;
				if (size != 0 && size != item->size) continue;
			}
			value = r_reg_get_value (dbg->reg, item);
			r_reg_arena_swap (dbg->reg, false);
			diff = r_reg_get_value (dbg->reg, item);
			r_reg_arena_swap (dbg->reg, false);
			delta = value-diff;
			itmidx++;

			switch (rad) {
			case 'j':
				dbg->cb_printf ("%s\"%s\":%"PFMT64d,
					n?",":"", item->name, value);
				break;
			case '-':
				dbg->cb_printf ("f-%s\n", item->name);
				break;
			case 1:
			case '*':
				dbg->cb_printf ("f %s 1 0x%"PFMT64x"\n",
					item->name, value);
				break;
			case 'd':
			case 2:
				{
					int len, highlight = use_color && pr && pr->cur_enabled && itmidx == pr->cur;
					char *str, whites[32], content[128];
					const char *a = "", *b = "";
					if (highlight) {
						a = Color_INVERT;
						b = Color_INVERT_RESET;
						dbg->creg = item->name;
					}
					strcpy (whites, kwhites);
					if (delta && use_color) {
						dbg->cb_printf (use_color);
					}
					if (item->flags) {
						str = r_reg_get_bvalue (dbg->reg, item);
						len = 12 - strlen (str);
						memset (whites, ' ', sizeof (whites));
						whites[len] = 0;
						dbg->cb_printf (" %s%s%s %s%s", a, item->name, b,
							str, ((n+1)%cols)? whites: "\n");
						free (str);
					} else {
						snprintf (content, sizeof (content),
							fmt2, "", item->name, "", value, "");
						len = colwidth - strlen (content);
						if (len < 0) len = 0;
						memset (whites, ' ', sizeof (whites));
						whites[len] = 0;
						dbg->cb_printf (fmt2, a, item->name, b, value,
							((n+1)%cols)? whites: "\n");
					}
					if (highlight) {
						dbg->cb_printf (Color_INVERT_RESET);
					}
					if (delta && use_color) {
						dbg->cb_printf (Color_RESET);
					}
				}
				break;
			case 3:
				if (delta) {
					char woot[64];
					snprintf (woot, sizeof (woot),
						" was 0x%08"PFMT64x" delta %d\n", diff, delta);
					dbg->cb_printf (fmt, item->name, value, woot);
				}
				break;
			default:
				if (delta && use_color) {
					dbg->cb_printf (use_color);
					dbg->cb_printf (fmt, item->name, value, Color_RESET"\n");
				} else {
					dbg->cb_printf (fmt, item->name, value, "\n");
				}
				break;
			}
			n++;
		}
	}
	if (rad == 'j') {
		dbg->cb_printf ("}\n");
	} else if (n > 0 && rad == 2 && ((n%cols))) {
		dbg->cb_printf ("\n");
	}
	return n;
}

R_API int r_debug_reg_set(struct r_debug_t *dbg, const char *name, ut64 num) {
	RRegItem *ri;
	int role = r_reg_get_name_idx (name);
	if (!dbg || !dbg->reg) {
		return false;
	}
	if (role != -1) {
		name = r_reg_get_name (dbg->reg, role);
	}
	ri = r_reg_get (dbg->reg, name, R_REG_TYPE_ALL);
	if (ri) {
		r_reg_set_value (dbg->reg, ri, num);
		r_debug_reg_sync (dbg, R_REG_TYPE_ALL, true);
	}
	return (ri != NULL);
}

R_API ut64 r_debug_reg_get(RDebug *dbg, const char *name) {
	// ignores errors
	return r_debug_reg_get_err (dbg, name, NULL);
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
		if (!name || *name == '\0') {
			eprintf ("No debug register profile defined for '%s'.\n", pname);
			if (err) *err = 1;
			return UT64_MAX;
		}
	}
	ri = r_reg_get (dbg->reg, name, R_REG_TYPE_ALL);
	if (ri) {
		r_debug_reg_sync (dbg, R_REG_TYPE_ALL, false);
		ret = r_reg_get_value (dbg->reg, ri);
	}
	return ret;
}

// XXX: dup for get_Err!
R_API ut64 r_debug_num_callback(RNum *userptr, const char *str, int *ok) {
	RDebug *dbg = (RDebug *)userptr;
	// resolve using regnu
	return r_debug_reg_get_err (dbg, str, ok);
}

