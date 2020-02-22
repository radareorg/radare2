/* radare - LGPL - Copyright 2009-2018 - pancake */

#include <r_core.h> // just to get the RPrint instance
#include <r_debug.h>
#include <r_cons.h>
#include <r_reg.h>

R_API int r_debug_reg_sync(RDebug *dbg, int type, int write) {
	int i, n, size;
	if (!dbg || !dbg->reg || !dbg->h) {
		return false;
	}
	// There's no point in syncing a dead target
	if (r_debug_is_dead (dbg)) {
		return false;
	}
	// Check if the functions needed are available
	if (write && !dbg->h->reg_write) {
		return false;
	}
	if (!write && !dbg->h->reg_read) {
		return false;
	}
	// Sync all the types sequentially if asked
	i = (type == R_REG_TYPE_ALL)? R_REG_TYPE_GPR: type;
	// Check to get the correct arena when using @ into reg profile (arena!=type)
	// if request type is positive and the request regset don't have regs
	if (i >= R_REG_TYPE_GPR && dbg->reg->regset[i].regs && !dbg->reg->regset[i].regs->length) {
		// seek into the other arena for redirections.
		for (n = R_REG_TYPE_GPR; n < R_REG_TYPE_LAST; n++) {
			// get regset mask
			int mask = dbg->reg->regset[n].maskregstype;
			// convert request arena to mask value
			int v = ((int)1 << i);
			// skip checks on same request arena and check if this arena have inside the request arena type
			if (n != i && (mask & v)) {
				//eprintf(" req = %i arena = %i mask = %x search = %x \n", i, n, mask, v);
				//eprintf(" request arena %i found at arena %i\n", i, n );
				// if this arena have the request arena type, force to use this arena.
				i = n;
				break;
			}
		}
	}
	do {
		if (write) {
			ut8 *buf = r_reg_get_bytes (dbg->reg, i, &size);
			if (!buf || !dbg->h->reg_write (dbg, i, buf, size)) {
				if (!i) {
					eprintf ("r_debug_reg: error writing "
						"registers %d to %d\n", i, dbg->tid);
				}
				free (buf);
				return false;
			}
			free (buf);
		} else {
			// int bufsize = R_MAX (1024, dbg->reg->size*2); // i know. its hacky
			int bufsize = dbg->reg->size;
			//int bufsize = dbg->reg->regset[i].arena->size;
			if (bufsize > 0) {
				ut8 *buf = calloc (1 + 1, bufsize);
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
		// Continue the synchronization or just stop if it was asked only for a single type of regs
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
	char strvalue[256];
	if (!dbg || !dbg->reg) {
		return false;
	}
	if (dbg->corebind.core) {
		pr = ((RCore*)dbg->corebind.core)->print;
	}
	if (size != 0 && !(dbg->reg->bits & size)) {
		// TODO: verify if 32bit exists, otherwise use 64 or 8?
		size = 32;
	}
	if (dbg->bits & R_SYS_BITS_64) {
		//fmt = "%s = 0x%08"PFMT64x"%s";
		fmt = "%s = %s%s";
		fmt2 = "%s%7s%s %s%s";
		kwhites = "         ";
		colwidth = dbg->regcols? 20: 25;
		cols = 3;
	} else {
		//fmt = "%s = 0x%08"PFMT64x"%s";
		fmt = "%s = %s%s";
		fmt2 = "%s%7s%s %s%s";
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
	// with the new field "arena" into reg items why need
	// to get all arenas.
	from = 0;
	to = R_REG_TYPE_LAST;

	int itmidx = -1;
	dbg->creg = NULL;
	for (i = from; i < to; i++) {
		head = r_reg_get_list (dbg->reg, i);
		if (!head) {
			continue;
		}
		r_list_foreach (head, iter, item) {
			ut64 value;
			utX valueBig;
			if (type != -1) {
				if (type != item->type && R_REG_TYPE_FLG != item->type) {
					continue;
				}
				if (size != 0 && size != item->size) {
					continue;
				}
			}
			// Is this register being asked?
			if (dbg->q_regs) {
				if (!r_list_empty (dbg->q_regs)) {
					RListIter *iterreg;
					RList *q_reg = dbg->q_regs;
					char *q_name;
					bool found = false;
					r_list_foreach (q_reg, iterreg, q_name) {
						if (!strcmp (item->name, q_name)) {
							found = true;
							break;
						}
					}
					if (!found) {
					        continue;
					}
					r_list_delete (q_reg, iterreg);
				} else {
					// List is empty, all requested regs were taken, no need to go further
					goto beach;
				}
			}
			int regSize = item->size;
			if (regSize < 80) {
				value = r_reg_get_value (dbg->reg, item);
				r_reg_arena_swap (dbg->reg, false);
				diff = r_reg_get_value (dbg->reg, item);
				r_reg_arena_swap (dbg->reg, false);
				delta = value-diff;
				if (tolower ((ut8)rad) == 'j') {
					snprintf (strvalue, sizeof (strvalue),"%"PFMT64u, value);
				} else {
					if (pr && pr->wide_offsets && dbg->bits & R_SYS_BITS_64) {
						snprintf (strvalue, sizeof (strvalue),"0x%016"PFMT64x, value);
					} else {
						snprintf (strvalue, sizeof (strvalue),"0x%08"PFMT64x, value);
					}
				}
			} else {
				value = r_reg_get_value_big (dbg->reg, item, &valueBig);
				switch (regSize) {
				case 80:
					snprintf (strvalue, sizeof (strvalue), "0x%04x%016"PFMT64x"", valueBig.v80.High, valueBig.v80.Low);
					break;
				case 96:
					snprintf (strvalue, sizeof (strvalue), "0x%08x%016"PFMT64x"", valueBig.v96.High, valueBig.v96.Low);
					break;
				case 128:
					snprintf (strvalue, sizeof (strvalue), "0x%016"PFMT64x"%016"PFMT64x"", valueBig.v128.High, valueBig.v128.Low);
					break;
				case 256:
					snprintf (strvalue, sizeof (strvalue), "0x%016"PFMT64x"%016"PFMT64x"%016"PFMT64x"%016"PFMT64x"",
						valueBig.v256.High.High, valueBig.v256.High.Low, valueBig.v256.Low.High, valueBig.v256.Low.Low);
					break;
				default:
					snprintf (strvalue, sizeof (strvalue), "ERROR");
				}
				delta = 0; // TODO: calculate delta with big values.
			}
			itmidx++;

			switch (rad) {
			case 'J':
			case 'j':
				dbg->cb_printf ("%s\"%s\":%s",
					n?",":"", item->name, strvalue);
				break;
			case '-':
				dbg->cb_printf ("f-%s\n", item->name);
				break;
			case 'R':
				dbg->cb_printf ("aer %s = %s\n", item->name, strvalue);
				break;
			case 1:
			case '*':
				dbg->cb_printf ("f %s %d %s\n", item->name, item->size / 8, strvalue);
				break;
			case '.':
				dbg->cb_printf ("dr %s=%s\n", item->name, strvalue);
				break;
			case '=':
				{
					int len, highlight = use_color && pr && pr->cur_enabled && itmidx == pr->cur;
					char whites[32], content[300];
					const char *a = "", *b = "";
					if (highlight) {
						a = Color_INVERT;
						b = Color_INVERT_RESET;
						dbg->creg = item->name;
					}
					strcpy (whites, kwhites);
					if (delta && use_color) {
						dbg->cb_printf ("%s", use_color);
					}
					snprintf (content, sizeof (content),
						fmt2, "", item->name, "", strvalue, "");
					len = colwidth - strlen (content);
					if (len < 0) {
						len = 0;
					}
					memset (whites, ' ', sizeof (whites));
					whites[len] = 0;
					dbg->cb_printf (fmt2, a, item->name, b, strvalue,
							((n+1)%cols)? whites: "\n");
					if (highlight) {
						dbg->cb_printf (Color_INVERT_RESET);
					}
					if (delta && use_color) {
						dbg->cb_printf (Color_RESET);
					}
				}
				break;
			case 'd':
			case 3:
				if (delta) {
					char woot[512];
					snprintf (woot, sizeof (woot),
						" was 0x%"PFMT64x" delta %d\n", diff, delta);
					dbg->cb_printf (fmt, item->name, strvalue, woot);
				}
				break;
			default:
				if (delta && use_color) {
					dbg->cb_printf (use_color);
					dbg->cb_printf (fmt, item->name, strvalue, Color_RESET"\n");
				} else {
					dbg->cb_printf (fmt, item->name, strvalue, "\n");
				}
				break;
			}
			n++;
		}
	}
beach:
	if (rad == 'j') {
		dbg->cb_printf ("}\n");
	} else if (rad == 'J') {
		// do nothing
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
	return r_debug_reg_get_err (dbg, name, NULL, NULL);
}

R_API ut64 r_debug_reg_get_err(RDebug *dbg, const char *name, int *err, utX *value) {
	RRegItem *ri = NULL;
	ut64 ret = 0LL;
	int role = r_reg_get_name_idx (name);
	const char *pname = name;
	if (err) {
		*err = 0;
	}
	if (!dbg || !dbg->reg) {
		if (err) {
			*err = 1;
		}
		return UT64_MAX;
	}
	if (role != -1) {
		name = r_reg_get_name (dbg->reg, role);
		if (!name || *name == '\0') {
			eprintf ("No debug register profile defined for '%s'.\n", pname);
			if (err) {
				*err = 1;
			}
			return UT64_MAX;
		}
	}
	ri = r_reg_get (dbg->reg, name, R_REG_TYPE_ALL);
	if (ri) {
		r_debug_reg_sync (dbg, R_REG_TYPE_ALL, false);
		if (value && ri->size > 64) {
			if (err) {
				*err = ri->size;
			}
			ret = r_reg_get_value_big (dbg->reg, ri, value);
		} else {
		    ret = r_reg_get_value (dbg->reg, ri);
		}
	} else {
		if (err) {
			*err = 1;
		}
	}
	return ret;
}

// XXX: dup for get_Err!
R_API ut64 r_debug_num_callback(RNum *userptr, const char *str, int *ok) {
	RDebug *dbg = (RDebug *)userptr;
	// resolve using regnu
	return r_debug_reg_get_err (dbg, str, ok, NULL);
}
