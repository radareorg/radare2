/* radare - LGPL - Copyright 2009-2024 - pancake */

#include <r_debug.h>
#include <r_core.h> // just to get the RPrint instance

R_API bool r_debug_reg_sync(RDebug *dbg, int type, int must_write) {
	R_RETURN_VAL_IF_FAIL (dbg && dbg->reg, false);
	if (dbg->current == NULL) {
		return true;
	}
	RDebugPlugin *plugin = R_UNWRAP3 (dbg, current, plugin);
	if (!plugin) {
		// if dbg->current is null means that we didnt selected any debug plugin
		// this function is only needed to sync the local regstate into the target process
		return true;
	}
	int n, size;
	if (r_debug_is_dead (dbg)) {
		return false;
	}
	if (must_write) {
		if (!plugin->reg_write) {
			return false;
		}
	} else {
		if (!plugin->reg_read) {
			return false;
		}
	}
	// Sync all the types sequentially if asked
	ut32 i = (type == R_REG_TYPE_ALL)? R_REG_TYPE_GPR: type;
	// Check to get the correct arena when using @ into reg profile (arena!=type)
	// if request type is positive and the request regset don't have regs
	if (i >= R_REG_TYPE_GPR || (dbg->reg->regset[i].regs && !dbg->reg->regset[i].regs->length)) {
		// seek into the other arena for redirections.
		for (n = R_REG_TYPE_GPR; n < R_REG_TYPE_LAST; n++) {
			// get regset mask
			const ut32 mask = dbg->reg->regset[n].maskregstype;
			// convert request arena to mask value
			const ut32 v = ((ut32)1 << i);
			// skip checks on same request arena and check if this arena have inside the request arena type
			if (n != i && (mask & v)) {
				// eprintf(" req = %i arena = %i mask = %x search = %x \n", i, n, mask, v);
				// eprintf(" request arena %i found at arena %i\n", i, n );
				// if this arena have the request arena type, force to use this arena.
				i = n;
				break;
			}
		}
	}
	do {
		if (must_write) {
			ut8 *buf = r_reg_get_bytes (dbg->reg, i, &size);
			if (!buf || !plugin->reg_write (dbg, i, buf, size)) {
				if (i == R_REG_TYPE_GPR) {
					R_LOG_ERROR ("cannot write registers %d to %d", i, dbg->tid);
				}
				if (type != R_REG_TYPE_ALL || i == R_REG_TYPE_GPR) {
					free (buf);
					return false;
				}
			}
			free (buf);
		} else {
			int bufsize = dbg->reg->size;
			if (bufsize > 0) {
				ut8 *buf = calloc (2, bufsize);
				if (buf) {
					if (plugin->reg_read (dbg, i, buf, bufsize)) {
						r_reg_set_bytes (dbg->reg, i, buf, bufsize);
					}
					free (buf);
				}
			}
		}
		// DO NOT BREAK R_REG_TYPE_ALL PLEASE
		//   break;
		// Continue the synchronization or just stop if it was asked only for a single type of regs
		i++;
	} while ((type == R_REG_TYPE_ALL) && (i < R_REG_TYPE_LAST));
	return true;
}

static bool is_mandatory(RRegItem *item, const char *pcname, const char *spname) {
	R_RETURN_VAL_IF_FAIL (item, true);
	// if regname is PC or SP should return false, otherwise return true
	if (pcname && !strcmp (item->name, pcname)) {
		return false;
	}
	if (spname && !strcmp (item->name, spname)) {
		return false;
	}
	return true;
}

R_API bool r_debug_reg_list(RDebug *dbg, int type, int size, PJ *pj, int rad, const char *use_color) {
	R_RETURN_VAL_IF_FAIL (dbg && dbg->reg, false);
	int delta, cols, n = 0;
	const char *fmt, *fmt2, *kwhites;
	RPrint *pr = NULL;
	int colwidth = 20;
	RListIter *iter;
	RRegItem *item;
	ut64 diff;
	char strvalue[256];
	bool isJson = tolower (rad) == 'j';
	R_RETURN_VAL_IF_FAIL (!isJson || (isJson && pj), false);

	if (dbg->coreb.core) {
		pr = ((RCore*)dbg->coreb.core)->print;
	}
	if (size != 0 && !r_reg_hasbits_check (dbg->reg, size)) {
		if (r_reg_hasbits_check (dbg->reg, 64)) {
			size = 64;
		} else if (r_reg_hasbits_check (dbg->reg, 32)) {
			size = 32;
		} else {
			// TODO: verify if 32bit exists too?
			size = 16;
		}
	}
	if (size == 64) {
		fmt = "%s = %s%s";
		fmt2 = "%s%6s%s %s%s";
		kwhites = "         ";
		colwidth = dbg->regcols? 30: 25;
		cols = 3;
	} else {
		fmt = "%s = %s%s";
		fmt2 = "%s%7s%s %s%s";
		kwhites = "    ";
		colwidth = 20;
		cols = 4;
	}
	if (dbg->regcols) {
		cols = dbg->regcols;
	}
	if (isJson) {
		pj_o (pj);
	}
	// with the new field "arena" into reg items why need
	// to get all arenas.

	int itmidx = -1;
	dbg->creg = NULL;
	RList *list = r_reg_get_list (dbg->reg, type);
	if (!list) {
		return false;
	}
	if (rad == 1 || rad == '*') {
		dbg->cb_printf ("fs+%s\n", R_FLAGS_FS_REGISTERS);
	}
	const char *pcname = r_reg_alias_getname (dbg->reg, R_REG_ALIAS_PC);
	const char *spname = r_reg_alias_getname (dbg->reg, R_REG_ALIAS_SP);
	bool isfirst = true;
	r_list_foreach (list, iter, item) {
		ut64 value;
		utX valueBig;
		if (type != -1 && is_mandatory (item, pcname, spname)) {
			if (type != item->type && R_REG_TYPE_FLG != item->type) {
				continue;
			}
			if (size == 8 && item->size == 16) {
				// avr workaround
			} else if (size != 0 && size != item->size) {
				continue;
			}
		}
		// skip wired-to-ground registers
		if (item->offset < 0) {
			continue;
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
			delta = value - diff;
			if (isJson) {
				pj_kn (pj, item->name, value);
			} else {
				if (pr && pr->wide_offsets && R_SYS_BITS_CHECK (dbg->bits, 64)) {
					snprintf (strvalue, sizeof (strvalue), "0x%016"PFMT64x, value);
				} else {
					snprintf (strvalue, sizeof (strvalue),"0x%08"PFMT64x, value);
				}
			}
		} else {
			value = r_reg_get_value_big (dbg->reg, item, &valueBig);
			switch (regSize) {
			case 80:
				snprintf (strvalue, sizeof (strvalue), "0x%04x%016"PFMT64x, valueBig.v80.High, valueBig.v80.Low);
				break;
			case 96:
				snprintf (strvalue, sizeof (strvalue), "0x%08x%016"PFMT64x, valueBig.v96.High, valueBig.v96.Low);
				break;
			case 128:
				snprintf (strvalue, sizeof (strvalue), "0x%016"PFMT64x"%016"PFMT64x, valueBig.v128.High, valueBig.v128.Low);
				break;
			case 256:
				snprintf (strvalue, sizeof (strvalue), "0x%016"PFMT64x"%016"PFMT64x"%016"PFMT64x"%016"PFMT64x,
						valueBig.v256.High.High, valueBig.v256.High.Low, valueBig.v256.Low.High, valueBig.v256.Low.Low);
				break;
			default:
				snprintf (strvalue, sizeof (strvalue), "ERROR");
				break;
			}
			if (isJson) {
				pj_ks (pj, item->name, strvalue);
			}
			delta = 0; // TODO: calculate delta with big values.
		}
		itmidx++;

		if (isJson) {
			continue;
		}
		switch (rad) {
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
		case 'e':
			dbg->cb_printf ("%s%s,%s,:=", isfirst?"":",", strvalue, item->name);
			isfirst = false;
			break;
		case '.':
			dbg->cb_printf ("dr %s=%s\n", item->name, strvalue);
			break;
		case '=':
			{
				bool highlight = (use_color && pr && pr->cur_enabled && itmidx == pr->cur);
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
				int len = colwidth - strlen (content);
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
				dbg->cb_printf ("%s", use_color);
				dbg->cb_printf (fmt, item->name, strvalue, Color_RESET"\n");
			} else {
				dbg->cb_printf (fmt, item->name, strvalue, "\n");
			}
			break;
		}
		n++;
	}
	if (rad == 'e') {
		dbg->cb_printf ("\n");
	}
	if (rad == 1 || rad == '*') {
		dbg->cb_printf ("fs-\n");
	}
beach:
	if (isJson) {
		pj_end (pj);
	} else if (n > 0 && (rad == 2 || rad == '=') && ((n % cols))) {
		dbg->cb_printf ("\n");
	}
	return n != 0;
}

R_API bool r_debug_reg_set(RDebug *dbg, const char *name, ut64 num) {
	R_RETURN_VAL_IF_FAIL (dbg && name, false);
	if (!dbg->reg) {
		return false;
	}
#if 0
	int alias = r_reg_get_name_idx (name);
	if (role != -1) {
		name = r_reg_get_name (dbg->reg, role);
	}
#endif
	RRegItem *ri = r_reg_get (dbg->reg, name, R_REG_TYPE_ALL);
	if (ri) {
		r_reg_set_value (dbg->reg, ri, num);
		r_debug_reg_sync (dbg, R_REG_TYPE_ALL, true);
		r_unref (ri);
	}
	return (ri);
}

R_API ut64 r_debug_reg_get_err(RDebug *dbg, const char *name, bool *err, utX *value) {
	RRegItem *ri = NULL;
	ut64 ret = 0LL;
	if (err) {
		*err = false;
	}
	if (!dbg || !dbg->reg) {
		if (err) {
			*err = 1;
		}
		return UT64_MAX;
	}
#if 0
	int alias = r_reg_alias_tostring (name);
	if (alias != -1) {
		name = r_reg_get_name (dbg->reg, alias);
		if (R_STR_ISEMPTY (name)) {
			if (err) {
				*err = 1;
			}
			return UT64_MAX;
		}
	}
#endif
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
		r_unref (ri);
	} else {
		if (err) {
			*err = 1;
		}
	}
	return ret;
}

R_API ut64 r_debug_reg_get(RDebug *dbg, const char *name) {
	return r_debug_reg_get_err (dbg, name, NULL, NULL);
}

