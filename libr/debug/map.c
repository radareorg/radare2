/* radare - LGPL - Copyright 2009-2016 - pancake */

#include <r_debug.h>
#include <r_list.h>

R_API void r_debug_map_list(RDebug *dbg, ut64 addr, int rad) {
	const char *fmtstr;
	char buf[128];
	bool notfirst = false;
	RListIter *iter;
	RDebugMap *map;
	if (!dbg) {
		return;
	}
	switch (rad) {
	case 'j':
		dbg->cb_printf ("[");
		r_list_foreach (dbg->maps, iter, map) {
			if (notfirst) dbg->cb_printf (",");
			dbg->cb_printf ("{\"name\":\"%s\",",map->name);
			if (map->file && *map->file)
				dbg->cb_printf ("\"file\":\"%s\",", map->file);
			dbg->cb_printf ("\"addr\":%"PFMT64u",", map->addr);
			dbg->cb_printf ("\"addr_end\":%"PFMT64u",", map->addr_end);
			dbg->cb_printf ("\"type\":\"%c\",", map->user?'u':'s');
			dbg->cb_printf ("\"perm\":\"%s\"}", r_str_rwx_i (map->perm));
			notfirst = true;
		}
		r_list_foreach (dbg->maps_user, iter, map) {
			if (notfirst) dbg->cb_printf (",");
			dbg->cb_printf ("{\"name\":\"%s\",", map->name);
			if (map->file && *map->file)
				dbg->cb_printf ("\"file\":\"%s\",", map->file);
			dbg->cb_printf ("\"addr\":%"PFMT64u",", map->addr);
			dbg->cb_printf ("\"addr_end\":%"PFMT64u",", map->addr_end);
			dbg->cb_printf ("\"type\":\"%c\",", map->user?'u':'s');
			dbg->cb_printf ("\"perm\":\"%s\"}", r_str_rwx_i (map->perm));
			notfirst = true;
		}
		dbg->cb_printf ("]\n");
		break;
	case '*':
		r_list_foreach (dbg->maps, iter, map) {
			char *name = r_str_newf ("%s.%s", map->name,
				r_str_rwx_i (map->perm));
			r_name_filter (name, 0);
			dbg->cb_printf ("f map.%s 0x%08"PFMT64x" 0x%08"PFMT64x"\n",
				name, map->addr_end - map->addr, map->addr);
			free (name);
		}
		r_list_foreach (dbg->maps_user, iter, map) {
			char *name = r_str_newf ("%s.%s", map->name,
				r_str_rwx_i (map->perm));
			r_name_filter (name, 0);
			dbg->cb_printf ("f map.%s 0x%08"PFMT64x" 0x%08"PFMT64x"\n",
				name, map->addr_end - map->addr, map->addr);
			free (name);
		}
		break;
	case 'q':
		r_list_foreach (dbg->maps, iter, map) {
			char *name = r_str_newf ("%s.%s", map->name,
				r_str_rwx_i (map->perm));
			r_name_filter (name, 0);
			dbg->cb_printf ("0x%016"PFMT64x" - 0x%016"PFMT64x" %6s %5s %s\n",
				map->addr, map->addr_end,
				r_num_units (buf, map->addr_end - map->addr),
				r_str_rwx_i (map->perm), name);
			free (name);
		}
		r_list_foreach (dbg->maps_user, iter, map) {
			char *name = r_str_newf ("%s.%s", map->name,
				r_str_rwx_i (map->perm));
			r_name_filter (name, 0);
			dbg->cb_printf ("f map.%s 0x%08"PFMT64x" 0x%08"PFMT64x"\n",
				name, map->addr_end - map->addr, map->addr);
			free (name);
		}
		break;
	default:
		fmtstr = dbg->bits& R_SYS_BITS_64?
			"sys %04s 0x%016"PFMT64x" %c 0x%016"PFMT64x" %c %s %s %s%s%s\n":
			"sys %04s 0x%08"PFMT64x" %c 0x%08"PFMT64x" %c %s %s %s%s%s\n";
		r_list_foreach (dbg->maps, iter, map) {
			const char *flagname = dbg->corebind.getName
				? dbg->corebind.getName (dbg->corebind.core, map->addr) : NULL;
			if (!flagname || !*flagname) {
				flagname = "";
			} else {
				if (!strncmp (flagname, "map.", 4)) {
					if (!strncmp (flagname + 4, map->name, 4)) {
						flagname = "";
					}
				}
			}
			r_num_units (buf, map->size);
			dbg->cb_printf (fmtstr,
				buf, map->addr, (addr>=map->addr && addr<map->addr_end)?'*':'-',
				map->addr_end, map->user?'u':'s',
				r_str_rwx_i (map->perm),
				map->file?map->file:"?",
				map->name,
				*flagname? " ; ": "", 
				flagname);
		}
		fmtstr = dbg->bits& R_SYS_BITS_64?
			"usr %04s 0x%016"PFMT64x" - 0x%016"PFMT64x" %c %x %s %s\n":
			"usr %04s 0x%08"PFMT64x" - 0x%08"PFMT64x" %c %x %s %s\n";
		r_list_foreach (dbg->maps_user, iter, map) {
			r_num_units (buf, map->size);
			dbg->cb_printf (fmtstr, buf, map->addr, map->addr_end,
				map->user?'u':'s', (ut32)map->perm, 
				map->file?map->file:"?",
				map->name);
		}
		break;
	}
}

static void print_debug_map_ascii_art(RList *maps, ut64 addr, int use_color, PrintfCallback cb_printf, int bits, int cons_width) {
	ut64 mul, min = -1, max = 0;
	int width = cons_width - 80;
	RListIter *iter;
	RDebugMap *map;
	if (width < 1) width = 30;
	r_list_foreach (maps, iter, map) {
		if (map->addr < min)
			min = map->addr;
		if (map->addr_end > max)
			max = map->addr_end;
	}
	mul = (max - min) / width;
	if (min != -1 && mul != 0) {
		const char *c = "", *c_end = "";
		const char *fmtstr;
		char buf[56];
		int j;
		r_list_foreach (maps, iter, map) {
			r_num_units (buf, map->size);
			if (use_color) {
				c_end = Color_RESET;
				if (map->perm & 2) {
					c = Color_RED;
				} else if (map->perm & 1) {
					c = Color_GREEN;
				} else {
					c = "";
					c_end = "";
				}
			} else {
				c = "";
				c_end = "";
			}
			fmtstr = bits & R_SYS_BITS_64 ?
				"sys %04s %c %s0x%016"PFMT64x"%s |" :
				"sys %04s %c %s0x%08"PFMT64x"%s |";
			cb_printf (fmtstr, buf,
				(addr >= map->addr && \
				addr < map->addr_end) ? '*' : '-',
				c, map->addr, c_end);
			for (j = 0; j < width; j++) {
				ut64 pos = min + (j * mul);
				ut64 npos = min + ((j + 1) * mul);
				if (map->addr < npos && map->addr_end > pos) {
					cb_printf ("#");
				} else {
					cb_printf ("-");
				}
			}
			fmtstr = bits & R_SYS_BITS_64 ?
				"| %s0x%016"PFMT64x"%s %s %s\n" :
				"| %s0x%08"PFMT64x"%s %s %s\n";
			cb_printf (fmtstr, c, map->addr_end, c_end,
				r_str_rwx_i (map->perm), map->name);
		}
	}
}

R_API void r_debug_map_list_visual(RDebug *dbg, ut64 addr, int use_color, int cons_cols) {
	if (dbg) {
		if (dbg->maps) {
			print_debug_map_ascii_art (dbg->maps, addr,
				use_color, dbg->cb_printf,
				dbg->bits, cons_cols);
		}
		if (dbg->maps_user) {
			print_debug_map_ascii_art (dbg->maps_user,
				addr, use_color,
				dbg->cb_printf, dbg->bits, cons_cols);
		}
	}
}

R_API RDebugMap *r_debug_map_new(char *name, ut64 addr, ut64 addr_end, int perm, int user) {
	RDebugMap *map;
	/* range could be 0k on OpenBSD, it's a honeypot */
	if (!name || addr > addr_end) {
		eprintf ("r_debug_map_new: error assert(\
			%"PFMT64x">%"PFMT64x")\n", addr, addr_end);
		return NULL;
	}
	map = R_NEW0 (RDebugMap);
	if (!map) return NULL;
	map->name = strdup (name);
	map->addr = addr;
	map->addr_end = addr_end;
	map->size = addr_end-addr;
	map->perm = perm;
	map->user = user;
	return map;
}

R_API RList *r_debug_modules_list(RDebug *dbg) {
	return (dbg && dbg->h && dbg->h->modules_get)?
		dbg->h->modules_get (dbg): NULL;
}

R_API int r_debug_map_sync(RDebug *dbg) {
	bool ret = false;
	if (dbg && dbg->h && dbg->h->map_get) {
		RList *newmaps = dbg->h->map_get (dbg);
		if (newmaps) {
			r_list_free (dbg->maps);
			dbg->maps = newmaps;
			ret = true;
		}
	}
	return (int)ret;
}

R_API RDebugMap* r_debug_map_alloc(RDebug *dbg, ut64 addr, int size) {
	RDebugMap *map = NULL;
	if (dbg && dbg->h && dbg->h->map_alloc) {
		map = dbg->h->map_alloc (dbg, addr, size);
	}
	return map;
}

R_API int r_debug_map_dealloc(RDebug *dbg, RDebugMap *map) {
	bool ret = false;
	ut64 addr = map->addr;
	if (dbg && dbg->h && dbg->h->map_dealloc)
		if (dbg->h->map_dealloc (dbg, addr, map->size))
			ret = true;
	return (int)ret;
}

R_API RDebugMap *r_debug_map_get(RDebug *dbg, ut64 addr) {
	RDebugMap *map, *ret = NULL;
	RListIter *iter;
	r_list_foreach (dbg->maps, iter, map) {
		if (addr >= map->addr && addr <= map->addr_end) {
			ret = map;
			break;
		}
	}
	return ret;
}

R_API void r_debug_map_free(RDebugMap *map) {
	free (map->name);
	free (map);
}

R_API RList *r_debug_map_list_new() {
	RList *list = r_list_new ();
	if (!list) return NULL;
	list->free = (RListFree)r_debug_map_free;
	return list;
}
