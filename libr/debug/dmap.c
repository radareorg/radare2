/* radare - LGPL - Copyright 2009-2017 - pancake */

#include <r_debug.h>
#include <r_list.h>

/* Print out the JSON body for memory maps in the passed map region */
static void print_debug_map_json(RDebugMap *map, PJ *pj) {
	pj_o (pj);
	if (map->name && *map->name) {
		pj_ks (pj, "name", map->name);
	}
	if (map->file && *map->file) {
		pj_ks (pj, "file", map->file);
	}
	pj_kn (pj, "addr", map->addr);
	pj_kn (pj, "addr_end", map->addr_end);
	pj_ks (pj, "type", map->user ? "u" : "s");
	pj_ks (pj, "perm", r_str_rwx_i (map->perm));
	pj_end (pj);
}

/* Write the memory map header describing the line columns */
static void print_debug_map_line_header(RDebug *dbg, const char *input) {
	// TODO: Write header to console based on which command is being ran
}

/* Write a single memory map line to the console */
static void print_debug_map_line(RDebug *dbg, RDebugMap *map, ut64 addr, const char *input) {
	char humansz[8];
	if (input[0] == 'q') { // "dmq"
		char *name = (map->name && *map->name)
			? r_str_newf ("%s.%s", map->name, r_str_rwx_i (map->perm))
			: r_str_newf ("%08" PFMT64x ".%s", map->addr, r_str_rwx_i (map->perm));
		r_name_filter (name, 0);
		r_num_units (humansz, sizeof (humansz), map->addr_end - map->addr);
		dbg->cb_printf ("0x%016" PFMT64x " - 0x%016" PFMT64x " %6s %5s %s\n",
			map->addr,
			map->addr_end,
			humansz,
			r_str_rwx_i (map->perm),
			name
		);
		free (name);
	} else {
		const char *fmtstr = dbg->bits & R_SYS_BITS_64
			? "0x%016" PFMT64x " - 0x%016" PFMT64x " %c %s %6s %c %s %s %s%s%s\n"
			: "0x%08" PFMT64x " - 0x%08" PFMT64x " %c %s %6s %c %s %s %s%s%s\n";
		const char *type = map->shared ? "sys": "usr";
		const char *flagname = dbg->corebind.getName
			? dbg->corebind.getName (dbg->corebind.core, map->addr) : NULL;
		if (!flagname) {
			flagname = "";
		} else if (map->name) {
			char *filtered_name = strdup (map->name);
			r_name_filter (filtered_name, 0);
			if (!strncmp (flagname, "map.", 4) && \
				!strcmp (flagname + 4, filtered_name)) {
				flagname = "";
			}
			free (filtered_name);
		}
		r_num_units (humansz, sizeof (humansz), map->size);
		dbg->cb_printf (fmtstr,
			map->addr,
			map->addr_end,
			(addr >= map->addr && addr < map->addr_end) ? '*' : '-',
			type,
			humansz,
			map->user ? 'u' : 's',
			r_str_rwx_i (map->perm),
			r_str_get_fail (map->name, "?"),
			r_str_get_fail (map->file, "?"),
			*flagname ? " ; " : "",
			flagname
		);
	}
}

R_API void r_debug_map_list(RDebug *dbg, ut64 addr, const char *input) {
	int i;
	RListIter *iter;
	RDebugMap *map;
	PJ *pj = NULL;
	if (!dbg) {
		return;
	}

	switch (input[0]) {
	case 'j': // "dmj" add JSON opening array brace
		pj = pj_new ();
		if (!pj) {
			return;
		}
		pj_a (pj);
		break;
	case '*': // "dm*" don't print a header for r2 commands output
		break;
	default:
		// TODO: Find a way to only print headers if output isn't being grepped
		print_debug_map_line_header (dbg, input);
	}

	for (i = 0; i < 2; i++) { // Iterate over dbg::maps and dbg::maps_user
		RList *maps = (i == 0) ? dbg->maps : dbg->maps_user;
		r_list_foreach (maps, iter, map) {
			switch (input[0]) {
			case 'j': // "dmj"
				print_debug_map_json (map, pj);
				break;
			case '*': // "dm*"
				{
					char *name = (map->name && *map->name)
						? r_str_newf ("%s.%s", map->name, r_str_rwx_i (map->perm))
						: r_str_newf ("%08" PFMT64x ".%s", map->addr, r_str_rwx_i (map->perm));
					r_name_filter (name, 0);
					dbg->cb_printf ("f map.%s 0x%08" PFMT64x " 0x%08" PFMT64x "\n",
						name, map->addr_end - map->addr + 1, map->addr);
					free (name);
				}
				break;
			case 'q': // "dmq"
				if (input[1] == '.') { // "dmq."
					if (addr >= map->addr && addr < map->addr_end) {
						print_debug_map_line (dbg, map, addr, input);
					}
					break;
				}
				print_debug_map_line (dbg, map, addr, input);
				break;
			case '.':
				if (addr >= map->addr && addr < map->addr_end) {
					print_debug_map_line (dbg, map, addr, input);
				}
				break;
			default:
				print_debug_map_line (dbg, map, addr, input);
				break;
			}
		}
	}

	if (pj) { // "dmj" add JSON closing array brace
		pj_end (pj);
		dbg->cb_printf ("%s\n", pj_string (pj));
		pj_free (pj);
	}
}

static int cmp(const void *a, const void *b) {
	RDebugMap *ma = (RDebugMap*) a;
	RDebugMap *mb = (RDebugMap*) b;
	return ma->addr - mb->addr;
}

/**
 * \brief Find the min and max addresses in an RList of maps.
 * \param maps RList of maps that will be searched through
 * \param min Pointer to a ut64 that the min will be stored in
 * \param max Pointer to a ut64 that the max will be stored in
 * \param skip How many maps to skip at the start of iteration
 * \param width Divisor for the return value
 * \return (max-min)/width
 *
 * Used to determine the min & max addresses of maps and
 * scale the ascii bar to the width of the terminal
 */
static int findMinMax(RList *maps, ut64 *min, ut64 *max, int skip, int width) {
	RDebugMap *map;
	RListIter *iter;
	*min = UT64_MAX;
	*max = 0;
	r_list_foreach (maps, iter, map) {
		if (skip > 0) {
			skip--;
			continue;
		}
		if (map->addr < *min) {
			*min = map->addr;
		}
		if (map->addr_end > *max) {
			*max = map->addr_end;
		}
	}
	return (*max - *min) / width;
}

static void print_debug_maps_ascii_art(RDebug *dbg, RList *maps, ut64 addr, int colors) {
	ut64 mul; // The amount of address space a single console column will represent in bar graph
	ut64 min = -1, max = 0;
	int width = r_cons_get_size (NULL) - 90;
	RListIter *iter;
	RDebugMap *map;
	RConsPrintablePalette *pal = &r_cons_singleton ()->context->pal;
	if (width < 1) {
		width = 30;
	}
	r_list_sort (maps, cmp);
	mul = findMinMax (maps, &min, &max, 0, width);
	ut64 last = min;
	if (min != -1 && mul != 0) {
		const char *color_prefix = ""; // Color escape code prefixed to string (address coloring)
		const char *color_suffix = ""; // Color escape code appended to end of string
		const char *fmtstr;
		char humansz[8]; // Holds the human formatted size string [124K]
		int skip = 0; // Number of maps to skip when re-calculating the minmax
		r_list_foreach (maps, iter, map) {
			r_num_units (humansz, sizeof (humansz), map->size); // Convert map size to human readable string
			if (colors) {
				color_suffix = Color_RESET;
				if ((map->perm & 2) && (map->perm & 1)) { // Writable & Executable
					color_prefix = pal->widget_sel;
				} else if (map->perm & 2) { // Writable
					color_prefix = pal->graph_false;
				} else if (map->perm & 1) { // Executable
					color_prefix = pal->graph_true;
				} else {
					color_prefix = "";
					color_suffix = "";
				}
			} else {
				color_prefix = "";
				color_suffix = "";
			}
			if ((map->addr - last) > UT32_MAX) { // TODO: Comment what this is for
				mul = findMinMax (maps, &min, &max, skip, width); //  Recalculate minmax
			}
			skip++;
			fmtstr = dbg->bits & R_SYS_BITS_64 // Prefix formatting string (before bar)
				? "map %4.8s %c %s0x%016" PFMT64x "%s |"
				: "map %4.8s %c %s0x%08" PFMT64x "%s |";
			dbg->cb_printf (fmtstr, humansz,
				(addr >= map->addr && \
				addr < map->addr_end) ? '*' : '-',
				color_prefix, map->addr, color_suffix); // * indicates map is within our current sought offset
			int col;
			for (col = 0; col < width; col++) { // Iterate over the available width/columns for bar graph
				ut64 pos = min + (col * mul); // Current address space to check
				ut64 npos = min + ((col + 1) * mul); // Next address space to check
				if (map->addr < npos && map->addr_end > pos) {
					dbg->cb_printf ("#"); // TODO: Comment what a # represents
				} else {
					dbg->cb_printf ("-");
				}
			}
			fmtstr = dbg->bits & R_SYS_BITS_64 ? // Suffix formatting string (after bar)
				"| %s0x%016" PFMT64x "%s %s %s\n" :
				"| %s0x%08" PFMT64x "%s %s %s\n";
			dbg->cb_printf (fmtstr, color_prefix, map->addr_end, color_suffix,
				r_str_rwx_i (map->perm), map->name);
			last = map->addr;
		}
	}
}

R_API void r_debug_map_list_visual(RDebug *dbg, ut64 addr, const char *input, int colors) {
	if (dbg) {
		int i;
		for (i = 0; i < 2; i++) { // Iterate over dbg::maps and dbg::maps_user
			RList *maps = (i == 0) ? dbg->maps : dbg->maps_user;
			if (maps) {
				RListIter *iter;
				RDebugMap *map;
				if (input[1] == '.') { // "dm=." Only show map overlapping current offset
					dbg->cb_printf ("TODO:\n");
					r_list_foreach (maps, iter, map) {
						if (addr >= map->addr && addr < map->addr_end) {
							// print_debug_map_ascii_art (dbg, map);
						}
					}
				} else { // "dm=" Show all maps with a graph
					print_debug_maps_ascii_art (dbg, maps, addr, colors);
				}
			}
		}
	}
}

R_API RDebugMap *r_debug_map_new(char *name, ut64 addr, ut64 addr_end, int perm, int user) {
	RDebugMap *map;
	/* range could be 0k on OpenBSD, it's a honeypot */
	if (!name || addr > addr_end) {
		eprintf ("r_debug_map_new: error (\
			%" PFMT64x ">%" PFMT64x ")\n", addr, addr_end);
		return NULL;
	}
	map = R_NEW0 (RDebugMap);
	if (!map) {
		return NULL;
	}
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

R_API bool r_debug_map_sync(RDebug *dbg) {
	bool ret = false;
	if (dbg && dbg->h && dbg->h->map_get) {
		RList *newmaps = dbg->h->map_get (dbg);
		if (newmaps) {
			r_list_free (dbg->maps);
			dbg->maps = newmaps;
			ret = true;
		}
	}
	return ret;
}

R_API RDebugMap* r_debug_map_alloc(RDebug *dbg, ut64 addr, int size, bool thp) {
	RDebugMap *map = NULL;
	if (dbg && dbg->h && dbg->h->map_alloc) {
		map = dbg->h->map_alloc (dbg, addr, size, thp);
	}
	return map;
}

R_API int r_debug_map_dealloc(RDebug *dbg, RDebugMap *map) {
	bool ret = false;
	ut64 addr = map->addr;
	if (dbg && dbg->h && dbg->h->map_dealloc) {
		if (dbg->h->map_dealloc (dbg, addr, map->size)) {
			ret = true;
		}
	}
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
	free (map->file);
	free (map);
}

R_API RList *r_debug_map_list_new(void) {
	RList *list = r_list_new ();
	if (!list) {
		return NULL;
	}
	list->free = (RListFree)r_debug_map_free;
	return list;
}
