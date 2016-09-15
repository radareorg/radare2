/* radare2 - LGPL - Copyright 2016 - n4x0r, soez */

static void update_main_arena_32(RCore *core, ut32 m_arena, RHeap_MallocState32 *main_arena) {
	r_core_read_at (core, m_arena, (ut8 *)main_arena, sizeof (RHeap_MallocState32));
}

static void get_brks_32 (RCore *core, ut32 *brk_start, ut32 *brk_end) {
	RListIter *iter;
	RDebugMap *map;
	r_debug_map_sync (core->dbg);
	r_list_foreach (core->dbg->maps, iter, map) {
		if (strstr (map->name, "[heap]")) {
		        *brk_start = map->addr;
			*brk_end = map->addr_end;
		        break;
		}
	}
}

static void print_main_arena_32(RCore *core, ut32 m_arena, RHeap_MallocState32 *main_arena, int format) {
	int i, j, k, offset = SZ * 12 + sizeof (int) * 2, start;
	ut32 apart[NSMALLBINS + 1] = {0LL};

	if (format == '*') {
		for (i = 0; i < NBINS * 2 - 2; i += 2) {
			ut32 addr = m_arena + offset + SZ * i - SZ * 2;
			ut32 bina = main_arena->bins[i];
			r_cons_printf ("f chunk.%d.bin = 0x%"PFMT32x"\n", i, addr);
			r_cons_printf ("f chunk.%d.fd = 0x%"PFMT32x"\n", i, bina);
			bina = main_arena->bins[i+1];
			r_cons_printf ("f chunk.%d.bk = 0x%"PFMT32x"\n", i, bina);
		}
		for (i = 0; i < BINMAPSIZE; i++) {
			r_cons_printf ("f binmap.%d = 0x%x", i, main_arena->binmap[i]);
		}
		{	/* maybe use SDB instead of flags for this? */
			char *units = r_num_units (NULL, main_arena->max_system_mem);
			r_cons_printf ("f heap.maxmem = %s\n", units);
			free (units);
			units = r_num_units (NULL, main_arena->system_mem);
			r_cons_printf ("f heap.sysmem = %s\n", units);
			free (units);
			units = r_num_units (NULL, main_arena->next_free);
			r_cons_printf ("f heap.nextfree = %s\n", units);
			free (units);
			units = r_num_units (NULL, main_arena->next);
			r_cons_printf ("f heap.next= %s\n", units);
			free (units);
		}
		return;
	}

	PRINT_GA ("malloc_state @ ");
	PRINTF_BA ("0x%"PFMT32x"\n\n", m_arena);
	PRINT_GA ("struct malloc_state main_arena {\n");
	PRINT_GA ("  mutex = ");
	PRINTF_BA ("0x%"PFMT32x"\n", main_arena->mutex);
	PRINT_GA ("  flags = ");
	PRINTF_BA ("0x%"PFMT32x"\n", main_arena->flags);
	PRINT_GA ("  fastbinsY = {\n");

	for (i = 0, j = 1, k = SZ * 4; i < NFASTBINS; i++, j++, k += SZ * 2) {
		PRINTF_YA (" Fastbin %02d: ", j);
		PRINT_GA (" chunksize:");
		PRINTF_BA (" ==%04d ", k);
		PRINTF_GA ("0x%"PFMT32x, main_arena->fastbinsY[i]);
		PRINT_GA (",\n");
	}
	PRINT_GA ("}\n");
	PRINT_GA ("  top = ");
	PRINTF_BA ("0x%"PFMT32x, main_arena->top);
	PRINT_GA (",\n");
	PRINT_GA ("  last_remainder = ");
	PRINTF_BA ("0x%"PFMT32x, main_arena->last_remainder);
	PRINT_GA (",\n");
	PRINT_GA ("  bins {\n");

	/* Index & size for largebins */
	start = SZ * 128;
	for (i = start, k = 0, j = 0; j < NBINS - 2 && i < 1024*1024; i += 64) {
		j = largebin_index (i);
		if (j == k + NSMALLBINS + 1) {
			apart[k++] = i;
		}
	}

	for (i = 0, j = 1, k = SZ * 4; i < NBINS * 2 - 2; i += 2, j++) {
		PRINTF_YA (" Bin %03d: ", j);
		if (j == 1) {
			PRINT_GA ("Unsorted Bin");
			PRINT_GA (" [");
			PRINT_GA (" chunksize:");
			PRINT_BA (" undefined ");
		} else if (j > 1 && j <= NSMALLBINS) {
			if (j == 2) {
				PRINT_GA ("             ┌");
			} else if (j == (NSMALLBINS / 2)) {
				PRINT_GA ("  Small Bins │");
			} else if (j != 2 && j != (NSMALLBINS / 2) && j != NSMALLBINS) {
				PRINT_GA ("             │");
			} else {
				PRINT_GA ("             └");
			}
			PRINT_GA (" chunksize:");
			PRINTF_BA (" ==%06d  ", k);
			if (j < NSMALLBINS) {
				k += SZ * 2;
			}
		} else {
			if (j == NSMALLBINS + 1) {
				PRINT_GA ("             ┌");
			} else if (j == (NSMALLBINS / 2) * 3) {
				PRINT_GA ("  Large Bins │");
			} else if (j != NSMALLBINS + 1 && j != (NSMALLBINS / 2) * 3 && j != NBINS - 1) {
				PRINT_GA ("             │");
			} else {
				PRINT_GA ("             └");
			}

			PRINT_GA (" chunksize:");
			if (j != NBINS - 1) {
				PRINTF_BA (" >=%06d  ", apart[j - NSMALLBINS - 1]);
			} else {
				PRINT_BA (" remaining ");
			}
		}

		ut32 bin = m_arena + offset + SZ * i - SZ * 2;
		PRINTF_GA ("0x%"PFMT32x"->fd = ", bin);
		PRINTF_BA ("0x%"PFMT32x, main_arena->bins[i]);
		PRINT_GA (", ");
		PRINTF_GA ("0x%"PFMT32x"->bk = ", (ut32)bin);
		PRINTF_BA ("0x%"PFMT32x, main_arena->bins[i+1] );
		PRINT_GA (", ");
		r_cons_print ("\n");
	}

	PRINT_GA ("  }\n");
	PRINT_GA ("  binmap = {");

	for (i = 0; i < BINMAPSIZE; i++) {
		PRINTF_BA ("0x%x", main_arena->binmap[i]);
		if (i < BINMAPSIZE - 1) {
			PRINT_GA (",");
		}
	}
	PRINT_GA ("}\n");
	PRINT_GA ("  next = ");
	PRINTF_BA ("0x%"PFMT32x, main_arena->next);
	PRINT_GA (",\n");
	PRINT_GA ("  next_free = ");
	PRINTF_BA ("0x%"PFMT32x, main_arena->next_free);
	PRINT_GA (",\n");
	PRINT_GA ("  system_mem = ");
	PRINTF_BA ("0x%"PFMT32x, main_arena->system_mem);
	PRINT_GA (",\n");
	PRINT_GA ("  max_system_mem = ");
	PRINTF_BA ("0x%"PFMT32x, main_arena->max_system_mem);
	PRINT_GA (",\n");
	PRINT_GA ("}\n\n");
}

static ut32 get_vaddr_symbol_32(const char *path, const char *symname) {
	RListIter *iter;
	RBinSymbol *s;
	RCore *core = r_core_new ();
	RList * syms = NULL;
	ut32 vaddr = 0LL;

	if (!core) {
		return UT32_MAX;
	}
	r_bin_load (core->bin, path, 0, 0, 0, -1, false);
	syms = r_bin_get_symbols (core->bin);
	if (!syms) {
		return UT32_MAX;
	}
	r_list_foreach (syms, iter, s) {
		if (strstr (s->name, symname)) {
			vaddr = s->vaddr;
			break;
		}
	}
	r_core_free (core);
	return vaddr;
}

static bool r_resolve_main_arena_32(RCore *core, ut32 *m_arena, RHeap_MallocState32 *main_arena) {
	RListIter *iter;
	RDebugMap *map;

	if (*m_arena == UT32_MAX) {
		const char *dir_dbg = "/usr/lib/debug";
		const char *dir_build_id = "/.build-id";
		const char *symname = "main_arena";
		const char *libc_ver_end = NULL;
		char hash[64] = {0}, *path = NULL;
		bool is_debug_file[4];
		ut32 libc_addr = UT32_MAX, vaddr = UT32_MAX;

		if (!core || !core->dbg || !core->dbg->maps){
			return false;
		}
		r_debug_map_sync (core->dbg);
		r_list_foreach (core->dbg->maps, iter, map) {
			if (strstr (map->name, "/libc-")) {
				libc_addr = map->addr;
				libc_ver_end = map->name;
				break;
			}
		}
		if (!libc_ver_end) {
			eprintf ("Warning: Is glibc mapped in memory? (see dm command)\n");
			return false;
		}

		is_debug_file[0] = str_start_with (libc_ver_end, "/usr/lib/");
		is_debug_file[1] = str_start_with (libc_ver_end, "/usr/lib32/");
		is_debug_file[2] = str_start_with (libc_ver_end, "/lib/");
		is_debug_file[3] = str_start_with (libc_ver_end, "/lib32/");
  
		if (!is_debug_file[0] && !is_debug_file[1] && !is_debug_file[2] && !is_debug_file[3]) {
			path = r_cons_input ("Is a custom library? (LD_PRELOAD=..) Enter full path glibc: ");
			if (r_file_exists (path)) {
				goto arena;
			}
		}

		if (is_debug_file[0] || is_debug_file[1]) {
			path = r_str_newf ("%s", libc_ver_end);
			if (r_file_exists (path)) {
				goto arena;
			}
		}

		if ((is_debug_file[2] || is_debug_file[3]) && r_file_is_directory ("/usr/lib/debug")) {
			path = r_str_newf ("%s%s", dir_dbg, libc_ver_end);
			if (r_file_exists (path)) {
				goto arena;
			}
		}
	
		if ((is_debug_file[2] || is_debug_file[3]) && r_file_is_directory ("/usr/lib/debug/.build-id")) {
			get_hash_debug_file (libc_ver_end, hash, sizeof (hash) - 1);
			libc_ver_end = hash;
			path = r_str_newf ("%s%s%s", dir_dbg, dir_build_id, libc_ver_end);
			if (r_file_exists (path)) {
				goto arena;
			}
		}

		goto not_arena;
arena:
		vaddr = get_vaddr_symbol_32 (path, symname);
		if (libc_addr != UT32_MAX && vaddr && vaddr != UT32_MAX) {
			*m_arena = libc_addr + vaddr;
			if (main_arena){
				update_main_arena_32 (core, *m_arena, main_arena);
				free (path);
				return true;
			} else {
				free (path);
				return false;
			}
		} else {
			eprintf ("Warning: Symbol main_arena could not be found. Is libc6-dbg installed?\n");
			free (path);
			return false;
		}	
not_arena:
		eprintf ("Warning: glibc library with symbol main_arena could not be found. Is libc6-dbg installed?\n");
		return false;
	} else {
		update_main_arena_32 (core, *m_arena, main_arena);
	}

	return true;
}

void print_heap_chunk_32(RCore *core) {
	RHeapChunk32 *cnk = R_NEW0 (RHeapChunk32);
	ut32 chunk = core->offset;
	
	if (!cnk) {
		return;
	}

	r_core_read_at (core, chunk, (ut8 *)cnk, sizeof (RHeapChunk32));

	PRINT_GA ("struct malloc_chunk @ ");
	PRINTF_BA ("0x%"PFMT32x, chunk);
	PRINT_GA (" {\n  prev_size = ");	
	PRINTF_BA ("0x%"PFMT32x, cnk->prev_size);
	PRINT_GA (",\n  size = ");
	PRINTF_BA ("0x%"PFMT32x, cnk->size);
	PRINT_GA(",\n  flags: |N:");
	PRINTF_BA("%1d", cnk->size & 4);
	PRINT_GA(" |M:");
	PRINTF_BA("%1d", cnk->size & 2);
	PRINT_GA(" |P:");
	PRINTF_BA("%1d", cnk->size & 1);
	
	PRINT_GA (",\n  fd = ");
	PRINTF_BA ("0x%"PFMT32x, cnk->fd);
	
	PRINT_GA (",\n  bk = ");
	PRINTF_BA ("0x%"PFMT32x, cnk->bk);
		
	if (cnk->size  > SZ * 128) {
		PRINT_GA (",\n  fd-nextsize = ");
		PRINTF_BA ("0x%"PFMT32x, cnk->fd_nextsize);
		PRINT_GA (",\n  bk-nextsize = ");
		PRINTF_BA ("0x%"PFMT32x, cnk->bk_nextsize);
	}

	PRINT_GA (",\n}\n");
	ut32 size = ((cnk->size >> 3) << 3) - SZ * 2;
	if (size > SZ * 128) {
		PRINT_GA ("chunk too big to be displayed\n");
		size = SZ * 128;
	}

	char *data = calloc (1, size);
	r_core_read_at (core, chunk + SZ * 2, (ut8 *)data, size);
	PRINT_GA ("chunk data = \n");
	r_print_hexdump (core->print, chunk + SZ * 2, (ut8 *)data, size, SZ * 8, SZ);
	free (cnk);
	free (data);
}

static int print_double_linked_list_bin_simple_32(RCore *core, ut32 bin, RHeap_MallocState32 *main_arena, ut32 brk_start) {
	ut32 next = UT32_MAX;
	RHeapChunk32 *cnk = R_NEW0 (RHeapChunk32);
	
	if (!cnk) {
		return -1;
	}

	r_core_read_at (core, bin, (ut8 *)cnk, sizeof (RHeapChunk32));

	PRINTF_GA ("    0x%"PFMT32x, bin);
	while (cnk->fd != bin) {
		PRINTF_BA ("->fd = 0x%"PFMT32x, cnk->fd);
		next = cnk->fd; 
		if (next < brk_start || next > main_arena->top) {
			PRINT_RA ("Double linked list corrupted\n");
			return -1;
		}
		r_core_read_at (core, next, (ut8 *)cnk, sizeof (RHeapChunk32));
	}

	PRINTF_GA ("->fd = 0x%"PFMT32x, cnk->fd);
	next = cnk->fd;

	if (next != bin) {
		PRINT_RA ("Double linked list corrupted\n");
		return -1;
	}
	r_core_read_at (core, next, (ut8 *)cnk, sizeof (RHeapChunk32));
	PRINTF_GA ("\n    0x%"PFMT32x, bin);

	while (cnk->bk != bin) {
		PRINTF_BA ("->bk = 0x%"PFMT32x, cnk->bk);
		next = cnk->bk;
		if (next < brk_start || next > main_arena->top) {
			PRINT_RA ("Double linked list corrupted\n");
			return -1;
		}
		r_core_read_at (core, next, (ut8 *)cnk, sizeof (RHeapChunk32));
	}

	PRINTF_GA ("->bk = 0x%"PFMT32x, cnk->bk);
	free (cnk);
	return 1;
}

static int print_double_linked_list_bin_graph_32(RCore *core, ut32 bin, RHeap_MallocState32 *main_arena, ut32 brk_start) {
	RAGraph *g = r_agraph_new (r_cons_canvas_new (1, 1));
	g->can->color = r_config_get_i (core->config, "scr.color");
	ut32 next = UT32_MAX;
	char title[256], chunk[256];
	RANode *bin_node = NULL, *prev_node = NULL, *next_node = NULL;	
	RHeapChunk32 *cnk = R_NEW0 (RHeapChunk32);

	if (!cnk) {
		return -1;
	}

	r_core_read_at (core, bin, (ut8 *)cnk, sizeof (RHeapChunk32));
	snprintf (title, sizeof (title) - 1, "bin @ 0x%"PFMT32x"\n", bin);
	snprintf (chunk, sizeof (chunk) - 1, "fd: 0x%"PFMT32x"\nbk: 0x%"PFMT32x"\n", cnk->fd, cnk->bk);	
	bin_node = r_agraph_add_node (g, title, chunk);
	prev_node = bin_node;

	while (cnk->bk != bin) {
		next = cnk->bk;
		if (next < brk_start || next > main_arena->top) {
			PRINT_RA ("Double linked list corrupted\n");
			return -1;
		}	

		r_core_read_at (core, next, (ut8 *)cnk, sizeof (RHeapChunk32));
		snprintf (title, sizeof (title) - 1, "Chunk @ 0x%"PFMT32x"\n", next);
		snprintf (chunk, sizeof (chunk) - 1, "fd: 0x%"PFMT32x"\nbk: 0x%"PFMT32x"\n", cnk->fd, cnk->bk);
		next_node = r_agraph_add_node (g, title, chunk);
		r_agraph_add_edge (g, prev_node, next_node);
		r_agraph_add_edge (g, next_node, prev_node);
		prev_node = next_node;
	}
	
	r_agraph_add_edge (g, prev_node, bin_node);
	r_agraph_add_edge (g, bin_node, prev_node);
	r_agraph_print (g);

	free (cnk);
	r_agraph_free (g);

	return 1;
}

static int print_double_linked_list_bin_32(RCore *core,  RHeap_MallocState32 *main_arena, ut32 m_arena, ut32 offset, ut32 num_bin, int graph) {
	int ret = 0;
	ut32 brk_start = UT32_MAX, brk_end = UT32_MAX;
	ut32 bin = main_arena->bins[num_bin];
	if (!bin) {
		return ret;
	}

	if (!core || !core->dbg || !core->dbg->maps) {
                return ret;
	}

	get_brks_32 (core, &brk_start, &brk_end);
	if (brk_start == UT32_MAX || brk_end == UT32_MAX) {
		eprintf ("No Heap section\n");
		return ret;		
	}

	bin = m_arena + offset + SZ * num_bin * 2 - SZ * 2;

	switch (num_bin) {
	case 0:
		PRINT_GA ("  double linked list unsorted bin {\n");
		break;
	case 1 ... NSMALLBINS - 1:
		PRINT_GA ("  double linked list small bin {\n");
		break;
	case NSMALLBINS ... NBINS - 2:
		PRINT_GA ("  double linked list large bin {\n");
		break;
	}

	if (!graph || graph == 1) {
		ret = print_double_linked_list_bin_simple_32 (core, bin, main_arena, brk_start);
	} else {
		ret = print_double_linked_list_bin_graph_32 (core, bin,  main_arena, brk_start);	
	}

	PRINT_GA ("\n  }\n");

	return ret;
}

static void print_heap_bin_32(RCore *core, ut32 m_arena, RHeap_MallocState32 *main_arena, const char *input) {
	int i, j = 2;
	ut32 num_bin = UT32_MAX;
	ut32 offset = 12 * SZ + sizeof (int) * 2;

	switch (input[0]) {
	case '\0': // dmhb
		PRINT_YA ("Bins {\n");
		for (i = 0; i < NBINS - 1; i++) {
			PRINTF_YA (" Bin %03d:\n", i + 1);
			if (!print_double_linked_list_bin_32 (core, main_arena, m_arena, offset, i, 0)) {
				PRINT_GA ("  Empty bin");
				PRINT_BA ("  0x0\n");
			} 
		}
		PRINT_YA ("\n}\n");
		break;
	case ' ': // dmhb [bin_num]
		j--; // for spaces after input
	case 'g': // dmhbg [bin_num]
		num_bin = r_num_math (core->num, input + j) - 1;
		if (num_bin > NBINS - 2) {
			eprintf ("Error: 0 < bin <= %d\n", NBINS - 1);
			break;
		}
		PRINTF_YA ("  Bin %03d:\n", num_bin + 1);
		if (!print_double_linked_list_bin_32 (core, main_arena, m_arena, offset, num_bin, j)) {
			PRINT_GA ("Empty bin");
			PRINT_BA (" 0x0\n");
		}
		break;
	}
}

static int print_single_linked_list_bin_32(RCore *core, RHeap_MallocState32 *main_arena, ut32 m_arena, ut32 offset, ut32 bin_num) {
	ut32 next = UT32_MAX, brk_start = UT32_MAX, brk_end = UT32_MAX;
	ut32 bin = main_arena->fastbinsY[bin_num];
	if (!bin) {
		return 0;
	}

	RHeapChunk32 *cnk = R_NEW0 (RHeapChunk32);
	if (!cnk) {
		return 0;
	}

	if (!core || !core->dbg || !core->dbg->maps) {
                return 0;
	}

	bin = m_arena + offset + SZ * bin_num;
	r_core_read_at (core, bin, (ut8 *)&next, SZ);

        get_brks_32 (core, &brk_start, &brk_end);
	if (brk_start == UT32_MAX || brk_end == UT32_MAX) {
		eprintf ("No Heap section\n");
		return 0;		
	}

	PRINTF_GA ("  fastbin %d @ ", bin_num + 1);
	PRINTF_GA ("0x%"PFMT32x" {\n   ", bin);

	ut32 size = main_arena->top - brk_start;
	ut32 next_root = next, next_tmp = next, double_free = UT32_MAX;
	while (next && next >= brk_start && next < main_arena->top) {
		PRINTF_BA ("0x%"PFMT32x, next);
		while (double_free == UT32_MAX && next_tmp && next_tmp >= brk_start && next_tmp <= main_arena->top) {
			r_core_read_at (core, next_tmp, (ut8 *)cnk, sizeof (RHeapChunk32));
			next_tmp = cnk->fd;
			if (cnk->prev_size > size || ((cnk->size >> 3) << 3) > size) {
				break;
			}
			if (next_root == next_tmp) {
				double_free = next_root;
				break;	
			}
		}
		r_core_read_at (core, next, (ut8 *)cnk, sizeof (RHeapChunk32));
		next = cnk->fd;
		PRINTF_BA ("%s", next ? "->fd = " : "");
		if (cnk->prev_size > size || ((cnk->size >> 3) << 3) > size) {
			PRINTF_RA (" 0x%"PFMT32x, next);
			PRINT_RA (" Linked list corrupted\n");
			PRINT_GA ("\n  }\n");
			return -1;	
		}

		next_root = next_tmp = next;
		if (double_free == next) {
			PRINTF_RA ("0x%"PFMT32x, next);
			PRINT_RA (" Double free detected\n");
			PRINT_GA ("\n  }\n");
			return -1;
		}
	}

	if (next && (next < brk_start || next >= main_arena->top)) {
		PRINTF_RA ("0x%"PFMT32x, next);
		PRINT_RA (" Linked list corrupted\n");
		PRINT_GA ("\n  }\n");
		return 1;
	}
		
	PRINT_GA ("\n  }\n");
	return -1;
}

void print_heap_fastbin_32(RCore *core, ut32 m_arena, RHeap_MallocState32 *main_arena, const char *input) {
	int i;
	ut32 num_bin = UT32_MAX;
	ut32 offset = sizeof (int) * 2;

	switch (input[0]) {
	case '\0': // dmhf
		PRINT_YA ("fastbinY {\n");
		for (i = 1; i <= NFASTBINS; i++) {
			PRINTF_YA (" Fastbin %02d\n", i);
			if (!print_single_linked_list_bin_32 (core, main_arena, m_arena, offset, i - 1)) {
				PRINT_GA ("  Empty bin");
				PRINT_BA ("  0x0\n");
			}
		}
		PRINT_YA ("}\n");
		break;
	case ' ': // dmhf [bin_num]
		num_bin = r_num_math (core->num, input + 1) - 1;
		if (num_bin >= NFASTBINS) {
			eprintf ("Error: 0 < bin <= %d\n", NFASTBINS);
			break;
		}
		if (!print_single_linked_list_bin_32 (core, main_arena, m_arena, offset, num_bin)) {
			PRINT_GA (" Empty bin");
			PRINT_BA (" 0x0\n");
		}
		break;
	}
}

static void print_mmap_graph_32(RCore *core, RHeap_MallocState32 *malloc_state, ut32 m_state) {
	int w, h;
	ut32 top_size = UT32_MAX;

	if (!core || !core->dbg || !core->dbg->maps) {
		return;
	}

	w = r_cons_get_size (&h);
	RConsCanvas *can = r_cons_canvas_new (w, h);
	can->color = r_config_get_i (core->config, "scr.color");
	RAGraph *g = r_agraph_new (can);
	RANode *top = {0}, *chunk_node = {0}, *prev_node = {0};
	RHeapChunk32 *cnk = R_NEW0 (RHeapChunk32),
	             *prev_c = R_NEW0 (RHeapChunk32);
	
	if (!cnk || !prev_c) {
		free (cnk);
		free (prev_c);
		return;
	}

	ut32 next_chunk_ref, prev_chunk_ref, size_tmp;
	char *top_title, *top_data, *node_title, *node_data;
	bool first_node = true;

	r_agraph_set_title (g, "Mmmaped Heap");
	top_title = r_str_newf ("Top chunk @ 0x%"PFMT32x"\n", malloc_state->top);

	ut32 start_mmap = m_state + sizeof(RHeap_MallocState32); //0x8b0;
	r_core_read_at (core, malloc_state->top, (ut8*)cnk, sizeof (RHeapChunk32));
	ut32 end_mmap = malloc_state->top;

	top_data = r_str_newf ("[mmap_start:0x%"PFMT32x", mmap_end:0x%"PFMT32x"]\n", start_mmap, end_mmap + ((cnk->size >> 3) << 3));
	next_chunk_ref = start_mmap, prev_chunk_ref = next_chunk_ref;
	top_size = (cnk->size >> 3) << 3;

	while (next_chunk_ref != malloc_state->top && next_chunk_ref != end_mmap) {
		r_core_read_at (core, next_chunk_ref, (ut8 *)prev_c, sizeof (RHeapChunk32));
	       	node_title = r_str_newf ("  Malloc chunk @ 0x%"PFMT32x" ", prev_chunk_ref);
		size_tmp = (prev_c->size >> 3) << 3;
		if (top_size != UT64_MAX && (size_tmp > top_size  || next_chunk_ref + size_tmp > malloc_state->top)) {
			node_data = r_str_newf ("[corrupted] size: 0x%x\n fd: 0x%"PFMT32x", bk: 0x%"PFMT64x"\nHeap graph could not be recovered\n", prev_c->size, prev_c->fd, prev_c->bk) ;
			r_agraph_add_node (g, node_title, node_data);
			if (first_node) first_node = false;
			break;	
		} 
		next_chunk_ref += size_tmp;
		prev_chunk_ref = next_chunk_ref;
		r_core_read_at (core, next_chunk_ref, (ut8 *)cnk, sizeof (RHeapChunk32));
		node_data = r_str_newf ("size: 0x%x\n fd: 0x%"PFMT32x", bk: 0x%"PFMT32x"\n", prev_c->size, prev_c->fd, prev_c->bk) ;
		chunk_node = r_agraph_add_node (g, node_title, node_data);
		if (first_node) {
			first_node = false; 
		} else { 
			r_agraph_add_edge (g, prev_node, chunk_node);
		}
		prev_node = chunk_node;
	}
	top = r_agraph_add_node (g, top_title, top_data);
	if (!first_node) {
		r_agraph_add_edge (g, prev_node, top);
		free (node_data);
		free (node_title);
	}
	r_agraph_print (g);

	free (cnk);
	free (prev_c);
	free (top_data);
	free (top_title);
}

static void print_heap_graph_32(RCore *core, RHeap_MallocState32 *main_arena, ut32 *initial_brk) {
	int w, h;
	ut32 top_size = UT32_MAX;
	w = r_cons_get_size (&h);
	RConsCanvas *can = r_cons_canvas_new (w, h);
	can->color = r_config_get_i (core->config, "scr.color");
	RAGraph *g = r_agraph_new (can);
	RANode *top = {0}, *chunk_node = {0}, *prev_node = {0};
	RHeapChunk32 *cnk = R_NEW0 (RHeapChunk32), *prev_c = R_NEW0 (RHeapChunk32);

	if (!cnk || !prev_c) {
		return;
	}

	ut32 next_chunk_ref, prev_chunk_ref, brk_start = UT32_MAX, brk_end = UT32_MAX, size_tmp;
	char *top_title, *top_data, *node_title, *node_data;
	bool first_node = true;

	r_agraph_set_title (g, "Heap Layout");
	top_title = r_str_newf ("Top chunk @ 0x%"PFMT32x"\n", main_arena->top);

	if (!core || !core->dbg || !core->dbg->maps) {
		return;
	}

	get_brks_32 (core, &brk_start, &brk_end);
	*initial_brk = (brk_start >> 12) << 12;
	if (brk_start == UT32_MAX || brk_end == UT32_MAX || *initial_brk == UT32_MAX) {
		eprintf ("No Heap section\n");
		return;
	}

	top_data = r_str_newf ("[brk_start:0x%"PFMT64x", brk_end:0x%"PFMT64x"]\n", brk_start, brk_end);
	next_chunk_ref = *initial_brk, prev_chunk_ref = next_chunk_ref;
	top_size = main_arena->top - brk_start;

	while (next_chunk_ref != main_arena->top && next_chunk_ref != brk_end) {
		r_core_read_at (core, next_chunk_ref, (ut8 *)prev_c, sizeof (RHeapChunk32));
	       	node_title = r_str_newf ("  Malloc chunk @ 0x%"PFMT32x" ", prev_chunk_ref);
		size_tmp = (prev_c->size >> 3) << 3;
		if (top_size != UT32_MAX && (size_tmp > top_size  || next_chunk_ref + size_tmp > main_arena->top)) {
			node_data = r_str_newf ("[corrupted] size: 0x%x\n fd: 0x%"PFMT32x", bk: 0x%"PFMT32x"\nHeap graph could not be recovered\n", prev_c->size, prev_c->fd, prev_c->bk) ;
			r_agraph_add_node (g, node_title, node_data);
			if (first_node) first_node = false;
			//r_agraph_add_edge (g, prev_node, chunk_node);
			break;	
		} 
		next_chunk_ref += size_tmp;
		prev_chunk_ref = next_chunk_ref;
		r_core_read_at (core, next_chunk_ref, (ut8 *)cnk, sizeof (RHeapChunk32));
		node_data = r_str_newf ("size: 0x%x\n fd: 0x%"PFMT32x", bk: 0x%"PFMT32x"\n", prev_c->size, prev_c->fd, prev_c->bk) ;
		chunk_node = r_agraph_add_node (g, node_title, node_data);
		if (first_node) {
			first_node = false; 
		} else { 
			r_agraph_add_edge (g, prev_node, chunk_node);
		}
		prev_node = chunk_node;
	}
	top = r_agraph_add_node (g, top_title, top_data);
	if (!first_node) {
		r_agraph_add_edge (g, prev_node, top);
		free (node_data);
		free (node_title);
	}
	r_agraph_print (g);

	free (cnk);
	free (prev_c);
	free (top_data);
	free (top_title);
}

static void print_heap_segment32(RCore *core, RHeap_MallocState32 *main_arena, ut32 *initial_brk) {
	ut32 brk_start = UT32_MAX, brk_end = UT32_MAX, size_tmp, top_size = UT32_MAX;
	RHeapChunk32 *cnk = R_NEW0 (RHeapChunk32);

	if (!cnk) {
		return;
	}

	if (!core || !core->dbg || !core->dbg->maps){
		return;
	}

	get_brks_32 (core, &brk_start, &brk_end);
	*initial_brk = (brk_start >> 12) << 12;
	if (brk_start == UT32_MAX || brk_end == UT32_MAX || *initial_brk == UT32_MAX) {
		eprintf ("No Heap section\n");
		return;
	}

	ut32 next_chunk = *initial_brk, prev_chunk = next_chunk;
	top_size = main_arena->top - brk_start;
	bool list_corrupted = false;
	while (next_chunk && next_chunk >= brk_start && next_chunk < main_arena->top) {
		r_core_read_at (core, next_chunk, (ut8 *)cnk, sizeof (RHeapChunk32));
		size_tmp = (cnk->size >> 3) << 3;
		if (top_size != UT32_MAX && (size_tmp > top_size || next_chunk + size_tmp > main_arena->top)) {
			PRINT_YA ("\n  Malloc chunk @ ");
			PRINTF_BA ("0x%"PFMT32x" ", next_chunk);
			PRINT_RA ("[corrupted]\n");
			PRINTF_RA ("   size: 0x%"PFMT32x"\n   fd: 0x%"PFMT32x", bk: 0x%"PFMT32x"\n", cnk->size, cnk->fd, cnk->bk);
			break;
		}
		PRINT_YA ("\n  Malloc chunk @ ");
		PRINTF_BA ("0x%"PFMT32x" ", prev_chunk);
		
		bool is_free = false;
		ut32 double_free = UT32_MAX;
		if (size_tmp >= SZ * 4 && size_tmp <= SZ * 24) {
			int i = (size_tmp / (SZ * 2)) - 2;
			ut32 next = main_arena->fastbinsY[i];
			double_free = next;
			while (next && next >= brk_start && next < main_arena->top) {
				if (prev_chunk == next) {
					 is_free = true;
				}
				r_core_read_at (core, next, (ut8 *)cnk, sizeof (RHeapChunk32));
				next = cnk->fd;
							
				if (double_free == next) {
					if (prev_chunk <= double_free) {
						PRINT_RA ("Double free detected ");
					}		
					break;			
				}
			}
		}

		if (list_corrupted)  {
			break;		
		}

		next_chunk += size_tmp;
		prev_chunk = next_chunk;
		r_core_read_at (core, next_chunk, (ut8 *)cnk, sizeof (RHeapChunk32));
		if (is_free) {
			PRINT_GA ("[free]");
		} else  {
			if (cnk->size % 2 == 0) { 
				PRINT_GA ("[free]");
			} else {
				PRINT_GA ("[allocated]");
			}
		}
	}

	PRINT_YA ("\n  Top chunk @ ");
	PRINTF_BA ("0x%"PFMT32x, main_arena->top);
	PRINT_GA (" - [brk_start: ");
	PRINTF_BA ("0x%"PFMT32x, brk_start);
	PRINT_GA (", brk_end: ");
	PRINTF_BA ("0x%"PFMT32x, brk_end);
	PRINT_GA ("]\n");
	r_cons_printf ("\n");
	free (cnk);
}

static void print_heap_mmaped32(RCore *core, ut32 malloc_state) {
	ut32 mmap_start = UT32_MAX, mmap_end = UT32_MAX, size_tmp;
	ut32 top_size = UT32_MAX;
	RHeapChunk32 *cnk = R_NEW0 (RHeapChunk32);
	RHeap_MallocState32 *ms = R_NEW0 (RHeap_MallocState32);
	
	if (!cnk) {
		return;
	}

	if (!core || !core->dbg || !core->dbg->maps){
		return;
	}

	mmap_start = ((malloc_state >> 16) << 16) + sizeof(RHeapInfo32) + sizeof(RHeap_MallocState32);//0x460;
	r_core_read_at (core, malloc_state, (ut8*)ms, sizeof (RHeap_MallocState32));
	mmap_end = ms->top;


	ut32 next_chunk = mmap_start, prev_chunk = next_chunk;
	r_core_read_at (core, malloc_state, (ut8*)ms, sizeof (RHeap_MallocState32));
	r_core_read_at (core, ms->top, (ut8*)cnk, sizeof (RHeapChunk32));
	top_size = (cnk->size >> 3) << 3;
	
	bool list_corrupted = false;
	while (next_chunk && next_chunk >= mmap_start && next_chunk < ms->top) {
		r_core_read_at (core, next_chunk, (ut8 *)cnk, sizeof (RHeapChunk32));
		size_tmp = (cnk->size >> 3) << 3;
		if (top_size != UT32_MAX && (size_tmp > top_size)) {
			PRINT_YA ("\n  Malloc chunk @ ");
			PRINTF_BA ("0x%"PFMT32x" ", next_chunk);
			PRINT_RA ("[corrupted]\n");
			PRINTF_RA ("   size: %0x"PFMT32x"\n   fd: 0x%"PFMT32x", bk: 0x%"PFMT32x"\n", cnk->size, cnk->fd, cnk->bk);
			break;
		}
		PRINT_YA ("\n  Malloc chunk @ ");
		PRINTF_BA ("0x%"PFMT32x" ", prev_chunk);
	
		bool is_free = false;
		ut32 double_free = UT32_MAX;
		if (size_tmp >= SZ * 4 && size_tmp <= SZ * 24) {
			int i = (size_tmp / (SZ * 2)) - 2;
			ut32 next = ms->fastbinsY[i];
			double_free = next;
			while (next && next >= mmap_start && next < ms->top) {
				if (prev_chunk == next) {
					 is_free = true;
				}
				r_core_read_at (core, next, (ut8 *)cnk, sizeof (RHeapChunk32));
				next = cnk->fd;
			
				if (double_free == next) {
					if (prev_chunk <= double_free) {
						PRINT_RA ("Double free detected ");
					}	
					break;			
				}
			}
		}

		if (list_corrupted)  {
			break;		
		}

		next_chunk += size_tmp;
		prev_chunk = next_chunk;
		r_core_read_at (core, next_chunk, (ut8 *)cnk, sizeof (RHeapChunk32));
		if (is_free) {
			PRINT_GA ("[free]");
		} else  {
			if (cnk->size % 2 == 0) { 
				PRINT_GA ("[free]");
			} else {
				PRINT_GA ("[allocated]");
			}
		}
	}

	PRINT_YA ("\n  Top chunk @ ");
	PRINTF_BA ("0x%"PFMT32x, ms->top);
	PRINT_GA (" - [mmap_start: ");
	PRINTF_BA ("0x%"PFMT32x, mmap_start);
	PRINT_GA (", mmap_end: ");
	r_core_read_at (core, ms->top, (ut8*)cnk, sizeof(RHeapChunk32));
	PRINTF_BA ("0x%"PFMT32x, mmap_end + ((cnk->size >> 3) << 3));
	PRINT_GA ("]\n");
	r_cons_printf ("\n");
	free (cnk);
	free (ms);
}

void print_malloc_states32 ( RCore *core, ut32 m_arena, RHeap_MallocState32 *main_arena) {
	RHeap_MallocState32 *ta = R_NEW0 (RHeap_MallocState32);
	PRINT_YA ("main_arena @ ");
	PRINTF_BA ("0x%"PFMT32x"\n", m_arena);	

	if (main_arena->next == m_arena) return;
	else {
		ta->next = main_arena->next;
		while (ta->next != UT32_MAX && ta->next != m_arena) {
			PRINT_YA ("thread arena @ ");
			PRINTF_BA ("0x%"PFMT32x"\n", ta->next);
			r_core_read_at (core, ta->next, (ut8 *)ta, sizeof (RHeap_MallocState32));
		}
	}
	free(ta);
	return;
}
void print_inst_minfo32(RHeapInfo32 *heap_info, ut32 hinfo) {
	PRINT_YA ("malloc_info @ ");
	PRINTF_BA ("0x%"PFMT32x, hinfo);
	PRINT_YA ("{\n  ar_ptr = " );
	PRINTF_BA ("0x%"PFMT32x"\n", heap_info->ar_ptr);
	PRINT_YA ("  prev = ");
	PRINTF_BA ("0x%"PFMT32x"\n", heap_info->prev);
	PRINT_YA ("  size = ");
	PRINTF_BA ("0x%"PFMT32x"\n", heap_info->size);
	PRINT_YA ("  mprotect_size = ");
	PRINTF_BA ("0x%"PFMT32x"\n", heap_info->mprotect_size);	
	PRINT_YA ("}\n\n");	
	return;
}

void print_malloc_info32(RCore *core, ut32 m_state) {
	ut32 malloc_state = core->offset, h_info;
	
	if (malloc_state == m_state) PRINT_RA ("main_arena does not have an instance of malloc_info\n");
	else {
		h_info = (malloc_state >> 16) << 16;
		RHeapInfo32 *heap_info = R_NEW0 (RHeapInfo32);
		r_core_read_at (core, h_info, (ut8*)heap_info, sizeof (RHeapInfo32));
		print_inst_minfo32 (heap_info, h_info);
		RHeap_MallocState32 *ms = R_NEW0 (RHeap_MallocState32);
	
		while (heap_info->prev != 0x0 && heap_info->prev != UT32_MAX) {
			r_core_read_at (core, h_info, (ut8*)ms, sizeof (RHeap_MallocState32));
			if ((ms->top >> 16) << 16 != h_info) {
				h_info = (ms->top >> 16) << 16;
				r_core_read_at (core, h_info, (ut8*)heap_info, sizeof (RHeapInfo32));
				print_inst_minfo32 (heap_info, h_info);
			}	
		} 
		free (heap_info);
		free (ms);
	}
	return;
}	

static int cmd_dbg_map_heap_glibc_32(RCore *core, const char *input) {
	static ut32 m_arena = UT32_MAX, initial_brk = UT32_MAX;
	RHeap_MallocState32 *main_arena = R_NEW0 (RHeap_MallocState32);
	if (!main_arena) {
		return false;
	}

	const char* help_msg[] = {
		"Usage:", " dmh", " # Memory map heap",
		"dmh", "", "List chunks in heap segment",
		"dmh", " [malloc_state]", "List heap chunks of a particular arena",
		"dmha", "", "List all malloc_state instances in application",
		"dmhb", "", "Display all parsed Double linked list of main_arena's bins instance",
		"dmhb", " [bin_num|bin_num:malloc_state]", "Display parsed double linked list of bins instance from a particular arena",
		"dmhbg"," [bin_num]", "Display double linked list graph of main_arena's bin [Under developemnt]",
		"dmhc", " @[chunk_addr]", "Display malloc_chunk struct for a given malloc chunk",
		"dmhf", "", "Display all parsed fastbins of main_arena's fastbinY instance",
		"dmhf", " [fastbin_num|fastbin_num:malloc_state]", "Display parsed single linked list in fastbinY instance from a particular arena",
		"dmhg", "", "Display heap graph of heap segment",
		"dmhg", " [malloc_state]", "Display heap graph of a particular arena",
		"dmhi", " @[malloc_state]", "Display heap_info structure/structures for a given arena",
		"dmhm", "", "List all elemnts of struct malloc_state of main thread (main_arena)",
		"dmhm", " [malloc_state]", "List all malloc_state instance of a particular arena",
		"dmh?", "", "Show map heap help",
		NULL
	};

	switch (input[0]) {
	
	case '\0': // dmh
		if (r_resolve_main_arena_32 (core, &m_arena, main_arena)) {
			print_heap_segment32 (core, main_arena, &initial_brk);
		}	
		break;
	case ' ' : // dmh [malloc_state]
		if (r_resolve_main_arena_32 (core, &m_arena, main_arena)) {
			ut32 m_state = strstr (input, "0x") ? (ut32)strtol (input, NULL, 0) :  (ut32)strtol (input, NULL, 16);
			if (m_state == m_arena) print_heap_segment32 (core, main_arena, &initial_brk); 
			print_heap_mmaped32 (core, m_state);
		}
		break;
	case 'a': // dmha
		if (r_resolve_main_arena_32 (core, &m_arena, main_arena)) {
			print_malloc_states32 (core, m_arena, main_arena);
		}
		break;
	case 'i': //dmhi
		if (r_resolve_main_arena_32 (core, &m_arena, main_arena)) {
			print_malloc_info32 (core, m_arena);
		}
		break;
	case '*':
	case 'm': // "dmhm"	
		if (r_resolve_main_arena_32 (core, &m_arena, main_arena)) {
			input += 1;
			if (!strcmp (input,"\0")) {
				 print_main_arena_32 (core, m_arena, main_arena, *input);
			} else {
				ut32 m_state = strstr(input, "0x") ? (ut32)strtol (input, NULL, 0) : (ut32)strtol (input, NULL, 16); 
				RHeap_MallocState32 *malloc_state = R_NEW0 (RHeap_MallocState32);
				r_core_read_at (core, m_state, (ut8*)malloc_state, sizeof (RHeap_MallocState32));
				print_main_arena_32 (core, m_state, malloc_state, *input);
				free(malloc_state);
			}
		}
		break;
	case 'b': // "dmhb"
		if (r_resolve_main_arena_32 (core, &m_arena, main_arena)) {

			if (!strstr (input+1, ":")) {
				print_heap_bin_32 (core, m_arena, main_arena, input+1);
			} else {
				char *m_state_str, *bin, *dup = strdup (input+1);
				bin = strtok (dup, ":");
				m_state_str = strtok (NULL, ":");
				
				ut32 m_state = strstr (m_state_str, "0x") ? (ut32)strtol (m_state_str, NULL, 0) : (ut32)strtol (m_state_str, NULL, 16); 
				RHeap_MallocState32 *malloc_state = R_NEW0 (RHeap_MallocState32);
				r_core_read_at (core, m_state, (ut8*)malloc_state, sizeof (RHeap_MallocState32));
				print_heap_bin_32 (core, m_state, malloc_state, bin); 
				free(malloc_state);
			}
		}
		break;
	case 'c': // "dmhc"
		if (r_resolve_main_arena_32 (core, &m_arena, main_arena)) {
            		print_heap_chunk_32 (core);
		}
		break;
	case 'f': // "dmhf"
		if (r_resolve_main_arena_32 (core, &m_arena, main_arena)) {

			if (!strstr (input+1, ":")) {
				print_heap_fastbin_32 (core, m_arena, main_arena, input+1);
			} else {
				char *m_state_str, *bin, *dup = strdup (input+1);
				bin = strtok (dup, ":");
				m_state_str = strtok (NULL, ":");
				
				ut32 m_state = strstr (m_state_str, "0x") ? (ut32)strtol (m_state_str, NULL, 0) : (ut32)strtol (m_state_str, NULL, 16);
				RHeap_MallocState32 *malloc_state = R_NEW0 (RHeap_MallocState32);
				r_core_read_at (core, m_state, (ut8*)malloc_state, sizeof (RHeap_MallocState32));
				print_heap_fastbin_32 (core, m_state, malloc_state, bin); 
				free(malloc_state);
			}
		}
		break;
	case 'g': // "dmhg"
		if (r_resolve_main_arena_32 (core, &m_arena, main_arena)) {
			input += 1;
			if (!strcmp (input, "\0")) {
				print_heap_graph_32 (core, main_arena, &initial_brk);
			} else {
				ut32 m_state = strstr (input, "0x") ? (ut32)strtol (input, NULL, 0) : (ut32)strtol (input, NULL, 16);
				if (m_state == m_arena) print_heap_graph_32 (core, main_arena, &initial_brk);
				else {
					RHeap_MallocState32 *malloc_state = R_NEW0 (RHeap_MallocState32);
					r_core_read_at (core, m_state, (ut8*)malloc_state, sizeof (RHeap_MallocState32));
					print_mmap_graph_32 (core, malloc_state, m_state);
					free (malloc_state);
				}
			}
		}
		break;
	case 'j': // "dmhj"
		eprintf ("TODO: JSON output for dmh is not yet implemented\n");
		break;
	case '?':
		r_core_cmd_help (core, help_msg);
		break;
	}
	free (main_arena);
	return true;
}

