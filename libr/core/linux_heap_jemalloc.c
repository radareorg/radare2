#ifndef INCLUDE_HEAP_JEMALLOC_STD_C
#define INCLUDE_HEAP_JEMALLOC_STD_C
#define HEAP32 1
#include "linux_heap_jemalloc.c"
#undef HEAP32
#endif

#undef GH
#undef GHT
#undef GHT_MAX
#undef PFMTx

#if HEAP32
#define GH(x) x##_32
#define GHT ut32
#define GHT_MAX UT32_MAX
#define PFMTx PFMT32x 
#else
#define GH(x) x##_64
#define GHT ut64
#define GHT_MAX UT64_MAX
#define PFMTx PFMT64x
#endif

static GHT GH(je_get_va_symbol)(const char *path, const char *symname) {
	RListIter *iter;
	RBinSymbol *s;
	RCore *core = r_core_new ();
	RList * syms = NULL;
	GHT vaddr = 0LL;

	if (!core) {
		return GHT_MAX;
	}
	r_bin_load (core->bin, path, 0, 0, 0, -1, false);
	syms = r_bin_get_symbols (core->bin);
	if (!syms) {
		return GHT_MAX;
	}
	r_list_foreach (syms, iter, s) {
		if (!strcmp(s->name, symname)) {
			vaddr = s->vaddr;
			break;
		}
	}
	r_core_free (core);
	return vaddr;
}

static int GH(je_matched)(const char *ptr, const char *str) {
        int ret = strncmp (ptr, str, strlen (str) - 1);
	return !ret;
}

static bool GH(r_resolve_jemalloc)(RCore *core, char *symname, GHT *symbol) {
	RListIter *iter;
	RDebugMap *map;
	const char *jemalloc_ver_end = NULL;
	ut64 jemalloc_addr = UT64_MAX, vaddr = UT64_MAX;

	if (!core || !core->dbg || !core->dbg->maps){
		return false;
	}
	r_debug_map_sync (core->dbg);
	r_list_foreach (core->dbg->maps, iter, map) {
		if (strstr (map->name, "libjemalloc.so")) {
			jemalloc_addr = map->addr;
			jemalloc_ver_end = map->name;
			break;
		}
	}

	if (!jemalloc_ver_end) {
		eprintf ("Warning: Is jemalloc mapped in memory? (see dm command)\n");
		return false;
	}

	bool is_debug_file = GH(je_matched)(jemalloc_ver_end, "/usr/local/lib");

	if (!is_debug_file) {
		eprintf ("Warning: Is libjemalloc.so.2 in /usr/local/lib path?\n");
		return false;
	}
	char *path = r_str_newf ("%s", jemalloc_ver_end);
	if (r_file_exists (path)) {
		vaddr = GH(je_get_va_symbol)(path, symname);
		if (jemalloc_addr != GHT_MAX && vaddr != 0) {
			*symbol = jemalloc_addr + vaddr;
			free (path);
			return true;
		} 
	}
	free (path);
	return false;
}
 
static void GH(jemalloc_get_chunks)(RCore *core, const char *input) {
	GHT cnksz = GHT_MAX;

	if (GH(r_resolve_jemalloc)(core, "je_chunksize", &cnksz)) {
		r_core_read_at (core, cnksz, (ut8 *)&cnksz, sizeof (GHT));     
	} else {
		eprintf ("Fail at read symbol je_chunksize\n");
	}

	switch (input[0]) {
	case '\0':
		eprintf ("need an arena_t to associate chunks");
		break;
        case ' ':
        	{
			GHT arena = GHT_MAX;
			arena_t *ar = R_NEW0 (arena_t);
			extent_node_t *node = R_NEW0 (extent_node_t), *head = R_NEW0 (extent_node_t);
			input += 1;
			arena = strstr (input, "0x") ? (GHT)strtol (input, NULL, 0) : (GHT)strtol (input, NULL, 16);

			if (arena) {
				r_core_read_at (core, arena, (ut8 *)ar, sizeof (arena_t));
				r_core_read_at (core, (ut64)(size_t)ar->achunks.qlh_first, (ut8 *)head, sizeof (extent_node_t));
				if (head->en_addr) {
					PRINT_YA ("\t Chunk - start: ");
					PRINTF_BA ("0x%"PFMTx, (GHT)head->en_addr); 
					PRINT_YA (", end: ");
					PRINTF_BA ("0x%"PFMTx, (GHT)(head->en_addr + cnksz));
					PRINT_YA (", size: ");
					PRINTF_BA ("0x%"PFMTx"\n", (GHT)cnksz); 
					r_core_read_at (core, (ut64)(size_t)head->ql_link.qre_next, (ut8 *)node, sizeof (extent_node_t));
					while (node && node->en_addr != head->en_addr) {
						PRINT_YA ("\t Chunk - start: ");
						PRINTF_BA ("0x%"PFMTx, (GHT)node->en_addr); 
						PRINT_YA (", end: ");
						PRINTF_BA ("0x%"PFMTx, (GHT)(node->en_addr + cnksz));
						PRINT_YA (", size: ");
						PRINTF_BA ("0x%"PFMTx"\n", (GHT)cnksz); 
						r_core_read_at (core, (ut64)(size_t)node->ql_link.qre_next, (ut8 *)node, sizeof (extent_node_t));
					}
				}
			}
			free (ar);
			free (head);
			free (node);
		break;
        	}            
        case '*':           
		{
			int i = 0;
			GHT arenas = GHT_MAX, arena = GHT_MAX, sym = GHT_MAX;
			arena_t *ar = R_NEW0 (arena_t);
			extent_node_t *node = R_NEW0 (extent_node_t);
			extent_node_t *head = R_NEW0 (extent_node_t);
			// TODO : check for null allocations here
			input += 1;
			
			if (GH(r_resolve_jemalloc) (core, "je_arenas", &sym)) {
				r_core_read_at (core, sym, (ut8 *)&arenas, sizeof (GHT));
				for (;;) {
					r_core_read_at (core, arenas + i * sizeof (GHT), (ut8 *)&arena, sizeof (GHT));
					if (!arena) {
						break;
					}
					PRINTF_GA ("arenas[%d]: @ 0x%"PFMTx" { \n", i++, (GHT)arena);
					r_core_read_at (core, arena, (ut8 *)ar, sizeof (arena_t));
					r_core_read_at (core, (ut64)(size_t)ar->achunks.qlh_first, (ut8 *)head, sizeof (extent_node_t));
					if (head->en_addr != 0) {
						PRINT_YA ("\t Chunk - start: ");
						PRINTF_BA ("0x%"PFMTx, (GHT)head->en_addr); 
						PRINT_YA (", end: ");
						PRINTF_BA ("0x%"PFMTx, (GHT)(head->en_addr + cnksz));
						PRINT_YA (", size: ");
						PRINTF_BA ("0x%"PFMTx"\n", (GHT)cnksz); 
						ut64 addr = (ut64) head->ql_link.qre_next;
						r_core_read_at (core, addr, (ut8 *)node, sizeof (extent_node_t));
						while (node && node->en_addr != head->en_addr) {
							PRINT_YA ("\t Chunk - start: ");
							PRINTF_BA ("0x%"PFMTx, (GHT)node->en_addr); 
							PRINT_YA (", end: ");
							PRINTF_BA ("0x%"PFMTx, (GHT)(node->en_addr + cnksz));
							PRINT_YA (", size: ");
							PRINTF_BA ("0x%"PFMTx"\n", (GHT)cnksz);
							r_core_read_at (core, (ut64)(size_t)node->ql_link.qre_next, (ut8 *)node, sizeof (extent_node_t));
						}
					}
					PRINT_GA ("}\n");
				}
			}
			free (ar);
			free (head);
			free (node);
		}
		break;
	}
}

static void GH(jemalloc_print_narenas)(RCore *core, const char *input) {
	GHT sym = GHT_MAX, arena = GHT_MAX, arenas = GHT_MAX;
	arena_t *ar = R_NEW0 (arena_t);
	arena_stats_t *stats = R_NEW0 (arena_stats_t);
	int i = 0 , narenas;

	switch (input[0]) {
	case '\0':
		if (GH(r_resolve_jemalloc)(core, "narenas_total", &sym)) {
			r_core_read_at (core, sym, (ut8 *)&narenas, sizeof (GHT));
			PRINTF_GA ("narenas : %d\n", narenas);
		}
		
		if (GH(r_resolve_jemalloc)(core, "je_arenas", &arenas)) {
			r_core_read_at (core, arenas, (ut8 *)&arenas, sizeof (GHT));
			PRINTF_GA ("arenas @ 0x%"PFMTx" {\n", (GHT)arenas);
			
        	for (;;) {
				r_core_read_at (core, arenas + i * sizeof (GHT), (ut8 *)&arena, sizeof (GHT));
				if (!arena) {
					break;
				}
				PRINTF_YA ("\t arenas[%d]: ", i++);
				PRINTF_BA ("@ 0x%"PFMTx"\n", (GHT)arena);
			}
		}
			PRINT_GA ("}\n");
		break;
	case ' ':
		input += 1;
		ut64 arena = strstr (input, "0x") ? (GHT)strtol (input, NULL, 0) : (GHT)strtol (input, NULL, 16);
		r_core_read_at (core, (GHT)arena, (ut8 *)ar, sizeof (arena_t));

    		PRINT_GA ("struct arena_s {\n");
		PRINTF_BA ("\tind = 0x%"PFMTx"\n", (GHT)ar->ind);
		PRINTF_BA ("\tnthreads: application allocation = 0x%"PFMTx"\n", ar->nthreads[0]);
		PRINTF_BA ("\tnthreads: internal metadata allocation = 0x%"PFMTx"\n", ar->nthreads[1]);
		PRINTF_BA ("\tlock = 0x%"PFMTx"\n", *(GHT *)&ar->lock);
		PRINTF_BA ("\tstats = 0x%"PFMTx"\n", *(GHT *)&ar->stats);
		PRINTF_BA ("\ttcache_ql = 0x%"PFMTx"\n", *(GHT *)&ar->tcache_ql);
		PRINTF_BA ("\tprof_accumbytes = 0x%"PFMTx"x\n", (GHT)ar->prof_accumbytes); 
		PRINTF_BA ("\toffset_state = 0x%"PFMTx"\n", (GHT)ar->offset_state); 
		PRINTF_BA ("\tdss_prec_t = 0x%"PFMTx"\n", *(GHT *)&ar->dss_prec); 
		PRINTF_BA ("\tachunks = 0x%"PFMTx"\n", *(GHT *)&ar->achunks);
		PRINTF_BA ("\textent_sn_next = 0x%"PFMTx"\n", (GHT)ar->extent_sn_next);
		PRINTF_BA ("\tspare = 0x%"PFMTx"\n", *(GHT *)&ar->spare);
		PRINTF_BA ("\tlg_dirty_mult = 0x%"PFMTx"\n", (GHT)ar->lg_dirty_mult);
		PRINTF_BA ("\tpurging = 0x%"PFMTx"\n", (GHT)ar->purging);
		PRINTF_BA ("\tnactive = 0x%"PFMTx"\n", (GHT)ar->nactive);
		PRINTF_BA ("\tndirty = 0x%"PFMTx"\n", (GHT)ar->ndirty);
		PRINTF_BA ("\truns_dirty = 0x%"PFMTx"\n", *(GHT *)&ar->runs_dirty);
		PRINTF_BA ("\tchunks_cache = 0x%"PFMTx"\n", *(GHT *)&ar->chunks_cache);
		PRINTF_BA ("\thuge = 0x%"PFMTx"\n", *(GHT *)&ar->huge);
		PRINTF_BA ("\thuge_mtx = 0x%"PFMTx"\n", *(GHT *)&ar->huge_mtx);
		PRINTF_BA ("\tchunks_szsnad_cached = 0x%"PFMTx"\n", *(GHT *)&ar->chunks_szsnad_cached);
		PRINTF_BA ("\tchunks_ad_cached = 0x%"PFMTx"\n", *(GHT *)&ar->chunks_ad_cached);
		PRINTF_BA ("\tchunks_szsnad_retained = 0x%"PFMTx"\n", *(GHT *)&ar->chunks_szsnad_retained);
		PRINTF_BA ("\tchunks_ad_cached = 0x%"PFMTx"\n", *(GHT *)&ar->chunks_ad_retained);
		PRINTF_BA ("\tchunks_mtx = 0x%"PFMTx"\n", *(GHT *)&ar->chunks_mtx);
		PRINTF_BA ("\tnode_cache = 0x%"PFMTx"\n", *(GHT *)&ar->node_cache);
		PRINTF_BA ("\tnode_cache_mtx = 0x%"PFMTx"\n", *(GHT *)&ar->node_cache_mtx);
		PRINTF_BA ("\tchunks_hooks = 0x%"PFMTx"\n", *(GHT *)&ar->chunk_hooks);
		PRINTF_BA ("\tbins = 0x%"PFMTx"\n", NBINS, *(GHT *)&ar->bins);
		PRINTF_BA ("\truns_avail = 0x%"PFMTx"\n", NPSIZES, *(GHT *)&ar->runs_avail);
		PRINT_GA ("}\n");
		break;
	} 
	free (ar);
	free (stats);
}

static void GH(jemalloc_get_bins)(RCore *core, const char *input) {
	switch (input[0]) {
        case ' ':
        	{
			int i = 0, j;
			GHT arenas = GHT_MAX, arena = GHT_MAX, bin = GHT_MAX, bin_info;
			arena_t *ar = R_NEW0 (arena_t);
			arena_bin_info_t *b = R_NEW0 (arena_bin_info_t);

		   	if (GH(r_resolve_jemalloc)(core, "je_arena_bin_info", &bin_info)) {
	    		} else {
				eprintf ("Error resolving je_arena_bin_info\n");
				return;    
	    		}
			
			if (GH(r_resolve_jemalloc)(core, "je_arenas", &arenas)) {
				r_core_read_at (core, arenas, (ut8 *)&arenas, sizeof (GHT));
				PRINTF_GA ("arenas @ 0x%"PFMTx" {\n", (GHT)arenas);
				for (;;) {
					r_core_read_at (core, arenas + i * sizeof (GHT), (ut8 *)&arena, sizeof (GHT));
					if (!arena) {
						break;
					}
					PRINTF_YA ("\t arenas[%d]: ", i++);
					PRINTF_BA ("@ 0x%"PFMTx, (GHT)arena);
					PRINT_YA (" {\n");
					r_core_read_at (core, arena, (ut8 *)ar, sizeof (arena_t));
					for (j = 0; j < NBINS; j++) {
						r_core_read_at (core, (GHT)(bin_info + j * sizeof(arena_bin_info_t)), (ut8*)b, sizeof(arena_bin_info_t));
						PRINT_YA ("\t\t{\n");
		
						PRINT_YA ("\t\t\t regsize : ");
						PRINTF_BA ("0x%"PFMTx"\n", (GHT*)b->reg_size);
						PRINT_YA ("\t\t\t redzone size ");
						PRINTF_BA ("0x%"PFMTx"\n", (GHT*)b->redzone_size);
						PRINT_YA ("\t\t\t reg_interval : ");
						PRINTF_BA ("0x%"PFMTx"\n", (GHT*)b->reg_interval);
						PRINT_YA ("\t\t\t run_size : ");
						PRINTF_BA ("0x%"PFMTx"\n", (GHT*)b->run_size);
						PRINT_YA ("\t\t\t nregs : ");
						PRINTF_BA ("0x%"PFMTx"\n", (GHT*)b->nregs);
						PRINT_YA ("\t\t\t bitmap_info : ");
						PRINTF_BA ("0x%"PFMTx"\n", *(GHT*)&b->bitmap_info);
						PRINT_YA ("\t\t\t reg0_offset : ");
						PRINTF_BA ("0x%"PFMTx"\n\n", (GHT*)b->reg0_offset);
						
						PRINTF_YA ("\t\t\t bins[%d]->lock ", j);
						PRINTF_BA ("= 0x%"PFMTx"\n", *(GHT *)&ar->bins[j].lock);
						PRINTF_YA ("\t\t\t bins[%d]->runcur ", j);
						PRINTF_BA ("@ 0x%"PFMTx"\n", *(GHT *)&ar->bins[j].runcur);	
						PRINTF_YA ("\t\t\t bins[%d]->runs ", j);
						PRINTF_BA ("@ 0x%"PFMTx"\n", *(GHT *)&ar->bins[j].runs);
						PRINTF_YA ("\t\t\t bins[%d]->stats ", j);
						PRINTF_BA ("= 0x%"PFMTx"\n", *(GHT *)&ar->bins[j].stats);
						PRINT_YA ("\t\t}\n");
					}
					PRINT_YA ("\t}\n");
				}
			}
			PRINT_GA ("}\n");
			free (ar);
		}
		break;
	}
}

static int GH(cmd_dbg_map_jemalloc)(RCore *core, const char *input) {
	const char *help_msg[] = {
		"Usage:", "dmh", " # Memory map heap",
		"dmha", "[arena_t]", "show all arenas created, or print arena_t sructure for given arena",
		"dmhb", "[arena_t]", "show all bins created for given arena",
		"dmhc", "*|[arena_t]", "show all chunks created in all arenas, or show all chunks created for a given arena_t instance",
		// "dmhr", "[arena_chunk_t]", "print all runs created for a given arena_chunk_t instance",
		"dmh?", "", "Show map heap help", NULL
	};

	switch (input[0]) {
	case '?':
		r_core_cmd_help (core, help_msg);
		break;
	case 'a': //dmha
		GH(jemalloc_print_narenas) (core, input + 1);
		break;
	case 'b': //dmhb
		GH(jemalloc_get_bins) (core, input + 1);
		break;
	case 'c': //dmhc
		GH(jemalloc_get_chunks) (core, input + 1);
		break;
	/*
	case 'r': //dmhr
		GH(jemalloc_get_runs) (core, input + 1);
		break;
	*/
	}
	return 0;
}
 
