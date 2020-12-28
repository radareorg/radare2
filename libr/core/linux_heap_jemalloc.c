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

// FIXME: It should be detected at runtime, not during the compilation stage
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

#if __linux__
// TODO: provide proper api in cbin to resolve symbols and load libraries from debug maps and such
// this is, provide a programmatic api for the slow dmi command
static GHT GH(je_get_va_symbol)(const char *path, const char *symname) {
	RListIter *iter;
	RBinSymbol *s;
	RCore *core = r_core_new ();
	GHT vaddr = 0LL;

	if (!core) {
		return GHT_MAX;
	}

	RBinOptions opt;
	r_bin_options_init (&opt, -1, 0, 0, false);
	if (r_bin_open (core->bin, path, &opt)) {
		RList *syms = r_bin_get_symbols (core->bin);
		if (!syms) {
			r_core_free (core);
			return GHT_MAX;
		}
		r_list_foreach (syms, iter, s) {
			if (!strcmp(s->name, symname)) {
				vaddr = s->vaddr;
				break;
			}
		}
	}
	r_core_free (core);
	return vaddr;
}

static int GH(je_matched)(const char *ptr, const char *str) {
        int ret = strncmp (ptr, str, strlen (str) - 1);
	return !ret;
}
#endif

static bool GH(r_resolve_jemalloc)(RCore *core, char *symname, ut64 *symbol) {
	RListIter *iter;
	RDebugMap *map;
	const char *jemalloc_ver_end = NULL;
	ut64 jemalloc_addr = UT64_MAX;

	if (!core || !core->dbg || !core->dbg->maps){
		return false;
	}
	r_debug_map_sync (core->dbg);
	r_list_foreach (core->dbg->maps, iter, map) {
		if (strstr (map->name, "libjemalloc.")) {
			jemalloc_addr = map->addr;
			jemalloc_ver_end = map->name;
			break;
		}
	}
	if (!jemalloc_ver_end) {
		eprintf ("Warning: Is jemalloc mapped in memory? (see dm command)\n");
		return false;
	}
#if __linux__
	bool is_debug_file = GH(je_matched)(jemalloc_ver_end, "/usr/local/lib");

	if (!is_debug_file) {
		eprintf ("Warning: Is libjemalloc.so.2 in /usr/local/lib path?\n");
		return false;
	}
	char *path = r_str_newf ("%s", jemalloc_ver_end);
	if (r_file_exists (path)) {
		ut64 vaddr = GH(je_get_va_symbol)(path, symname);
		if (jemalloc_addr != GHT_MAX && vaddr != 0) {
			*symbol = jemalloc_addr + vaddr;
			free (path);
			return true;
		}
	}
	free (path);
	return false;
#else
	eprintf ("[*] Resolving %s from libjemalloc.2... ", symname);
	// this is quite sloooow, we must optimize dmi
	char *va = r_core_cmd_strf (core, "dmi libjemalloc.2 %s$~[1]", symname);
	ut64 n = r_num_get (NULL, va);
	if (n && n != UT64_MAX) {
		*symbol = n;
		eprintf ("0x%08"PFMT64x"\n", n);
	} else {
		eprintf ("NOT FOUND\n");
	}
	free (va);
	return true;
#endif
}

static void GH(jemalloc_get_chunks)(RCore *core, const char *input) {
	ut64 cnksz;
	RConsPrintablePalette *pal = &r_cons_singleton ()->context->pal;

	if (!GH(r_resolve_jemalloc)(core, "je_chunksize", &cnksz)) {
		eprintf ("Fail at read symbol je_chunksize\n");
		return;
	}
	r_io_read_at (core->io, cnksz, (ut8 *)&cnksz, sizeof (GHT));

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
			arena = r_num_math (core->num, input);

			if (arena) {
				r_io_read_at (core->io, arena, (ut8 *)ar, sizeof (arena_t));
				r_io_read_at (core->io, (GHT)(size_t)ar->achunks.qlh_first, (ut8 *)head, sizeof (extent_node_t));
				if (head->en_addr) {
					PRINT_YA ("   Chunk - start: ");
					PRINTF_BA ("0x%08"PFMT64x, (ut64)(size_t)head->en_addr);
					PRINT_YA (", end: ");
					PRINTF_BA ("0x%08"PFMT64x, (ut64)(size_t)((char *)head->en_addr + cnksz));
					PRINT_YA (", size: ");
					PRINTF_BA ("0x%08"PFMT64x"\n", (ut64)cnksz);
					r_io_read_at (core->io, (ut64)(size_t)head->ql_link.qre_next, (ut8 *)node, sizeof (extent_node_t));
					while (node && node->en_addr != head->en_addr) {
						PRINT_YA ("   Chunk - start: ");
						PRINTF_BA ("0x%08"PFMT64x, (ut64)(size_t)node->en_addr);
						PRINT_YA (", end: ");
						PRINTF_BA ("0x%"PFMT64x, (ut64)(size_t)((char *)node->en_addr + cnksz));
						PRINT_YA (", size: ");
						PRINTF_BA ("0x%08"PFMT64x"\n", cnksz);
						r_io_read_at (core->io, (ut64)(size_t)node->ql_link.qre_next, (ut8 *)node, sizeof (extent_node_t));
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
			ut64 sym;
			GHT arenas = GHT_MAX, arena = GHT_MAX;
			arena_t *ar = R_NEW0 (arena_t);
			extent_node_t *node = R_NEW0 (extent_node_t);
			extent_node_t *head = R_NEW0 (extent_node_t);

			if (!node || !head) {
				eprintf ("Error calling calloc\n");
				free (ar);
				free (node);
				free (head);
				return;
			}

			input += 1;

			if (GH(r_resolve_jemalloc) (core, "je_arenas", &sym)) {
				r_io_read_at (core->io, sym, (ut8 *)&arenas, sizeof (GHT));
				for (;;) {
					r_io_read_at (core->io, arenas + i * sizeof (GHT), (ut8 *)&arena, sizeof (GHT));
					if (!arena) {
						break;
					}
					PRINTF_GA ("arenas[%d]: @ 0x%"PFMTx" { \n", i++, (GHT)arena);
					r_io_read_at (core->io, arena, (ut8 *)ar, sizeof (arena_t));
					r_io_read_at (core->io, (GHT)(size_t)ar->achunks.qlh_first, (ut8 *)head, sizeof (extent_node_t));
					if (head->en_addr != 0) {
						PRINT_YA ("   Chunk - start: ");
						PRINTF_BA ("0x%08"PFMT64x, (ut64)(size_t)head->en_addr);
						PRINT_YA (", end: ");
						PRINTF_BA ("0x%"PFMT64x, (ut64)(size_t)((char *)head->en_addr + cnksz));
						PRINT_YA (", size: ");
						PRINTF_BA ("0x%08"PFMT64x"\n", (ut64)cnksz);
						ut64 addr = (ut64) (size_t)head->ql_link.qre_next;
						r_io_read_at (core->io, addr, (ut8 *)node, sizeof (extent_node_t));
						while (node && head && node->en_addr != head->en_addr) {
							PRINT_YA ("   Chunk - start: ");
							PRINTF_BA ("0x%08"PFMT64x, (ut64)(size_t)node->en_addr);
							PRINT_YA (", end: ");
							PRINTF_BA ("0x%"PFMT64x, (ut64)(size_t)((char *)node->en_addr + cnksz));
							PRINT_YA (", size: ");
							PRINTF_BA ("0x%"PFMT64x"\n", cnksz);
							r_io_read_at (core->io, (GHT)(size_t)node->ql_link.qre_next, (ut8 *)node, sizeof (extent_node_t));
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
	ut64 symaddr;
	ut64 arenas;
	GHT arena = GHT_MAX;
	arena_t *ar = R_NEW0 (arena_t);
	if (!ar) {
		return;
	}
	arena_stats_t *stats = R_NEW0 (arena_stats_t);
	if (!stats) {
		free (ar);
		return;
	}
	int i = 0;
	GHT narenas = 0;
	RConsPrintablePalette *pal = &r_cons_singleton ()->context->pal;

	switch (input[0]) {
	case '\0':
		if (GH(r_resolve_jemalloc)(core, "narenas_total", &symaddr)) {
			r_io_read_at (core->io, symaddr, (ut8 *)&narenas, sizeof (GHT));
			PRINTF_GA ("narenas : %"PFMT64d"\n", (ut64)narenas);
		}
		if (narenas == 0) {
			eprintf ("No arenas allocated.\n");
			free (stats);
			free (ar);
			return;
		}
		if (narenas == GHT_MAX) {
			eprintf ("Cannot find narenas_total\n");
			free (stats);
			free (ar);
			return;
		}

		if (GH(r_resolve_jemalloc)(core, "je_arenas", &arenas)) {
			r_io_read_at (core->io, arenas, (ut8 *)&arenas, sizeof (GHT));
			PRINTF_GA ("arenas[%"PFMT64d"] @ 0x%"PFMT64x" {\n", (ut64)narenas, (ut64)arenas);
			for (i = 0; i < narenas; i++) {
				ut64 at = arenas + (i * sizeof (GHT));
				r_io_read_at (core->io, at, (ut8 *)&arena, sizeof (GHT));
				if (!arena) {
					PRINTF_YA ("  arenas[%d]: (empty)\n", i);
					continue;
				}
				PRINTF_YA ("  arenas[%d]: ", i);
				PRINTF_BA ("@ 0x%"PFMT64x"\n", at);
			}
		}
		PRINT_GA ("}\n");
		break;
	case ' ':
		arena = r_num_math (core->num, input + 1);
		r_io_read_at (core->io, (GHT)arena, (ut8 *)ar, sizeof (arena_t));

		PRINT_GA ("struct arena_s {\n");
#define OO(x) (ut64)(arena + r_offsetof (arena_t, x))
		PRINTF_BA ("  ind = 0x%x\n", ar->ind);
		PRINTF_BA ("  nthreads: application allocation = 0x%"PFMT64x"\n", (ut64)ar->nthreads[0]);
		PRINTF_BA ("  nthreads: internal metadata allocation = 0x%"PFMT64x"\n", (ut64)ar->nthreads[1]);
		PRINTF_BA ("  lock = 0x%"PFMT64x"\n", OO(lock));
		PRINTF_BA ("  stats = 0x%"PFMT64x"\n", OO(stats));
		PRINTF_BA ("  tcache_ql = 0x%"PFMT64x"\n", OO(tcache_ql));
		PRINTF_BA ("  prof_accumbytes = 0x%"PFMT64x"x\n", (ut64)ar->prof_accumbytes);
		PRINTF_BA ("  offset_state = 0x%"PFMT64x"\n", (ut64)ar->offset_state);
		PRINTF_BA ("  dss_prec_t = 0x%"PFMT64x"\n",OO(dss_prec));
		PRINTF_BA ("  achunks = 0x%"PFMT64x"\n", OO(achunks));
		PRINTF_BA ("  extent_sn_next = 0x%"PFMT64x"\n", (ut64)(size_t)ar->extent_sn_next);
		PRINTF_BA ("  spare = 0x%"PFMT64x"\n", (ut64)(size_t)ar->spare);
		PRINTF_BA ("  lg_dirty_mult = 0x%"PFMT64x"\n", (ut64)(ssize_t)ar->lg_dirty_mult);
		PRINTF_BA ("  purging = %s\n", r_str_bool (ar->purging));
		PRINTF_BA ("  nactive = 0x%"PFMT64x"\n", (ut64)(size_t)ar->nactive);
		PRINTF_BA ("  ndirty = 0x%"PFMT64x"\n", (ut64)(size_t)ar->ndirty);

		PRINTF_BA ("  runs_dirty = 0x%"PFMT64x"\n", OO(runs_dirty));
		PRINTF_BA ("  chunks_cache = 0x%"PFMT64x"\n", OO(chunks_cache));
		PRINTF_BA ("  huge = 0x%"PFMT64x"\n", OO(huge));
		PRINTF_BA ("  huge_mtx = 0x%"PFMT64x"\n", OO(huge_mtx));

		PRINTF_BA ("  chunks_szsnad_cached = 0x%"PFMT64x"\n", OO(chunks_szsnad_cached));
		PRINTF_BA ("  chunks_ad_cached = 0x%"PFMT64x"\n", OO(chunks_ad_cached));
		PRINTF_BA ("  chunks_szsnad_retained = 0x%"PFMT64x"\n", OO(chunks_szsnad_retained));
		PRINTF_BA ("  chunks_ad_cached = 0x%"PFMT64x"\n", OO(chunks_ad_retained));

		PRINTF_BA ("  chunks_mtx = 0x%"PFMT64x"\n", OO(chunks_mtx));
		PRINTF_BA ("  node_cache = 0x%"PFMT64x"\n", OO(node_cache));
		PRINTF_BA ("  node_cache_mtx = 0x%"PFMT64x"\n", OO(node_cache_mtx));
		PRINTF_BA ("  chunks_hooks = 0x%"PFMT64x"\n", OO(chunk_hooks));
		PRINTF_BA ("  bins = %d 0x%"PFMT64x"\n", JM_NBINS, OO(bins));
		PRINTF_BA ("  runs_avail = %d 0x%"PFMT64x"\n", NPSIZES, OO(runs_avail));
		PRINT_GA ("}\n");
		break;
	}
	free (ar);
	free (stats);
}

static void GH(jemalloc_get_bins)(RCore *core, const char *input) {
	int i = 0, j;
	ut64 bin_info;
	ut64 arenas;
	GHT arena = GHT_MAX; //, bin = GHT_MAX;
	arena_t *ar = NULL;
	arena_bin_info_t *b = NULL;
	RConsPrintablePalette *pal = &r_cons_singleton ()->context->pal;

	switch (input[0]) {
	case ' ':
		ar = R_NEW0 (arena_t);
		if (!ar) {
			break;
		}
		b = R_NEW0 (arena_bin_info_t);
		if (!b) {
			break;
		}
		if (!GH(r_resolve_jemalloc)(core, "je_arena_bin_info", &bin_info)) {
			eprintf ("Error resolving je_arena_bin_info\n");
			R_FREE (b);
			break;
		}
		if (GH(r_resolve_jemalloc)(core, "je_arenas", &arenas)) {
			r_io_read_at (core->io, arenas, (ut8 *)&arenas, sizeof (GHT));
			PRINTF_GA ("arenas @ 0x%"PFMTx" {\n", (GHT)arenas);
			for (;;) {
				r_io_read_at (core->io, arenas + i * sizeof (GHT), (ut8 *)&arena, sizeof (GHT));
				if (!arena) {
					R_FREE (b);
					break;
				}
				PRINTF_YA ("   arenas[%d]: ", i++);
				PRINTF_BA ("@ 0x%"PFMTx, (GHT)arena);
				PRINT_YA (" {\n");
				r_io_read_at (core->io, arena, (ut8 *)ar, sizeof (arena_t));
				for (j = 0; j < JM_NBINS; j++) {
					r_io_read_at (core->io, (GHT)(bin_info + j * sizeof (arena_bin_info_t)),
						(ut8*)b, sizeof (arena_bin_info_t));
					PRINT_YA ("    {\n");
					PRINT_YA ("       regsize : ");
					PRINTF_BA ("0x%zx\n", b->reg_size);
					PRINT_YA ("       redzone size ");
					PRINTF_BA ("0x%zx\n", b->redzone_size);
					PRINT_YA ("       reg_interval : ");
					PRINTF_BA ("0x%zx\n", b->reg_interval);
					PRINT_YA ("       run_size : ");
					PRINTF_BA ("0x%zx\n", b->run_size);
					PRINT_YA ("       nregs : ");
					PRINTF_BA ("0x%x\n", b->nregs);
					// FIXME: It's a structure of bitmap_info_t
					//PRINT_YA ("       bitmap_info : ");
					//PRINTF_BA ("0x%"PFMT64x"\n", b->bitmap_info);
					PRINT_YA ("       reg0_offset : ");
					PRINTF_BA ("0x%"PFMT64x"\n\n", (ut64)b->reg0_offset);
					// FIXME: It's a structure of malloc_mutex_t
					//PRINTF_YA ("       bins[%d]->lock ", j);
					//PRINTF_BA ("= 0x%"PFMT64x"\n", ar->bins[j].lock);
					// FIXME: It's a structure of arena_run_t*
					//PRINTF_YA ("       bins[%d]->runcur ", j);
					//PRINTF_BA ("@ 0x%"PFMT64x"\n", ar->bins[j].runcur);
					// FIXME: It's a structure of arena_run_heap_t*
					//PRINTF_YA ("       bins[%d]->runs ", j);
					//PRINTF_BA ("@ 0x%"PFMTx"\n", ar->bins[j].runs);
					// FIXME: It's a structure of malloc_bin_stats_t
					//PRINTF_YA ("       bins[%d]->stats ", j);
					//PRINTF_BA ("= 0x%"PFMTx"\n", ar->bins[j].stats);
					PRINT_YA ("    }\n");
				}
				PRINT_YA ("  }\n");
			}
		}
		PRINT_GA ("}\n");
		break;
	}
	free (ar);
	free (b);
}

#if 0
static void GH(jemalloc_get_runs)(RCore *core, const char *input) {
	switch (input[0]) {
	case ' ':
		{
			int pageind;
			ut64 npages, chunksize_mask, map_bias, map_misc_offset, chunk, mapbits;;
			arena_chunk_t *c = R_NEW0 (arena_chunk_t);

			if (!c) {
				eprintf ("Error calling calloc\n");
				return;
			}

			input += 1;
			chunk = r_num_math (core->num, input);

			if (!GH(r_resolve_jemalloc)(core, "je_chunk_npages", &npages)) {
				eprintf ("Error resolving je_chunk_npages\n");
				return;
			}
			if (!GH(r_resolve_jemalloc)(core, "je_chunksize_mask", &chunksize_mask)) {
				eprintf ("Error resolving je_chunksize_mask\n");
				return;
			}
			if (!GH(r_resolve_jemalloc)(core, "je_map_bias", &map_bias)) {
				eprintf ("Error resolving je_map_bias");
				return;
			}
			if (!GH(r_resolve_jemalloc)(core, "je_map_misc_offset", &map_misc_offset)) {
				eprintf ("Error resolving je_map_misc_offset");
				return;
			}

			r_io_read_at (core->io, npages, (ut8*)&npages, sizeof (GHT));
			r_io_read_at (core->io, chunksize_mask, (ut8*)&chunksize_mask, sizeof (GHT));
			r_io_read_at (core->io, map_bias, (ut8*)&map_bias, sizeof (GHT));
			r_io_read_at (core->io, map_misc_offset, (ut8*)&map_misc_offset, sizeof (GHT));

			eprintf ("map_misc_offset 0x%08"PFMT64x"\n", (ut64)map_misc_offset);

			r_io_read_at (core->io, chunk, (ut8 *)c, sizeof (arena_chunk_t));
			mapbits = *(GHT *)&c->map_bits;
			eprintf ("map_bits: 0x%08"PFMT64x"\n", (ut64)mapbits);

			uint32_t offset = r_offsetof (arena_chunk_t, map_bits);

			arena_chunk_map_bits_t *dwords = (void *)calloc (sizeof (arena_chunk_map_bits_t), npages);
			r_io_read_at (core->io, chunk + offset, (ut8*)dwords, sizeof (arena_chunk_map_bits_t) * npages);
			eprintf ("map_bits @ 0x%08"PFMT64x"\n", (ut64)(chunk + offset));

			arena_run_t *r = R_NEW0 (arena_run_t);
			if (!r) {
				eprintf ("Error calling calloc\n");
				return;
			}
			for (pageind = map_bias; pageind < npages; pageind++) {
				arena_chunk_map_bits_t mapelm = dwords[pageind-map_bias];
				if (mapelm.bits & CHUNK_MAP_ALLOCATED) {
					// ut64 elm = ((arena_chunk_map_misc_t *)((uintptr_t)chunk + (uintptr_t)map_misc_offset) + pageind-map_bias);
					ut64 elm = chunk + map_misc_offset + pageind-map_bias;
					eprintf ("\nelm: 0x%"PFMT64x"\n", elm);
					arena_chunk_map_misc_t *m = R_NEW0 (arena_chunk_map_misc_t);
					if (m) {
						ut64 run = elm + r_offsetof (arena_chunk_map_misc_t, run);
						r_io_read_at (core->io, elm, (ut8*)m, sizeof (arena_chunk_map_misc_t));
						eprintf ("Small run @ 0x%08"PFMT64x"\n", (ut64)elm);
						r_io_read_at (core->io, run, (ut8*)r, sizeof (arena_run_t));
						eprintf ("binind: 0x%08"PFMT64x"\n", (ut64)r->binind);
						eprintf ("nfree: 0x%08"PFMT64x"\n", (ut64)r->nfree);
						eprintf ("bitmap: 0x%08"PFMT64x"\n\n", (ut64)*(GHT*)r->bitmap);
						free (m);
					}
				} else if (mapelm.bits & CHUNK_MAP_LARGE) {
					ut64 run = (ut64) (size_t) chunk + (pageind << LG_PAGE);
					eprintf ("Large run @ 0x%08"PFMT64x"\n", run);
					r_io_read_at (core->io, run, (ut8*)r, sizeof (arena_run_t));
					eprintf ("binind: 0x%08"PFMT64x"\n", (ut64)r->binind);
					eprintf ("nfree: 0x%08"PFMT64x"\n", (ut64)r->nfree);
					eprintf ("bitmap: 0x%08"PFMT64x"\n\n", (ut64)*(GHT*)r->bitmap);
				}
			}
			free (c);
			free (r);
         	}
	break;
	}
}
#endif

static int GH(cmd_dbg_map_jemalloc)(RCore *core, const char *input) {
	const char *help_msg[] = {
		"Usage:", "dmh", " # Memory map heap",
		"dmha", "[arena_t]", "show all arenas created, or print arena_t structure for given arena",
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

