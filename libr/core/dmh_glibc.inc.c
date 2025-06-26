/* radare2 - LGPL - Copyright 2016-2025 - n4x0r, soez, pancake */

#if R_INCLUDE_BEGIN
// https://levelup.gitconnected.com/understand-heap-memory-allocation-a-hands-on-approach-775151caf2ea
// https://github.com/bminor/glibc/blob/glibc-2.28/malloc/malloc.c#L1658
#ifndef INCLUDE_HEAP_GLIBC_C
#define INCLUDE_HEAP_GLIBC_C
#include "r_config.h"
#define HEAP32 1
#include "dmh_glibc.inc.c"
#undef HEAP32
#endif

#undef GH
#undef GHT
#undef GHT_MAX
#undef read_le

#if HEAP32
#define GH(x) x##_32
#define GHT ut32
#define GHT_MAX UT32_MAX
#define read_le(x) r_read_le##32(x)
#else
#define GH(x) x##_64
#define GHT ut64
#define GHT_MAX UT64_MAX
#define read_le(x) r_read_le##64(x)
#endif

/**
 * \brief Find the address of a given symbol
 * \param core RCore Pointer to the r2's core
 * \param path Pointer to the binary path in which to look for the symbol
 * \param sym_name Pointer to the symbol's name to search for
 * \return address
 *
 * Used to find the address of a given symbol inside a binary
 *
 * TODO: Stop using deprecated functions like r_bin_cur
 */
static GHT GH(get_va_symbol)(RCore *core, const char *path, const char *sym_name) {
	GHT vaddr = GHT_MAX;
	RBin *bin = core->bin;
	RBinFile *bf = r_bin_cur (bin);

	RBinFileOptions opt;
	r_bin_file_options_init (&opt, -1, 0, 0, false);
	if (r_bin_open (bin, path, &opt)) {
		RVecRBinSymbol *syms = r_bin_get_symbols_vec (bin);
		RBinSymbol *s;
		R_VEC_FOREACH (syms, s) {
			const char *sname = r_bin_name_tostring (s->name);
			if (!strcmp (sname, sym_name)) {
				vaddr = s->vaddr;
				break;
			}
		}
		RBinFile *libc_bf = r_bin_cur (bin);
		r_bin_file_delete (bin, libc_bf->id);
		r_bin_file_set_cur_binfile (bin, bf);
	}
	return vaddr;
}

static inline GHT GH(align_address_to_size)(ut64 addr, ut64 align) {
	return addr + ((align - (addr % align)) % align);
}

static inline GHT GH(get_next_pointer)(RCore *core, GHT pos, GHT next) {
	return (core->dbg->glibc_version < 232) ? next : PROTECT_PTR (pos, next);
}

static GHT GH(get_main_arena_offset_with_symbol)(RCore *core, const char *libc_filename) {
	GHT vaddr = GHT_MAX;
	if (libc_filename && r_file_exists (libc_filename)) {
		vaddr = GH (get_va_symbol)(core, libc_filename, "main_arena");
		if (vaddr != GHT_MAX) {
			R_LOG_INFO("Found main_arena with symbol");
		}
	}
	return vaddr;
}

static GH(section_content) GH(get_section_content)(RCore *core, const char *path, const char *section_name) {
	RBin *bin = core->bin;
	RBinFile *bf = r_bin_cur (bin);
	bool found_section = false;
	GHT paddr;
	GH(section_content) content = {.size = GHT_MAX, .buf = NULL};

	RBinFileOptions opt;
	r_bin_file_options_init (&opt, -1, 0, 0, false);
	if (!r_bin_open (bin, path, &opt)) {
		R_LOG_ERROR ("get_section_content: r_bin_open failed on path %s", path);
		return content;
	}

	RBinFile *libc_bf = r_bin_cur (bin);
	RList *sections = r_bin_get_sections (bin);
	RBinSection *section;
	RListIter *iter;

	r_list_foreach (sections, iter, section) {
		if (!strcmp (section->name, section_name)) {
			found_section = true;
			paddr = section->paddr;
			content.size = section->size;
			break;
		}
	}

	if (!found_section) {
		R_LOG_WARN ("get_section_content: section %s not found", section_name);
		goto cleanup_exit;
	}

	// eprintf ("get_section_bytes: section found: %s content.size: %#08x  paddr: %#08x\n", section_name, content.size, paddr);
	content.buf = calloc (content.size, 1);
	if (!content.buf) {
		R_LOG_ERROR ("get_section_content: calloc failed");
		goto cleanup_exit;
	}

	st64 read_size = r_buf_read_at (libc_bf->buf, paddr, content.buf, content.size);

	if (read_size != content.size) {
		R_LOG_ERROR ("get_section_content: section read unexpected content.size: %#08x  (section->size: %d)", read_size, content.size);
		free (content.buf);
		content.buf = NULL;
	}

cleanup_exit:
	r_bin_file_delete (bin, libc_bf->id);
	if (bf) {
		r_bin_file_set_cur_binfile (bin, bf);
	}
	return content;
}

R_API double GH(get_glibc_version)(RCore *core, const char *libc_path) {
	double version = 0.0;

	// First see if there is a "__libc_version" symbol
	// If yes read version from there
	GHT version_symbol = GH (get_va_symbol) (core, libc_path, "__libc_version");
	if (version_symbol != GHT_MAX) {
		FILE *libc_file = fopen (libc_path, "rb");
		if (libc_file == NULL) {
			R_LOG_WARN ("resolve_glibc_version: Failed to open %s", libc_path);
			return false;
		}
		// TODO: futureproof this
		char version_buffer[5] = {0};
		fseek (libc_file, version_symbol, SEEK_SET);
		if (fread (version_buffer, 1, 4, libc_file) != 4)	{
			R_LOG_WARN ("resolve_glibc_version: Failed to read 4 bytes of version symbol");
			return false;
		};

		fclose (libc_file);
		if (!r_regex_match ("\\d.\\d\\d", "e", version_buffer)) {
			R_LOG_WARN ("resolve_glibc_version: Unexpected version format: %s", version_buffer);
			return false;
		}
		version = strtod (version_buffer, NULL);
		R_LOG_INFO ("libc version %.2f identified from symbol", version);
		return version;
	}

	// Next up we try to read version from banner in .rodata section
	// also inspired by pwndbg
	GH(section_content)  rodata = GH (get_section_content) (core, libc_path, ".rodata");

	const ut8 *banner_start = NULL;
	if (rodata.buf != NULL) {
		banner_start = r_mem_mem (rodata.buf, rodata.size, (const ut8 *)"GNU C Library", strlen ("GNU C Library"));
	}
	if (banner_start != NULL) {
		RRegex *rx = r_regex_new ("release version (\\d.\\d\\d)", "en");
		RList *matches = r_regex_match_list (rx, (const char *)banner_start);
		// We only care about the first match
		const char *first_match = r_list_first (matches);
		if (first_match)	{
			const char *version_start = first_match + strlen ("release version ");
			version = strtod (version_start, NULL);
		}
		r_list_free (matches);
		r_regex_free (rx);
	}
	free (rodata.buf);
	if (version != 0) {
		R_LOG_INFO ("libc version %.2f identified from .rodata banner", version);
		return version;
	}

	R_LOG_WARN ("get_glibc_version failed");
	return version;
}

static const char* GH(get_libc_filename_from_maps)(RCore *core) {
	R_RETURN_VAL_IF_FAIL (core && core->dbg && core->dbg->maps && core->bin && core->bin->file, NULL);
	RListIter *iter;
	RDebugMap *map = NULL;

	r_debug_map_sync (core->dbg);

	// Search for binary in memory maps named *libc-* or *libc.*  *libc6_* or similiar
	// TODO: This is very brittle, other bin names or LD_PRELOAD could be a problem
	r_list_foreach (core->dbg->maps, iter, map) {
		if (!map->name || r_str_startswith (core->bin->file, map->name)) {
			continue;
		}
		if (r_regex_match (".*libc6?[-_\\.]", "e", r_file_basename(map->name))) {
			r_config_set (core->config, "dbg.glibc.path", map->file);
			return map->file;
		}
	}
	return NULL;
}

// TODO: more options to get libc filename
static const char* GH(get_libc_filename)(RCore *core) {
	const char *dbg_glibc_path = r_config_get (core->config, "dbg.glibc.path");
	if (!R_STR_ISEMPTY (dbg_glibc_path)) {
		return dbg_glibc_path;
	}
	return GH(get_libc_filename_from_maps) (core);
}

static bool GH(resolve_glibc_version)(RCore *core) {
	R_RETURN_VAL_IF_FAIL (core && core->dbg && core->dbg->maps, false);

	double version = 0;

	if (core->dbg->glibc_version_resolved) {
		return true;
	}

	const char *dbg_glibc_version = r_config_get (core->config, "dbg.glibc.version");
	if (R_STR_ISEMPTY (dbg_glibc_version)) {
		dbg_glibc_version = NULL;
	}

	if (dbg_glibc_version)	{
		// TODO: use ^ and $ which appear to be broken
		if (r_regex_match ("\\d.\\d\\d", "e", dbg_glibc_version)) {
			version = strtod (dbg_glibc_version, NULL);
			core->dbg->glibc_version = (int) round ((version * 100));
			core->dbg->glibc_version_d = version;
			core->dbg->glibc_version_resolved = true;
			R_LOG_INFO ("libc version %.2f set from dbg.glibc.version", core->dbg->glibc_version_d);
			return true;
		}
		R_LOG_WARN ("resolve_glibc_version: Unexpected version format in dbg.glibc.version: %s"
			" (expected format \"\\d.\\d\\d\")", dbg_glibc_version);
	}

	const char *libc_filename = GH(get_libc_filename_from_maps) (core);
	if (!libc_filename) {
		R_LOG_WARN ("resolve_glibc_version: no libc found in maps (static binary?)");
		return false;
	}
	// At this point we found a map in memory that _should_ be libc
	version = GH (get_glibc_version) (core, libc_filename);
	if (version != 0) {
		core->dbg->glibc_version = (int) round ((version * 100));
		core->dbg->glibc_version_d = version;
		core->dbg->glibc_version_resolved = true;
		char *s = r_str_newf ("%.2f", version);
		r_config_set (core->config, "dbg.glibc.version", s);
		free (s);
		return true;
	}

	R_LOG_WARN ("Unknown version of libc");
	return false;
}

static bool GH(is_tcache)(RCore *core) {
	if (!r_config_get_b (core->config, "cfg.debug")) {
		return r_config_get_b (core->config, "dbg.glibc.tcache");
	}
	if (core->dbg->glibc_version_resolved || GH (resolve_glibc_version) (core))	{
		return core->dbg->glibc_version_d > 2.25;
	}
	R_LOG_WARN ("is_tcache: glibc_version could not be resolved");
	return false;
}

static GHT GH(tcache_chunk_size)(RCore *core, GHT brk_start) {
	GH (RHeapChunk) *cnk = R_NEW0 (GH (RHeapChunk));
	r_io_read_at (core->io, brk_start, (ut8 *)cnk, sizeof (GH (RHeapChunk)));
	return (cnk->size >> 3) << 3; // clear chunk flag
}

static void GH(update_arena_with_tc)(GH(RHeap_MallocState_227) *cmain_arena, MallocState *main_arena) {
	int i = 0;
	main_arena->mutex = cmain_arena->mutex;
	main_arena->flags = cmain_arena->flags;
	for (i = 0; i < BINMAPSIZE; i++) {
		main_arena->binmap[i] = cmain_arena->binmap[i];
	}
	main_arena->have_fast_chunks = cmain_arena->have_fast_chunks;
	main_arena->attached_threads = cmain_arena->attached_threads;
	for (i = 0; i < NFASTBINS; i++) {
		main_arena->GH (fastbinsY)[i] = cmain_arena->fastbinsY[i];
	}
	main_arena->GH (top) = cmain_arena->top;
	main_arena->GH (last_remainder) = cmain_arena->last_remainder;
	for (i = 0; i < NBINS * 2 - 2; i++) {
		main_arena->GH (bins)[i] = cmain_arena->bins[i];
	}
	main_arena->GH(next) = cmain_arena->next;
	main_arena->GH(next_free) = cmain_arena->next_free;
	main_arena->GH(system_mem) = cmain_arena->system_mem;
	main_arena->GH(max_system_mem) = cmain_arena->max_system_mem;
}

static void GH(update_arena_without_tc)(GH(RHeap_MallocState_223) *cmain_arena, MallocState *main_arena) {
	size_t i = 0;
	main_arena->mutex = cmain_arena->mutex;
	main_arena->flags = cmain_arena->flags;
	for (i = 0; i < BINMAPSIZE; i++) {
		main_arena->binmap[i] = cmain_arena->binmap[i];
	}
	main_arena->attached_threads = 1;
	for (i = 0; i < NFASTBINS; i++) {
		main_arena->GH(fastbinsY)[i] = cmain_arena->fastbinsY[i];
	}
	main_arena->GH(top) = cmain_arena->top;
	main_arena->GH(last_remainder) = cmain_arena->last_remainder;
	for (i = 0; i < NBINS * 2 - 2; i++) {
		main_arena->GH(bins)[i] = cmain_arena->bins[i];
	}
	main_arena->GH(next) = cmain_arena->next;
	main_arena->GH(next_free) = cmain_arena->next_free;
	main_arena->GH(system_mem) = cmain_arena->system_mem;
	main_arena->GH(max_system_mem) = cmain_arena->max_system_mem;
}

static bool GH(update_main_arena)(RCore *core, GHT m_arena, MallocState *main_arena) {
	const bool tcache = r_config_get_b (core->config, "dbg.glibc.tcache");
	if (tcache) {
		GH(RHeap_MallocState_227) *cmain_arena = R_NEW0 (GH(RHeap_MallocState_227));
		if (!r_io_read_at (core->io, m_arena, (ut8 *)cmain_arena, sizeof (GH(RHeap_MallocState_227)))) {
			R_LOG_ERROR ("Cannot read");
			return false;
		}
		GH(update_arena_with_tc)(cmain_arena, main_arena);
	} else {
		GH(RHeap_MallocState_223) *cmain_arena = R_NEW0 (GH(RHeap_MallocState_223));
		if (!r_io_read_at (core->io, m_arena, (ut8 *)cmain_arena, sizeof (GH(RHeap_MallocState_223)))) {
			R_LOG_ERROR ("Cannot read");
			return false;
		}
		GH(update_arena_without_tc)(cmain_arena, main_arena);
	}
	return true;
}

static void GH(get_brks)(RCore *core, GHT *brk_start, GHT *brk_end) {
	if (r_config_get_b (core->config, "cfg.debug")) {
		RListIter *iter;
		RDebugMap *map;
		r_debug_map_sync (core->dbg);
		r_list_foreach (core->dbg->maps, iter, map) {
			if (map->name && strstr (map->name, "[heap]")) {
				*brk_start = map->addr;
				*brk_end = map->addr_end;
				break;
			}
		}
	}
	// coredump
	RIOBank *bank = r_io_bank_get (core->io, core->io->bank);
	if (!bank) {
		return;
	}
	RIOMapRef *mapref;
	RListIter *iter;
	r_list_foreach (bank->maprefs, iter, mapref) {
		RIOMap *map = r_io_map_get (core->io, mapref->id);
		if (map->name) {
			if (strstr (map->name, "[heap]")) {
				*brk_start = r_io_map_begin (map);
				*brk_end = r_io_map_end (map);
				break;
			}
		}
	}
}

static void GH(print_arena_stats)(RCore *core, GHT m_arena, MallocState *main_arena, GHT global_max_fast, int format) {
	size_t i, j, k, start;
	GHT align = 12 * SZ + sizeof (int) * 2;
	const bool tcache = r_config_get_b (core->config, "dbg.glibc.tcache");
	RConsPrintablePalette *pal = &core->cons->context->pal;

	if (tcache) {
		align = 16;
	}

	GHT apart[NSMALLBINS + 1] = { 0LL };
	if (format == '*') {
		for (i = 0; i < NBINS * 2 - 2; i += 2) {
			GHT addr = m_arena + align + SZ * i - SZ * 2;
			GHT bina = main_arena->GH(bins)[i];
			r_cons_printf (core->cons, "f chunk.%zu.bin=0x%"PFMT64x"\n", i, (ut64)addr);
			r_cons_printf (core->cons, "f chunk.%zu.fd=0x%"PFMT64x"\n", i, (ut64)bina);
			bina = main_arena->GH(bins)[i + 1];
			r_cons_printf (core->cons, "f chunk.%zu.bk=0x%"PFMT64x"\n", i, (ut64)bina);
		}
		for (i = 0; i < BINMAPSIZE; i++) {
			r_cons_printf (core->cons, "f binmap.%zu=0x%"PFMT64x, i, (ut64)main_arena->binmap[i]);
		}
		{	/* maybe use SDB instead of flags for this? */
			char units[8];
			r_num_units (units, sizeof (units), main_arena->GH(max_system_mem));
			r_cons_printf (core->cons, "f heap.maxmem=%s\n", units);

			r_num_units (units, sizeof (units), main_arena->GH(system_mem));
			r_cons_printf (core->cons, "f heap.sysmem=%s\n", units);

			r_num_units (units, sizeof (units), main_arena->GH(next_free));
			r_cons_printf (core->cons, "f heap.nextfree=%s\n", units);

			r_num_units (units, sizeof (units), main_arena->GH(next));
			r_cons_printf (core->cons, "f heap.next=%s\n", units);
		}
		return;
	}

	PRINT_GA ("malloc_state @ ");
	PRINTF_BA ("0x%"PFMT64x"\n\n", (ut64)m_arena);
	PRINT_GA ("struct malloc_state main_arena {\n");
	PRINT_GA ("  mutex = ");
	PRINTF_BA ("0x%08x\n", (ut32)main_arena->mutex);
	PRINT_GA ("  flags = ");
	PRINTF_BA ("0x%08x\n", (ut32)main_arena->flags);
	PRINT_GA ("  fastbinsY = {\n");

	for (i = 0, j = 1, k = SZ * 4; i < NFASTBINS; i++, j++, k += SZ * 2) {
		if (FASTBIN_IDX_TO_SIZE (j) <= global_max_fast) {
			PRINTF_YA (" Fastbin %02zu\n", j);
		} else {
			PRINTF_RA (" Fastbin %02zu\n", j);
		}
		PRINT_GA (" chunksize:");
		PRINTF_BA (" == %04zu ", k);
		PRINTF_GA ("0x%"PFMT64x, (ut64)main_arena->GH(fastbinsY)[i]);
		PRINT_GA (",\n");
	}
	PRINT_GA ("}\n");
	PRINT_GA ("  top = ");
	PRINTF_BA ("0x%"PFMT64x, (ut64)main_arena->GH(top));
	PRINT_GA (",\n");
	PRINT_GA ("  last_remainder = ");
	PRINTF_BA ("0x%"PFMT64x, (ut64)main_arena->GH(last_remainder));
	PRINT_GA (",\n");
	PRINT_GA ("  bins {\n");

	/* Index & size for largebins */
	start = SZ * 128;
	for (i = start, k = 0, j = 0; j < NBINS - 2 && i < 1024 * 1024; i += 64) {
		j = largebin_index (i);
		if (j == k + NSMALLBINS + 1) {
			apart[k++] = i;
		}
	}
	for (i = 0, j = 1, k = SZ * 4; i < NBINS * 2 - 2; i += 2, j++) {
		PRINTF_YA (" Bin %03zu: ", j);
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
			PRINTF_BA (" == %06zu  ", k);
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
				PRINTF_BA (" >= %06"PFMT64d"  ", (ut64)apart[j - NSMALLBINS - 1]);
			} else {
				PRINT_BA (" remaining ");
			}
		}
		GHT bin = m_arena + align + SZ * i - SZ * 2;
		PRINTF_GA ("0x%"PFMT64x"->fd = ", (ut64)bin);
		PRINTF_BA ("0x%"PFMT64x, (ut64)main_arena->GH(bins)[i]);
		PRINT_GA (", ");
		PRINTF_GA ("0x%"PFMT64x"->bk = ", (ut64)bin);
		PRINTF_BA ("0x%"PFMT64x, (ut64)main_arena->GH(bins)[i + 1] );
		PRINT_GA (", ");
		r_cons_newline (core->cons);
	}

	PRINT_GA ("}\n");
	PRINT_GA (" binmap = { ");

	for (i = 0; i < BINMAPSIZE; i++) {
		if (i) {
			PRINT_GA (",");
		}
		PRINTF_BA ("0x%x", (ut32)main_arena->binmap[i]);
	}
	PRINT_GA ("}\n");
	PRINT_GA ("  next = ");
	PRINTF_BA ("0x%"PFMT64x, (ut64)main_arena->GH(next));
	PRINT_GA (",\n");
	PRINT_GA ("  next_free = ");
	PRINTF_BA ("0x%"PFMT64x, (ut64)main_arena->GH(next_free));
	PRINT_GA (",\n");
	PRINT_GA ("  system_mem = ");
	PRINTF_BA ("0x%"PFMT64x, (ut64)main_arena->GH(system_mem));
	PRINT_GA (",\n");
	PRINT_GA ("  max_system_mem = ");
	PRINTF_BA ("0x%"PFMT64x, (ut64)main_arena->GH(max_system_mem));
	PRINT_GA (",\n");
	PRINT_GA ("}\n\n");
}

typedef struct GH(expected_arenas) {
	GH(RHeap_MallocState_227) expected_227;
	GH(RHeap_MallocState_223) expected_223;
	GH(RHeap_MallocState_212) expected_212;
} GH(expected_arenas_s);

static GH(expected_arenas_s) GH (get_expected_main_arena_structures ) (RCore *core, GHT addend) {
	GH(expected_arenas_s) expected_arenas = {
			.expected_227 = {.next = addend, .attached_threads = 1},
			.expected_223 = {.next = addend, .attached_threads = 1},
			.expected_212 = {.next = addend}
	};
	return expected_arenas;
}

static GHT GH (get_main_arena_offset_with_relocs) (RCore *core, const char *libc_path) {
	RBin *bin = core->bin;
	RBinFile *bf = r_bin_cur (bin);
	GHT main_arena_offset = GHT_MAX;
	RBinFileOptions opt;
	r_bin_file_options_init (&opt, -1, 0, 0, false);
	if (!r_bin_open (bin, libc_path, &opt)) {
		R_LOG_WARN ("get_main_arena_with_relocs: Failed to open libc %s", libc_path);
		return GHT_MAX;
	}
	RRBTree *relocs = r_bin_get_relocs (bin);
	if (!relocs) {
		R_LOG_WARN ("get_main_arena_with_relocs: Failed to get relocs from libc %s", libc_path);
		return GHT_MAX;
	}

	// Get .data section to limit search
	RList *section_list = r_bin_get_sections (bin);
	RListIter *iter;
	RBinSection *section;
	RBinSection *data_section = NULL;
	r_list_foreach (section_list, iter, section) {
		if (!strcmp (section->name, ".data")) {
			data_section = section;
			break;
		}
	}
	if (!data_section) {
		R_LOG_WARN ("get_main_arena_with_relocs: Failed to find .data section in %s", libc_path);
		return GHT_MAX;
	}
	GH(section_content) libc_data = GH (get_section_content)(core, libc_path, ".data");

	if (!core->dbg->glibc_version_resolved && !GH (resolve_glibc_version)(core)) {
		R_LOG_WARN("get_main_arena_offset_with_relocs: glibc_version could not be resolved");
		return GHT_MAX;
	}
	GHT next_field_offset = GHT_MAX;
	GHT malloc_state_size = GHT_MAX;

	if (core->dbg->glibc_version_d >= 2.27) {
		next_field_offset = offsetof (GH(RHeap_MallocState_227), next);
		malloc_state_size = sizeof (GH(RHeap_MallocState_227));
	} else if (core->dbg->glibc_version_d >= 2.23) {
		next_field_offset = offsetof (GH(RHeap_MallocState_223), next);
		malloc_state_size = sizeof (GH(RHeap_MallocState_223));
	} else if (core->dbg->glibc_version_d >= 2.12) {
		next_field_offset = offsetof (GH(RHeap_MallocState_212), next);
		malloc_state_size = sizeof (GH(RHeap_MallocState_212));
	} else  {
		R_LOG_WARN ("get_main_arena_offset_with_relocs: cannot handle glibc version %.2f", core->dbg->glibc_version_d);
		return GHT_MAX;
	}

	// Iterate over relocations and look for malloc_state structure
	RRBNode *node;
	RBinReloc *reloc;

	r_crbtree_foreach (relocs, node, RBinReloc, reloc) {
		// We only care about relocations in .data section
		if (reloc->vaddr - next_field_offset < data_section->vaddr ||
			reloc->vaddr > data_section->vaddr + data_section->size)
			continue;
		// If reloc->addend is the offset of main_arena, then reloc->vaddr should be the offset of main_arena.next
		if (reloc->vaddr - next_field_offset == reloc->addend)	{
			// Candidate found, to be sure compare data with expected malloc_state
			GHT search_start = reloc->addend - data_section->vaddr;
			GH(expected_arenas_s) expected_arenas = GH(get_expected_main_arena_structures) (core, reloc->addend);
			void *expected_p = NULL;

			if (core->dbg->glibc_version_d >= 2.27) {
				expected_p = (void *)&expected_arenas.expected_227;
			} else if (core->dbg->glibc_version_d >= 2.23) {
				expected_p = (void *)&expected_arenas.expected_223;
			} else if (core->dbg->glibc_version_d >= 2.12) {
				expected_p = (void *)&expected_arenas.expected_212;
			} // else checked above
			if (!memcmp (libc_data.buf + search_start, expected_p, malloc_state_size)) {
				R_LOG_INFO ("Found main_arena offset with relocations");
				main_arena_offset = reloc->addend;
				break;
			} else {
				R_LOG_WARN ("get_main_arena_offset_with_relocs: main_arena candidate did not match");
			}
		}
	}

	RBinFile *libc_bf = r_bin_cur (bin);
	r_bin_file_delete (bin, libc_bf->id);
	r_bin_file_set_cur_binfile (bin, bf);
	return main_arena_offset;
}

static bool GH(resolve_main_arena)(RCore *core, GHT *m_arena) {
	R_RETURN_VAL_IF_FAIL (core && core->dbg && core->dbg->maps, false);

	if (core->dbg->main_arena_resolved) {
		GHT dbg_glibc_main_arena = r_config_get_i (core->config, "dbg.glibc.main_arena");
		if (!dbg_glibc_main_arena) {
			R_LOG_ERROR ("core->dbg->main_arena_resolved is true but dbg.glibc.main_arena is NULL");
			return false;
		}
		*m_arena = dbg_glibc_main_arena;
		return true;
	}

	if (!GH (resolve_glibc_version) (core)) {
		R_LOG_WARN ("resolve_main_arena: Could not resolve main glibc version!");
		return false;
	}

	GHT brk_start = GHT_MAX, brk_end = GHT_MAX;
	GHT libc_addr_sta = GHT_MAX, libc_addr_end = 0;
	GHT main_arena_addr = GHT_MAX;
	GHT main_arena_offset = GHT_MAX;

	const bool in_debugger = r_config_get_b (core->config, "cfg.debug");

	if (in_debugger) {
		const char *libc_filename = GH(get_libc_filename) (core);
		if (!libc_filename)	{
			R_LOG_WARN ("resolve_main_arena: Could not resolve libc filename");
			return false;
		}

		// TODO: add test for main_arena resolution via symbol
		main_arena_offset = GH (get_main_arena_offset_with_symbol) (core, libc_filename);
		if (main_arena_offset == GHT_MAX) {
			main_arena_offset = GH (get_main_arena_offset_with_relocs) (core, libc_filename);
		}
		if (main_arena_offset == GHT_MAX) {
			R_LOG_WARN ("Could not find main_arena via symbol or relocations");
			// in this case fall back to bruteforce below
		}

		RListIter *iter;
		RDebugMap *map;
		r_debug_map_sync (core->dbg);
		r_list_foreach (core->dbg->maps, iter, map) {
			if (!strstr (map->name, libc_filename)) {
				continue;
			}
			//  main_arena_offset should be relative to libc base address e.g. first occurrence in maps
			if (main_arena_addr == GHT_MAX && main_arena_offset != GHT_MAX) {
				main_arena_addr = map->addr + main_arena_offset;
			}
			if (map->perm == R_PERM_RW) {
				libc_addr_sta = map->addr;
				libc_addr_end = map->addr_end;
				break;
			}
		}
	} else {
		// TODO: this is never hit unless libc version is set manually since it is resolved using `dm`
		RIOBank *bank = r_io_bank_get (core->io, core->io->bank);
		if (!bank) {
			return false;
		}
		RIOMapRef *mapref;
		RListIter *iter;
		r_list_foreach (bank->maprefs, iter, mapref) {
			RIOMap *map = r_io_map_get (core->io, mapref->id);
			if (map->name && strstr (map->name, "arena")) {
				libc_addr_sta = r_io_map_begin (map);
				libc_addr_end = r_io_map_end (map);
				break;
			}
		}
	}

	if (libc_addr_sta == GHT_MAX || libc_addr_end == GHT_MAX) {
		const char *cmd = r_config_get_b (core->config, "cfg.debug")? "dm": "om";
		R_LOG_WARN ("Can't find arena mapped in memory (see %s)", cmd);
		return false;
	}

	GH(get_brks) (core, &brk_start, &brk_end);
	if (brk_start == GHT_MAX || brk_end == GHT_MAX) {
		R_LOG_ERROR ("No heap section found");
		return false;
	}

	GHT addr_srch = libc_addr_sta;
	GHT heap_sz = brk_end - brk_start;
	MallocState *ta = R_NEW0 (MallocState);

	if (main_arena_addr != GHT_MAX) {
		if (!GH (update_main_arena) (core, main_arena_addr, ta)) {
			return false;
		}
		*m_arena = main_arena_addr;
		core->dbg->main_arena_resolved = true;
		r_config_set_i (core->config, "dbg.glibc.main_arena", *m_arena);
		free (ta);
		return true;
	}
	while (addr_srch < libc_addr_end) {
		if (!GH (update_main_arena) (core, addr_srch, ta)) {
			break;
		}
		if (ta->GH(top) > brk_start && ta->GH(top) < brk_end &&
			ta->GH(system_mem) == heap_sz) {
			*m_arena = addr_srch;
			free (ta);
			if (in_debugger) {
				core->dbg->main_arena_resolved = true;
			}
			r_config_set_i (core->config, "dbg.glibc.main_arena", *m_arena);
			R_LOG_WARN ("Found main_arena offset with pattern matching");
			return true;
		}
		addr_srch += sizeof (GHT);
	}
	R_LOG_WARN ("Cannot find main_arena");
	free (ta);
	return false;
}

void GH(print_heap_chunk)(RCore *core) {
	GH(RHeapChunk) *cnk = R_NEW0 (GH(RHeapChunk));
	GHT chunk = core->addr;
	RConsPrintablePalette *pal = &core->cons->context->pal;

	(void) r_io_read_at (core->io, chunk, (ut8 *)cnk, sizeof (*cnk));

	PRINT_GA ("struct malloc_chunk @ ");
	PRINTF_BA ("0x%"PFMT64x, (ut64)chunk);
	PRINT_GA (" {\n  prev_size = ");
	PRINTF_BA ("0x%"PFMT64x, (ut64)cnk->prev_size);
	PRINT_GA (",\n  size = ");
	PRINTF_BA ("0x%"PFMT64x, (ut64)cnk->size & ~(NON_MAIN_ARENA | IS_MMAPPED | PREV_INUSE));
	PRINT_GA(",\n  flags: |N:");
	PRINTF_BA("%1"PFMT64u, (ut64)(cnk->size & NON_MAIN_ARENA ) >> 2);
	PRINT_GA(" |M:");
	PRINTF_BA("%1"PFMT64u, (ut64)(cnk->size & IS_MMAPPED) >> 1);
	PRINT_GA(" |P:");
	PRINTF_BA("%1"PFMT64u, (ut64)cnk->size & PREV_INUSE);

	PRINT_GA (",\n  fd = ");
	PRINTF_BA ("0x%"PFMT64x, (ut64)cnk->fd);

	PRINT_GA (",\n  bk = ");
	PRINTF_BA ("0x%"PFMT64x, (ut64)cnk->bk);

	if (cnk->size  > SZ * 128) {
		PRINT_GA (",\n  fd-nextsize = ");
		PRINTF_BA ("0x%"PFMT64x, (ut64) cnk->fd_nextsize);
		PRINT_GA (",\n  bk-nextsize = ");
		PRINTF_BA ("0x%"PFMT64x, (ut64) cnk->bk_nextsize);
	}

	PRINT_GA (",\n}\n");
	GHT size = ((cnk->size >> 3) << 3) - SZ * 2;
	if (size > SZ * 128) {
		PRINT_GA ("chunk too big to be displayed\n");
		size = SZ * 128;
	}

	char *data = calloc (1, size);
	if (data) {
		r_io_read_at (core->io, chunk + SZ * 2, (ut8 *)data, size);
		PRINT_GA ("chunk data = \n");
		r_print_hexdump (core->print, chunk + SZ * 2, (ut8 *)data, size, SZ * 8, SZ, 1);
		free (data);
	}
	free (cnk);
}

static bool GH(is_arena)(RCore *core, GHT m_arena, GHT m_state) {
	if (m_arena == m_state) {
		return true;
	}
	MallocState *ta = R_NEW0 (MallocState);
	if (!GH(update_main_arena) (core, m_arena, ta)) {
		free (ta);
		return false;
	}
	if (ta->GH(next) == m_state) {
		free (ta);
		return true;
	}
	while (ta->GH(next) != GHT_MAX && ta->GH(next) != m_arena) {
		if (!GH(update_main_arena) (core, ta->GH(next), ta)) {
			free (ta);
			return false;
		}
		if (ta->GH(next) == m_state) {
			free (ta);
			return true;
		}
	}
	free (ta);
	return false;
}

static int GH(print_double_linked_list_bin_simple)(RCore *core, GHT bin, MallocState *main_arena, GHT brk_start) {
	GHT next = GHT_MAX;
	int ret = 1;
	GH(RHeapChunk) *cnk = R_NEW0 (GH(RHeapChunk));
	RConsPrintablePalette *pal = &core->cons->context->pal;

	if (!cnk) {
		return -1;
	}

	r_io_read_at (core->io, bin, (ut8 *)cnk, sizeof (GH(RHeapChunk)));

	PRINTF_GA ("    0x%"PFMT64x, (ut64)bin);
	if (cnk->fd != bin) {
		ret = 0;
	}
	while (cnk->fd != bin) {
		PRINTF_BA ("->fd = 0x%"PFMT64x, (ut64)cnk->fd);
		next = cnk->fd;
		if (next < brk_start || next > main_arena->GH(top)) {
			PRINT_RA ("Double linked list corrupted\n");
			free (cnk);
			return -1;
		}
		r_io_read_at (core->io, next, (ut8 *)cnk, sizeof (GH(RHeapChunk)));
	}

	PRINTF_GA ("->fd = 0x%"PFMT64x, (ut64)cnk->fd);
	next = cnk->fd;

	if (next != bin) {
		PRINT_RA ("Double linked list corrupted\n");
		free (cnk);
		return -1;
	}
	(void)r_io_read_at (core->io, next, (ut8 *)cnk, sizeof (GH(RHeapChunk)));
	PRINTF_GA ("\n    0x%"PFMT64x, (ut64)bin);

	while (cnk->bk != bin) {
		PRINTF_BA ("->bk = 0x%"PFMT64x, (ut64) cnk->bk);
		next = cnk->bk;
		if (next < brk_start || next > main_arena->GH(top)) {
			PRINT_RA ("Double linked list corrupted.\n");
			free (cnk);
			return -1;
		}
		(void)r_io_read_at (core->io, next, (ut8 *)cnk, sizeof (GH(RHeapChunk)));
	}

	PRINTF_GA ("->bk = 0x%"PFMT64x, (ut64)cnk->bk);
	free (cnk);
	return ret;
}

static int GH(print_double_linked_list_bin_graph)(RCore *core, GHT bin, MallocState *main_arena, GHT brk_start) {
	int flags = r_cons_canvas_flags (core->cons);
	RAGraph *g = r_agraph_new (r_cons_canvas_new (core->cons, 1, 1, flags));
	GHT next = GHT_MAX;
	char title[256], chunk[256];
	GH(RHeapChunk) *cnk = R_NEW0 (GH(RHeapChunk));
	RConsPrintablePalette *pal = &core->cons->context->pal;

	if (!cnk || !g) {
		free (cnk);
		r_agraph_free (g);
		return -1;
	}
	g->can->color = r_config_get_i (core->config, "scr.color");

	(void)r_io_read_at (core->io, bin, (ut8 *)cnk, sizeof (GH(RHeapChunk)));
	snprintf (title, sizeof (title) - 1, "bin @ 0x%"PFMT64x"\n", (ut64)bin);
	snprintf (chunk, sizeof (chunk) - 1, "fd: 0x%"PFMT64x"\nbk: 0x%"PFMT64x"\n",
		(ut64)cnk->fd, (ut64)cnk->bk);
	RANode *bin_node = r_agraph_add_node (g, title, chunk, NULL);
	RANode *prev_node = bin_node;

	while (cnk->bk != bin) {
		next = cnk->bk;
		if (next < brk_start || next > main_arena->GH (top)) {
			PRINT_RA ("Double linked list corrupted\n");
			free (cnk);
			free (g);
			return -1;
		}

		r_io_read_at (core->io, next, (ut8 *)cnk, sizeof (GH(RHeapChunk)));
		char *title = r_str_newf ("Chunk @ 0x%"PFMT64x"\n", (ut64)next);
		char *chunk = r_str_newf ("fd: 0x%"PFMT64x"\nbk: 0x%"PFMT64x"\n", (ut64)cnk->fd, (ut64)cnk->bk);
		RANode *next_node = r_agraph_add_node (g, title, chunk, NULL);
		free (title);
		free (chunk);
		if (!next_node) {
			break;
		}
		r_agraph_add_edge (g, prev_node, next_node, false);
		r_agraph_add_edge (g, next_node, prev_node, false);
		prev_node = next_node;
	}
	r_agraph_add_edge (g, prev_node, bin_node, false);
	r_agraph_add_edge (g, bin_node, prev_node, false);
	r_agraph_print (g, core);

	free (cnk);
	r_agraph_free (g);
	return 0;
}

static int GH(print_double_linked_list_bin)(RCore *core, MallocState *main_arena, GHT m_arena, GHT offset, GHT num_bin, int graph) {
	R_RETURN_VAL_IF_FAIL (core && core->dbg, -1);
	if (!core->dbg->maps) {
		return -1;
	}
	int ret = 0;
	GHT brk_start = GHT_MAX, brk_end = GHT_MAX, initial_brk = GHT_MAX;
	RConsPrintablePalette *pal = &core->cons->context->pal;

	if (num_bin > 126) {
		return -1;
	}
	GHT bin = main_arena->GH(bins)[num_bin];

	if (!bin) {
		return -1;
	}

	GH(get_brks) (core, &brk_start, &brk_end);
	if (brk_start == GHT_MAX || brk_end == GHT_MAX) {
		R_LOG_ERROR ("No heap section found");
		return -1;
	}

	const bool tcache = r_config_get_b (core->config, "dbg.glibc.tcache");
	if (tcache) {
		const int fc_offset = r_config_get_i (core->config, "dbg.glibc.fc_offset");
		bin = m_arena + offset + SZ * num_bin * 2 + 10 * SZ;
		initial_brk = ( (brk_start >> 12) << 12 ) + fc_offset;
	} else {
		bin = m_arena + offset + SZ * num_bin * 2 - SZ * 2;
		initial_brk = (brk_start >> 12) << 12;
	}

	if (num_bin == 0) {
		PRINT_GA ("  double linked list unsorted bin {\n");
	} else if (num_bin > 0 && num_bin < NSMALLBINS) {
		PRINT_GA ("  double linked list small bin {\n");
	} else if (num_bin >= NSMALLBINS && num_bin < NBINS - 2) {
		PRINT_GA ("  double linked list large bin {\n");
	} else {
		// ???
	}
#if 0
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
#endif
	if (graph < 2) {
		ret = GH(print_double_linked_list_bin_simple)(core, bin, main_arena, initial_brk);
	} else {
		ret = GH(print_double_linked_list_bin_graph)(core, bin,  main_arena, initial_brk);
	}
	PRINT_GA ("\n  }\n");
	return ret;
}

static void GH(print_heap_bin)(RCore *core, GHT m_arena, MallocState *main_arena, const char *input) {
	int i, j = 2;
	GHT num_bin = GHT_MAX;
	GHT offset;
	RConsPrintablePalette *pal = &core->cons->context->pal;

	const bool tcache = r_config_get_b (core->config, "dbg.glibc.tcache");
	if (tcache) {
		offset = 16;
	} else {
		offset = 12 * SZ + sizeof (int) * 2;
	}

	switch (input[0]) {
	case '\0': // dmhb
		PRINT_YA ("Bins {\n");
		for (i = 0; i < NBINS - 1; i++) {
			PRINTF_YA (" Bin %03d:\n", i + 1);
			GH(print_double_linked_list_bin) (core, main_arena, m_arena, offset, i, 0);
		}
		PRINT_YA ("\n}\n");
		break;
	case ' ': // dmhb [bin_num]
		j--; // for spaces after input
		// fallthrough
	case 'g': // dmhbg [bin_num]
		num_bin = r_num_math (core->num, input + j) - 1;
		if (num_bin > NBINS - 2) {
			R_LOG_ERROR ("0 < bin <= %d", NBINS - 1);
			break;
		}
		PRINTF_YA ("  Bin %03"PFMT64u":\n", (ut64)num_bin + 1);
		GH(print_double_linked_list_bin) (core, main_arena, m_arena, offset, num_bin, j);
		break;
	case 'j':
	default:
		// unknown subcommand
		R_LOG_ERROR ("Unknown subcommand");
		break;
	}
}

// TODO. return bool
static int GH(print_single_linked_list_bin)(RCore *core, MallocState *main_arena, GHT m_arena, GHT offset, GHT bin_num, bool demangle) {
	R_RETURN_VAL_IF_FAIL (core && core->dbg, -1);
	if (!core->dbg->maps) {
		return -1;
	}
	GHT next = GHT_MAX, brk_start = GHT_MAX, brk_end = GHT_MAX;
	RConsPrintablePalette *pal = &core->cons->context->pal;

	GH(RHeapChunk) *cnk = R_NEW0 (GH(RHeapChunk));
	if (!cnk) {
		return 0;
	}

	if (!GH(update_main_arena) (core, m_arena, main_arena)) {
		free (cnk);
		return 0;
	}

	GHT bin = main_arena->GH(fastbinsY)[bin_num];
	if (!bin) {
		free (cnk);
		return -1;
	}
	bin = m_arena + offset + SZ * bin_num;
	r_io_read_at (core->io, bin, (ut8 *)&next, SZ);

	GH(get_brks) (core, &brk_start, &brk_end);
	if (brk_start == GHT_MAX || brk_end == GHT_MAX) {
		R_LOG_ERROR ("No heap section found");
		free (cnk);
		return 0;
	}

	PRINTF_GA ("  fastbin %"PFMT64d" @ ", (ut64)bin_num + 1);
	PRINTF_GA ("0x%"PFMT64x" {\n   ", (ut64)bin);

	GHT size = main_arena->GH(top) - brk_start;

	GHT next_root = next, next_tmp = next, double_free = GHT_MAX;
	while (next && next >= brk_start && next < main_arena->GH(top)) {
		PRINTF_BA ("0x%"PFMT64x, (ut64)next);
		while (double_free == GHT_MAX && next_tmp && next_tmp >= brk_start && next_tmp <= main_arena->GH(top)) {
			r_io_read_at (core->io, next_tmp, (ut8 *)cnk, sizeof (GH(RHeapChunk)));
			next_tmp = (!demangle) ? cnk->fd : PROTECT_PTR (next_tmp, cnk->fd);
			if (cnk->prev_size > size || ((cnk->size >> 3) << 3) > size) {
				break;
			}
			if (next_root == next_tmp) {
				double_free = next_root;
				break;
			}
		}
		r_io_read_at (core->io, next, (ut8 *)cnk, sizeof (GH(RHeapChunk)));
		next = (!demangle) ? cnk->fd : PROTECT_PTR (next, cnk->fd);
		PRINTF_BA ("%s", next ? "->fd = " : "");
		if (cnk->prev_size > size || ((cnk->size >> 3) << 3) > size) {
			PRINTF_RA (" 0x%"PFMT64x, (ut64)next);
			PRINT_RA (" Linked list corrupted\n");
			PRINT_GA ("\n  }\n");
			free (cnk);
			return -1;
		}

		next_root = next_tmp = next;
		if (double_free == next) {
			PRINTF_RA ("0x%"PFMT64x, (ut64)next);
			PRINT_RA (" Double free detected\n");
			PRINT_GA ("\n  }\n");
			free (cnk);
			return -1;
		}
	}

	if (next && (next < brk_start || next >= main_arena->GH(top))) {
		PRINTF_RA ("0x%"PFMT64x, (ut64)next);
		PRINT_RA (" Linked list corrupted\n");
		PRINT_GA ("\n  }\n");
		free (cnk);
		return -1;
	}

	PRINT_GA ("\n  }\n");
	free (cnk);
	return 0;
}

void GH(print_heap_fastbin)(RCore *core, GHT m_arena, MallocState *main_arena, GHT global_max_fast, const char *input, bool demangle) {
	int i;
	GHT num_bin = GHT_MAX, offset = sizeof (int) * 2;
	const bool tcache = r_config_get_b (core->config, "dbg.glibc.tcache");
	RConsPrintablePalette *pal = &core->cons->context->pal;

	if (tcache) {
		offset = 16;
	}

	switch (input[0]) {
	case '\0': // dmhf
		if (core->addr != core->prompt_addr) {
			m_arena = core->addr;
		}
		PRINT_YA ("fastbinY {\n");
		for (i = 1; i <= NFASTBINS; i++) {
			if (FASTBIN_IDX_TO_SIZE(i) <= global_max_fast) {
				PRINTF_YA (" Fastbin %02d\n", i);
			} else {
				PRINTF_RA (" Fastbin %02d\n", i);
			}
			if (GH(print_single_linked_list_bin) (core, main_arena, m_arena, offset, i - 1, demangle)) {
				PRINT_GA ("  Empty bin");
				PRINT_BA ("  0x0\n");
			}
		}
		PRINT_YA ("}\n");
		break;
	case ' ': // dmhf [bin_num]
		num_bin = r_num_get (core->num, input) - 1;
		if (num_bin >= NFASTBINS) {
			R_LOG_ERROR ("0 < bin <= %d", NFASTBINS);
			break;
		}
		if (GH(print_single_linked_list_bin)(core, main_arena, m_arena, offset, num_bin, demangle)) {
			PRINT_GA (" Empty bin");
			PRINT_BA (" 0x0\n");
		}
		break;
	case 'j': // TODO implement json listing with PJ
	default:
		R_LOG_ERROR ("Unknown subcommand");
		break;
	}
}

static GH (RTcache)* GH (tcache_new) (RCore *core) {
	R_RETURN_VAL_IF_FAIL (core, NULL);
	GH (RTcache) *tcache = R_NEW0 (GH (RTcache));
	if (R_UNLIKELY (!tcache)) {
		return NULL;
	}
	if (core->dbg->glibc_version >= TCACHE_NEW_VERSION) {
		tcache->type = NEW;
		tcache->RHeapTcache.heap_tcache = R_NEW0 (GH (RHeapTcache));
	} else {
		tcache->type = OLD;
		tcache->RHeapTcache.heap_tcache_pre_230 = R_NEW0 (GH (RHeapTcachePre230));
	}
	return tcache;
}

static void GH (tcache_free) (GH (RTcache)* tcache) {
	R_RETURN_IF_FAIL (tcache);
	tcache->type == NEW
		? free (tcache->RHeapTcache.heap_tcache)
		: free (tcache->RHeapTcache.heap_tcache_pre_230);
	free (tcache);
}

static bool GH (tcache_read) (RCore *core, GHT tcache_start, GH (RTcache)* tcache) {
	R_RETURN_VAL_IF_FAIL (core && tcache, false);
	if ((st64)(tcache_start | UT16_MAX) <1) {
		R_LOG_ERROR ("Cannot read at 0x%08"PFMT64x, (ut64)tcache_start);
		return false;
	}
	if (!r_io_is_valid_offset (core->io, tcache_start, R_PERM_R)) {
		return false;
	}
	return tcache->type == NEW
		? r_io_read_at (core->io, tcache_start, (ut8 *)tcache->RHeapTcache.heap_tcache, sizeof (GH (RHeapTcache)))
		: r_io_read_at (core->io, tcache_start, (ut8 *)tcache->RHeapTcache.heap_tcache_pre_230, sizeof (GH (RHeapTcachePre230)));
}

static int GH (tcache_get_count) (GH (RTcache)* tcache, int index) {
	R_RETURN_VAL_IF_FAIL (tcache, 0);
	return tcache->type == NEW
		? tcache->RHeapTcache.heap_tcache->counts[index]
		: tcache->RHeapTcache.heap_tcache_pre_230->counts[index];
}

static GHT GH (tcache_get_entry) (GH (RTcache)* tcache, int index) {
	R_RETURN_VAL_IF_FAIL (tcache, 0);
	return tcache->type == NEW
		? tcache->RHeapTcache.heap_tcache->entries[index]
		: tcache->RHeapTcache.heap_tcache_pre_230->entries[index];
}

static void GH (tcache_print) (RCore *core, GH (RTcache)* tcache, bool demangle) {
	R_RETURN_IF_FAIL (core && tcache);
	GHT tcache_fd = GHT_MAX;
	GHT tcache_tmp = GHT_MAX;
	RConsPrintablePalette *pal = &core->cons->context->pal;
	size_t i;
	for (i = 0; i < TCACHE_MAX_BINS; i++) {
		int count = GH (tcache_get_count) (tcache, i);
		GHT entry = GH (tcache_get_entry) (tcache, i);
		if (entry == GHT_MAX) {
			break;
		}
		if (count > 0) {
			PRINT_GA ("bin :");
			PRINTF_BA ("%2zu", i);
			PRINT_GA (", items :");
			PRINTF_BA ("%2d", count);
			PRINT_GA (", fd :");

			PRINTF_BA ("0x%"PFMT64x, (ut64)(entry - GH (HDR_SZ)));
			if (count > 1) {
				tcache_fd = entry;
				size_t n;
				for (n = 1; n < count; n++) {
					bool r = r_io_read_at (core->io, tcache_fd, (ut8 *)&tcache_tmp, sizeof (GHT));
					if (!r) {
						break;
					}
					tcache_tmp = (!demangle)
						? read_le (&tcache_tmp)
						: PROTECT_PTR (tcache_fd, read_le (&tcache_tmp));
					PRINTF_BA ("->0x%"PFMT64x, (ut64)(tcache_tmp - TC_HDR_SZ));
					tcache_fd = tcache_tmp;
				}
			}
			PRINT_BA ("\n");
		}
	}
}

static void GH (print_tcache_instance)(RCore *core, GHT m_arena, MallocState *main_arena, bool demangle) {
	R_RETURN_IF_FAIL (core && core->dbg && core->dbg->maps);

	const bool tcache = r_config_get_b (core->config, "dbg.glibc.tcache");
	if (!tcache || m_arena == GHT_MAX) {
		return;
	}
	GHT brk_start = GHT_MAX, brk_end = GHT_MAX, initial_brk = GHT_MAX;
	GH (get_brks) (core, &brk_start, &brk_end);
	GHT tcache_start = GHT_MAX;
	RConsPrintablePalette *pal = &core->cons->context->pal;

	tcache_start = brk_start + 0x10;
	GHT fc_offset = GH (tcache_chunk_size) (core, brk_start);
	initial_brk = brk_start + fc_offset;
	if (brk_start == GHT_MAX || brk_end == GHT_MAX || initial_brk == GHT_MAX) {
		R_LOG_ERROR ("No heap section found");
		return;
	}

	GH (RTcache)* r_tcache = GH (tcache_new) (core);
	if (!r_tcache) {
		return;
	}
	if (!GH (tcache_read) (core, tcache_start, r_tcache)) {
		return;
	}

	PRINT_GA ("Tcache main arena @");
	PRINTF_BA (" 0x%"PFMT64x"\n", (ut64)m_arena);
	GH (tcache_print) (core, r_tcache, demangle);

	if (main_arena->GH (next) != m_arena) {
		GHT mmap_start = GHT_MAX, tcache_start = GHT_MAX;
		MallocState *ta = R_NEW0 (MallocState);
		if (!ta) {
			free (ta);
			GH (tcache_free) (r_tcache);
			return;
		}
		ta->GH (next) = main_arena->GH (next);
		while (GH (is_arena) (core, m_arena, ta->GH (next)) && ta->GH (next) != m_arena) {
			PRINT_YA ("Tcache thread arena @ ");
			PRINTF_BA (" 0x%"PFMT64x, (ut64)ta->GH (next));
			mmap_start = ((ta->GH (next) >> 16) << 16);
			tcache_start = mmap_start + sizeof (GH (RHeapInfo)) + sizeof (GH (RHeap_MallocState_227)) + GH (MMAP_ALIGN);

			if (!GH (update_main_arena) (core, ta->GH (next), ta)) {
				free (ta);
				GH (tcache_free) (r_tcache);
				return;
			}

			if (ta->attached_threads) {
				PRINT_BA ("\n");
				if (!GH (tcache_read) (core, tcache_start, r_tcache)) {
					break;
				}
				GH (tcache_print) (core, r_tcache, demangle);
			} else {
				PRINT_GA (" free\n");
			}
		}
	}
	GH (tcache_free) (r_tcache);
}

static void GH(print_heap_segment)(RCore *core, MallocState *main_arena,
		GHT m_arena, GHT m_state, GHT global_max_fast, int format_out) {
	R_RETURN_IF_FAIL (core && main_arena);
	if (!core->dbg || !core->dbg->maps) {
		return;
	}

	int w, h;
	GHT brk_start = GHT_MAX, brk_end = GHT_MAX, size_tmp, min_size = SZ * 4;
	GHT tcache_fd = GHT_MAX, tcache_tmp = GHT_MAX;
	GHT initial_brk = GHT_MAX, tcache_initial_brk = GHT_MAX;

	const bool tcache = r_config_get_b (core->config, "dbg.glibc.tcache");
	const int offset = r_config_get_i (core->config, "dbg.glibc.fc_offset");
	RConsPrintablePalette *pal = &core->cons->context->pal;
	int glibc_version = core->dbg->glibc_version;

	if (m_arena == m_state) {
		GH(get_brks) (core, &brk_start, &brk_end);
		if (tcache) {
			initial_brk = ((brk_start >> 12) << 12) + GH(HDR_SZ);
			if (r_config_get_b (core->config, "cfg.debug")) {
				tcache_initial_brk = initial_brk;
			}
			initial_brk += (glibc_version < 230)
				? sizeof (GH (RHeapTcachePre230))
				: sizeof (GH (RHeapTcache));
		} else {
			initial_brk = (brk_start >> 12) << 12;
		}
	} else {
		brk_start = ((m_state >> 16) << 16) ;
		brk_end = brk_start + main_arena->GH(system_mem);
		if (tcache) {
			tcache_initial_brk = brk_start + sizeof (GH(RHeapInfo)) + sizeof (GH(RHeap_MallocState_227)) + GH(MMAP_ALIGN);
			initial_brk =  tcache_initial_brk + offset;
		} else {
			initial_brk =  brk_start + sizeof (GH(RHeapInfo)) + sizeof (GH(RHeap_MallocState_223)) + MMAP_OFFSET;
		}
	}

	if (brk_start == GHT_MAX || brk_end == GHT_MAX || initial_brk == GHT_MAX) {
		R_LOG_ERROR ("No heap section");
		return;
	}

	GHT next_chunk = initial_brk, prev_chunk = next_chunk;
	GH(RHeapChunk) *cnk = R_NEW0 (GH(RHeapChunk));
	if (!cnk) {
		return;
	}
	GH(RHeapChunk) *cnk_next = R_NEW0 (GH(RHeapChunk));
	if (!cnk_next) {
		free (cnk);
		return;
	}

	RConfigHold *hc = r_config_hold_new (core->config);
	if (!hc) {
		free (cnk);
		free (cnk_next);
		return;
	}

	w = r_cons_get_size (core->cons, &h);
	int flags = r_cons_canvas_flags (core->cons);
	RConsCanvas *can = r_cons_canvas_new (core->cons, w, h, flags);
	if (!can) {
		free (cnk);
		free (cnk_next);
		r_config_hold_free (hc);
		return;
	}

	RAGraph *g = r_agraph_new (can);
	if (!g) {
		free (cnk);
		free (cnk_next);
		r_cons_canvas_free (can);
		r_config_hold_restore (hc);
		r_config_hold_free (hc);
		return;
	}

	RANode *top = {0}, *chunk_node = {0}, *prev_node = {0};
	char *node_title, *node_data;
	bool first_node = true;

	char *top_data = strdup ("");
	char *top_title = strdup ("");

	if (!r_io_read_at (core->io, next_chunk, (ut8 *)cnk, sizeof (GH(RHeapChunk)))) {
		R_LOG_ERROR ("Cannot read");
		free (cnk);
		free (cnk_next);
		r_cons_canvas_free (can);
		r_config_hold_restore (hc);
		r_config_hold_free (hc);
		return;
	}
	size_tmp = (cnk->size >> 3) << 3;
	ut64 prev_chunk_addr;
	ut64 prev_chunk_size;
	PJ *pj = NULL;

	switch (format_out) {
	case 'j':
		pj = r_core_pj_new (core);
		if (!pj) {
			return;
		}
		pj_o (pj);
		pj_ka (pj, "chunks");
		break;
	case '*':
		r_cons_printf (core->cons, "fs+heap.allocated\n");
		break;
	case 'g':
		can->linemode = r_config_get_i (core->config, "graph.linemode");
		can->color = r_config_get_i (core->config, "scr.color");
		core->cons->use_utf8 = r_config_get_i (core->config, "scr.utf8");
		g->layout = r_config_get_i (core->config, "graph.layout");
		r_agraph_set_title (g, "Heap Layout");
		top_title = r_str_newf ("Top chunk @ 0x%"PFMT64x"\n", (ut64)main_arena->GH(top));
	}

	while (next_chunk && next_chunk >= brk_start && next_chunk < main_arena->GH(top)) {
		if (size_tmp < min_size || next_chunk + size_tmp > main_arena->GH(top)) {
			const char *status = "corrupted";
			switch (format_out) {
			case 'c':
				PRINT_YA ("\n  Malloc chunk @ ");
				PRINTF_BA ("0x%"PFMT64x" ", (ut64)next_chunk);
				PRINTF_RA ("[%s]\n",status);
				PRINTF_RA ("   size: 0x%"PFMT64x"\n   fd: 0x%"PFMT64x", bk: 0x%"PFMT64x"\n",
				(ut64)cnk->size, (ut64)cnk->fd, (ut64)cnk->bk);
				break;
			case 'j':
				pj_o (pj);
				pj_kn (pj, "addr", next_chunk);
				pj_kn (pj, "size", cnk->size);
				pj_ks (pj, "status", status);
				pj_kN (pj, "fd", cnk->fd);
				pj_kN (pj, "bk", cnk->bk);
				pj_end (pj);
				break;
			case '*':
				r_cons_printf (core->cons, "fs heap.corrupted\n");
				ut64 chunkflag = (ut64)((prev_chunk >> 4) & 0xffffULL);
				r_cons_printf (core->cons, "f chunk.corrupted.%06"PFMT64x" %d 0x%"PFMT64x"\n",
					chunkflag, (int)cnk->size, (ut64)prev_chunk);
				break;
			case 'g':
				node_title = r_str_newf ("  Malloc chunk @ 0x%"PFMT64x" ", (ut64)prev_chunk);
				node_data = r_str_newf ("[corrupted] size: 0x%"PFMT64x"\n fd: 0x%"PFMT64x", bk: 0x%"PFMT64x
					"\nHeap graph could not be recovered\n", (ut64)cnk->size, (ut64)cnk->fd, (ut64)cnk->bk);
				r_agraph_add_node (g, node_title, node_data, NULL);
				if (first_node) {
					first_node = false;
				}
				break;
			}
			break;
		}

		prev_chunk_addr = (ut64)prev_chunk;
		prev_chunk_size = (((ut64)cnk->size) >> 3) << 3;

		bool fastbin = size_tmp >= SZ * 4 && size_tmp <= global_max_fast;
		bool is_free = false, double_free = false;

		if (fastbin) {
			int i = (size_tmp / (SZ * 2)) - 2;
			GHT idx = (GHT)main_arena->GH(fastbinsY)[i];
			(void)r_io_read_at (core->io, idx, (ut8 *)cnk, sizeof (GH(RHeapChunk)));
			GHT next = GH (get_next_pointer) (core, idx, cnk->fd);
			if (prev_chunk == idx && idx && !next) {
				is_free = true;
			}
			while (next && next >= brk_start && next < main_arena->GH(top)) {
				if (prev_chunk == idx || prev_chunk == next || idx == next) {
					is_free = true;
					if (idx == next) {
						double_free = true;
						break;
					}
					(void)r_io_read_at (core->io, next, (ut8 *)cnk_next, sizeof (GH(RHeapChunk)));
					GHT next_node = GH (get_next_pointer) (core, next, cnk_next->fd);
					// avoid triple while?
					while (next_node && next_node >= brk_start && next_node < main_arena->GH(top)) {
						if (prev_chunk == next_node) {
							double_free = true;
							break;
						}
						(void)r_io_read_at (core->io, next_node, (ut8 *)cnk_next, sizeof (GH(RHeapChunk)));
						next_node = GH (get_next_pointer) (core, next_node, cnk_next->fd);
					}
					if (double_free) {
						break;
					}
				}
				(void)r_io_read_at (core->io, next, (ut8 *)cnk, sizeof (GH(RHeapChunk)));
				next = GH (get_next_pointer) (core, next, cnk->fd);
			}
			if (double_free) {
				PRINT_RA (" Double free in simple-linked list detected ");
				break;
			}
			prev_chunk_size = ((i + 1) * GH(HDR_SZ)) + GH(HDR_SZ);
		}

		if (tcache) {
			GH(RTcache)* tcache_heap = GH (tcache_new) (core);
			if (!tcache_heap) {
				r_cons_canvas_free (can);
				r_config_hold_restore (hc);
				r_config_hold_free (hc);
				free (g);
				free (cnk);
				free (cnk_next);
				return;
			}
			if (!GH (tcache_read) (core, tcache_initial_brk, tcache_heap)) {
				break;
			}
			size_t i;
			for (i = 0; i < TCACHE_MAX_BINS; i++) {
				int count = GH (tcache_get_count) (tcache_heap, i);
				GHT entry = GH (tcache_get_entry) (tcache_heap, i);
				if (count > 0) {
					if (entry - SZ * 2 == prev_chunk) {
						is_free = true;
						prev_chunk_size = ((i + 1) * TC_HDR_SZ + GH(TC_SZ));
						break;
					}
					if (count > 1) {
						tcache_fd = entry;
						int n;
						for (n = 1; n < count; n++) {
							bool r = r_io_read_at (core->io, tcache_fd, (ut8*)&tcache_tmp, sizeof (GHT));
							if (!r) {
								break;
							}
							tcache_tmp = GH (get_next_pointer) (core, tcache_fd, read_le (&tcache_tmp));
							if (tcache_tmp - SZ * 2 == prev_chunk) {
								is_free = true;
								prev_chunk_size = ((i + 1) * TC_HDR_SZ + GH(TC_SZ));
								break;
							}
							tcache_fd = (ut64)tcache_tmp;
						}
					}
				}
			}
			GH (tcache_free) (tcache_heap);
		}

		next_chunk += size_tmp;
		prev_chunk = next_chunk;
		r_io_read_at (core->io, next_chunk, (ut8 *)cnk, sizeof (GH(RHeapChunk)));
		size_tmp = (cnk->size >> 3) << 3;

		const char *status = "allocated";
		if (fastbin && is_free) {
			status = "free";
		}
		if (!(cnk->size & 1)) {
			status = "free";
		}
		if (tcache && is_free) {
			status = "free";
		}

		switch (format_out) {
		case 'c':
			PRINT_YA ("\n  Malloc chunk @ ");
			PRINTF_BA ("0x%"PFMT64x" ", prev_chunk_addr);
			PRINT_GA ("[size: ");
			PRINTF_BA ("0x%"PFMT64x, prev_chunk_size);
			PRINTF_GA ("][%s]",status);
			break;
		case 'j':
			pj_o (pj);
			pj_kn (pj, "addr", prev_chunk_addr);
			pj_kn (pj, "size", prev_chunk_size);
			pj_ks (pj, "status", status);
			pj_end (pj);
			break;
		case '*':
			r_cons_printf (core->cons, "fs heap.%s\n", status);
			ut64 chunkat = (prev_chunk_addr>>4) & 0xffff;
			r_cons_printf (core->cons, "f chunk.%06"PFMT64x" %d 0x%"PFMT64x"\n", chunkat, (int)prev_chunk_size, (ut64)prev_chunk_addr);
			break;
		case 'g':
			node_title = r_str_newf ("  Malloc chunk @ 0x%"PFMT64x" ", (ut64)prev_chunk_addr);
			node_data = r_str_newf ("size: 0x%"PFMT64x" status: %s\n", (ut64)prev_chunk_size, status);
			chunk_node = r_agraph_add_node (g, node_title, node_data, NULL);
			if (first_node) {
				first_node = false;
			} else {
				r_agraph_add_edge (g, prev_node, chunk_node, false);
			}
			prev_node = chunk_node;
			break;
		}
	}

	switch (format_out) {
	case 'c':
		PRINT_YA ("\n  Top chunk @ ");
		PRINTF_BA ("0x%"PFMT64x, (ut64)main_arena->GH (top));
		PRINT_GA (" - [brk_start: ");
		PRINTF_BA ("0x%"PFMT64x, (ut64)brk_start);
		PRINT_GA (", brk_end: ");
		PRINTF_BA ("0x%"PFMT64x, (ut64)brk_end);
		PRINT_GA ("]\n");
		break;
	case 'j':
		pj_end (pj);
		pj_kn (pj, "top", main_arena->GH(top));
		pj_kn (pj, "brk", brk_start);
		pj_kn (pj, "end", brk_end);
		pj_end (pj);
		r_kons_print (core->cons, pj_string (pj));
		pj_free (pj);
		break;
	case '*':
		r_cons_printf (core->cons, "fs-\n");
		r_cons_printf (core->cons, "f heap.top = 0x%08"PFMT64x"\n", (ut64)main_arena->GH (top));
		r_cons_printf (core->cons, "f heap.brk = 0x%08"PFMT64x"\n", (ut64)brk_start);
		r_cons_printf (core->cons, "f heap.end = 0x%08"PFMT64x"\n", (ut64)brk_end);
		break;
	case 'g':
		top = r_agraph_add_node (g, top_title, top_data, NULL);
		if (!first_node) {
			r_agraph_add_edge (g, prev_node, top, false);
			free (node_data);
			free (node_title);
		}
		r_agraph_print (g, core);
		r_cons_canvas_free (can);
		r_config_hold_restore (hc);
		r_config_hold_free (hc);
		break;
	}

	r_cons_newline (core->cons);
	free (g);
	free (top_data);
	free (top_title);
	free (cnk);
	free (cnk_next);
}

void GH(print_malloc_states)( RCore *core, GHT m_arena, MallocState *main_arena) {
	MallocState *ta = R_NEW0 (MallocState);
	RConsPrintablePalette *pal = &core->cons->context->pal;

	PRINT_YA ("main_arena @ ");
	PRINTF_BA ("0x%"PFMT64x"\n", (ut64)m_arena);
	if (main_arena->GH(next) != m_arena) {
		ta->GH(next) = main_arena->GH(next);
		while (GH(is_arena) (core, m_arena, ta->GH(next)) && ta->GH(next) != m_arena) {
			PRINT_YA ("thread arena @ ");
			PRINTF_BA ("0x%"PFMT64x, (ut64)ta->GH(next));
			// if the next pointer is equal to unsigned -1 we assume its invalid
			// and return. otherwise we get undefined behavior and weird output offten
			// times with thousands of lines in the output
			// saying thread arenas are at 0xffff... which is obviously incorrect
			// related to issue #20767
			if (ta->GH(next) == GHT_MAX) {
				break;
			}
			if (!GH(update_main_arena) (core, ta->GH(next), ta)) {
				free (ta);
				return;
			}
			if (ta->attached_threads) {
				PRINT_BA ("\n");
			} else {
				PRINT_GA (" free\n");
			}
		}
	}
	free (ta);
}

void GH(print_inst_minfo)(GH(RHeapInfo) *heap_info, GHT hinfo) {
	RConsPrintablePalette *pal = &r_cons_singleton()->context->pal;

	PRINT_YA ("malloc_info @ ");
	PRINTF_BA ("0x%"PFMT64x, (ut64)hinfo);
	PRINT_YA (" {\n  ar_ptr = " );
	PRINTF_BA ("0x%"PFMT64x"\n", (ut64)heap_info->ar_ptr);
	PRINT_YA ("  prev = ");
	PRINTF_BA ("0x%"PFMT64x"\n", (ut64)heap_info->prev);
	PRINT_YA ("  size = ");
	PRINTF_BA ("0x%"PFMT64x"\n", (ut64)heap_info->size);
	PRINT_YA ("  mprotect_size = ");
	PRINTF_BA ("0x%"PFMT64x"\n", (ut64)heap_info->mprotect_size);
	PRINT_YA ("}\n\n");
}

void GH(print_malloc_info)(RCore *core, GHT m_state, GHT malloc_state) {
	GHT h_info;

	if (malloc_state == m_state) {
		R_LOG_ERROR ("main_arena does not have an instance of malloc_info");
	} else if (GH(is_arena) (core, malloc_state, m_state)) {
		h_info = (malloc_state >> 16) << 16;
		GH(RHeapInfo) *heap_info = R_NEW0 (GH(RHeapInfo));
		r_io_read_at (core->io, h_info, (ut8*)heap_info, sizeof (GH(RHeapInfo)));
		GH(print_inst_minfo) (heap_info, h_info);
		MallocState *ms = R_NEW0 (MallocState);

		while (heap_info->prev != 0x0 && heap_info->prev != GHT_MAX) {
			if (!GH(update_main_arena) (core, malloc_state, ms)) {
				free (ms);
				free (heap_info);
				return;
			}
			if ((ms->GH(top) >> 16) << 16 != h_info) {
				h_info = (ms->GH(top) >> 16) << 16;
				r_io_read_at (core->io, h_info, (ut8*)heap_info, sizeof (GH(RHeapInfo)));
				GH(print_inst_minfo) (heap_info, h_info);
			}
		}
		free (heap_info);
		free (ms);
	} else {
		R_LOG_ERROR ("This address is not part of the arenas");
	}
}

// XXX. refactor to pass all those vars all together into a single struct
static void GH(dmhg)(RCore *core, const char *input, MallocState *main_arena, GHT global_max_fast, int format) {
	GHT m_state = GHT_MAX;
	GHT m_arena = GHT_MAX;
	if (!GH(resolve_main_arena) (core, &m_arena)) {
		R_LOG_ERROR ("Cannot find the main arena");
		return;
	}
	input++;
	bool get_state = false;
	if (!*input) {
		if (core->addr != core->prompt_addr) {
			m_state = core->addr;
			get_state = true;
		}
	} else {
		m_state = r_num_math (core->num, input);
		get_state = true;
	}
	if (!get_state) {
		m_state = m_arena;
	}
	if (GH(is_arena) (core, m_arena, m_state)) {
		if (!GH(update_main_arena) (core, m_state, main_arena)) {
			return;
		}
		GH(print_heap_segment) (core, main_arena, m_arena, m_state, global_max_fast, format);
	} else {
		R_LOG_ERROR ("This address is not part of the arenas");
	}
}

static const char* GH(help_msg)[] = {
	"Usage:", " dmh", " # Memory map heap",
	"dmh", " @[malloc_state]", "List heap chunks of a particular arena",
	"dmh", "", "List the chunks inside the heap segment",
	"dmh*", "", "Display heap details as radare2 commands",
	"dmha", "", "List all malloc_state instances in application",
	"dmhb", " @[malloc_state]", "Display all parsed Double linked list of main_arena's or a particular arena bins instance",
	"dmhb", " [bin_num|bin_num:malloc_state]", "Display parsed double linked list of bins instance from a particular arena",
	"dmhbg", " [bin_num]", "Display double linked list graph of main_arena's bin [Under developemnt]",
	"dmhc", " @[chunk_addr]", "Display malloc_chunk struct for a given malloc chunk",
	"dmhf", " @[malloc_state]", "Display all parsed fastbins of main_arena's or a particular arena fastbinY instance",
	"dmhf", " [fastbin_num(:malloc_state)]", "Display single linked list in fastbinY instance from a particular arena",
	"dmhg", " [malloc_state]", "Display heap graph of a particular arena",
	"dmhg", "", "Display heap graph of heap segment",
	"dmhi", " @[malloc_state]", "Display heap_info structure/structures for a given arena",
	"dmhj", "", "List the chunks inside the heap segment in JSON format",
	"dmhm", "[*j]", "List all malloc_state instance of a particular arena (@ malloc_state#addr)",
	"dmht", "", "Display all parsed thread cache bins of all arena's tcache instance",
	NULL
};

static int GH(dmh_glibc)(RCore *core, const char *input) {
	GHT m_arena = GHT_MAX, m_state = GHT_MAX;
	GHT global_max_fast = (64 * SZ / 4);

	MallocState *main_arena = R_NEW0 (MallocState);

	int format = 'c';
	bool get_state = false;

	if (input[0] != '?') {
		// fixes d?* glitch
		r_config_set_b (core->config, "dbg.glibc.tcache", GH(is_tcache) (core));
	}
	switch (input[0]) {
	case ' ' : // dmh [malloc_state]
		m_state = r_num_get (core->num, input);
		get_state = true;
		// pass through
	case '\0': // dmh
		if (GH(resolve_main_arena) (core, &m_arena)) {
			if (core->addr != core->prompt_addr) {
				m_state = core->addr;
			} else {
				if (!get_state) {
					m_state = m_arena;
				}
			}
			if (GH(is_arena) (core, m_arena, m_state)) {
				if (!GH(update_main_arena) (core, m_state, main_arena)) {
					break;
				}
				GH(print_heap_segment) (core, main_arena, m_arena, m_state, global_max_fast, format);
				break;
			} else {
				R_LOG_ERROR ("This address is not part of any arena");
				break;
			}
		}
		break;
	case 'a': // dmha
		if (GH(resolve_main_arena) (core, &m_arena)) {
			if (!GH(update_main_arena) (core, m_arena, main_arena)) {
				break;
			}
			GH(print_malloc_states) (core, m_arena, main_arena);
		}
		break;
	case 'i': // dmhi
		if (GH(resolve_main_arena) (core, &m_arena)) {
			if (!GH(update_main_arena) (core, m_arena, main_arena)) {
				break;
			}
			input++;
			if (!*input) {
				if (core->addr != core->prompt_addr) {
					m_state = core->addr;
				}
			} else {
				m_state = r_num_get (core->num, input);
			}
			GH(print_malloc_info) (core, m_arena, m_state);
		}
		break;
	case 'm': // "dmhm"
		if (GH(resolve_main_arena) (core, &m_arena)) {
			switch (input[1]) {
			case '*':
				format = '*';
				input++;
				break;
			case 'j':
				format = 'j';
				input++;
				break;
			}
			input++;
			if (!*input) {
				if (core->addr != core->prompt_addr) {
					m_arena = core->addr;
					if (!GH (update_main_arena) (core, m_arena, main_arena)) {
						break;
					}
				} else {
					if (!GH (update_main_arena) (core, m_arena, main_arena)) {
						break;
					}
				}
			} else {
				m_arena = r_num_get (core->num, input);
				if (!GH(update_main_arena) (core, m_arena, main_arena)) {
					break;
				}
			}
			GH(print_arena_stats) (core, m_arena, main_arena, global_max_fast, format);
		}
		break;
	case 'b': // "dmhb"
		if (GH(resolve_main_arena) (core, &m_arena)) {
			const char *arg = r_str_trim_head_ro (input + 1);
			if (*arg) {
				char *sep = strchr (arg, ':');
				if (sep) {
					m_state = r_num_get (core->num, sep + 1);
				}
				if (!m_state) {
					m_state = m_arena;
				}
			} else {
				m_state = (core->addr == core->prompt_addr)
					? m_arena: core->addr;
			}
			if (GH(is_arena) (core, m_arena, m_state)) {
				if (!GH(update_main_arena) (core, m_state, main_arena)) {
					break;
				}
				GH(print_heap_bin) (core, m_state, main_arena, arg);
			} else {
				R_LOG_ERROR ("This address is not part of the arenas");
				break;
			}
		}
		break;
	case 'c': // "dmhc"
		if (GH(resolve_main_arena)(core, &m_arena)) {
			GH(print_heap_chunk) (core);
		}
		break;
	case 'f': // "dmhf"
		if (GH(resolve_main_arena) (core, &m_arena)) {
			const bool demangle = r_config_get_b (core->config, "dbg.glibc.demangle"); // XXX reuse bin.demangle
			const char *arg = r_str_trim_head_ro (input + 1);
			if (*arg) {
				char *sep = strchr (arg, ':');
				if (sep) {
					m_state = r_num_get (core->num, arg);
				}
				if (!m_state) {
					m_state = m_arena;
				}
			} else {
				if (core->addr != core->prompt_addr) {
					m_state = core->addr;
				} else {
					m_state = m_arena;
				}
			}
			if (GH(is_arena) (core, m_arena, m_state)) {
				if (!GH(update_main_arena) (core, m_state, main_arena)) {
					break;
				}
				GH(print_heap_fastbin) (core, m_state, main_arena, global_max_fast, arg, demangle);
			} else {
				R_LOG_ERROR ("This address is not part of the arenas");
				break;
			}
		}
		break;
	case 'g': // "dmhg"
	case '*': // "dmh*"
	case 'j': // "dmhj"
		GH (dmhg) (core, input, main_arena, global_max_fast, input[0]);
		break;
	case 't':
		if (GH(resolve_main_arena) (core, &m_arena)) {
			if (!GH(update_main_arena) (core, m_arena, main_arena)) {
				break;
			}
			bool demangle = r_config_get_i (core->config, "dbg.glibc.demangle");
			GH(print_tcache_instance) (core, m_arena, main_arena, demangle);
		}
		break;
	case '?':
		r_core_cmd_help (core, GH(help_msg));
		break;
	}
	free (main_arena);
	return true;
}

#endif
