/* radare2 - LGPL - Copyright 2018-2025 - pancake, mrmacete, keegan */

#include <r_core.h>
#include <sdb/ht_su.h>
// #include "../format/mach0/mach0_defines.h"
#define R_BIN_MACH064 1
#include "../format/mach0/mach0.h"
#include "objc/mach0_classes.h"
#define MAX_N_HDR 128

typedef struct {
	ut64 local_symbols_offset;
	ut64 nlists_offset;
	ut64 nlists_count;
	ut64 strings_offset;
	ut64 strings_size;
} RDyldLocSym;

typedef struct _r_dyldcache {
	cache_hdr_t *hdr;
	ut64 *hdr_offset;
	ut64 *hdr_overhead;
	ut32 *maps_index;
	ut64 *maps_flags;
	ut32 n_hdr;
	cache_map_t *maps;
	ut32 n_maps;

	RList *bins;
	HtUP *bin_by_pa;
	RBuffer *buf;
	int (*original_io_read)(RIO *io, RIODesc *fd, ut8 *buf, int count);
	cache_accel_t *accel;
	RDyldLocSym *locsym;
	objc_cache_opt_info *oi;
	bool objc_opt_info_loaded;
	bool images_are_global;
} RDyldCache;

typedef struct _r_bin_image {
	char *file;
	ut64 header_at;
	ut64 hdr_offset;
	ut64 symbols_off;
	ut64 va;
	ut32 nlist_start_index;
	ut32 nlist_count;
} RDyldBinImage;

static ut64 va2pa(uint64_t addr, ut32 n_maps, cache_map_t *maps, RBuffer *cache_buf, ut64 slide, ut32 *offset, ut32 *left) {
	ut64 res = UT64_MAX;
	ut32 i;

	addr -= slide;

	for (i = 0; i < n_maps; i++) {
		if (addr >= maps[i].address && addr < maps[i].address + maps[i].size) {
			res = maps[i].fileOffset + addr - maps[i].address;
			if (offset) {
				*offset = addr - maps[i].address;
			}
			if (left) {
				*left = maps[i].size - (addr - maps[i].address);
			}
			break;
		}
	}

	return res;
}

static void free_bin(RDyldBinImage *bin) {
	if (!bin) {
		return;
	}

	R_FREE (bin->file);
	R_FREE (bin);
}

static cache_img_t *read_cache_images(RBuffer *cache_buf, cache_hdr_t *hdr, ut64 hdr_offset) {
	if (!cache_buf || !hdr) {
		return NULL;
	}
	if (!hdr->imagesCount || !hdr->imagesOffset || hdr->imagesOffset == UT32_MAX || hdr->imagesCount == UT32_MAX) {
		return NULL;
	}

	ut64 size = sizeof (cache_img_t) * hdr->imagesCount;
	cache_img_t *images = R_NEWS0 (cache_img_t, hdr->imagesCount);
	if (!images) {
		return NULL;
	}

	if (r_buf_fread_at (cache_buf, (ut64) hdr->imagesOffset + hdr_offset, (ut8*) images, "3l2i", hdr->imagesCount) != size) {
		R_FREE (images);
		return NULL;
	}

	if (hdr_offset) {
		ut32 i;
		for (i = 0; i < hdr->imagesCount; i++) {
			cache_img_t *img = &images[i];
			img->pathFileOffset += hdr_offset;
		}
	}

	return images;
}

static void match_bin_entries(RDyldCache *cache, void *entries, ut64 entries_count, bool has_large_entries) {
	R_RETURN_IF_FAIL (cache && cache->bin_by_pa && entries);

	ut32 i;
	for (i = 0; i < entries_count; i++) {
		if (has_large_entries) {
			cache_locsym_entry_large_t *e = &((cache_locsym_entry_large_t *) entries)[i];
			RDyldBinImage *bin = ht_up_find (cache->bin_by_pa, e->dylibOffset, NULL);
			if (bin) {
				bin->nlist_start_index = e->nlistStartIndex;
				bin->nlist_count = e->nlistCount;
			}
		} else {
			cache_locsym_entry_t *e = &((cache_locsym_entry_t *) entries)[i];
			RDyldBinImage *bin = ht_up_find (cache->bin_by_pa, e->dylibOffset, NULL);
			if (bin) {
				bin->nlist_start_index = e->nlistStartIndex;
				bin->nlist_count = e->nlistCount;
			}
		}
	}
}

static RDyldLocSym *r_dyld_locsym_new(RDyldCache *cache) {
	R_RETURN_VAL_IF_FAIL (cache && cache->buf, NULL);

	ut32 i;
	for (i = 0; i < cache->n_hdr; i++) {
		cache_hdr_t *hdr = &cache->hdr[i];
		if (!hdr || !hdr->localSymbolsSize || !hdr->localSymbolsOffset) {
			continue;
		}

		void *entries = NULL;

		ut64 info_size = sizeof (cache_locsym_info_t);
		cache_locsym_info_t *info = R_NEW0 (cache_locsym_info_t);
		if (r_buf_fread_at (cache->buf, hdr->localSymbolsOffset, (ut8*) info, "6i", 1) != info_size) {
			R_LOG_ERROR ("incomplete local symbol info");
			goto beach;
		}
		ut64 entries_count = info->entriesCount;
		bool has_large_entries = cache->n_hdr > 1;
		if (has_large_entries) {
			ut64 entries_size = sizeof (cache_locsym_entry_large_t) * info->entriesCount;
			cache_locsym_entry_large_t *large_entries = R_NEWS0 (cache_locsym_entry_large_t, info->entriesCount);
			if (!large_entries) {
				goto beach;
			}
			if (r_buf_fread_at (cache->buf, hdr->localSymbolsOffset + info->entriesOffset, (ut8*) large_entries, "lii",
					info->entriesCount) != entries_size) {
				R_LOG_ERROR ("incomplete local symbol (large) entries");
				goto beach;
			}
			entries = large_entries;
		} else {
			ut64 entries_size = sizeof (cache_locsym_entry_t) * info->entriesCount;
			cache_locsym_entry_t *regular_entries = R_NEWS0 (cache_locsym_entry_t, info->entriesCount);
			if (!regular_entries) {
				goto beach;
			}
			if (r_buf_fread_at (cache->buf, hdr->localSymbolsOffset + info->entriesOffset,
					(ut8*) regular_entries, "iii", info->entriesCount) != entries_size) {
				R_LOG_ERROR ("Incomplete local symbol entries");
				goto beach;
			}
			entries = regular_entries;
		}
		RDyldLocSym * locsym = R_NEW0 (RDyldLocSym);
		match_bin_entries (cache, entries, entries_count, has_large_entries);
		locsym->local_symbols_offset = hdr->localSymbolsOffset;
		locsym->nlists_offset = info->nlistOffset;
		locsym->nlists_count = info->nlistCount;
		locsym->strings_offset = info->stringsOffset;
		locsym->strings_size = info->stringsSize;

		free (info);
		free (entries);

		return locsym;
beach:
		free (info);
		free (entries);

		R_LOG_ERROR ("something went wrong parsing local symbols");
		break;
	}
	return NULL;
}

static ut64 rebase_infos_get_slide(RDyldCache *cache) {
	// TODO: implement slide detection from io and ask here
	return 0;
}

static void symbols_from_locsym(RDyldCache *cache, RDyldBinImage *bin, RBinFile * bf, SetU *hash) {
	RDyldLocSym *locsym = cache->locsym;
	if (!locsym) {
		return;
	}

	if (bin->nlist_start_index >= locsym->nlists_count ||
			bin->nlist_start_index + bin->nlist_count > locsym->nlists_count) {
		eprintf ("dyldcache: malformed local symbol entry\n");
		return;
	}

	ut64 nlists_size = sizeof (struct MACH0_(nlist)) * bin->nlist_count;
	struct MACH0_(nlist) *nlists = R_NEWS0 (struct MACH0_(nlist), bin->nlist_count);
	if (!nlists) {
		return;
	}
	ut64 nlists_offset = locsym->local_symbols_offset + locsym->nlists_offset +
		bin->nlist_start_index * sizeof (struct MACH0_(nlist));
	if (r_buf_fread_at (cache->buf, nlists_offset, (ut8*) nlists, "iccsl", bin->nlist_count) != nlists_size) {
		free (nlists);
		return;
	}

	ut32 j;
	for (j = 0; j != bin->nlist_count; j++) {
		struct MACH0_(nlist) *nlist = &nlists[j];
		if (set_u_contains (hash, (ut64)nlist->n_value)) {
			continue;
		}
		set_u_add (hash, (ut64)nlist->n_value);
		if (nlist->n_strx >= locsym->strings_size) {
			continue;
		}
		RBinSymbol *sym = RVecRBinSymbol_emplace_back (&bf->bo->symbols_vec);
		if (!sym) {
			break;
		}
		memset (sym, 0, sizeof (RBinSymbol));
		sym->type = R_BIN_TYPE_FUNC_STR;
		sym->vaddr = nlist->n_value;
		ut64 slide = rebase_infos_get_slide (cache);
		sym->paddr = va2pa (nlist->n_value, cache->n_maps, cache->maps, cache->buf, slide, NULL, NULL);

		char *symstr = r_buf_get_string (cache->buf, locsym->local_symbols_offset + locsym->strings_offset + nlist->n_strx);
		if (symstr) {
			sym->name = r_bin_name_new (symstr);
		} else {
			static R_TH_LOCAL ut32 k = 0;
			char *s = r_str_newf ("unk_local%d", k++);
			sym->name = r_bin_name_new (s);
			free (s);
		}
	}

	free (nlists);
}

static void r_dyldcache_free(RDyldCache *cache) {
	if (!cache) {
		return;
	}

	ht_up_free (cache->bin_by_pa);
	r_list_free (cache->bins);
	cache->bins = NULL;
	r_buf_free (cache->buf);
	cache->buf = NULL;
	R_FREE (cache->hdr);
	R_FREE (cache->maps);
	R_FREE (cache->maps_index);
	R_FREE (cache->maps_flags);
	R_FREE (cache->hdr_offset);
	R_FREE (cache->hdr_overhead);
	R_FREE (cache->accel);
	R_FREE (cache->locsym);
	R_FREE (cache->oi);
	R_FREE (cache);
}

static ut64 bin_obj_va2pa(ut64 p, ut32 *offset, ut32 *left, RBinFile *bf) {
	if (!bf || !bf->bo || !bf->bo->bin_obj) {
		return 0;
	}

	RDyldCache *cache = (RDyldCache*) ((struct MACH0_(obj_t)*)bf->bo->bin_obj)->user;
	if (!cache) {
		return 0;
	}

	ut64 slide = rebase_infos_get_slide (cache);
	ut64 res = va2pa (p, cache->n_maps, cache->maps, cache->buf, slide, offset, left);
	if (res == UT64_MAX) {
		res = 0;
	}
	return res;
}

static struct MACH0_(obj_t) *bin_to_mach0(RBinFile *bf, RDyldBinImage *bin) {
	if (!bin || !bf) {
		return NULL;
	}

	RDyldCache *cache = (RDyldCache*) bf->bo->bin_obj;
	if (!cache) {
		return NULL;
	}

	RBuffer *buf = r_buf_new_slice (cache->buf, bin->hdr_offset, r_buf_size (cache->buf) - bin->hdr_offset);
	if (!buf) {
		return NULL;
	}

	struct MACH0_(opts_t) opts;
	MACH0_(opts_set_default) (&opts, bf);
	opts.header_at = bin->header_at - bin->hdr_offset;
	if (bin->symbols_off) {
		opts.symbols_off = bin->symbols_off - bin->hdr_offset;
	}

	struct MACH0_(obj_t) *mach0 = MACH0_(new_buf) (bf, buf, &opts);
	if (mach0) {
		mach0->user = cache;
		mach0->va2pa = &bin_obj_va2pa;
	}
	r_buf_free (buf);

	return mach0;
}

static int prot2perm(int x) {
	int r = 0;
	if (x & 1) {
		r |= 4;
	}
	if (x & 2) {
		r |= 2;
	}
	if (x & 4) {
		r |= 1;
	}
	return r;
}

static bool check_magic(const char *magic) {
	return !strcmp (magic, "dyld_v1   arm64")
		|| !strcmp (magic, "dyld_v1  arm64e")
		|| !strcmp (magic, "dyld_v1  x86_64")
		|| !strcmp (magic, "dyld_v1 x86_64h");
}

static bool check(RBinFile *bf, RBuffer *buf) {
	if (r_buf_size (buf) < 32) {
		return false;
	}

	char hdr[17] = {0};
	int rhdr = r_buf_read_at (buf, 0, (ut8 *)&hdr, sizeof (hdr) - 1);
	if (rhdr != sizeof (hdr) - 1) {
		return false;
	}

	return check_magic (hdr);
}

static cache_imgxtr_t *read_cache_imgextra(RBuffer *cache_buf, cache_hdr_t *hdr, cache_accel_t *accel, ut64 * out_count) {
	*out_count = 0;
	if (!cache_buf || !hdr || !hdr->imagesCount || !accel || !accel->imageExtrasCount || !accel->imagesExtrasOffset) {
		return NULL;
	}

	ut64 size = sizeof (cache_imgxtr_t) * accel->imageExtrasCount;
	cache_imgxtr_t *images = R_NEWS0 (cache_imgxtr_t, accel->imageExtrasCount);
	if (!images) {
		return NULL;
	}

	if (r_buf_fread_at (cache_buf, accel->imagesExtrasOffset, (ut8*) images, "ll4i", accel->imageExtrasCount) != size) {
		R_FREE (images);
		return NULL;
	}

	*out_count = accel->imageExtrasCount;

	return images;
}

static char *get_lib_name(RBuffer *cache_buf, cache_img_t *img) {
	char file[256];
	const char *lib_name = file;
	if (r_buf_read_at (cache_buf, img->pathFileOffset, (ut8*) &file, sizeof (file)) == sizeof (file)) {
		file[sizeof (file) - 1] = 0; // wtf
#if 0
		char * last_slash = strrchr (file, '/');
		if (last_slash && *last_slash) {
			lib_name = last_slash + 1;
		}
#endif
		return strdup (lib_name);
	}
	return strdup ("FAIL"); /// XXX return NULL instead
}

static int string_contains(const void *a, const void *b) {
	return !strstr ((const char*) a, (const char*) b);
}

static HtSU *create_path_to_index(RBuffer *cache_buf, cache_img_t *img, cache_hdr_t *hdr) {
	HtSU *path_to_idx = ht_su_new0 ();
	if (!path_to_idx) {
		return NULL;
	}
	size_t i;
	for (i = 0; i != hdr->imagesCount; i++) {
		char file[256];
		if (r_buf_read_at (cache_buf, img[i].pathFileOffset, (ut8*) &file, sizeof (file)) != sizeof (file)) {
			continue;
		}
		file[sizeof (file) - 1] = 0;
		ht_su_insert (path_to_idx, file, (ut64)i);

		const char versions_pattern[] = ".framework/Versions/";
		char *versions = strstr (file, versions_pattern);
		if (versions) {
			char *next_slash = strchr (versions + 20, '/');
			if (next_slash) {
				char *tail = strdup (next_slash);
				if (!tail) {
					break;
				}
				strcpy (versions + 10, tail);
				free (tail);
				ht_su_insert (path_to_idx, file, (ut64)i); // XXX already inserted?
			}
		}
	}
	return path_to_idx;
}

static void carve_deps_at_address(RDyldCache *cache, cache_img_t *img, HtSU *path_to_idx, ut64 address, int *deps, bool printing) {
	ut64 pa = va2pa (address, cache->n_maps, cache->maps, cache->buf, 0, NULL, NULL);
	if (pa == UT64_MAX) {
		return;
	}
	struct MACH0_(mach_header) mh;
	if (r_buf_fread_at (cache->buf, pa, (ut8*) &mh, "8i", 1) != sizeof (struct MACH0_(mach_header))) {
		return;
	}
	if (mh.magic != MH_MAGIC_64 || mh.sizeofcmds == 0) {
		return;
	}
	ut64 cmds_at = pa + sizeof (struct MACH0_(mach_header));
	ut8 *cmds = malloc (mh.sizeofcmds + 1);
	if (!cmds || r_buf_read_at (cache->buf, cmds_at, cmds, mh.sizeofcmds) != mh.sizeofcmds) {
		goto beach;
	}
	cmds[mh.sizeofcmds] = 0;
	ut8 *cursor = cmds;
	ut8 *end = cmds + mh.sizeofcmds;
	while (cursor < end) {
		ut32 cmd = r_read_le32 (cursor);
		ut32 cmdsize = r_read_le32 (cursor + sizeof (ut32));
		ut8 *cmd_end = cursor + cmdsize;
		if (cmd == LC_LOAD_DYLIB ||
				cmd == LC_LOAD_WEAK_DYLIB ||
				cmd == LC_REEXPORT_DYLIB ||
				cmd == LC_LOAD_UPWARD_DYLIB) {
			ut32 path_offset = r_read_le32 (cursor + 2 * sizeof (ut32));
			bool found;
			if (cursor + path_offset >= cmd_end) {
				R_LOG_ERROR ("Malformed load command");
				goto nextcmd;
			}
			const char *key = (const char *) cursor + path_offset;
			size_t dep_index = (size_t)ht_su_find (path_to_idx, key, &found);
			if (!found || dep_index >= cache->hdr->imagesCount) {
				R_LOG_WARN ("alien dep '%s'", key);
				goto nextcmd;
			}
			deps[dep_index]++;
			if (printing) {
				eprintf ("-> %s\n", key);
			}
		}
nextcmd:
		cursor += cmdsize;
	}
beach:
	free (cmds);
}

static ut64 resolve_symbols_off(RDyldCache *cache, ut64 pa) {
	struct MACH0_(mach_header) mh;
	if (r_buf_fread_at (cache->buf, pa, (ut8*) &mh, "8i", 1) != sizeof (struct MACH0_(mach_header))) {
		return 0;
	}
	if (mh.magic != MH_MAGIC_64 || mh.sizeofcmds == 0) {
		return 0;
	}
	ut64 cmds_at = pa + sizeof (struct MACH0_(mach_header));
	ut64 cursor = cmds_at;
	ut64 end = cursor + mh.sizeofcmds;
	while (cursor < end) {
		ut32 cmd = r_buf_read_le32_at (cache->buf, cursor);
		if (cmd == UT32_MAX) {
			return 0;
		}
		ut32 cmdsize = r_buf_read_le32_at (cache->buf, cursor + sizeof (ut32));
		if (cmdsize == UT32_MAX || cmdsize < 1) {
			return 0;
		}
		if (cmd == LC_SEGMENT || cmd == LC_SEGMENT_64) {
			char segname[17];
			segname[16] = 0;
			if (r_buf_read_at (cache->buf, cursor + 2 * sizeof (ut32), (ut8 *)segname, 16) != 16) {
				return 0;
			}
			if (!strncmp (segname, "__LINKEDIT", 16)) {
				ut64 vmaddr = r_buf_read_le64_at (cache->buf, cursor + 2 * sizeof (ut32) + 16);
				if (vmaddr == UT64_MAX) {
					return 0;
				}
				ut64 original_off = r_buf_read_le64_at (cache->buf, cursor + 2 * sizeof (ut32) + 16 + 16);
				if (original_off == UT64_MAX) {
					return 0;
				}

				ut32 i,j;
				for (i = 0; i < cache->n_hdr; i++) {
					cache_hdr_t *hdr = &cache->hdr[i];
					ut32 maps_index = cache->maps_index[i];
					for (j = 0; j < hdr->mappingCount; j++) {
						ut64 map_start = cache->maps[maps_index + j].address;
						ut64 map_end = map_start + cache->maps[maps_index + j].size;
						if (vmaddr >= map_start && vmaddr < map_end) {
							ut64 map_off = vmaddr - map_start + cache->maps[maps_index + j].fileOffset;
							return map_off - original_off;
						}
					}
				}
			}
		}
		cursor += cmdsize;
	}
	return 0;
}

static void create_cache_bins(RBinFile *bf, RDyldCache *cache) {
	RList *bins = r_list_newf ((RListFree)free_bin);
	ut16 *depArray = NULL;
	int *deps = NULL;
	char *target_libs = NULL;
	RList *target_lib_names = NULL;

	ut64 extras_count = 0;
	cache_imgxtr_t *extras = NULL;
	if (!bins) {
		return;
	}
	HtUP *bin_by_pa = ht_up_new0 ();
	if (!bin_by_pa) {
		goto end;
	}

	target_libs = r_sys_getenv ("R_DYLDCACHE_FILTER");
	if (target_libs) {
		target_lib_names = r_str_split_list (target_libs, ":", 0);
		if (!target_lib_names) {
			r_list_free (bins);
			return;
		}
		deps = R_NEWS0 (int, cache->hdr->imagesCount);
		if (!deps) {
			r_list_free (bins);
			r_list_free (target_lib_names);
			return;
		}
	} else {
		eprintf ("bin.dyldcache: Use R_DYLDCACHE_FILTER to specify a colon ':' separated\n");
		eprintf ("bin.dyldcache: list of names to avoid loading all the files in memory.\n");
	}

	cache_img_t *img = NULL;
	if (cache->images_are_global) {
		img = read_cache_images (cache->buf, cache->hdr, 0);
		if (!img) {
			free (deps);
			return;
		}
	}

	ut32 i;
	for (i = 0; i < cache->n_hdr; i++) {
		cache_hdr_t *hdr = &cache->hdr[i];
		ut64 hdr_offset = cache->hdr_offset[i];
		ut64 hdr_overhead = cache->hdr_overhead[i];
		ut32 maps_index = cache->maps_index[i];
		if (!img) {
			img = read_cache_images (cache->buf, hdr, hdr_offset);
			if (!img) {
				goto next;
			}
		}

		ut32 j;
		if (target_libs) {
			HtSU *path_to_idx = NULL;
			const ut32 depListCount = (cache->accel)? cache->accel->depListCount: 0;
			if (cache->accel && depListCount > 0) {
				depArray = R_NEWS0 (ut16, depListCount);
				if (!depArray) {
					goto next;
				}

				if (r_buf_fread_at (cache->buf, cache->accel->depListOffset,
					(ut8*) depArray, "s", depListCount) != depListCount * 2) {
					goto next;
				}

				extras = read_cache_imgextra (cache->buf, hdr, cache->accel, &extras_count);
				if (!extras) {
					goto next;
				}
			} else {
				path_to_idx = create_path_to_index (cache->buf, img, hdr);
			}

			for (j = 0; j < hdr->imagesCount; j++) {
				bool printing = !deps[j];
				char *lib_name = get_lib_name (cache->buf, &img[j]);
				if (!lib_name) {
					break;
				}
				if (strstr (lib_name, "libobjc.A.dylib")) {
					deps[j]++;
				}
				if (!r_list_find (target_lib_names, lib_name, string_contains)) {
					R_FREE (lib_name);
					continue;
				}
				if (printing) {
					eprintf ("FILTER: %s\n", lib_name);
				}
				R_FREE (lib_name);
				deps[j]++;

				if (extras && depArray && j < extras_count) {
					ut32 k;
					for (k = extras[j].dependentsStartArrayIndex; k < depListCount && depArray[k] != 0xffff; k++) {
						ut16 dep_index = depArray[k] & 0x7fff;
						if (dep_index >= cache->hdr->imagesCount) {
							R_LOG_ERROR ("invalid dep index");
							continue;
						}
						deps[dep_index]++;

						char *dep_name = get_lib_name (cache->buf, &img[dep_index]);
						if (!dep_name) {
							break;
						}
						if (printing) {
							eprintf ("-> %s\n", dep_name);
						}
						free (dep_name);
					}
				} else if (path_to_idx) {
					carve_deps_at_address (cache, img, path_to_idx, img[j].address, deps, printing);
				}
			}

			ht_su_free (path_to_idx);
			R_FREE (depArray);
			R_FREE (extras);
		}

		for (j = 0; j < hdr->imagesCount; j++) {
			if (deps && !deps[j]) {
				continue;
			}
			ut64 pa = va2pa (img[j].address, hdr->mappingCount, &cache->maps[maps_index], cache->buf, 0, NULL, NULL);
			if (pa == UT64_MAX) {
				continue;
			}
			bool already_loaded = false;
			ht_up_find (bin_by_pa, pa - hdr_overhead, &already_loaded);
			if (already_loaded) {
				continue;
			}
			ut8 magicbytes[4];
			r_buf_read_at (cache->buf, pa, magicbytes, 4);
			int magic = r_read_le32 (magicbytes);
			switch (magic) {
			case MH_MAGIC_64:
			{
				char file[256];
				RDyldBinImage *bin = R_NEW0 (RDyldBinImage);
				bin->header_at = pa;
				bin->hdr_offset = hdr_offset;
				bin->symbols_off = resolve_symbols_off (cache, pa);
				bin->va = img[j].address;
				if (r_buf_read_at (cache->buf, img[j].pathFileOffset, (ut8*) &file, sizeof (file)) == sizeof (file)) {
					file[255] = 0;
					char *last_slash = strrchr (file, '/');
					if (last_slash && *last_slash) {
						if (last_slash > file) {
							char *scan = last_slash - 1;
							while (scan > file && *scan != '/') {
								scan--;
							}
							if (*scan == '/') {
								bin->file = strdup (scan + 1);
							} else {
								bin->file = strdup (last_slash + 1);
							}
						} else {
							bin->file = strdup (last_slash + 1);
						}
					} else {
						bin->file = strdup (file);
					}
				}
				r_list_append (bins, bin);
				ht_up_insert (bin_by_pa, pa - hdr_overhead, bin);
				break;
			}
			default:
				if (magic != 0) {
					R_LOG_WARN ("Unknown sub-bin 0x%08x", magic);
				}
				break;
			}
		}
next:
		R_FREE (depArray);
		R_FREE (extras);
		if (!cache->images_are_global) {
			R_FREE (img);
		}
	}
	R_FREE (img);
end:
	if (r_list_empty (bins)) {
		r_list_free (bins);
		bins = NULL;
		ht_up_free (bin_by_pa);
		bin_by_pa = NULL;
	}
	R_FREE (deps);
	R_FREE (target_libs);
	r_list_free (target_lib_names);

	cache->bins = bins;
	cache->bin_by_pa = bin_by_pa;
}

static cache_hdr_t *read_cache_header(RBuffer *cache_buf, ut64 offset) {
	if (!cache_buf) {
		return NULL;
	}

	cache_hdr_t *hdr = R_NEW0 (cache_hdr_t);
	ut64 size = sizeof (cache_hdr_t);
	if (r_buf_fread_at (cache_buf, offset, (ut8*) hdr, "16c4i7l16clii4l", 1) != size) {
		R_FREE (hdr);
		return NULL;
	}
	if (!check_magic (hdr->magic)) {
		R_FREE (hdr);
		return NULL;
	}

	if (!hdr->imagesCount && !hdr->imagesOffset) {
		hdr->imagesOffset = r_buf_read_le32_at (cache_buf, 0x1c0 + offset);
		hdr->imagesCount = r_buf_read_le32_at (cache_buf, 0x1c4 + offset);
	}
	return hdr;
}

static void populate_cache_headers(RDyldCache *cache) {
	cache->n_hdr = 0;
	RList *hdrs = r_list_newf (NULL);
	if (!hdrs) {
		return;
	}

	cache_hdr_t *h;
	ut64 offsets[MAX_N_HDR];
	ut64 overheads[MAX_N_HDR];
	ut64 offset = 0, overhead = 0;
	ut64 buf_size = r_buf_size (cache->buf);
	ut32 n_zero_images = 0;
	do {
		offsets[cache->n_hdr] = offset;
		overheads[cache->n_hdr] = overhead;
		h = read_cache_header (cache->buf, offset);
		if (!h) {
			break;
		}

		if (!h->imagesCount && !h->imagesOffset) {
			n_zero_images++;
		}

		ut64 size = h->codeSignatureOffset + h->codeSignatureSize;
		if (!size || size > buf_size) {
			break;
		}

		r_list_append (hdrs, h);

#define SHIFT_MAYBE(x) \
	if (x) { \
		x += offset; \
	}

		SHIFT_MAYBE (h->codeSignatureOffset);
		SHIFT_MAYBE (h->slideInfoOffset);
		SHIFT_MAYBE (h->localSymbolsOffset);
		SHIFT_MAYBE (h->imagesTextOffset);

		offset += size;
		overhead += h->codeSignatureSize;
		cache->n_hdr++;
	} while (cache->n_hdr < MAX_N_HDR);

	if (!cache->n_hdr) {
		goto error;
	}

	cache->hdr = R_NEWS0 (cache_hdr_t, cache->n_hdr);
	if (!cache->hdr) {
		goto error;
	}

	cache->hdr_offset = R_NEWS0 (ut64, cache->n_hdr);
	if (!cache->hdr_offset) {
		goto error;
	}

	cache->hdr_overhead = R_NEWS0 (ut64, cache->n_hdr);
	if (!cache->hdr_overhead) {
		goto error;
	}

	memcpy (cache->hdr_offset, offsets, cache->n_hdr * sizeof (ut64));
	memcpy (cache->hdr_overhead, overheads, cache->n_hdr * sizeof (ut64));

	cache->images_are_global = n_zero_images == cache->n_hdr - 1;

	ut32 i = 0;
	RListIter *iter;
	cache_hdr_t *item;
	cache_hdr_t *prev_h = NULL;
	r_list_foreach (hdrs, iter, item) {
		if (i >= cache->n_hdr) {
			break;
		}
		if (cache->images_are_global) {
			if (!item->imagesCount && !item->imagesOffset && prev_h) {
				item->imagesCount = prev_h->imagesCount;
				item->imagesOffset = prev_h->imagesOffset;
			}
			prev_h = item;
		}
		memcpy (&cache->hdr[i++], item, sizeof (cache_hdr_t));
	}

beach:
	r_list_free (hdrs);
	return;

error:
	cache->n_hdr = 0;
	R_FREE (cache->hdr);
	R_FREE (cache->hdr_offset);

	goto beach;

}

static void populate_cache_maps(RDyldCache *cache) {
	R_RETURN_IF_FAIL (cache && cache->buf);

	ut32 i;
	size_t n_maps = 0;
	for (i = 0; i < cache->n_hdr; i++) {
		cache_hdr_t *hdr = &cache->hdr[i];
		if (!hdr->mappingCount || !hdr->mappingOffset) {
			continue;
		}
		n_maps += hdr->mappingCount;
	}

	if (n_maps > (r_buf_size (cache->buf) / 4)) {
		R_LOG_WARN ("Invalid n_maps (%d)", (int)n_maps);
		return;
	}

	cache_map_t *maps = NULL;
	if (n_maps != 0) {
		cache->maps_index = R_NEWS0 (ut32, cache->n_hdr);
		if (!cache->maps_index) {
			return;
		}
		maps = R_NEWS0 (cache_map_t, n_maps);
	}
	if (!maps) {
		cache->maps = NULL;
		cache->n_maps = 0;
		return;
	}
	ut64 * maps_flags = NULL;
	if (cache->hdr->mappingOffset >= 0x140) {
		maps_flags = R_NEWS0 (ut64, n_maps);
	}
	ut32 next_map = 0;
	for (i = 0; i < cache->n_hdr; i++) {
		cache_hdr_t *hdr = &cache->hdr[i];
		cache->maps_index[i] = next_map;

		if (!hdr->mappingCount || !hdr->mappingOffset) {
			continue;
		}
		ut64 hdr_offset = cache->hdr_offset[i];
		ut64 mapping_slide_offset = 0;
		if (maps_flags && hdr->mappingOffset >= 0x140) {
			ut32 mapping_slide_count = r_buf_read_le32_at (cache->buf, 0x13c + hdr_offset);
			if (mapping_slide_count == hdr->mappingCount) {
				mapping_slide_offset = r_buf_read_le32_at (cache->buf, 0x138 + hdr_offset);
			}
		}

		ut64 size = sizeof (cache_map_t) * hdr->mappingCount;
		if (r_buf_fread_at (cache->buf, (ut64) hdr->mappingOffset + hdr_offset, (ut8*) &maps[next_map], "3l2i", hdr->mappingCount) != size) {
			continue;
		}
		ut32 j;
		for (j = 0; j < hdr->mappingCount; j++) {
			cache_map_t *map = &maps[next_map + j];
			map->fileOffset += hdr_offset;
			if (maps_flags && mapping_slide_offset) {
				maps_flags[next_map + j] = r_buf_read_le64_at(cache->buf,
						mapping_slide_offset + hdr_offset + (ut64)j * sizeof (cache_mapping_slide) + offsetof(cache_mapping_slide, flags));
			}
		}
		next_map += hdr->mappingCount;
	}

	cache->maps = maps;
	cache->n_maps = next_map;
	cache->maps_flags = maps_flags;
}

static cache_accel_t *read_cache_accel(RBuffer *cache_buf, cache_hdr_t *hdr, cache_map_t *maps, int n_maps) {
	if (!cache_buf || !hdr || !hdr->accelerateInfoSize || !hdr->accelerateInfoAddr) {
		return NULL;
	}
	size_t mc = R_MIN (hdr->mappingCount, n_maps);
	ut64 offset = va2pa (hdr->accelerateInfoAddr, mc, maps, cache_buf, 0, NULL, NULL);
	if (!offset) {
		return NULL;
	}

	ut64 size = sizeof (cache_accel_t);
	cache_accel_t *accel = R_NEW0 (cache_accel_t);
	if (r_buf_fread_at (cache_buf, offset, (ut8*) accel, "16il", 1) != size) {
		R_FREE (accel);
		return NULL;
	}

	accel->imagesExtrasOffset += offset;
	accel->bottomUpListOffset += offset;
	accel->dylibTrieOffset += offset;
	accel->initializersOffset += offset;
	accel->dofSectionsOffset += offset;
	accel->reExportListOffset += offset;
	accel->depListOffset += offset;
	accel->rangeTableOffset += offset;

	return accel;
}

static objc_cache_opt_info *get_objc_opt_info(RBinFile *bf, RDyldCache *cache) {
	objc_cache_opt_info *result = NULL;
	RListIter *iter;
	RDyldBinImage *bin;
	r_list_foreach (cache->bins, iter, bin) {
		if (bin->file && strcmp (bin->file, "lib/libobjc.A.dylib")) {
			continue;
		}

		struct MACH0_(opts_t) opts = {0};
		MACH0_(opts_set_default) (&opts, bf);
		opts.verbose = bf->rbin->options.verbose;
		opts.header_at = bin->header_at;
		opts.symbols_off = 0;

		struct MACH0_(obj_t) *mach0 = MACH0_(new_buf) (bf, cache->buf, &opts);
		if (!mach0) {
			goto beach;
		}

		const RVecSection *sections = MACH0_(load_sections) (mach0);
		if (!sections) {
			MACH0_(mach0_free) (mach0);
			goto beach;
		}

		ut64 scoffs_offset = 0;
		ut64 scoffs_size = 0;
		ut64 optro_offset = 0;
		ut64 optro_size = 0;
		ut64 selrefs_offset = 0;
		ut64 selrefs_size = 0;
		ut64 const_selrefs_offset = 0;
		ut64 const_selrefs_size = 0;
		ut8 remaining = 4;
		ut64 slide = rebase_infos_get_slide (cache);

		struct section_t *section;
		R_VEC_FOREACH (sections, section) {
			if (section->size == 0) {
				continue;
			}
			if (strstr (section->name, "__objc_opt_ro")) {
				optro_offset = va2pa (section->vaddr, cache->n_maps, cache->maps, cache->buf, slide, NULL, NULL);
				optro_size = section->size;
				remaining--;
				if (remaining == 0) {
					break;
				}
			}
			if (strstr (section->name, "__objc_scoffs")) {
				scoffs_offset = va2pa (section->vaddr, cache->n_maps, cache->maps, cache->buf, slide, NULL, NULL);
				scoffs_size = section->size;
				remaining--;
				if (remaining == 0) {
					break;
				}
			}
			if (strstr (section->name, "__DATA.__objc_selrefs")) {
				selrefs_offset = va2pa (section->vaddr, cache->n_maps, cache->maps, cache->buf, slide, NULL, NULL);
				selrefs_size = section->size;
				remaining--;
				if (remaining == 0) {
					break;
				}
			}
			if (strstr (section->name, "__DATA_CONST.__objc_selrefs")) {
				const_selrefs_offset = va2pa (section->vaddr, cache->n_maps, cache->maps, cache->buf, slide, NULL, NULL);
				const_selrefs_size = section->size;
				remaining--;
				if (remaining == 0) {
					break;
				}
			}
		}

		MACH0_(mach0_free) (mach0);

		if (!selrefs_offset || !selrefs_size) {
			selrefs_offset = const_selrefs_offset;
			selrefs_size = const_selrefs_size;
		}

		ut32 opt_version = 0;
		if (optro_offset && optro_size > 4) {
			opt_version = r_buf_read_le32_at (cache->buf, optro_offset);
			if (opt_version == UT32_MAX) {
				opt_version = 0;
			}
		}

		ut64 sel_string_base = 0;
		if (!scoffs_offset || scoffs_size < 40) {
			if (!selrefs_offset || !selrefs_size || opt_version < 16) {
				break;
			}
			ut64 cursor = selrefs_offset;
			ut64 end = cursor + selrefs_size;
			while (cursor + 8 <= end) {
				ut64 sel_ptr = r_buf_read_le64_at (cache->buf, cursor);
				if (sel_ptr == UT64_MAX) {
					break;
				}

				ut64 sel_offset = va2pa (sel_ptr, cache->n_maps, cache->maps, cache->buf, slide, NULL, NULL);
				char * selector = r_buf_get_string (cache->buf, sel_offset);
				if (!selector) {
					break;
				}

				bool is_magic_selector = !strncmp (selector, "\xf0\x9f\xa4\xaf", 4);
				free (selector);

				if (is_magic_selector) {
					sel_string_base = sel_ptr;
					break;
				}

				cursor += 8;
			}
			if (sel_string_base == 0) {
				break;
			}
		} else {
			ut64 check = r_buf_read_le64_at (cache->buf, scoffs_offset);
			if (check < 2) {
				break;
			}
			sel_string_base = r_buf_read_le64_at (cache->buf, scoffs_offset + 8);
			if (sel_string_base == UT64_MAX) {
				break;
			}
			ut64 sel_string_end = r_buf_read_le64_at (cache->buf, scoffs_offset + 16);
			if (sel_string_end == sel_string_base || sel_string_end == UT64_MAX) {
				break;
			}
		}

		result = R_NEW0 (objc_cache_opt_info);
		result->sel_string_base = sel_string_base;
	}
beach:
	return result;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	if (!bf || !bf->rbin || !bf->rbin->iob.desc_get) {
		return false;
	}
	RIODesc *desc = bf->rbin->iob.desc_get (bf->rbin->iob.io, bf->fd);
	if (!desc) {
		return false;
	}
	const char * io_plugin_name = desc->plugin->meta.name;
	if (strcmp (io_plugin_name, "dsc") != 0) {
		R_LOG_ERROR ("Use dsc:// for dyld caches");
		return false;
	}

	RDyldCache *cache = R_NEW0 (RDyldCache);
	cache->buf = r_buf_ref (buf);
	populate_cache_headers (cache);
	if (!cache->hdr) {
		r_dyldcache_free (cache);
		return false;
	}
	populate_cache_maps (cache);
	if (!cache->maps) {
		r_dyldcache_free (cache);
		return false;
	}
	cache->accel = read_cache_accel (cache->buf, cache->hdr, cache->maps, cache->n_maps);
	create_cache_bins (bf, cache);
	if (!cache->bins) {
		r_dyldcache_free (cache);
		return false;
	}
	cache->locsym = r_dyld_locsym_new (cache);
	bf->bo->bin_obj = cache;
	return true;
}

static RList *entries(RBinFile *bf) {
	RDyldCache *cache = (RDyldCache*) bf->bo->bin_obj;
	if (!cache) {
		return NULL;
	}

	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}
	RBinAddr *ptr = R_NEW0 (RBinAddr);
	if (cache->n_maps > 0) {
		size_t i;
		for (i = 0; i < cache->n_maps; i++) {
			cache_map_t * map = &cache->maps[i];
			if (map->fileOffset == 0) {
				ptr->paddr = 0;
				ptr->vaddr = map->address;
				break;
			}
		}
	}
	r_list_append (ret, ptr);
	return ret;
}

static RBinInfo *info(RBinFile *bf) {

	if (!bf || !bf->bo) {
		return NULL;
	}

	RDyldCache *cache = (RDyldCache*) bf->bo->bin_obj;
	if (!cache) {
		return NULL;
	}

	bool big_endian = 0;
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = strdup (bf->file);
	ret->bclass = strdup ("dyldcache");
	ret->rclass = strdup ("ios");
	ret->os = strdup ("iOS");
	if (strstr (cache->hdr->magic, "x86_64")) {
		ret->arch = strdup ("x86");
		ret->bits = 64;
	} else {
		ret->arch = strdup ("arm");
		ret->bits = strstr (cache->hdr->magic, "arm64")? 64: 32;
	}
	ret->machine = strdup (ret->arch);
	ret->subsystem = strdup ("xnu");
	ret->type = strdup ("library-cache");
	ret->has_va = true;
	ret->big_endian = big_endian;
	ret->dbg_info = 0;
	return ret;
}

#if 0
static void parse_mach0(RList *ret, ut64 paddr, RBinFile *bf) {
	// TODO
}
#endif

static ut64 baddr(RBinFile *bf) {
	// XXX hardcoded
	return 0x180000000;
}

void symbols_from_bin(RBinFile *bf, RDyldBinImage *bin) {
	struct MACH0_(obj_t) *mo = bin_to_mach0 (bf, bin);
	if (!mo) {
		return;
	}

	MACH0_(load_symbols) (mo);
	MACH0_(mach0_free) (mo);
}

static bool __is_data_section(const char *name) {
	if (strstr (name, "_cstring")) {
		return true;
	}
	if (strstr (name, "_os_log")) {
		return true;
	}
	if (strstr (name, "_objc_methname")) {
		return true;
	}
	if (strstr (name, "_objc_classname")) {
		return true;
	}
	if (strstr (name, "_objc_methtype")) {
		return true;
	}
	return false;
}

static void sections_from_bin(RList *ret, RBinFile *bf, RDyldBinImage *bin) {
	RDyldCache *cache = (RDyldCache*) bf->bo->bin_obj;
	if (!cache) {
		return;
	}

	struct MACH0_(obj_t) *mach0 = bin_to_mach0 (bf, bin);
	if (!mach0) {
		return;
	}

	const RVecSection *sections = MACH0_(load_sections) (mach0);
	if (!sections) {
		return;
	}

	ut64 slide = rebase_infos_get_slide (cache);
	struct section_t *section;
	R_VEC_FOREACH (sections, section) {
		RBinSection *ptr = R_NEW0 (RBinSection);
		if (bin->file) {
			ptr->name = r_str_newf ("%s.%s", bin->file, (char*)section->name);
		} else {
			ptr->name = r_str_newf ("%s", (char*)section->name);
		}
		if (strstr (ptr->name, "la_symbol_ptr")) {
			int len = section->size / 8;
			ptr->format = r_str_newf ("Cd %d[%d]", 8, len);
		}
		ptr->is_data = __is_data_section (ptr->name);
		ptr->size = section->size;
		ptr->vsize = section->vsize;
		ptr->vaddr = section->vaddr;
		ptr->paddr = va2pa (section->vaddr, cache->n_maps, cache->maps, cache->buf, slide, NULL, NULL);
		if (!ptr->vaddr) {
			ptr->vaddr = ptr->paddr;
		}
		ptr->perm = section->perm;
		r_list_append (ret, ptr);
	}
	MACH0_(mach0_free) (mach0);
}

static RList *sections(RBinFile *bf) {
	RDyldCache *cache = (RDyldCache*) bf->bo->bin_obj;
	if (!cache) {
		return NULL;
	}

	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}

	RListIter *iter;
	RDyldBinImage *bin;
	ut32 i = 0;
	RCons *cons = bf->rbin->consb.cons;
	RConsIsBreaked is_breaked = (bf->rbin && bf->rbin->consb.is_breaked)? bf->rbin->consb.is_breaked: NULL;
	r_list_foreach (cache->bins, iter, bin) {
		i++;
		if (is_breaked && is_breaked (cons)) {
			eprintf ("Parsing sections stopped %d / %d\n", i, r_list_length (cache->bins));
			break;
		}
		sections_from_bin (ret, bf, bin);
	}

	RBinSection *ptr = NULL;
	for (i = 0; i < cache->n_maps; i++) {
		ptr = R_NEW0 (RBinSection);
		ptr->name = r_str_newf ("cache_map.%d", i);
		ptr->size = cache->maps[i].size;
		ptr->vsize = ptr->size;
		ptr->paddr = cache->maps[i].fileOffset;
		ptr->vaddr = cache->maps[i].address;
		ptr->add = true;
		ptr->is_segment = true;
		ptr->perm = prot2perm (cache->maps[i].initProt);
		r_list_append (ret, ptr);
	}

	ut64 slide = rebase_infos_get_slide (cache);
	if (slide) {
		RBinSection *section;
		r_list_foreach (ret, iter, section) {
			section->vaddr += slide;
		}
	}

	ut32 j = 0;
	for (i = 0; i < cache->n_hdr; i++) {
		cache_hdr_t *hdr = &cache->hdr[i];
		if (hdr->mappingCount < 1) {
			continue;
		}
		ut32 maps_index = cache->maps_index[i];
		cache_map_t * first_map = &cache->maps[maps_index];

		if (cache->maps_flags) {
			if ((cache->maps_flags[maps_index] & DYLD_CACHE_MAPPING_TEXT_STUBS) == 0) {
				continue;
			}
		} else {
			bool is_stubs_fallback =
				!cache->images_are_global && (
					hdr->imagesCount == 0 &&
					hdr->mappingCount == 1 &&
					first_map->size > 0x4000 &&
					first_map->initProt == 5
				);

			if (!is_stubs_fallback) {
				continue;
			}
		}

		ptr = R_NEW0 (RBinSection);
		ptr->name = r_str_newf ("STUBS_ISLAND.%d", j++);
		ptr->size = first_map->size - 0x4000;
		ptr->vsize = ptr->size;
		ptr->paddr = first_map->fileOffset + 0x4000;
		ptr->vaddr = first_map->address + 0x4000;
		ptr->add = true;
		ptr->is_segment = false;
		ptr->perm = prot2perm (first_map->initProt);
		r_list_append (ret, ptr);
	}

	return ret;
}

static bool symbols_vec(RBinFile *bf) {
	RVecRBinSymbol *symbols = &bf->bo->symbols_vec;
	RBinSymbol *sym;

	RDyldCache *cache = (RDyldCache*) bf->bo->bin_obj;
	if (!cache) {
		return false;
	}

	RListIter *iter;
	RDyldBinImage *bin;
	ut32 i = 0;
	RConsBind *consb = &bf->rbin->consb;
	RConsIsBreaked is_breaked = (consb->is_breaked)? consb->is_breaked: NULL;
	r_list_foreach (cache->bins, iter, bin) {
		i++;
		if (is_breaked && is_breaked (consb->cons)) {
			eprintf ("Parsing symbols stopped %d / %d\n", i, r_list_length (cache->bins));
			break;
		}
		symbols_from_bin (bf, bin);
	}

	SetU *hash = set_u_new ();
	if (!hash) {
		goto beach;
	}

	R_VEC_FOREACH (symbols, sym) {
		set_u_add (hash, sym->vaddr);
	}

	i = 0;
	r_list_foreach (cache->bins, iter, bin) {
		i++;
		if (is_breaked && is_breaked (consb->cons)) {
			eprintf ("Parsing symbols stopped %d / %d\n", i, r_list_length (cache->bins));
			break;
		}
		symbols_from_locsym (cache, bin, bf, hash);
	}

	set_u_free (hash);

	ut64 slide = rebase_infos_get_slide (cache);
	if (slide) {
		R_VEC_FOREACH (symbols, sym) {
			sym->vaddr += slide;
		}
	}

beach:
	return !RVecRBinSymbol_empty (symbols);
}

static void destroy(RBinFile *bf) {
	RDyldCache *cache = (RDyldCache*) bf->bo->bin_obj;
	// unswizzle_io_read (cache, bf->rbin->iob.io); // XXX io may be dead here
	r_dyldcache_free (cache);
}

static RList *classes(RBinFile *bf) {
	RDyldCache *cache = (RDyldCache*) bf->bo->bin_obj;
	if (!cache) {
		return NULL;
	}

	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}

	if (!cache->objc_opt_info_loaded) {
		cache->oi = get_objc_opt_info (bf, cache);
		cache->objc_opt_info_loaded = true;
	}

	RListIter *iter;
	RDyldBinImage *bin;
	ut64 slide = rebase_infos_get_slide (cache);

	RBuffer *orig_buf = bf->buf;
	ut32 num_of_unnamed_class = 0;
	ut32 i = 0;
	RCons *cons = bf->rbin->consb.cons;
	RConsIsBreaked is_breaked = (bf->rbin && bf->rbin->consb.is_breaked)? bf->rbin->consb.is_breaked: NULL;
	r_list_foreach (cache->bins, iter, bin) {
		i++;
		if (is_breaked && is_breaked (cons)) {
			eprintf ("Parsing classes stopped %d / %d\n", i, r_list_length (cache->bins));
			break;
		}
		struct MACH0_(obj_t) *mach0 = bin_to_mach0 (bf, bin);
		if (!mach0) {
			goto beach;
		}

		const RVecSection *sections = MACH0_(load_sections) (mach0);
		if (!sections) {
			MACH0_(mach0_free) (mach0);
			goto beach;
		}

		struct section_t *section;
		R_VEC_FOREACH (sections, section) {
			if (section->size == 0) {
				continue;
			}

			bool is_classlist = strstr (section->name, "__objc_classlist");
			bool is_catlist = r_str_endswith (section->name, "__objc_catlist");

			if (!is_classlist && !is_catlist) {
				continue;
			}

			ut8 *pointers = malloc (section->size);
			if (!pointers) {
				continue;
			}

			ut64 offset = va2pa (section->vaddr, cache->n_maps, cache->maps, cache->buf, slide, NULL, NULL);
			if (r_buf_read_at (cache->buf, offset, pointers, section->size) < section->size) {
				R_FREE (pointers);
				continue;
			}
			ut8 *cursor = pointers;
			ut8 *pointers_end = pointers + section->size;

			for (; cursor + 8 <= pointers_end; cursor += 8) {
				ut64 pointer_to_class = r_read_le64 (cursor);

				RBinClass *klass = R_NEW0 (RBinClass);
				klass->methods = r_list_new ();
				klass->fields = r_list_new ();
				klass->origin = R_BIN_CLASS_ORIGIN_BIN;

				bf->bo->bin_obj = mach0;
				bf->buf = cache->buf;
				if (is_classlist) {
					MACH0_(get_class_t) (bf, klass, pointer_to_class, false, NULL, cache->oi);
				} else {
					MACH0_(get_category_t) (bf, klass, pointer_to_class, NULL, cache->oi);
				}
				bf->bo->bin_obj = cache;
				bf->buf = orig_buf;

				if (!klass->name) {
					if (bf->rbin->options.verbose) {
						R_LOG_ERROR ("KLASS failed at 0x%"PFMT64x" [pa 0x%"PFMT64x" va 0x%"PFMT64x"], is_classlist %d",
								pointer_to_class, cursor - pointers + offset, cursor - pointers + section->vaddr,  is_classlist);
					}
					char *kname = r_str_newf ("UnnamedClass%u", num_of_unnamed_class);
					klass->name = r_bin_name_new (kname);
					free (kname);
					num_of_unnamed_class++;
				}
				klass->index = r_list_length (ret);
				r_list_append (ret, klass);
			}

			R_FREE (pointers);
		}

		MACH0_(mach0_free) (mach0);
	}

	return ret;

beach:
	r_list_free (ret);
	return NULL;
}

static void header(RBinFile *bf) {
	if (!bf || !bf->bo) {
		return;
	}

	RDyldCache *cache = (RDyldCache*) bf->bo->bin_obj;
	if (!cache) {
		return;
	}

	RBin *bin = bf->rbin;
	ut64 slide = rebase_infos_get_slide (cache);
	PrintfCallback p = bin->cb_printf;

	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}

	pj_o (pj);
	pj_k (pj, "header");
	pj_o (pj);
	pj_ks (pj, "magic", cache->hdr->magic);
	pj_kn (pj, "mappingOffset", cache->hdr->mappingOffset);
	pj_kn (pj, "mappingCount", cache->hdr->mappingCount);
	pj_kn (pj, "imagesOffset", cache->hdr->imagesOffset);
	pj_kn (pj, "imagesCount", cache->hdr->imagesCount);
	pj_kn (pj, "dyldBaseAddress", cache->hdr->dyldBaseAddress);
	pj_kn (pj, "codeSignatureOffset", cache->hdr->codeSignatureOffset);
	pj_kn (pj, "codeSignatureSize", cache->hdr->codeSignatureSize);
	pj_kn (pj, "slideInfoOffset", cache->hdr->slideInfoOffset);
	pj_kn (pj, "slideInfoSize", cache->hdr->slideInfoSize);
	pj_kn (pj, "localSymbolsOffset", cache->hdr->localSymbolsOffset);
	pj_kn (pj, "localSymbolsSize", cache->hdr->localSymbolsSize);
	char uuidstr[128];
	r_hex_bin2str ((ut8*)cache->hdr->uuid, 16, uuidstr);
	pj_ks (pj, "uuid", uuidstr);
	pj_ks (pj, "cacheType", (cache->hdr->cacheType == 0) ? "development" : "production");
	pj_kn (pj, "branchPoolsOffset", cache->hdr->branchPoolsOffset);
	pj_kn (pj, "branchPoolsCount", cache->hdr->branchPoolsCount);
	pj_kn (pj, "accelerateInfoAddr", cache->hdr->accelerateInfoAddr + slide);
	pj_kn (pj, "accelerateInfoSize", cache->hdr->accelerateInfoSize);
	pj_kn (pj, "imagesTextOffset", cache->hdr->imagesTextOffset);
	pj_kn (pj, "imagesTextCount", cache->hdr->imagesTextCount);
	pj_end (pj);

	if (cache->accel) {
		pj_k (pj, "accelerator");
		pj_o (pj);
		pj_kn (pj, "version", cache->accel->version);
		pj_kn (pj, "imageExtrasCount", cache->accel->imageExtrasCount);
		pj_kn (pj, "imagesExtrasOffset", cache->accel->imagesExtrasOffset);
		pj_kn (pj, "bottomUpListOffset", cache->accel->bottomUpListOffset);
		pj_kn (pj, "dylibTrieOffset", cache->accel->dylibTrieOffset);
		pj_kn (pj, "dylibTrieSize", cache->accel->dylibTrieSize);
		pj_kn (pj, "initializersOffset", cache->accel->initializersOffset);
		pj_kn (pj, "initializersCount", cache->accel->initializersCount);
		pj_kn (pj, "dofSectionsOffset", cache->accel->dofSectionsOffset);
		pj_kn (pj, "dofSectionsCount", cache->accel->dofSectionsCount);
		pj_kn (pj, "reExportListOffset", cache->accel->reExportListOffset);
		pj_kn (pj, "reExportCount", cache->accel->reExportCount);
		pj_kn (pj, "depListOffset", cache->accel->depListOffset);
		pj_kn (pj, "depListCount", cache->accel->depListCount);
		pj_kn (pj, "rangeTableOffset", cache->accel->rangeTableOffset);
		pj_kn (pj, "rangeTableCount", cache->accel->rangeTableCount);
		pj_kn (pj, "dyldSectionAddr", cache->accel->dyldSectionAddr + slide);
		pj_end (pj);
	}

	if (cache->hdr->imagesTextCount) {
		pj_k (pj, "images");
		pj_a (pj);
		ut64 total_size = cache->hdr->imagesTextCount * sizeof (cache_text_info_t);
		cache_text_info_t * text_infos = malloc (total_size);
		if (!text_infos) {
			goto beach;
		}
		if (r_buf_fread_at (cache->buf, cache->hdr->imagesTextOffset, (ut8*)text_infos, "16clii", cache->hdr->imagesTextCount) != total_size) {
			free (text_infos);
			goto beach;
		}
		size_t i;
		for (i = 0; i != cache->hdr->imagesTextCount; i++) {
			cache_text_info_t * text_info = &text_infos[i];
			r_hex_bin2str ((ut8*)text_info->uuid, 16, uuidstr);
			pj_o (pj);
			pj_ks (pj, "uuid", uuidstr);
			pj_kn (pj, "address", text_info->loadAddress + slide);
			pj_kn (pj, "textSegmentSize", text_info->textSegmentSize);
			char file[256];
			if (r_buf_read_at (cache->buf, text_info->pathOffset, (ut8*) &file, sizeof (file)) == sizeof (file)) {
				file[255] = 0;
				pj_ks (pj, "path", file);
				char *last_slash = strrchr (file, '/');
				if (last_slash && *last_slash) {
					pj_ks (pj, "name", last_slash + 1);
				} else {
					pj_ks (pj, "name", file);
				}
			}
			pj_end (pj);
		}
		pj_end (pj);
		free (text_infos);
	}

	pj_end (pj);
	p ("%s", pj_string (pj));

beach:
	pj_free (pj);
}

RBinPlugin r_bin_plugin_dyldcache = {
	.meta = {
		.name = "dyldcache",
		.desc = "Apple dynamic system library shared cache",
		.author = "mrmacete",
		.license = "LGPL-3.0-only",
	},
	.load = &load,
	.entries = &entries,
	.baddr = &baddr,
	.symbols_vec = &symbols_vec,
	.sections = &sections,
	.minstrlen = 5,
	.check = &check,
	.destroy = &destroy,
	.classes = &classes,
	.header = &header,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_dyldcache,
	.version = R2_VERSION
};
#endif
