/* radare2 - LGPL - Copyright 2018-2022 - pancake, mrmacete, keegan */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <r_core.h>
#include <r_io.h>
#include <ht_pu.h>
// #include "../format/mach0/mach0_defines.h"
#define R_BIN_MACH064 1
#include "../format/mach0/mach0.h"
#include "objc/mach0_classes.h"

#define R_IS_PTR_AUTHENTICATED(x) B_IS_SET(x, 63)
#define MAX_N_HDR 16

typedef struct {
	ut8 version;
	ut64 slide;
	ut8 *one_page_buf;
	ut32 page_size;
	ut64 start_of_data;
} RDyldRebaseInfo;

typedef struct {
	ut64 start;
	ut64 end;
	RDyldRebaseInfo *info;
} RDyldRebaseInfosEntry;

typedef struct {
	RDyldRebaseInfosEntry *entries;
	size_t length;
} RDyldRebaseInfos;

typedef struct {
	ut8 version;
	ut64 slide;
	ut8 *one_page_buf;
	ut32 page_size;
	ut64 start_of_data;
	ut16 *page_starts;
	ut32 page_starts_count;
	ut64 delta_mask;
	ut32 delta_shift;
	ut64 auth_value_add;
} RDyldRebaseInfo3;

typedef struct {
	ut8 version;
	ut64 slide;
	ut8 *one_page_buf;
	ut32 page_size;
	ut64 start_of_data;
	ut16 *page_starts;
	ut32 page_starts_count;
	ut16 *page_extras;
	ut32 page_extras_count;
	ut64 delta_mask;
	ut64 value_mask;
	ut32 delta_shift;
	ut64 value_add;
} RDyldRebaseInfo2;

typedef struct {
	ut8 version;
	ut64 slide;
	ut8 *one_page_buf;
	ut32 page_size;
	ut64 start_of_data;
	ut16 *toc;
	ut32 toc_count;
	ut8 *entries;
	ut32 entries_size;
} RDyldRebaseInfo1;

typedef struct {
	ut64 local_symbols_offset;
	ut64 nlists_offset;
	ut64 nlists_count;
	ut64 strings_offset;
	ut64 strings_size;
} RDyldLocSym;

typedef struct _r_dyldcache {
	ut8 magic[8];

	cache_hdr_t *hdr;
	ut64 *hdr_offset;
	ut32 *maps_index;
	ut32 n_hdr;
	cache_map_t *maps;
	ut32 n_maps;

	RList *bins;
	RBuffer *buf;
	int (*original_io_read)(RIO *io, RIODesc *fd, ut8 *buf, int count);
	RDyldRebaseInfos *rebase_infos;
	cache_accel_t *accel;
	RDyldLocSym *locsym;
	objc_cache_opt_info *oi;
	bool objc_opt_info_loaded;
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

static R_TH_LOCAL RList *pending_bin_files = NULL;

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

static void rebase_info3_free(RDyldRebaseInfo3 *rebase_info) {
	if (rebase_info) {
		R_FREE (rebase_info->page_starts);
		R_FREE (rebase_info);
	}
}

static void rebase_info2_free(RDyldRebaseInfo2 *rebase_info) {
	if (rebase_info) {
		R_FREE (rebase_info->page_starts);
		R_FREE (rebase_info->page_extras);
		R_FREE (rebase_info);
	}
}

static void rebase_info1_free(RDyldRebaseInfo1 *rebase_info) {
	if (rebase_info) {
		R_FREE (rebase_info->toc);
		R_FREE (rebase_info->entries);
		R_FREE (rebase_info);
	}
}

static void rebase_info_free(RDyldRebaseInfo *rebase_info) {
	if (!rebase_info) {
		return;
	}
	R_FREE (rebase_info->one_page_buf);
	ut8 version = rebase_info->version;
	if (version == 1) {
		rebase_info1_free ((RDyldRebaseInfo1*) rebase_info);
	} else if (version == 2 || version == 4) {
		rebase_info2_free ((RDyldRebaseInfo2*) rebase_info);
	} else if (version == 3) {
		rebase_info3_free ((RDyldRebaseInfo3*) rebase_info);
	} else {
		R_FREE (rebase_info);
	}
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

	if (r_buf_fread_at (cache_buf, hdr->imagesOffset, (ut8*) images, "3l2i", hdr->imagesCount) != size) {
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

static void match_bin_entries(RDyldCache *cache, void *entries) {
	r_return_if_fail (cache && cache->bins && entries);

	cache_img_t *imgs = read_cache_images (cache->buf, cache->hdr, 0);
	if (!imgs) {
		return;
	}

	RDyldBinImage *bin = NULL;
	RListIter *it = r_list_iterator (cache->bins);

	bool has_large_entries = cache->n_hdr > 1;

	ut32 i;
	for (i = 0; i < cache->hdr->imagesCount; i++) {
		cache_img_t *img = &imgs[i];
		if (!it) {
			break;
		}
		bin = it->data;
		if (!bin) {
			break;
		}
		if (bin && bin->va == img->address) {
			if (has_large_entries) {
				cache_locsym_entry_large_t *e = &((cache_locsym_entry_large_t *) entries)[i];
				bin->nlist_start_index = e->nlistStartIndex;
				bin->nlist_count = e->nlistCount;
			} else {
				cache_locsym_entry_t *e = &((cache_locsym_entry_t *) entries)[i];
				bin->nlist_start_index = e->nlistStartIndex;
				bin->nlist_count = e->nlistCount;
			}
			it = it->n;
		}
	}

	R_FREE (imgs);
}

static RDyldLocSym *r_dyld_locsym_new(RDyldCache *cache) {
	r_return_val_if_fail (cache && cache->buf, NULL);

	ut32 i;
	for (i = 0; i < cache->n_hdr; i++) {
		cache_hdr_t *hdr = &cache->hdr[i];
		if (!hdr || !hdr->localSymbolsSize || !hdr->localSymbolsOffset) {
			continue;
		}

		cache_locsym_info_t *info = NULL;
		void *entries = NULL;

		ut64 info_size = sizeof (cache_locsym_info_t);
		info = R_NEW0 (cache_locsym_info_t);
		if (!info) {
			goto beach;
		}
		if (r_buf_fread_at (cache->buf, hdr->localSymbolsOffset, (ut8*) info, "6i", 1) != info_size) {
			eprintf ("locsym err 01\n");
			goto beach;
		}
		if (info->entriesCount != cache->hdr->imagesCount) {
			eprintf ("locsym err 02\n");
			goto beach;
		}

		bool has_large_entries = cache->n_hdr > 1;
		if (has_large_entries) {
			ut64 entries_size = sizeof (cache_locsym_entry_large_t) * info->entriesCount;
			cache_locsym_entry_large_t *large_entries = R_NEWS0 (cache_locsym_entry_large_t, info->entriesCount);
			if (!large_entries) {
				goto beach;
			}
			if (r_buf_fread_at (cache->buf, hdr->localSymbolsOffset + info->entriesOffset, (ut8*) large_entries, "lii",
					info->entriesCount) != entries_size) {
				eprintf ("locsym err 03\n");
				goto beach;
			}
			entries = large_entries;
		} else {
			ut64 entries_size = sizeof (cache_locsym_entry_t) * info->entriesCount;
			cache_locsym_entry_t *regular_entries = R_NEWS0 (cache_locsym_entry_t, info->entriesCount);
			if (!regular_entries) {
				goto beach;
			}
			if (r_buf_fread_at (cache->buf, hdr->localSymbolsOffset + info->entriesOffset, (ut8*) regular_entries, "iii",
					info->entriesCount) != entries_size) {
				eprintf ("locsym err 04\n");
				goto beach;
			}
			entries = regular_entries;
		}
		RDyldLocSym * locsym = R_NEW0 (RDyldLocSym);
		if (!locsym) {
			goto beach;
		}

		match_bin_entries (cache, entries);

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

		eprintf ("dyldcache: malformed local symbols metadata\n");
		break;
	}
	return NULL;
}

static ut64 rebase_infos_get_slide(RDyldCache *cache) {
	if (!cache->rebase_infos || !cache->rebase_infos->length) {
		return 0;
	}

	size_t i;
	for (i = 0; i < cache->rebase_infos->length; i++) {
		if (cache->rebase_infos->entries[i].info) {
			return cache->rebase_infos->entries[i].info->slide;
		}
	}

	return 0;
}

static void symbols_from_locsym(RDyldCache *cache, RDyldBinImage *bin, RList *symbols, SetU *hash) {
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
		RBinSymbol *sym = R_NEW0 (RBinSymbol);
		if (!sym) {
			break;
		}
		sym->type = "LOCAL";
		sym->vaddr = nlist->n_value;
		ut64 slide = rebase_infos_get_slide (cache);
		sym->paddr = va2pa (nlist->n_value, cache->n_maps, cache->maps, cache->buf, slide, NULL, NULL);

		char *symstr =r_buf_get_string (cache->buf, locsym->local_symbols_offset + locsym->strings_offset + nlist->n_strx);
		if (symstr) {
			sym->name = symstr;
		} else {
			static R_TH_LOCAL ut32 k = 0;
			sym->name = r_str_newf ("unk_local%d", k++);
		}

		r_list_append (symbols, sym);
	}

	free (nlists);
}

static void r_dyldcache_free(RDyldCache *cache) {
	if (!cache) {
		return;
	}

	r_list_free (cache->bins);
	cache->bins = NULL;
	r_buf_free (cache->buf);
	cache->buf = NULL;
	if (cache->rebase_infos) {
		int i;
		for (i = 0; i < cache->rebase_infos->length; i++) {
			rebase_info_free (cache->rebase_infos->entries[i].info);
			cache->rebase_infos->entries[i].info = NULL;
		}
		R_FREE (cache->rebase_infos->entries);
		R_FREE (cache->rebase_infos);
	}
	R_FREE (cache->hdr);
	R_FREE (cache->maps);
	R_FREE (cache->maps_index);
	R_FREE (cache->hdr_offset);
	R_FREE (cache->accel);
	R_FREE (cache->locsym);
	R_FREE (cache->oi);
	R_FREE (cache);
}

static ut64 bin_obj_va2pa(ut64 p, ut32 *offset, ut32 *left, RBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return 0;
	}

	RDyldCache *cache = (RDyldCache*) ((struct MACH0_(obj_t)*)bf->o->bin_obj)->user;
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

	RDyldCache *cache = (RDyldCache*) bf->o->bin_obj;
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
	opts.symbols_off = bin->symbols_off;

	struct MACH0_(obj_t) *mach0 = MACH0_(new_buf) (buf, &opts);
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

static ut32 dumb_ctzll(ut64 x) {
	ut64 result = 0;
	int i, j;
	for (i = 0; i < 64; i += 8) {
		ut8 byte = (x >> i) & 0xff;
		if (!byte) {
			result += 8;
		} else {
			for (j = 0; j < 8; j++) {
				if (!((byte >> j) & 1)) {
					result++;
				} else {
					break;
				}
			}
			break;
		}
	}
	return result;
}

static ut64 estimate_slide(RBinFile *bf, RDyldCache *cache, ut64 value_mask, ut64 value_add) {
	ut64 slide = 0;
	if (cache->n_hdr > 1) {
		return slide;
	}
	ut64 *classlist = malloc (64);
	if (!classlist) {
		goto beach;
	}

	RListIter *iter;
	RDyldBinImage *bin;
	r_list_foreach (cache->bins, iter, bin) {
		bool found_sample = false;

		struct MACH0_(opts_t) opts = {0};
		opts.verbose = bf->rbin->verbose;
		opts.header_at = bin->header_at;
		opts.symbols_off = 0;

		struct MACH0_(obj_t) *mach0 = MACH0_(new_buf) (cache->buf, &opts);
		if (!mach0) {
			goto beach;
		}

		struct section_t *sections = NULL;
		if (!(sections = MACH0_(get_sections) (mach0))) {
			MACH0_(mach0_free) (mach0);
			goto beach;
		}

		int i;
		int incomplete = 2;
		int classlist_idx = 0, data_idx = 0;
		for (i = 0; !sections[i].last && incomplete; i++) {
			if (sections[i].size == 0) {
				continue;
			}
			if (strstr (sections[i].name, "__objc_classlist")) {
				incomplete--;
				classlist_idx = i;
				continue;
			}
			if (strstr (sections[i].name, "__objc_data")) {
				incomplete--;
				data_idx = i;
				continue;
			}
		}

		if (incomplete) {
			goto next_bin;
		}

		int classlist_sample_size = R_MIN (64, sections[classlist_idx].size);
		int n_classes = classlist_sample_size / 8;
		ut64 sect_offset = sections[classlist_idx].offset + bin->hdr_offset;

		if (r_buf_fread_at (cache->buf, sect_offset, (ut8*) classlist, "l", n_classes) != classlist_sample_size) {
			goto next_bin;
		}

		ut64 data_addr = sections[data_idx].addr;
		ut64 data_tail = data_addr & 0xfff;
		ut64 data_tail_end = (data_addr + sections[data_idx].size) & 0xfff;
		for (i = 0; i < n_classes; i++) {
			ut64 cl_addr = (classlist[i] & value_mask) + value_add;
			ut64 cl_tail = cl_addr & 0xfff;
			if (cl_tail >= data_tail && cl_tail < data_tail_end) {
				ut64 off = cl_tail - data_tail;
				slide = ((cl_addr - off) & value_mask) - (data_addr & value_mask);
				found_sample = true;
				break;
			}
		}

next_bin:
		MACH0_(mach0_free) (mach0);
		R_FREE (sections);

		if (found_sample) {
			break;
		}
	}

beach:
	R_FREE (classlist);
	return slide;
}

static RDyldRebaseInfo *get_rebase_info(RBinFile *bf, RDyldCache *cache, ut64 slideInfoOffset, ut64 slideInfoSize, ut64 start_of_data, ut64 slide) {
	ut8 *tmp_buf_1 = NULL;
	ut8 *tmp_buf_2 = NULL;
	ut8 *one_page_buf = NULL;
	RBuffer *cache_buf = cache->buf;

	ut64 offset = slideInfoOffset;
	ut32 slide_info_version = 0;
	if (r_buf_read_at (cache_buf, offset, (ut8*) &slide_info_version, 4) != 4) {
		return NULL;
	}

	if (slide_info_version == 3) {
		cache_slide3_t slide_info;
		ut64 size = sizeof (cache_slide3_t);
		if (r_buf_fread_at (cache_buf, offset, (ut8*) &slide_info, "4i1l", 1) < 20) {
			return NULL;
		}

		ut64 page_starts_offset = offset + size;
		ut64 page_starts_size = slide_info.page_starts_count * 2;

		if (page_starts_size + size > slideInfoSize) {
			return NULL;
		}

		if (page_starts_size > 0) {
			tmp_buf_1 = malloc (page_starts_size);
			if (!tmp_buf_1) {
				goto beach;
			}
			if (r_buf_fread_at (cache_buf, page_starts_offset, tmp_buf_1, "s", slide_info.page_starts_count) != page_starts_size) {
				goto beach;
			}
		}

		if (slide_info.page_size > 0) {
			one_page_buf = malloc (slide_info.page_size);
			if (!one_page_buf) {
				goto beach;
			}
		}

		RDyldRebaseInfo3 *rebase_info = R_NEW0 (RDyldRebaseInfo3);
		if (!rebase_info) {
			goto beach;
		}

		rebase_info->version = 3;
		rebase_info->delta_mask = 0x3ff8000000000000ULL;
		rebase_info->delta_shift = 51;
		rebase_info->start_of_data = start_of_data;
		rebase_info->page_starts = (ut16*) tmp_buf_1;
		rebase_info->page_starts_count = slide_info.page_starts_count;
		rebase_info->auth_value_add = slide_info.auth_value_add;
		rebase_info->page_size = slide_info.page_size;
		rebase_info->one_page_buf = one_page_buf;
		if (slide == UT64_MAX) {
			rebase_info->slide = estimate_slide (bf, cache, 0x7ffffffffffffULL, 0);
			if (rebase_info->slide) {
				eprintf ("dyldcache is slid: 0x%"PFMT64x"\n", rebase_info->slide);
			}
		} else {
			rebase_info->slide = slide;
		}

		return (RDyldRebaseInfo*) rebase_info;
	} else if (slide_info_version == 2 || slide_info_version == 4) {
		cache_slide2_t slide_info;
		ut64 size = sizeof (cache_slide2_t);
		if (r_buf_fread_at (cache_buf, offset, (ut8*) &slide_info, "6i2l", 1) != size) {
			return NULL;
		}

		if (slide_info.page_starts_offset == 0 ||
			slide_info.page_starts_offset > slideInfoSize ||
			slide_info.page_starts_offset + slide_info.page_starts_count * 2 > slideInfoSize) {
			return NULL;
		}

		if (slide_info.page_extras_offset == 0 ||
			slide_info.page_extras_offset > slideInfoSize ||
			slide_info.page_extras_offset + slide_info.page_extras_count * 2 > slideInfoSize) {
			return NULL;
		}

		if (slide_info.page_starts_count > 0) {
			ut64 size = slide_info.page_starts_count * 2;
			ut64 at = slideInfoOffset + slide_info.page_starts_offset;
			tmp_buf_1 = malloc (size);
			if (!tmp_buf_1) {
				goto beach;
			}
			if (r_buf_fread_at (cache_buf, at, tmp_buf_1, "s", slide_info.page_starts_count) != size) {
				goto beach;
			}
		}

		if (slide_info.page_extras_count > 0) {
			ut64 size = slide_info.page_extras_count * 2;
			ut64 at = slideInfoOffset + slide_info.page_extras_offset;
			tmp_buf_2 = malloc (size);
			if (!tmp_buf_2) {
				goto beach;
			}
			if (r_buf_fread_at (cache_buf, at, tmp_buf_2, "s", slide_info.page_extras_count) != size) {
				goto beach;
			}
		}

		if (slide_info.page_size > 0) {
			one_page_buf = malloc (slide_info.page_size);
			if (!one_page_buf) {
				goto beach;
			}
		}

		RDyldRebaseInfo2 *rebase_info = R_NEW0 (RDyldRebaseInfo2);
		if (!rebase_info) {
			goto beach;
		}

		rebase_info->version = slide_info_version;
		rebase_info->start_of_data = start_of_data;
		rebase_info->page_starts = (ut16*) tmp_buf_1;
		rebase_info->page_starts_count = slide_info.page_starts_count;
		rebase_info->page_extras = (ut16*) tmp_buf_2;
		rebase_info->page_extras_count = slide_info.page_extras_count;
		rebase_info->value_add = slide_info.value_add;
		rebase_info->delta_mask = slide_info.delta_mask;
		rebase_info->value_mask = ~rebase_info->delta_mask;
		rebase_info->delta_shift = dumb_ctzll (rebase_info->delta_mask) - 2;
		rebase_info->page_size = slide_info.page_size;
		rebase_info->one_page_buf = one_page_buf;
		if (slide == UT64_MAX) {
			rebase_info->slide = estimate_slide (bf, cache, rebase_info->value_mask, rebase_info->value_add);
			if (rebase_info->slide) {
				eprintf ("dyldcache is slid: 0x%"PFMT64x"\n", rebase_info->slide);
			}
		} else {
			rebase_info->slide = slide;
		}

		return (RDyldRebaseInfo*) rebase_info;
	} else if (slide_info_version == 1) {
		cache_slide1_t slide_info;
		ut64 size = sizeof (cache_slide1_t);
		if (r_buf_fread_at (cache_buf, offset, (ut8*) &slide_info, "6i", 1) != size) {
			return NULL;
		}

		if (slide_info.toc_offset == 0 ||
			slide_info.toc_offset > slideInfoSize ||
			slide_info.toc_offset + slide_info.toc_count * 2 > slideInfoSize) {
			return NULL;
		}

		if (slide_info.entries_offset == 0 ||
			slide_info.entries_offset > slideInfoSize ||
			slide_info.entries_offset + slide_info.entries_count * slide_info.entries_size > slideInfoSize) {
			return NULL;
		}

		if (slide_info.toc_count > 0) {
			ut64 size = slide_info.toc_count * 2;
			ut64 at = slideInfoOffset + slide_info.toc_offset;
			tmp_buf_1 = malloc (size);
			if (!tmp_buf_1) {
				goto beach;
			}
			if (r_buf_fread_at (cache_buf, at, tmp_buf_1, "s", slide_info.toc_count) != size) {
				goto beach;
			}
		}

		if (slide_info.entries_count > 0) {
			ut64 size = (ut64) slide_info.entries_count * (ut64) slide_info.entries_size;
			ut64 at = slideInfoOffset + slide_info.entries_offset;
			tmp_buf_2 = malloc (size);
			if (!tmp_buf_2) {
				goto beach;
			}
			if (r_buf_read_at (cache_buf, at, tmp_buf_2, size) != size) {
				goto beach;
			}
		}

		one_page_buf = malloc (4096);
		if (!one_page_buf) {
			goto beach;
		}

		RDyldRebaseInfo1 *rebase_info = R_NEW0 (RDyldRebaseInfo1);
		if (!rebase_info) {
			goto beach;
		}

		rebase_info->version = 1;
		rebase_info->start_of_data = start_of_data;
		rebase_info->one_page_buf = one_page_buf;
		rebase_info->page_size = 4096;
		rebase_info->toc = (ut16*) tmp_buf_1;
		rebase_info->toc_count = slide_info.toc_count;
		rebase_info->entries = tmp_buf_2;
		rebase_info->entries_size = slide_info.entries_size;
		if (slide == UT64_MAX) {
			rebase_info->slide = estimate_slide (bf, cache, UT64_MAX, 0);
			if (rebase_info->slide) {
				eprintf ("dyldcache is slid: 0x%"PFMT64x"\n", rebase_info->slide);
			}
		} else {
			rebase_info->slide = slide;
		}

		return (RDyldRebaseInfo*) rebase_info;
	} else {
		eprintf ("unsupported slide info version %d\n", slide_info_version);
		return NULL;
	}

beach:
	R_FREE (tmp_buf_1);
	R_FREE (tmp_buf_2);
	R_FREE (one_page_buf);
	return NULL;
}

static RDyldRebaseInfos *get_rebase_infos(RBinFile *bf, RDyldCache *cache) {
	RDyldRebaseInfos *result = R_NEW0 (RDyldRebaseInfos);
	if (!result) {
		return NULL;
	}

	if (!cache->hdr->slideInfoOffset || !cache->hdr->slideInfoSize) {
		size_t total_slide_infos = 0;
		ut32 n_slide_infos[MAX_N_HDR];

		size_t i;
		for (i = 0; i < cache->n_hdr && i < MAX_N_HDR; i++) {
			ut64 hdr_offset = cache->hdr_offset[i];
			if ((n_slide_infos[i] = r_buf_read_le32_at (cache->buf, 0x13c + hdr_offset)) == UT32_MAX) {
				goto beach;
			}
			if (!SZT_ADD_OVFCHK (total_slide_infos, n_slide_infos[i])) {
				goto beach;
			}
			total_slide_infos += n_slide_infos[i];
		}

		if (!total_slide_infos) {
			goto beach;
		}

		RDyldRebaseInfosEntry * infos = R_NEWS0 (RDyldRebaseInfosEntry, total_slide_infos);
		if (!infos) {
			goto beach;
		}

		size_t k = 0;
		for (i = 0; i < cache->n_hdr && i < MAX_N_HDR; i++) {
			ut64 hdr_offset = cache->hdr_offset[i];
			ut64 slide_infos_offset;
			if (!n_slide_infos[i]) {
				continue;
			}
			if ((slide_infos_offset = r_buf_read_le32_at (cache->buf, 0x138 + hdr_offset)) == UT32_MAX) {
				continue;
			}
			if (!slide_infos_offset) {
				continue;
			}
			slide_infos_offset += hdr_offset;

			ut32 j;
			RDyldRebaseInfo *prev_info = NULL;
			for (j = 0; j < n_slide_infos[i]; j++) {
				ut64 offset = slide_infos_offset + j * sizeof (cache_mapping_slide);
				cache_mapping_slide entry;
				if (r_buf_fread_at (cache->buf, offset, (ut8*)&entry, "6lii", 1) != sizeof (cache_mapping_slide)) {
					break;
				}

				if (entry.slideInfoOffset && entry.slideInfoSize) {
					infos[k].start = entry.fileOffset + hdr_offset;
					infos[k].end = infos[k].start + entry.size;
					ut64 slide = prev_info ? prev_info->slide : UT64_MAX;
					infos[k].info = get_rebase_info (bf, cache, entry.slideInfoOffset + hdr_offset, entry.slideInfoSize, entry.fileOffset + hdr_offset, slide);
					prev_info = infos[k].info;
					k++;
				}
			}
		}

		if (!k) {
			free (infos);
			goto beach;
		}

		if (k < total_slide_infos) {
			RDyldRebaseInfosEntry * pruned_infos = R_NEWS0 (RDyldRebaseInfosEntry, k);
			if (!pruned_infos) {
				free (infos);
				goto beach;
			}

			memcpy (pruned_infos, infos, sizeof (RDyldRebaseInfosEntry) * k);
			free (infos);
			infos = pruned_infos;
		}

		result->entries = infos;
		result->length = k;
		return result;
	}

	if (cache->hdr->mappingCount > 1) {
		RDyldRebaseInfosEntry * infos = R_NEWS0 (RDyldRebaseInfosEntry, 1);
		if (!infos) {
			goto beach;
		}

		infos[0].start = cache->maps[1].fileOffset;
		infos[0].end = infos[0].start + cache->maps[1].size;
		infos[0].info = get_rebase_info (bf, cache, cache->hdr->slideInfoOffset, cache->hdr->slideInfoSize, infos[0].start, UT64_MAX);

		result->entries = infos;
		result->length = 1;
		return result;
	}

beach:
	free (result);
	return NULL;
}

static bool check_magic(const char *magic) {
	return !strcmp (magic, "dyld_v1   arm64")
		|| !strcmp (magic, "dyld_v1  arm64e")
		|| !strcmp (magic, "dyld_v1  x86_64")
		|| !strcmp (magic, "dyld_v1 x86_64h");
}

static bool check_buffer(RBinFile *bf, RBuffer *buf) {
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

static cache_imgxtr_t *read_cache_imgextra(RBuffer *cache_buf, cache_hdr_t *hdr, cache_accel_t *accel) {
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

	return images;
}

static char *get_lib_name(RBuffer *cache_buf, cache_img_t *img) {
	char file[256];
	char *lib_name = file;
	if (r_buf_read_at (cache_buf, img->pathFileOffset, (ut8*) &file, sizeof (file)) == sizeof (file)) {
		file[255] = 0;
		/*char * last_slash = strrchr (file, '/');
		if (last_slash && *last_slash) {
			lib_name = last_slash + 1;
		}*/
		return strdup (lib_name);
	}
	return strdup ("FAIL");
}

static int string_contains(const void *a, const void *b) {
	return !strstr ((const char*) a, (const char*) b);
}

static HtPU *create_path_to_index(RBuffer *cache_buf, cache_img_t *img, cache_hdr_t *hdr) {
	HtPU *path_to_idx = ht_pu_new0 ();
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
		ht_pu_insert (path_to_idx, file, (ut64)i);

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
				ht_pu_insert (path_to_idx, file, (ut64)i);
			}
		}
	}
	return path_to_idx;
}

static void carve_deps_at_address(RDyldCache *cache, cache_img_t *img, HtPU *path_to_idx, ut64 address, int *deps, bool printing) {
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
		if (cmd == LC_LOAD_DYLIB ||
				cmd == LC_LOAD_WEAK_DYLIB ||
				cmd == LC_REEXPORT_DYLIB ||
				cmd == LC_LOAD_UPWARD_DYLIB) {
			bool found;
			if (cursor + 24 >= end) {
				break;
			}
			const char *key = (const char *) cursor + 24;
			size_t dep_index = (size_t)ht_pu_find (path_to_idx, key, &found);
			if (!found || dep_index >= cache->hdr->imagesCount) {
				R_LOG_WARN ("alien dep '%s'", key);
				continue;
			}
			deps[dep_index]++;
			if (printing) {
				eprintf ("-> %s\n", key);
			}
		}
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
		if (cmdsize == UT32_MAX) {
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

				ut32 i,j;
				for (i = 0; i < cache->n_hdr; i++) {
					cache_hdr_t *hdr = &cache->hdr[i];
					ut64 hdr_offset = cache->hdr_offset[i];
					ut32 maps_index = cache->maps_index[i];
					for (j = 0; j < hdr->mappingCount; j++) {
						ut64 map_start = cache->maps[maps_index + j].address;
						ut64 map_end = map_start + cache->maps[maps_index + j].size;
						if (vmaddr >= map_start && vmaddr < map_end) {
							return hdr_offset;
						}
					}
				}
			}
		}
		cursor += cmdsize;
	}
	return 0;
}

static RList *create_cache_bins(RBinFile *bf, RDyldCache *cache) {
	RList *bins = r_list_newf ((RListFree)free_bin);
	ut16 *depArray = NULL;
	cache_imgxtr_t *extras = NULL;
	if (!bins) {
		return NULL;
	}

	char *target_libs = NULL;
	RList *target_lib_names = NULL;
	int *deps = NULL;
	target_libs = r_sys_getenv ("R_DYLDCACHE_FILTER");
	if (target_libs) {
		target_lib_names = r_str_split_list (target_libs, ":", 0);
		if (!target_lib_names) {
			r_list_free (bins);
			return NULL;
		}
		deps = R_NEWS0 (int, cache->hdr->imagesCount);
		if (!deps) {
			r_list_free (bins);
			r_list_free (target_lib_names);
			return NULL;
		}
	} else {
		eprintf ("bin.dyldcache: Use R_DYLDCACHE_FILTER to specify a colon ':' separated\n");
		eprintf ("bin.dyldcache: list of names to avoid loading all the files in memory.\n");
	}

	ut32 i;
	for (i = 0; i < cache->n_hdr; i++) {
		cache_hdr_t *hdr = &cache->hdr[i];
		ut64 hdr_offset = cache->hdr_offset[i];
		ut32 maps_index = cache->maps_index[i];
		cache_img_t *img = read_cache_images (cache->buf, hdr, hdr_offset);
		if (!img) {
			goto next;
		}

		ut32 j;
		if (target_libs) {
			HtPU *path_to_idx = NULL;
			if (cache->accel) {
				depArray = R_NEWS0 (ut16, cache->accel->depListCount);
				if (!depArray) {
					goto next;
				}

				if (r_buf_fread_at (cache->buf, cache->accel->depListOffset, (ut8*) depArray, "s", cache->accel->depListCount) != cache->accel->depListCount * 2) {
					goto next;
				}

				extras = read_cache_imgextra (cache->buf, hdr, cache->accel);
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

				if (extras && depArray) {
					ut32 k;
					for (k = extras[j].dependentsStartArrayIndex; depArray[k] != 0xffff; k++) {
						ut16 dep_index = depArray[k] & 0x7fff;
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

			ht_pu_free (path_to_idx);
			R_FREE (depArray);
			R_FREE (extras);
		}

		for (j = 0; j < hdr->imagesCount; j++) {
			if (deps && !deps[j]) {
				continue;
			}
			// ut64 pa = va2pa (img[j].address, hdr->mappingCount, &cache->maps[maps_index], cache->buf, 0, NULL, NULL);
			ut64 pa = va2pa (img[j].address, cache->n_maps, &cache->maps[maps_index], cache->buf, 0, NULL, NULL);
			if (pa == UT64_MAX) {
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
				if (!bin) {
					goto next;
				}
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
				break;
			}
			default:
				eprintf ("Unknown sub-bin\n");
				break;
			}
		}
next:
		R_FREE (depArray);
		R_FREE (extras);
		R_FREE (img);
	}
	if (r_list_empty (bins)) {
		r_list_free (bins);
		bins = NULL;
	}
	R_FREE (deps);
	R_FREE (target_libs);
	r_list_free (target_lib_names);
	return bins;
}

static void rebase_bytes_v1(RDyldRebaseInfo1 *rebase_info, ut8 *buf, ut64 offset, int count, ut64 start_of_write) {
	int in_buf = 0;
	while (in_buf < count) {
		ut64 offset_in_data = offset - rebase_info->start_of_data;
		ut64 page_index = offset_in_data / rebase_info->page_size;
		ut64 page_offset = offset_in_data % rebase_info->page_size;
		ut64 to_next_page = rebase_info->page_size - page_offset;
		ut64 entry_index = page_offset / 32;
		ut64 offset_in_entry = (page_offset % 32) / 4;

		if (entry_index >= rebase_info->entries_size) {
			in_buf += to_next_page;
			offset += to_next_page;
			continue;
		}

		if (page_index >= rebase_info->toc_count) {
			break;
		}

		ut8 *entry = &rebase_info->entries[rebase_info->toc[page_index] * rebase_info->entries_size];
		ut8 b = entry[entry_index];

		if (b & (1 << offset_in_entry)) {
			ut64 value = r_read_le64 (buf + in_buf);
			value += rebase_info->slide;
			r_write_le64 (buf + in_buf, value);
			in_buf += 8;
			offset += 8;
		} else {
			in_buf += 4;
			offset += 4;
		}
	}
}

static void rebase_bytes_v2(RDyldRebaseInfo2 *rebase_info, ut8 *buf, ut64 offset, int count, ut64 start_of_write) {
	int in_buf = 0;
	while (in_buf < count) {
		ut64 offset_in_data = offset - rebase_info->start_of_data;
		ut64 page_index = offset_in_data / rebase_info->page_size;
		ut64 page_offset = offset_in_data % rebase_info->page_size;
		ut64 to_next_page = rebase_info->page_size - page_offset;

		if (page_index >= rebase_info->page_starts_count) {
			goto next_page;
		}
		ut16 page_flag = rebase_info->page_starts[page_index];

		if (page_flag == DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE) {
			goto next_page;
		}

		if (!(page_flag & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA)) {
			ut64 first_rebase_off = rebase_info->page_starts[page_index] * 4;
			if (first_rebase_off >= page_offset && first_rebase_off < page_offset + count) {
				ut32 delta = 1;
				while (delta) {
					ut64 position = in_buf + first_rebase_off - page_offset;
					if (position + 8 >= count) {
						break;
					}
					ut64 raw_value = r_read_le64 (buf + position);
					delta = ((raw_value & rebase_info->delta_mask) >> rebase_info->delta_shift);
					if (position >= start_of_write) {
						ut64 new_value = raw_value & rebase_info->value_mask;
						if (new_value != 0) {
							new_value += rebase_info->value_add;
							new_value += rebase_info->slide;
						}
						r_write_le64 (buf + position, new_value);
					}
					first_rebase_off += delta;
				}
			}
		}
next_page:
		in_buf += to_next_page;
		offset += to_next_page;
	}
}

static void rebase_bytes_v3(RDyldRebaseInfo3 *rebase_info, ut8 *buf, ut64 offset, int count, ut64 start_of_write) {
	int in_buf = 0;
	while (in_buf < count) {
		ut64 offset_in_data = offset - rebase_info->start_of_data;
		ut64 page_index = offset_in_data / rebase_info->page_size;
		ut64 page_offset = offset_in_data % rebase_info->page_size;
		ut64 to_next_page = rebase_info->page_size - page_offset;

		if (page_index >= rebase_info->page_starts_count) {
			goto next_page;
		}
		ut64 delta = rebase_info->page_starts[page_index];

		if (delta == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE) {
			goto next_page;
		}

		ut64 first_rebase_off = delta;
		if (first_rebase_off >= page_offset && first_rebase_off < page_offset + count) {
			do {
				ut64 position = in_buf + first_rebase_off - page_offset;
				if (position + 8 >= count) {
					break;
				}
				ut64 raw_value = r_read_le64 (buf + position);
				delta = ((raw_value & rebase_info->delta_mask) >> rebase_info->delta_shift) * 8;
				if (position >= start_of_write) {
					ut64 new_value = 0;
					if (R_IS_PTR_AUTHENTICATED (raw_value)) {
						new_value = (raw_value & 0xFFFFFFFFULL) + rebase_info->auth_value_add;
						// TODO: don't throw auth info away
					} else {
						new_value = ((raw_value << 13) & 0xFF00000000000000ULL) | (raw_value & 0x7ffffffffffULL);
						new_value &= 0x00FFFFFFFFFFFFFFULL;
					}
					if (new_value != 0) {
						new_value += rebase_info->slide;
					}
					r_write_le64 (buf + position, new_value);
				}
				first_rebase_off += delta;
			} while (delta);
		}
next_page:
		in_buf += to_next_page;
		offset += to_next_page;
	}
}

static RDyldRebaseInfo *rebase_info_by_range(RDyldRebaseInfos *infos, ut64 offset, int count) {
	int imid;
	int imin = 0;
	int imax = infos->length - 1;

	while (imin < imax) {
		imid = (imin + imax) / 2;
		RDyldRebaseInfosEntry *entry = &infos->entries[imid];
		if ((entry->end) <= offset) {
			imin = imid + 1;
		} else {
			imax = imid;
		}
	}

	RDyldRebaseInfosEntry *minEntry = &infos->entries[imin];
	if ((imax == imin) && (minEntry->start <= offset + count) && (minEntry->end >= offset)) {
		return minEntry->info;
	}
	return NULL;
}

static void rebase_bytes(RDyldRebaseInfo *rebase_info, ut8 *buf, ut64 offset, int count, ut64 start_of_write) {
	if (!rebase_info || !buf) {
		return;
	}

	if (rebase_info->version == 3) {
		rebase_bytes_v3 ((RDyldRebaseInfo3*) rebase_info, buf, offset, count, start_of_write);
	} else if (rebase_info->version == 2 || rebase_info->version == 4) {
		rebase_bytes_v2 ((RDyldRebaseInfo2*) rebase_info, buf, offset, count, start_of_write);
	} else if (rebase_info->version == 1) {
		rebase_bytes_v1 ((RDyldRebaseInfo1*) rebase_info, buf, offset, count, start_of_write);
	}
}

static int dyldcache_io_read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	r_return_val_if_fail (io, -1);
	RCore *core = (RCore*) io->coreb.core;

	if (!core || !core->bin || !core->bin->binfiles) {
		return -1;
	}

	RDyldCache *cache = NULL;
	RListIter *iter;
	RBinFile *bf;
	r_list_foreach (core->bin->binfiles, iter, bf) {
		if (bf->fd == fd->fd ) {
			if (!strncmp ((char*) bf->o->bin_obj, "dyldcac", 7)) {
				cache = bf->o->bin_obj;
			} else {
				cache = ((struct MACH0_(obj_t)*) bf->o->bin_obj)->user;
			}
			if (pending_bin_files) {
				RListIter *to_remove = r_list_contains (pending_bin_files, bf);
				if (to_remove) {
					r_list_delete (pending_bin_files, to_remove);
					if (r_list_empty (pending_bin_files)) {
						r_list_free (pending_bin_files);
						pending_bin_files = NULL;
					}
				}
			}
			break;
		}
	}
	if (!cache) {
		r_list_foreach (pending_bin_files, iter, bf) {
			if (bf->fd == fd->fd && bf->o) {
				if (!strncmp ((char*) bf->o->bin_obj, "dyldcac", 7)) {
					cache = bf->o->bin_obj;
				} else {
					cache = ((struct MACH0_(obj_t)*) bf->o->bin_obj)->user;
				}
				break;
			}
		}
	}
	if (!cache || !cache->original_io_read) {
		if (fd->plugin->read == &dyldcache_io_read) {
			return -1;
		}
		return fd->plugin->read (io, fd, buf, count);
	}

	RDyldRebaseInfo *rebase_info = rebase_info_by_range (cache->rebase_infos, io->off, count);

	int result = 0;

	if (rebase_info && count > 0) {
		ut64 offset_in_data = io->off - rebase_info->start_of_data;
		ut64 page_offset = offset_in_data % rebase_info->page_size;

		ut64 internal_offset = io->off & ~(rebase_info->page_size - 1);
		ut64 internal_end = io->off + count;
		int rounded_count = internal_end - internal_offset;

		ut8 *internal_buf = rebase_info->one_page_buf;
		if (rounded_count > rebase_info->page_size) {
			internal_buf = malloc (rounded_count);
			if (!internal_buf) {
				R_LOG_ERROR ("Cannot allocate memory for 'internal_buf'");
				return -1;
			}
		}

		ut64 original_off = io->off;
		io->off = internal_offset;

		int internal_result = cache->original_io_read (io, fd, internal_buf, rounded_count);

		io->off = original_off;

		if (internal_result >= page_offset + count) {
			rebase_bytes (rebase_info, internal_buf, internal_offset, internal_result, page_offset);
			result = R_MIN (count, internal_result);
			memcpy (buf, internal_buf + page_offset, result);
		} else {
			R_LOG_ERROR ("rebasing");
			result = cache->original_io_read (io, fd, buf, count);
		}

		if (internal_buf != rebase_info->one_page_buf) {
			R_FREE (internal_buf);
		}
	} else {
		result = cache->original_io_read (io, fd, buf, count);
	}

	return result;
}

static void swizzle_io_read(RDyldCache *cache, RIO *io) {
	if (!io || !io->desc || !io->desc->plugin) {
		return;
	}

	RIOPlugin *plugin = io->desc->plugin;
	cache->original_io_read = plugin->read;
	plugin->read = &dyldcache_io_read;
}

static cache_hdr_t *read_cache_header(RBuffer *cache_buf, ut64 offset) {
	if (!cache_buf) {
		return NULL;
	}

	cache_hdr_t *hdr = R_NEW0 (cache_hdr_t);
	if (!hdr) {
		return NULL;
	}

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
	ut64 offset = 0;
	do {
		offsets[cache->n_hdr] = offset;
		h = read_cache_header (cache->buf, offset);
		if (!h) {
			break;
		}
		r_list_append (hdrs, h);

		ut64 size = h->codeSignatureOffset + h->codeSignatureSize;

#define SHIFT_MAYBE(x) \
	if (x) { \
		x += offset; \
	}

		SHIFT_MAYBE (h->mappingOffset);
		SHIFT_MAYBE (h->imagesOffset);
		SHIFT_MAYBE (h->codeSignatureOffset);
		SHIFT_MAYBE (h->slideInfoOffset);
		SHIFT_MAYBE (h->localSymbolsOffset);
		SHIFT_MAYBE (h->branchPoolsOffset);
		SHIFT_MAYBE (h->imagesTextOffset);

		offset += size;
		cache->n_hdr++;
	} while (cache->n_hdr < MAX_N_HDR);

	if (!cache->n_hdr) {
		goto beach;
	}

	cache->hdr = R_NEWS0 (cache_hdr_t, cache->n_hdr);
	if (!cache->hdr) {
		cache->n_hdr = 0;
		goto beach;
	}

	cache->hdr_offset = R_NEWS0 (ut64, cache->n_hdr);
	if (!cache->hdr_offset) {
		cache->n_hdr = 0;
		R_FREE (cache->hdr);
		goto beach;
	}

	memcpy (cache->hdr_offset, offsets, cache->n_hdr * sizeof (ut64));

	ut32 i = 0;
	RListIter *iter;
	cache_hdr_t *item;
	r_list_foreach (hdrs, iter, item) {
		if (i >= cache->n_hdr) {
			break;
		}
		memcpy (&cache->hdr[i++], item, sizeof (cache_hdr_t));
	}

beach:
	r_list_free (hdrs);
}

static void populate_cache_maps(RDyldCache *cache) {
	r_return_if_fail (cache && cache->buf);

	ut32 i;
	ut32 n_maps = 0;
	for (i = 0; i < cache->n_hdr; i++) {
		cache_hdr_t *hdr = &cache->hdr[i];
		if (!hdr->mappingCount || !hdr->mappingOffset) {
			continue;
		}
		n_maps += hdr->mappingCount;
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

	ut32 next_map = 0;
	for (i = 0; i < cache->n_hdr; i++) {
		cache_hdr_t *hdr = &cache->hdr[i];
		cache->maps_index[i] = next_map;

		if (!hdr->mappingCount || !hdr->mappingOffset) {
			continue;
		}
		ut64 size = sizeof (cache_map_t) * hdr->mappingCount;
		if (r_buf_fread_at (cache->buf, hdr->mappingOffset, (ut8*) &maps[next_map], "3l2i", hdr->mappingCount) != size) {
			continue;
		}
		ut32 j;
		ut64 hdr_offset = cache->hdr_offset[i];
		for (j = 0; j < hdr->mappingCount; j++) {
			cache_map_t *map = &maps[next_map + j];
			map->fileOffset += hdr_offset;
		}
		next_map += hdr->mappingCount;
	}

	cache->maps = maps;
	cache->n_maps = next_map;
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
	if (!accel) {
		return NULL;
	}

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
		if (strcmp (bin->file, "lib/libobjc.A.dylib")) {
			continue;
		}

		struct MACH0_(opts_t) opts = {0};
		opts.verbose = bf->rbin->verbose;
		opts.header_at = bin->header_at;
		opts.symbols_off = 0;

		struct MACH0_(obj_t) *mach0 = MACH0_(new_buf) (cache->buf, &opts);
		if (!mach0) {
			goto beach;
		}

		struct section_t *sections = NULL;
		if (!(sections = MACH0_(get_sections) (mach0))) {
			MACH0_(mach0_free) (mach0);
			goto beach;
		}

		int i;
		ut64 scoffs_offset = 0;
		ut64 scoffs_size = 0;
		ut64 selrefs_offset = 0;
		ut64 selrefs_size = 0;
		ut8 remaining = 2;
		ut64 slide = rebase_infos_get_slide (cache);
		for (i = 0; !sections[i].last; i++) {
			if (sections[i].size == 0) {
				continue;
			}
			if (strstr (sections[i].name, "__objc_scoffs")) {
				scoffs_offset = va2pa (sections[i].addr, cache->n_maps, cache->maps, cache->buf, slide, NULL, NULL);
				scoffs_size = sections[i].size;
				remaining--;
				if (remaining == 0) {
					break;
				}
			}
			if (strstr (sections[i].name, "__DATA.__objc_selrefs")) {
				selrefs_offset = va2pa (sections[i].addr, cache->n_maps, cache->maps, cache->buf, slide, NULL, NULL);
				selrefs_size = sections[i].size;
				remaining--;
				if (remaining == 0) {
					break;
				}
			}
		}

		MACH0_(mach0_free) (mach0);
		R_FREE (sections);

		ut64 sel_string_base = 0;
		if (!scoffs_offset || scoffs_size < 40) {
			if (!selrefs_offset || !selrefs_size || cache->n_hdr == 1) {
				break;
			}
			ut64 cursor = selrefs_offset;
			ut64 end = cursor + selrefs_size;
			while (cursor + 8 < end) {
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
			if (check != 2) {
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
		if (!result) {
			break;
		}
		result->sel_string_base = sel_string_base;
	}
beach:
	return result;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	RDyldCache *cache = R_NEW0 (RDyldCache);
	memcpy (cache->magic, "dyldcac", 7);
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
	cache->bins = create_cache_bins (bf, cache);
	if (!cache->bins) {
		r_dyldcache_free (cache);
		return false;
	}
	cache->locsym = r_dyld_locsym_new (cache);
	cache->rebase_infos = get_rebase_infos (bf, cache);
	if (cache->rebase_infos) {
		if (!rebase_infos_get_slide (cache)) {
			if (!pending_bin_files) {
				pending_bin_files = r_list_new ();
				if (!pending_bin_files) {
					r_dyldcache_free (cache);
					return false;
				}
			}
			r_list_push (pending_bin_files, bf);
			swizzle_io_read (cache, bf->rbin->iob.io);
		}
	}
	*bin_obj = cache;
	return true;
}

static RList *entries(RBinFile *bf) {
	RBinAddr *ptr = NULL;
	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}
	if ((ptr = R_NEW0 (RBinAddr))) {
		r_list_append (ret, ptr);
	}
	return ret;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = NULL;

	if (!bf || !bf->o) {
		return NULL;
	}

	RDyldCache *cache = (RDyldCache*) bf->o->bin_obj;
	if (!cache) {
		return NULL;
	}

	bool big_endian = 0;
	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
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

void symbols_from_bin(RDyldCache *cache, RList *ret, RBinFile *bf, RDyldBinImage *bin, SetU *hash) {
	struct MACH0_(obj_t) *mach0 = bin_to_mach0 (bf, bin);
	if (!mach0) {
		return;
	}

	// const RList*symbols = MACH0_(get_symbols_list) (mach0);
	const struct symbol_t *symbols = MACH0_(get_symbols) (mach0);
	if (!symbols) {
		return;
	}
	int i;
	for (i = 0; !symbols[i].last; i++) {
		if (!symbols[i].name || !symbols[i].name[0] || symbols[i].addr < 100) {
			continue;
		}
		if (strstr (symbols[i].name, "<redacted>")) {
			continue;
		}
		RBinSymbol *sym = R_NEW0 (RBinSymbol);
		if (!sym) {
			break;
		}
		sym->name = strdup (symbols[i].name);
		sym->vaddr = symbols[i].addr;
		sym->forwarder = "NONE";
		sym->bind = (symbols[i].type == R_BIN_MACH0_SYMBOL_TYPE_LOCAL)? R_BIN_BIND_LOCAL_STR: R_BIN_BIND_GLOBAL_STR;
		sym->type = R_BIN_TYPE_FUNC_STR;
		sym->paddr = symbols[i].offset + bf->o->boffset;
		sym->size = symbols[i].size;
		sym->ordinal = i;

		set_u_add (hash, sym->vaddr);
		r_list_append (ret, sym);
	}
	MACH0_(mach0_free) (mach0);
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
	RDyldCache *cache = (RDyldCache*) bf->o->bin_obj;
	if (!cache) {
		return;
	}

	struct MACH0_(obj_t) *mach0 = bin_to_mach0 (bf, bin);
	if (!mach0) {
		return;
	}

	struct section_t *sections = NULL;
	if (!(sections = MACH0_(get_sections) (mach0))) {
		return;
	}

	ut64 slide = rebase_infos_get_slide (cache);
	int i;
	for (i = 0; !sections[i].last; i++) {
		RBinSection *ptr = R_NEW0 (RBinSection);
		if (!ptr) {
			break;
		}
		if (bin->file) {
			ptr->name = r_str_newf ("%s.%s", bin->file, (char*)sections[i].name);
		} else {
			ptr->name = r_str_newf ("%s", (char*)sections[i].name);
		}
		if (strstr (ptr->name, "la_symbol_ptr")) {
			int len = sections[i].size / 8;
			ptr->format = r_str_newf ("Cd %d[%d]", 8, len);
		}
		ptr->is_data = __is_data_section (ptr->name);
		ptr->size = sections[i].size;
		ptr->vsize = sections[i].vsize;
		ptr->vaddr = sections[i].addr;
		ptr->paddr = va2pa (sections[i].addr, cache->n_maps, cache->maps, cache->buf, slide, NULL, NULL);
		if (!ptr->vaddr) {
			ptr->vaddr = ptr->paddr;
		}
		ptr->perm = sections[i].perm;
		r_list_append (ret, ptr);
	}
	free (sections);
	MACH0_(mach0_free) (mach0);
}

static RList *sections(RBinFile *bf) {
	RDyldCache *cache = (RDyldCache*) bf->o->bin_obj;
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
	RConsIsBreaked is_breaked = (bf->rbin && bf->rbin->consb.is_breaked)? bf->rbin->consb.is_breaked: NULL;
	r_list_foreach (cache->bins, iter, bin) {
		i++;
		if (is_breaked && is_breaked ()) {
			eprintf ("Parsing sections stopped %d / %d\n", i, r_list_length (cache->bins));
			break;
		}
		sections_from_bin (ret, bf, bin);
	}

	RBinSection *ptr = NULL;
	for (i = 0; i < cache->n_maps; i++) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			r_list_free (ret);
			return NULL;
		}
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

	return ret;
}

static RList *symbols(RBinFile *bf) {
	RDyldCache *cache = (RDyldCache*) bf->o->bin_obj;
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
	RConsIsBreaked is_breaked = (bf->rbin && bf->rbin->consb.is_breaked)? bf->rbin->consb.is_breaked: NULL;
	r_list_foreach (cache->bins, iter, bin) {
		i++;
		if (is_breaked && is_breaked ()) {
			eprintf ("Parsing symbols stopped %d / %d\n", i, r_list_length (cache->bins));
			break;
		}
		SetU *hash = set_u_new ();
		if (!hash) {
			r_list_free (ret);
			return NULL;
		}
		symbols_from_bin (cache, ret, bf, bin, hash);
		symbols_from_locsym (cache, bin, ret, hash);
		set_u_free (hash);
	}

	ut64 slide = rebase_infos_get_slide (cache);
	if (slide) {
		RBinSymbol *sym;
		r_list_foreach (ret, iter, sym) {
			sym->vaddr += slide;
		}
	}

	return ret;
}

/* static void unswizzle_io_read(RDyldCache *cache, RIO *io) {
	if (!io || !io->desc || !io->desc->plugin || !cache->original_io_read) {
		return;
	}

	RIOPlugin *plugin = io->desc->plugin;
	plugin->read = cache->original_io_read;
	cache->original_io_read = NULL;
} */

static void destroy(RBinFile *bf) {
	RDyldCache *cache = (RDyldCache*) bf->o->bin_obj;
	// unswizzle_io_read (cache, bf->rbin->iob.io); // XXX io may be dead here
	r_dyldcache_free (cache);
}

static RList *classes(RBinFile *bf) {
	RDyldCache *cache = (RDyldCache*) bf->o->bin_obj;
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
	RConsIsBreaked is_breaked = (bf->rbin && bf->rbin->consb.is_breaked)? bf->rbin->consb.is_breaked: NULL;
	r_list_foreach (cache->bins, iter, bin) {
		i++;
		if (is_breaked && is_breaked ()) {
			eprintf ("Parsing classes stopped %d / %d\n", i, r_list_length (cache->bins));
			break;
		}
		struct MACH0_(obj_t) *mach0 = bin_to_mach0 (bf, bin);
		if (!mach0) {
			goto beach;
		}

		struct section_t *sections = NULL;
		if (!(sections = MACH0_(get_sections) (mach0))) {
			MACH0_(mach0_free) (mach0);
			goto beach;
		}

		int i;
		for (i = 0; !sections[i].last; i++) {
			if (sections[i].size == 0) {
				continue;
			}

			bool is_classlist = strstr (sections[i].name, "__objc_classlist");
			bool is_catlist = strstr (sections[i].name, "__objc_catlist");

			if (!is_classlist && !is_catlist) {
				continue;
			}

			ut8 *pointers = malloc (sections[i].size);
			if (!pointers) {
				continue;
			}

			ut64 offset = va2pa (sections[i].addr, cache->n_maps, cache->maps, cache->buf, slide, NULL, NULL);
			if (r_buf_read_at (cache->buf, offset, pointers, sections[i].size) < sections[i].size) {
				R_FREE (pointers);
				continue;
			}
			ut8 *cursor = pointers;
			ut8 *pointers_end = pointers + sections[i].size;

			for (; cursor < pointers_end; cursor += 8) {
				ut64 pointer_to_class = r_read_le64 (cursor);

				RBinClass *klass;
				if (!(klass = R_NEW0 (RBinClass)) ||
					!(klass->methods = r_list_new ()) ||
					!(klass->fields = r_list_new ())) {
					R_FREE (klass);
					R_FREE (pointers);
					R_FREE (sections);
					MACH0_(mach0_free) (mach0);
					goto beach;
				}

				bf->o->bin_obj = mach0;
				bf->buf = cache->buf;
				if (is_classlist) {
					MACH0_(get_class_t) (pointer_to_class, bf, klass, false, NULL, cache->oi);
				} else {
					MACH0_(get_category_t) (pointer_to_class, bf, klass, NULL, cache->oi);
				}
				bf->o->bin_obj = cache;
				bf->buf = orig_buf;

				if (!klass->name) {
					if (bf->rbin->verbose) {
						eprintf ("KLASS ERROR AT 0x%"PFMT64x", is_classlist %d\n", pointer_to_class, is_classlist);
					}
					klass->name = r_str_newf ("UnnamedClass%u", num_of_unnamed_class);
					if (!klass->name) {
						R_FREE (klass);
						R_FREE (pointers);
						R_FREE (sections);
						MACH0_(mach0_free) (mach0);
						goto beach;
					}
					num_of_unnamed_class++;
				}
				r_list_append (ret, klass);
			}

			R_FREE (pointers);
		}

		R_FREE (sections);
		MACH0_(mach0_free) (mach0);
	}

	return ret;

beach:
	r_list_free (ret);
	return NULL;
}

static void header(RBinFile *bf) {
	if (!bf || !bf->o) {
		return;
	}

	RDyldCache *cache = (RDyldCache*) bf->o->bin_obj;
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

	if (cache->rebase_infos) {
		size_t i;
		pj_k (pj, "slideInfo");
		pj_a (pj);
		for (i = 0; i < cache->rebase_infos->length; i++) {
			RDyldRebaseInfo * rebase_info = cache->rebase_infos->entries[i].info;
			pj_o (pj);
			pj_kn (pj, "start", cache->rebase_infos->entries[i].start);
			pj_kn (pj, "end", cache->rebase_infos->entries[i].end);
			if (rebase_info) {
				ut8 version = rebase_info->version;
				pj_kn (pj, "version", version);
				pj_kn (pj, "slide", slide);
				if (version == 3) {
					RDyldRebaseInfo3 *info3 = (RDyldRebaseInfo3*) rebase_info;
					pj_kn (pj, "page_starts_count", info3->page_starts_count);
					pj_kn (pj, "page_size", info3->page_size);
					pj_kn (pj, "auth_value_add", info3->auth_value_add);
				} else if (version == 2 || version == 4) {
					RDyldRebaseInfo2 *info2 = (RDyldRebaseInfo2*) rebase_info;
					pj_kn (pj, "page_starts_count", info2->page_starts_count);
					pj_kn (pj, "page_extras_count", info2->page_extras_count);
					pj_kn (pj, "delta_mask", info2->delta_mask);
					pj_kn (pj, "value_mask", info2->value_mask);
					pj_kn (pj, "value_add", info2->value_add);
					pj_kn (pj, "delta_shift", info2->delta_shift);
					pj_kn (pj, "page_size", info2->page_size);
				} else if (version == 1) {
					RDyldRebaseInfo1 *info1 = (RDyldRebaseInfo1*) rebase_info;
					pj_kn (pj, "toc_count", info1->toc_count);
					pj_kn (pj, "entries_size", info1->entries_size);
					pj_kn (pj, "page_size", 4096);
				}
			}
			pj_end (pj);
		}
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
	.name = "dyldcache",
	.desc = "dyldcache bin plugin",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.entries = &entries,
	.baddr = &baddr,
	.symbols = &symbols,
	.sections = &sections,
	.minstrlen = 5,
	.check_buffer = &check_buffer,
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
