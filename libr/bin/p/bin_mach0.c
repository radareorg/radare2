/* radare - LGPL - Copyright 2009-2026 - pancake */

#include <r_core.h>
#include "../i/private.h"
#include "mach0/mach0.h"
#include "objc/mach0_classes.h"
#include <sdb/ht_uu.h>

R_VEC_TYPE (RVecExtReloc, struct reloc_t *);

typedef struct {
	ut8 *chunk;
	ut64 off;
	ut64 size;
	ut64 chunk_addr;
	ut64 chunk_size;
	ut64 chunk_capacity;
	bool chunk_dirty;
	bool chunk_valid;
	bool failed;
	struct MACH0_(obj_t) *obj;
} RFixupRebaseContext;

extern RBinWrite r_bin_write_mach0;

static bool rebase_buffer_callback2(void * context, RFixupEventDetails * event_details);
static RBinInfo *info(RBinFile *bf);
static RBuffer *swizzle_io_read(RBinFile *bf, struct MACH0_(obj_t) *obj, RIO *io);

#define IS_PTR_AUTH(x) ((x & (1ULL << 63)) != 0)
#define IS_PTR_BIND(x) ((x & (1ULL << 62)) != 0)

static Sdb *get_sdb(RBinFile *bf) {
	struct MACH0_(obj_t) *mo = (struct MACH0_(obj_t) *) R_UNWRAP3 (bf, bo, bin_obj);
	return mo? mo->kv: NULL;
}

static char *entitlements(RBinFile *bf, bool json) {
	struct MACH0_(obj_t) *mo = R_UNWRAP3 (bf, bo, bin_obj);
	if (!mo) {
		return NULL;
	}
	const char *xml = (const char *)mo->signature;
	char *der = NULL;
	if (mo->signature_der && mo->signature_der_size) {
		RAsn1 *a = r_asn1_new (mo->signature_der, (int)mo->signature_der_size, json? 'j': 0);
		if (a) {
			der = r_asn1_tostring (a);
			r_asn1_free (a);
		}
	}
	if (!xml && !der) {
		return NULL;
	}
	char *res = NULL;
	if (json) {
		PJ *pj = pj_new ();
		if (xml && der) {
			pj_o (pj);
			pj_ks (pj, "plist", xml);
			pj_k (pj, "der");
			pj_j (pj, der);
			pj_end (pj);
		} else if (xml) {
			pj_s (pj, xml);
		} else {
			pj_o (pj);
			pj_k (pj, "der");
			pj_j (pj, der);
			pj_end (pj);
		}
		res = pj_drain (pj);
	} else if (xml && der) {
		res = r_str_newf ("%s\n;; DER entitlements (slot 7, magic 0xfade7172)\n%s", xml, der);
	} else if (xml) {
		res = strdup (xml);
	} else {
		res = r_str_newf (";; DER entitlements (slot 7, magic 0xfade7172)\n%s", der);
	}
	free (der);
	return res;
}

// TODO: remove laddr, just pass RBinFileOptions which should be inside rbinfile
static bool load(RBinFile *bf, RBuffer *buf, ut64 laddr) {
	R_RETURN_VAL_IF_FAIL (bf && buf, false);
	struct MACH0_(opts_t) opts;
	MACH0_(opts_set_default) (&opts, bf);
	opts.parse_start_symbols = true;

	struct MACH0_(obj_t) *mo = MACH0_(new_buf) (bf, buf, &opts);
	if (mo) {
		bf->bo->bin_obj = mo;
		if (mo->chained_starts) {
			RIO *io = bf->rbin->iob.io;
			RBuffer *nb = swizzle_io_read (bf, mo, io);
			if (nb != bf->buf) {
				r_unref (bf->buf);
			}
			bf->buf = nb;
		}
		sdb_ns_set (bf->sdb, "info", mo->kv);
		return true;
	}
	return false;
}

static void destroy(RBinFile *bf) {
	MACH0_(mach0_free) (bf->bo->bin_obj);
}

static ut64 baddr(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, UT64_MAX);
	struct MACH0_(obj_t) *mo = bf->bo->bin_obj;
	return MACH0_(get_baddr)(mo);
}

static bool sections_vec(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, false);
	struct MACH0_(obj_t) *mo = bf->bo->bin_obj;
	RVecSegment *segments = MACH0_(get_segments_vec) (bf, mo);
	if (!segments) {
		return false;
	}
	RVecRBinSection *dst_sections = &bf->bo->sections_vec;
	RVecRBinSection_clear (dst_sections);
	if (!RVecRBinSection_reserve (dst_sections, RVecSegment_length (segments))) {
		return false;
	}
	RBinSection *section;
	R_VEC_FOREACH (segments, section) {
		RBinSection *dst = RVecRBinSection_emplace_back (dst_sections);
		*dst = *section;
		dst->name = section->name? strdup (section->name): NULL;
		dst->format = section->format? strdup (section->format): NULL;
	}
	return true;
}

static RBinAddr *newEntry(ut64 hpaddr, ut64 paddr, int type, int bits) {
	RBinAddr *ptr = R_NEW0 (RBinAddr);
	ptr->paddr = paddr;
	ptr->vaddr = paddr;
	ptr->hpaddr = hpaddr;
	ptr->bits = bits;
	ptr->type = type;
	// realign due to thumb
	if (bits == 16 && ptr->vaddr & 1) {
		// TODO add hint about thumb entrypoint
		ptr->paddr--;
		ptr->vaddr--;
	}
	return ptr;
}

static void process_constructors(RBinFile *bf, RList *ret, int bits, int limit) {
	struct MACH0_(obj_t) *mo = bf->bo->bin_obj;
	RVecSegment *secs = MACH0_(get_segments_vec) (bf, mo);
	RBinSection *sec;
	int i, type;
	R_VEC_FOREACH (secs, sec) {
		if (sec->is_segment) {
			continue;
		}
		if (limit_reached (ret, limit)) {
			break;
		}
		type = -1;
		if (strstr (sec->name, "_mod_fini_func")) {
			type  = R_BIN_ENTRY_TYPE_FINI;
		} else if (strstr (sec->name, "_mod_init_func")) {
			type  = R_BIN_ENTRY_TYPE_INIT;
		}
		if (type != -1) {
			if (sec->size == 0 || sec->size > ST32_MAX) {
				continue;
			}
			int ss = sec->size;
			ut8 *buf = calloc (ss, 1);
			if (!buf) {
				continue;
			}
			ut64 nread = r_buf_read_at (bf->buf, sec->paddr, buf, ss);
			if (nread < sec->size) {
				R_LOG_ERROR ("process_constructors: cannot process section %s", sec->name);
				free (buf);
				continue;
			}
			if (bits == 32) {
				for (i = 0; i + 3 < ss; i += 4) {
					if (limit_reached (ret, limit)) {
						break;
					}
					ut32 addr32 = r_read_le32 (buf + i);
					RBinAddr *ba = newEntry (sec->paddr + i, (ut64)addr32, type, bits);
					r_list_append (ret, ba);
				}
			} else {
				for (i = 0; i + 7 < ss; i += 8) {
					if (limit_reached (ret, limit)) {
						break;
					}
					ut64 addr64 = r_read_le64 (buf + i);
					RBinAddr *ba = newEntry (sec->paddr + i, addr64, type, bits);
					r_list_append (ret, ba);
				}
			}
			free (buf);
		}
	}
}

static RList *entries(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);

	RBinObject *bo = bf->bo;
	struct MACH0_(obj_t) *mo = bo->bin_obj;
	struct addr_t *entry = NULL;
	int limit = bf->rbin->options.limit;

	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}

	int bits = MACH0_(get_bits) (mo);
	if (!(entry = MACH0_(get_entrypoint) (mo))) {
		return ret;
	}
	RBinAddr *ptr = R_NEW0 (RBinAddr);
	ptr->paddr = entry->offset + bo->boffset;
	ptr->vaddr = entry->addr;
	ptr->hpaddr = entry->haddr;
	ptr->bits = bits;
	//realign due to thumb
	if (bits == 16) {
		if (ptr->vaddr & 1) {
			ptr->paddr--;
			ptr->vaddr--;
		}
	}
	r_list_append (ret, ptr);

	if (!limit_reached (ret, limit)) {
		process_constructors (bf, ret, bits, limit);
	}
	// constructors
	free (entry);
	return ret;
}

static bool symbols_vec(RBinFile *bf) {
	struct MACH0_(obj_t) *mo = R_UNWRAP3 (bf, bo, bin_obj);
	if (R_LIKELY (mo)) {
		if (MACH0_(load_symbols) (mo)) {
			return !RVecRBinSymbol_empty (&bf->bo->symbols_vec);
		}
	}
	return false;
}

static RBinImport *import_from_name(RBin *rbin, const char *orig_name, HtPP *imports_by_name) {
	if (!imports_by_name) {
		return NULL;
	}
	bool found = false;
	RBinImport *ptr = ht_pp_find (imports_by_name, orig_name, &found);
	if (found) {
		return ptr;
	}

	ptr = R_NEW0 (RBinImport);

	char *name = (char*) orig_name;
	const char *const _objc_class = "_OBJC_CLASS_$";
	const char *const _objc_metaclass = "_OBJC_METACLASS_$";
	const char *type = "FUNC";

	if (r_str_startswith (name, _objc_class)) {
		name += strlen (_objc_class);
		type = "OBJC_CLASS";
	} else if (r_str_startswith (name, _objc_metaclass)) {
		name += strlen (_objc_metaclass);
		type = "OBJC_METACLASS";
	}

	// Remove the extra underscore that every import seems to have in Mach-O.
	if (*name == '_') {
		name++;
	}
	ptr->name = r_bin_name_new (name);
	ptr->bind = "NONE";
	ptr->type = r_str_constpool_get (&rbin->constpool, type);

	ht_pp_insert (imports_by_name, orig_name, ptr);

	return ptr;
}

static bool imports_vec(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, false);
	RBinObject *bo = bf->bo;
	if (!RVecRBinImport_empty (&bo->imports_vec)) {
		return true;
	}
	struct MACH0_(obj_t) *mo = bo->bin_obj;
	RVecRBinImport *imports = MACH0_(load_imports) (bf, mo);
	if (!imports) {
		return false;
	}
	// Transfer ownership: swap vectors and reset source
	bo->imports_vec = mo->imports_cache;
	RVecRBinImport_init (&mo->imports_cache);
	mo->imports_loaded = false;
	return true;
}

static RVecRBinReloc *relocs(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	struct MACH0_(obj_t) *mo = bf->bo->bin_obj;
	const RSkipList *relocs = MACH0_(load_relocs) (mo);
	if (!relocs) {
		return NULL;
	}
	RVecRBinReloc *ret = RVecRBinReloc_new ();

	RVecRBinImport *imports = mo->imports_loaded
		? &mo->imports_cache
		: &bf->bo->imports_vec;
	RSkipListNode *it;
	struct reloc_t *reloc;
	r_skiplist_foreach (relocs, it, reloc) {
		if (reloc->external) {
			continue;
		}
		RBinReloc *ptr = RVecRBinReloc_emplace_back (ret);
		ptr->type = reloc->type;
		ptr->ntype = reloc->ntype;
		RBinImport *imp = NULL;
		if (reloc->name[0]) {
			imp = import_from_name (bf->rbin, (char*) reloc->name, mo->imports_by_name);
		} else if (reloc->ord >= 0) {
			imp = RVecRBinImport_at (imports, reloc->ord);
		}
		if (imp) {
			ptr->import = r_bin_import_clone (imp);
		}
		ptr->addend = reloc->addend;
		ptr->vaddr = reloc->addr;
		ptr->paddr = reloc->offset;
	}
	RBinReloc *r;
	R_VEC_FOREACH (&mo->reloc_fixups, r) {
		RBinReloc *ptr = RVecRBinReloc_emplace_back (ret);
		ptr->type = R_BIN_RELOC_64;
		ptr->ntype = r->ntype;
		ptr->vaddr = r->paddr + mo->baddr;
		ptr->paddr = r->vaddr;
		ptr->addend = r->vaddr;
	}
	return ret;
}

static RList *libs(RBinFile *bf) {
	RBinObject *obj = bf ? bf->bo : NULL;
	if (!obj) {
		return NULL;
	}
	const int limit = bf->rbin->options.limit;
	const RVecMach0Lib *libs = MACH0_(load_libs) (obj->bin_obj);
	if (!libs) {
		return NULL;
	}

	RList *result = r_list_new ();
	if (!result) {
		return NULL;
	}
	char **it;
	R_VEC_FOREACH (libs, it) {
		if (limit_reached (result, limit)) {
			break;
		}
		r_list_append (result, *it);
	}
	return result;
}

static RBinInfo *info(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	struct MACH0_(obj_t) *mo = bf->bo->bin_obj;
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (bf->file) {
		ret->file = strdup (bf->file);
	}
	ret->bclass = MACH0_(get_class) (mo);
	ret->has_canary = mo->has_canary;
	ret->has_retguard = -1;
	ret->has_sanitizers = mo->has_sanitizers;
	ret->has_libinjprot = mo->has_libinjprot;
	ret->dbg_info = mo->dbg_info;
	ret->lang = mo->lang;
	struct dyld_info_command *di = mo->dyld_info;
	if (di) {
		ut64 allbinds = 0;
		if ((int)di->bind_size > 0) {
			allbinds += di->bind_size;
		}
		if ((int)di->lazy_bind_size > 0) {
			allbinds += di->lazy_bind_size;
		}
		if ((int)di->weak_bind_size > 0) {
			allbinds += di->weak_bind_size;
		}
		if (allbinds > 0) {
			ret->dbg_info |= R_BIN_DBG_RELOCS;
		}
	}
	const char *intrp = MACH0_(get_intrp) (mo);
	ret->intrp = intrp? strdup (intrp): NULL;
	ret->compiler = strdup ("clang");
	ret->rclass = strdup ("mach0");
	ret->os = strdup (MACH0_(get_os) (mo));
	ret->subsystem = strdup ("darwin");
	ret->arch = strdup (MACH0_(get_cputype) (mo));
	ret->machine = MACH0_(get_cpusubtype) (mo);
	ret->has_lit = true;
	ret->type = MACH0_(get_filetype) (mo);
	ret->big_endian = MACH0_(is_big_endian) (mo);
	ret->has_crypto = mo->has_crypto;
	ret->bits = MACH0_(get_bits) (mo);
	ret->has_va = true;
	ret->has_pi = MACH0_(is_pie) (mo);
	ret->has_nx = MACH0_(has_nx) (mo);
	return ret;
}

static bool _patch_reloc(struct MACH0_(obj_t) *mo, RIOBind *iob, struct reloc_t *reloc, ut64 symbol_at) {
	ut64 pc = reloc->addr;
	ut64 ins_len = 0;

	switch (mo->hdr.cputype) {
	case CPU_TYPE_X86_64:
		switch (reloc->type) {
		case X86_64_RELOC_UNSIGNED:
			break;
		case X86_64_RELOC_BRANCH:
			pc--;
			ins_len = 5;
			break;
		default:
			R_LOG_WARN ("unsupported reloc type for X86_64 (%d), please file a bug", reloc->type);
			return false;
		}
		break;
	case CPU_TYPE_ARM64:
	case CPU_TYPE_ARM64_32:
		pc = reloc->addr & ~3;
		ins_len = 4;
		break;
	case CPU_TYPE_ARM:
		break;
	default:
		R_LOG_WARN ("unsupported architecture for patching relocs, please file a bug. %s",
				MACH0_(get_cputype_from_hdr)(&mo->hdr));
		return false;
	}

	ut64 val = reloc->pc_relative ? symbol_at - pc - ins_len : symbol_at;

	ut8 buf[8];
	r_write_ble (buf, val, false, reloc->size * 8);
	if (reloc->size < 1) {
		R_LOG_WARN ("invalid reloc size %d at 0x%08"PFMT64x, reloc->size, reloc->addr);
		return false;
	}
	if (!iob->overlay_write_at (iob->io, reloc->addr, buf, reloc->size)) {
		R_LOG_WARN ("cannot write reloc at 0x%"PFMT64x, reloc->addr);
		return false;
	}
	return true;
}

static RVecRBinReloc *patch_relocs(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin, NULL);

	RVecRBinReloc *ret = NULL;
	RIOMap *g = NULL;
	HtUU *relocs_by_sym = NULL;
	RIODesc *gotr2desc = NULL;

	RBin *b = bf->rbin;
	RIOBind *iob = &b->iob;
	RIO *io = iob->io;
	if (!io || !io->desc) {
		return NULL;
	}

	RBinObject *obj = r_bin_cur_object (b);
	if (!obj || !obj->bin_obj) {
		return NULL;
	}
	struct MACH0_(obj_t) *mo = obj->bin_obj;

	const RSkipList *all_relocs = MACH0_(load_relocs)(mo);
	if (!all_relocs) {
		return NULL;
	}
	RVecExtReloc ext_relocs;
	RVecExtReloc_init (&ext_relocs);
	RSkipListNode *it;
	struct reloc_t *reloc;
	r_skiplist_foreach (all_relocs, it, reloc) {
		if (!reloc->external) {
			continue;
		}
		RVecExtReloc_push_back (&ext_relocs, &reloc);
	}
#if 1
	// XXX for some reason we are patching this twice as relocs and fixups
	// may be good to find out why and comment back this code with an if0
	// fixups are now considered part of the relocs listing
	RVecRBinReloc *fixups = &mo->reloc_fixups;
	size_t relocs_count = RVecRBinReloc_length (fixups);
	if (relocs_count > 0) {
		ut8 buf[8], obuf[8];
		RBinReloc *r;

		size_t count = relocs_count;
		if (mo->limit > 0) {
			if (relocs_count > (size_t)mo->limit) {
				R_LOG_WARN ("mo.limit for relocs");
			}
			count = mo->limit;
		}
		R_VEC_FOREACH (fixups, r) {
			if (count-- == 0) {
				break;
			}
			ut64 paddr = r->paddr + mo->baddr;
			r_write_ble64 (buf, r->vaddr, false);
			iob->read_at (io, paddr, obuf, 8);
			if (memcmp (buf, obuf, 8)) {
				if (!iob->overlay_write_at (io, paddr, buf, 8)) {
					R_LOG_ERROR ("write error at 0x%"PFMT64x, paddr);
				}
			}
		}
	}
#endif
	ut64 num_ext_relocs = RVecExtReloc_length (&ext_relocs);
	if (!num_ext_relocs) {
		goto beach;
	}

	const int cdsz = obj->info ? obj->info->bits / 8 : 8;

	ut64 offset = 0;
	RIOBank *bank = iob->bank_get (io, io->bank);
	RListIter *iter;
	RIOMapRef *mapref;
	r_list_foreach (bank->maprefs, iter, mapref) {
		RIOMap *map = iob->map_get (io, mapref->id);
		if (r_io_map_from (map) > offset) {
			offset = r_io_map_from (map);
			g = map;
		}
	}
	if (!g) {
		R_LOG_WARN ("no maps for these territories");
		goto beach;
	}
	ut64 n_vaddr = g->itv.addr + g->itv.size;
	ut64 size = num_ext_relocs * cdsz;
	char *muri = r_str_newf ("malloc://%" PFMT64u, size);
	gotr2desc = iob->open_at (io, muri, R_PERM_R, 0664, n_vaddr);
	free (muri);
	if (!gotr2desc) {
		goto beach;
	}

	RIOMap *gotr2map = iob->map_get_at (io, n_vaddr);
	if (!gotr2map) {
		R_LOG_WARN ("no maps for 0x%"PFMT64x, n_vaddr);
		goto beach;
	}
	gotr2map->name = strdup (".got.r2");

	if (!(ret = RVecRBinReloc_new ())) {
		goto beach;
	}
	if (!(relocs_by_sym = ht_uu_new0 ())) {
		goto beach;
	}
	ut64 vaddr = n_vaddr;
	struct reloc_t **ext_reloc_iter;
	R_VEC_FOREACH (&ext_relocs, ext_reloc_iter) {
		reloc = *ext_reloc_iter;
		bool found = false;
		ut64 sym_addr = ht_uu_find (relocs_by_sym, reloc->ord, &found);
		if (!found || !sym_addr) {
			sym_addr = vaddr;
			ht_uu_insert (relocs_by_sym, reloc->ord, vaddr);
			vaddr += cdsz;
		}
		if (!_patch_reloc (mo, iob, reloc, sym_addr)) {
			continue;
		}
		RBinImport *imp = import_from_name (b, (char*) reloc->name, mo->imports_by_name);
		if (R_LIKELY (imp)) {
			RBinReloc *ptr = RVecRBinReloc_emplace_back (ret);
			ptr->type = reloc->type;
			ptr->ntype = reloc->ntype;
			ptr->vaddr = sym_addr;
			ptr->import = r_bin_import_clone (imp);
		}
	}
	if (RVecRBinReloc_empty (ret)) {
		goto beach;
	}
	ht_uu_free (relocs_by_sym);
	RVecExtReloc_fini (&ext_relocs);
	// XXX r_io_desc_free (gotr2desc);
	return ret;

beach:
	RVecExtReloc_fini (&ext_relocs);
	r_io_desc_free (gotr2desc);
	RVecRBinReloc_free (ret);
	ht_uu_free (relocs_by_sym);
	return NULL;
}

#define MACH0_SWIZZLE_DEFAULT_PAGE_SIZE 0x1000

static ut64 swizzle_max_fixup_page_size(struct MACH0_(obj_t) *obj) {
	ut64 chunk_capacity = MACH0_SWIZZLE_DEFAULT_PAGE_SIZE;
	if (!obj->chained_starts) {
		return chunk_capacity;
	}
	int i;
	int count = R_MIN (obj->nsegs, obj->segs_count);
	for (i = 0; i < count; i++) {
		struct r_dyld_chained_starts_in_segment *starts = obj->chained_starts[i];
		if (!starts || !starts->page_start || !starts->page_count) {
			continue;
		}
		ut64 page_size = starts->page_size? starts->page_size: MACH0_SWIZZLE_DEFAULT_PAGE_SIZE;
		chunk_capacity = R_MAX (chunk_capacity, page_size);
	}
	return chunk_capacity;
}

static bool flush_rebase_buffer_chunk(RFixupRebaseContext *ctx) {
	if (ctx->chunk_valid && ctx->chunk_dirty) {
		if (r_buf_write_at (ctx->obj->b, ctx->chunk_addr, ctx->chunk, ctx->chunk_size) < 1) {
			ctx->failed = true;
			return false;
		}
		ctx->chunk_dirty = false;
	}
	return true;
}

static ut8 *rebase_buffer_chunk_ptr(RFixupRebaseContext *ctx, ut64 in_buf, ut32 len) {
	if (len < 1 || in_buf >= ctx->size || len > ctx->size - in_buf) {
		ctx->failed = true;
		return NULL;
	}
	ut64 chunk_off = in_buf % ctx->chunk_capacity;
	ut64 chunk_addr = in_buf - chunk_off;
	if (len > ctx->chunk_capacity - chunk_off) {
		R_LOG_WARN ("chained fixup at 0x%"PFMT64x" straddles swizzle chunk boundary", in_buf);
		chunk_addr = in_buf;
		chunk_off = 0;
	}
	if (!ctx->chunk_valid || ctx->chunk_addr != chunk_addr) {
		if (!flush_rebase_buffer_chunk (ctx)) {
			return NULL;
		}
		if (!ctx->chunk) {
			ctx->chunk = malloc (ctx->chunk_capacity);
			if (!ctx->chunk) {
				ctx->failed = true;
				return NULL;
			}
		}
		ctx->chunk_addr = chunk_addr;
		ctx->chunk_size = R_MIN (ctx->chunk_capacity, ctx->size - chunk_addr);
		if (r_buf_read_at (ctx->obj->b, chunk_addr, ctx->chunk, ctx->chunk_size) != ctx->chunk_size) {
			ctx->failed = true;
			return NULL;
		}
		ctx->chunk_valid = true;
	}
	return ctx->chunk + chunk_off;
}

static RBuffer *swizzle_io_read(RBinFile *bf, struct MACH0_(obj_t) *obj, RIO *io) {
	(void)bf;
	R_RETURN_VAL_IF_FAIL (io && io->desc && io->desc->plugin, NULL);
	RFixupRebaseContext ctx = {0};
	RBuffer *nb = r_buf_new_with_cache (obj->b, false);
	if (!nb) {
		return obj->b;
	}
	RBuffer *ob = obj->b;
	obj->b = nb;
	ut64 count = r_buf_size (obj->b);
	ut64 off = 0;
	ctx.obj = obj;
	ctx.off = off;
	ctx.size = count;
	ctx.chunk_capacity = swizzle_max_fixup_page_size (obj);
	MACH0_(iterate_chained_fixups) (obj, off, off + count,
		R_FIXUP_EVENT_MASK_ALL, &rebase_buffer_callback2, &ctx);
	flush_rebase_buffer_chunk (&ctx);
	free (ctx.chunk);
	if (ctx.failed) {
		obj->b = ob;
		r_unref (nb);
		return ob;
	}
	obj->b = ob;
//	bf->buf = nb; // ???
	return nb;
}

static void add_fixup(RVecRBinReloc *fixups, ut64 addr, ut64 value) {
	if (!fixups) {
		return;
	}
	RBinReloc *r = RVecRBinReloc_emplace_back (fixups);
	r->type = R_BIN_RELOC_64;
	r->vaddr = value;
	r->paddr = addr;
}

static bool rebase_buffer_callback2(void *context, RFixupEventDetails * event_details) {
	RFixupRebaseContext *ctx = context;
	struct MACH0_(obj_t) *obj = ctx->obj;
	const ut32 psz = event_details->ptr_size;
	ut64 in_buf = event_details->offset - ctx->off;
	if (psz != 4 && psz != 8) {
		R_LOG_WARN ("rebase_buffer_callback2: invalid ptr_size %u, skipping", psz);
		return false;
	}
	RVecRBinReloc *rflist = &obj->reloc_fixups;
	switch (event_details->type) {
	case R_FIXUP_EVENT_BIND:
	case R_FIXUP_EVENT_BIND_AUTH:
		{
			ut8 *data = rebase_buffer_chunk_ptr (ctx, in_buf, psz);
			if (!data) {
				return false;
			}
			memset (data, 0, psz);
			ctx->chunk_dirty = true;
			add_fixup (rflist, in_buf, 0);
		}
		break;
	case R_FIXUP_EVENT_REBASE:
	case R_FIXUP_EVENT_REBASE_AUTH:
		{
			ut8 *data = rebase_buffer_chunk_ptr (ctx, in_buf, psz);
			if (!data) {
				return false;
			}
			ut64 v = event_details->ptr_value;
			add_fixup (rflist, in_buf, v);
			r_write_ble (data, v, false, psz * 8);
			ctx->chunk_dirty = true;
		}
		break;
	default:
		R_LOG_ERROR ("Unexpected event while rebasing buffer");
		return false;
	}

	return true;
}

static RList *classes(RBinFile *bf) {
	// 8s / 16s
	return MACH0_(parse_classes) (bf, NULL);
}

static bool load_resources(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, false);
	struct MACH0_(obj_t) *mo = bf->bo->bin_obj;
	RVecSegment *sections = MACH0_(get_segments_vec) (bf, mo);
	if (!sections) {
		return false;
	}
	ut32 index = 0;
	RBinSection *section;
	R_VEC_FOREACH (sections, section) {
		const char *type = NULL;
		if (strstr (section->name, ".__TEXT.__info_plist")) {
			type = "plist";
		} else if (strstr (section->name, ".__TEXT.__launchd_plist")) {
			type = "launchd_plist";
		} else if (strstr (section->name, ".__TEXT.__entitlements")) {
			type = "entitlements";
		}
		if (!type || !section->size) {
			continue;
		}
		RBinResource *resource = RVecRBinResource_emplace_back (&bf->bo->resources_vec);
		if (!resource) {
			return false;
		}
		resource->name = strdup (section->name);
		resource->type = strdup (type);
		resource->paddr = section->paddr;
		resource->vaddr = section->vaddr;
		resource->size = section->size;
		resource->id = UT64_MAX;
		resource->index = index++;
		resource->type_id = UT32_MAX;
		resource->language_id = UT32_MAX;
		resource->named = true;
	}
	if (mo->cs_present && mo->cs_size) {
		RBinResource *resource = RVecRBinResource_emplace_back (&bf->bo->resources_vec);
		if (!resource) {
			return false;
		}
		resource->name = strdup ("CodeSignature");
		resource->type = strdup ("signature");
		resource->paddr = mo->cs_paddr;
		resource->vaddr = mo->cs_paddr;
		resource->size = mo->cs_size;
		resource->id = UT64_MAX;
		resource->index = index++;
		resource->type_id = UT32_MAX;
		resource->language_id = UT32_MAX;
		resource->named = true;
		if (mo->cert_size) {
			resource = RVecRBinResource_emplace_back (&bf->bo->resources_vec);
			if (!resource) {
				return false;
			}
			resource->name = strdup ("Certificate");
			resource->type = strdup ("certificate");
			resource->paddr = mo->cert_paddr;
			resource->vaddr = mo->cert_paddr;
			resource->size = mo->cert_size;
			resource->id = UT64_MAX;
			resource->index = index++;
			resource->type_id = UT32_MAX;
			resource->language_id = UT32_MAX;
			resource->named = true;
		}
	}
	return true;
}

#if !R_BIN_MACH064

static bool check(RBinFile *bf, RBuffer *b) {
	if (r_buf_size (b) >= 4) {
		ut8 buf[4] = {0};
		if (r_buf_read_at (b, 0, buf, 4)) {
			if (!memcmp (buf, "\xce\xfa\xed\xfe", 4) ||
				!memcmp (buf, "\xfe\xed\xfa\xce", 4)) {
				return true;
			}
		}
	}
	return false;
}

static RBuffer *create(RBin *bin, const ut8 *code, int clen, const ut8 *data, int dlen, RBinArchOptions *opt) {
	const bool use_pagezero = true;
	const bool use_main = true;
	const bool use_dylinker = true;
	const bool use_libsystem = true;
	const bool use_linkedit = true;
	ut32 filesize, codeva, datava;
	ut32 ncmds, cmdsize, magiclen;
	ut32 p_codefsz = 0, p_codeva = 0, p_codesz = 0, p_codepa = 0;
	ut32 p_datafsz = 0, p_datava = 0, p_datasz = 0, p_datapa = 0;
	ut32 p_cmdsize = 0, p_entry = 0, p_tmp = 0;
	ut32 baddr = 0x1000;

	R_RETURN_VAL_IF_FAIL (bin && opt, NULL);

	bool is_arm = strstr (opt->arch, "arm");
	RBuffer *buf = r_buf_new ();
#ifndef R_BIN_MACH064
	if (opt->bits == 64) {
		R_LOG_TODO ("Please use mach064 instead of mach0");
		free (buf);
		return NULL;
	}
#endif

#define B(x,y) r_buf_append_bytes(buf,(const ut8*)(x),y)
#define D(x) r_buf_append_ut32(buf,x)
#define Z(x) r_buf_append_nbytes(buf,x)
#define W(x,y,z) r_buf_write_at(buf,x,(const ut8*)(y),z)
#define WZ(x,y) p_tmp=r_buf_size (buf);Z(x);W(p_tmp,y,strlen(y))

	/* MACH0 HEADER */
	B ("\xce\xfa\xed\xfe", 4); // header
// 64bit header	B ("\xce\xfa\xed\xfe", 4); // header
	if (is_arm) {
		D (12); // cpu type (arm)
		D (3); // subtype (all?)
	} else {
		/* x86-32 */
		D (7); // cpu type (x86)
// D(0x1000007); // x86-64
		D (3); // subtype (i386-all)
	}
	D (2); // filetype (executable)

	if (data && dlen > 0) {
		ncmds = 3;
		cmdsize = 0;
	} else {
		ncmds = 2;
		cmdsize = 0;
	}
	if (use_pagezero) {
		ncmds++;
	}
	if (use_dylinker) {
		ncmds++;
		if (use_linkedit) {
			ncmds += 3;
		}
		if (use_libsystem) {
			ncmds++;
		}
	}

	/* COMMANDS */
	D (ncmds); // ncmds
	p_cmdsize = r_buf_size (buf);
	D (-1); // cmdsize
	D (0); // flags
	// D (0x01200085); // alternative flags found in some a.out..
	magiclen = r_buf_size (buf);

	if (use_pagezero) {
		/* PAGEZERO */
		D (1);   // cmd.LC_SEGMENT
		D (56); // sizeof (cmd)
		WZ (16, "__PAGEZERO");
		D (0); // vmaddr
		D (0x00001000); // vmsize XXX
		D (0); // fileoff
		D (0); // filesize
		D (0); // maxprot
		D (0); // initprot
		D (0); // nsects
		D (0); // flags
	}

	/* TEXT SEGMENT */
	D (1);   // cmd.LC_SEGMENT
	D (124); // sizeof (cmd)
	WZ (16, "__TEXT");
	D (baddr); // vmaddr
	D (0x1000); // vmsize XXX
	D (0); // fileoff
	p_codefsz = r_buf_size (buf);
	D (-1); // filesize
	D (7); // maxprot
	D (5); // initprot
	D (1); // nsects
	D (0); // flags
	WZ (16, "__text");
	WZ (16, "__TEXT");
	p_codeva = r_buf_size (buf); // virtual address
	D (-1);
	p_codesz = r_buf_size (buf); // size of code (end-start)
	D (-1);
	p_codepa = r_buf_size (buf); // code - baddr
	D (-1); //_start-0x1000);
	D (0); // align // should be 2 for 64bit
	D (0); // reloff
	D (0); // nrelocs
	D (0); // flags
	D (0); // reserved
	D (0); // ??

	if (data && dlen > 0) {
		/* DATA SEGMENT */
		D (1); // cmd.LC_SEGMENT
		D (124); // sizeof (cmd)
		p_tmp = r_buf_size (buf);
		Z (16);
		W (p_tmp, "__TEXT", 6); // segment name
		D (0x2000); // vmaddr
		D (0x1000); // vmsize
		D (0); // fileoff
		p_datafsz = r_buf_size (buf);
		D (-1); // filesize
		D (6); // maxprot
		D (6); // initprot
		D (1); // nsects
		D (0); // flags

		WZ (16, "__data");
		WZ (16, "__DATA");

		p_datava = r_buf_size (buf);
		D (-1);
		p_datasz = r_buf_size (buf);
		D (-1);
		p_datapa = r_buf_size (buf);
		D (-1); //_start-0x1000);
		D (2); // align
		D (0); // reloff
		D (0); // nrelocs
		D (0); // flags
		D (0); // reserved
		D (0);
	}

	if (use_dylinker) {
		if (use_linkedit) {
			/* LINKEDIT */
			D (1);   // cmd.LC_SEGMENT
			D (56); // sizeof (cmd)
			WZ (16, "__LINKEDIT");
			D (0x3000); // vmaddr
			D (0x00001000); // vmsize XXX
			D (0x1000); // fileoff
			D (0); // filesize
			D (7); // maxprot
			D (1); // initprot
			D (0); // nsects
			D (0); // flags

			/* LC_SYMTAB */
			D (2); // cmd.LC_SYMTAB
			D (24); // sizeof (cmd)
			D (0x1000); // symtab offset
			D (0); // symtab size
			D (0x1000); // strtab offset
			D (0); // strtab size

			/* LC_DYSYMTAB */
			D (0xb); // cmd.LC_DYSYMTAB
			D (80); // sizeof (cmd)
			Z (18 * sizeof (ut32)); // empty
		}

		const char *dyld = "/usr/lib/dyld";
		const int dyld_len = strlen (dyld) + 1;
		D(0xe); /* LC_DYLINKER */
		D((4 * 3) + dyld_len);
		D(dyld_len - 2);
		WZ(dyld_len, dyld); // path

		if (use_libsystem) {
			/* add libSystem at least ... */
			const char *lib = "/usr/lib/libSystem.B.dylib";
			const int lib_len = strlen (lib) + 1;
			D (0xc); /* LC_LOAD_DYLIB */
			D (24 + lib_len); // cmdsize
			D (24); // offset where the lib string start
			D (0x2);
			D (0x1);
			D (0x1);
			WZ (lib_len, lib);
		}
	}

	if (use_main) {
		/* LC_MAIN */
		D (0x80000028);   // cmd.LC_MAIN
		D (24); // sizeof (cmd)
		D (baddr); // entryoff
		D (0); // stacksize
		D (0); // ???
		D (0); // ???
	} else {
		/* THREAD STATE */
		D (5); // LC_UNIXTHREAD
		D (80); // sizeof (cmd)
		if (is_arm) {
			/* arm */
			D (1); // i386-thread-state
			D (17); // thread-state-count
			p_entry = r_buf_size (buf) + (16 * sizeof (ut32));
			Z (17 * sizeof (ut32));
			// mach0-arm has one byte more
		} else {
			/* x86-32 */
			D (1); // i386-thread-state
			D (16); // thread-state-count
			p_entry = r_buf_size (buf) + (10 * sizeof (ut32));
			Z (16 * sizeof (ut32));
		}
	}

	/* padding to make mach_loader checks happy */
	/* binaries must be at least of 4KB :( not tiny anymore */
	WZ (4096 - r_buf_size (buf), "");

	cmdsize = r_buf_size (buf) - magiclen;
	codeva = r_buf_size (buf) + baddr;
	datava = r_buf_size (buf) + clen + baddr;
	if (p_entry != 0) {
		W (p_entry, &codeva, 4); // set PC
	}

	/* fill header variables */
	W (p_cmdsize, &cmdsize, 4);
	filesize = magiclen + cmdsize + clen + dlen;
	// TEXT SEGMENT should span the whole file //
	W (p_codefsz, &filesize, 4);
	W (p_codefsz - 8, &filesize, 4); // vmsize = filesize
	W (p_codeva, &codeva, 4);
	// clen = 4096;
	W (p_codesz, &clen, 4);
	p_tmp = codeva - baddr;
	W (p_codepa, &p_tmp, 4);

	B (code, clen);

	if (data && dlen > 0) {
		/* append data */
		W (p_datafsz, &filesize, 4);
		W (p_datava, &datava, 4);
		W (p_datasz, &dlen, 4);
		p_tmp = datava - baddr;
		W (p_datapa, &p_tmp, 4);
		B (data, dlen);
	}

	return buf;
}

static RBinAddr *binsym(RBinFile *bf, int sym) {
	RBinAddr *ret = NULL;
	if (sym == R_BIN_SYM_MAIN) {
		struct MACH0_(obj_t) *mo = R_UNWRAP3 (bf, bo, bin_obj);
		ut64 addr = MACH0_(get_main) (mo);
		if (addr != UT64_MAX && addr != 0) {
			ret = R_NEW0 (RBinAddr);
			ret->vaddr = ((addr >> 1) << 1);
			ret->paddr = ret->vaddr;
		}
	}
	return ret;
}

static ut64 size(RBinFile *bf) {
	ut64 off = 0;
	ut64 len = 0;
	if (sections_vec (bf)) {
		RBinSection *section;
		R_VEC_FOREACH (&bf->bo->sections_vec, section) {
			if (section->paddr > off) {
				off = section->paddr;
				len = section->size;
			}
		}
	}
	return off + len;
}

#endif

#define DW_EH_PE_OMIT 0xff
#define DW_EH_PE_ABSPTR 0x00
#define DW_EH_PE_ULEB128 0x01
#define DW_EH_PE_UDATA2 0x02
#define DW_EH_PE_UDATA4 0x03
#define DW_EH_PE_UDATA8 0x04
#define DW_EH_PE_SLEB128 0x09
#define DW_EH_PE_SDATA2 0x0a
#define DW_EH_PE_SDATA4 0x0b
#define DW_EH_PE_SDATA8 0x0c
#define DW_EH_PE_PCREL 0x10
#define DW_EH_PE_TEXTREL 0x20
#define DW_EH_PE_DATAREL 0x30
#define DW_EH_PE_FUNCREL 0x40
#define DW_EH_PE_INDIRECT 0x80

typedef struct {
	const ut8 *buf;
	const ut8 *p;
	const ut8 *end;
	ut64 vaddr;
	ut64 baddr;
	ut64 function;
	int bits;
	bool big_endian;
} Mach0EhReader;

static bool mach0_eh_uleb(Mach0EhReader *r, ut64 *value) {
	size_t left = r->end - r->p;
	if (!left) {
		return false;
	}
	size_t size = read_u64_leb128 (r->p, r->end, value);
	if (!size || size > left) {
		return false;
	}
	r->p += size;
	return true;
}

static bool mach0_eh_sleb(Mach0EhReader *r, st64 *value) {
	size_t left = r->end - r->p;
	if (!left) {
		return false;
	}
	size_t size = read_i64_leb128 (r->p, r->end, value);
	if (!size || size > left) {
		return false;
	}
	r->p += size;
	return true;
}

static bool mach0_eh_encoded(Mach0EhReader *r, ut8 encoding, ut64 *value, bool apply_base) {
	if (encoding == DW_EH_PE_OMIT || r->p >= r->end) {
		return false;
	}
	const ut64 field_addr = r->vaddr + (r->p - r->buf);
	ut64 raw = 0;
	st64 signed_raw = 0;
	size_t size = 0;
	switch (encoding & 0x0f) {
	case DW_EH_PE_ABSPTR:
		size = r->bits / 8;
		if (size != 4 && size != 8) {
			return false;
		}
		break;
	case DW_EH_PE_ULEB128:
		if (!mach0_eh_uleb (r, &raw)) {
			return false;
		}
		goto encoded_value;
	case DW_EH_PE_UDATA2:
	case DW_EH_PE_SDATA2:
		size = 2;
		break;
	case DW_EH_PE_UDATA4:
	case DW_EH_PE_SDATA4:
		size = 4;
		break;
	case DW_EH_PE_UDATA8:
	case DW_EH_PE_SDATA8:
		size = 8;
		break;
	case DW_EH_PE_SLEB128:
		if (!mach0_eh_sleb (r, &signed_raw)) {
			return false;
		}
		raw = signed_raw;
		goto encoded_value;
	default:
		return false;
	}
	if ((size_t)(r->end - r->p) < size) {
		return false;
	}
	raw = r_read_ble (r->p, r->big_endian, size * 8);
	if ((encoding & 0x0f) >= DW_EH_PE_SLEB128) {
		switch (size) {
		case 2: signed_raw = (st16)raw; break;
		case 4: signed_raw = (st32)raw; break;
		case 8: signed_raw = (st64)raw; break;
		}
		raw = signed_raw;
	}
	r->p += size;

encoded_value:
	if (apply_base && raw) {
		switch (encoding & 0x70) {
		case DW_EH_PE_PCREL:
			raw += field_addr;
			break;
		case DW_EH_PE_TEXTREL:
		case DW_EH_PE_DATAREL:
			raw += r->baddr;
			break;
		case DW_EH_PE_FUNCREL:
			raw += r->function;
			break;
		}
	}
	*value = raw;
	return true;
}

static size_t mach0_eh_encoding_size(ut8 encoding, int bits) {
	switch (encoding & 0x0f) {
	case DW_EH_PE_ABSPTR: return bits / 8;
	case DW_EH_PE_UDATA2:
	case DW_EH_PE_SDATA2: return 2;
	case DW_EH_PE_UDATA4:
	case DW_EH_PE_SDATA4: return 4;
	case DW_EH_PE_UDATA8:
	case DW_EH_PE_SDATA8: return 8;
	default: return 0;
	}
}

static RBinSection *mach0_section_named(RBinFile *bf, const char *suffix) {
	RBinSection *section;
	R_VEC_FOREACH (&bf->bo->sections_vec, section) {
		if (section->name && r_str_endswith (section->name, suffix)) {
			return section;
		}
	}
	return NULL;
}

static RBinSection *mach0_section_at(RBinFile *bf, ut64 vaddr) {
	RBinSection *section;
	R_VEC_FOREACH (&bf->bo->sections_vec, section) {
		if (vaddr >= section->vaddr && vaddr - section->vaddr < section->size) {
			return section;
		}
	}
	return NULL;
}

static char *mach0_eh_type_name(RBinFile *bf, ut64 type_addr) {
	const char *name = NULL;
	RBinReloc *reloc = r_bin_reloc_at (bf->bo->relocs, type_addr, 1);
	if (reloc) {
		if (reloc->import && reloc->import->name) {
			name = r_bin_name_tostring (reloc->import->name);
		} else if (reloc->symbol && reloc->symbol->name) {
			name = r_bin_name_tostring (reloc->symbol->name);
		}
	}
	if (!name) {
		RBinSymbol *symbol;
		R_VEC_FOREACH (&bf->bo->symbols_vec, symbol) {
			if (symbol->vaddr == type_addr && symbol->name) {
				name = r_bin_name_tostring (symbol->name);
				break;
			}
		}
	}
	if (!name) {
		return NULL;
	}
	char *demangled = r_bin_demangle (bf, "cxx", name, type_addr, false);
	if (!demangled) {
		return NULL;
	}
	const char *prefix = "typeinfo for ";
	if (r_str_startswith (demangled, prefix)) {
		char *type = strdup (demangled + strlen (prefix));
		free (demangled);
		return type;
	}
	return demangled;
}

static char *mach0_eh_read_type(RBinFile *bf, const Mach0EhReader *lsda,
		const ut8 *type_table, ut8 encoding, st64 type_filter, bool *catch_all) {
	*catch_all = false;
	if (type_filter <= 0 || !type_table) {
		return NULL;
	}
	size_t entry_size = mach0_eh_encoding_size (encoding, lsda->bits);
	if (!entry_size || (ut64)type_filter > (ut64)(type_table - lsda->buf) / entry_size) {
		return NULL;
	}
	Mach0EhReader entry = *lsda;
	entry.p = type_table - (type_filter * entry_size);
	ut64 type_addr;
	if (!mach0_eh_encoded (&entry, encoding, &type_addr, true)) {
		return NULL;
	}
	if (!type_addr) {
		*catch_all = true;
		return NULL;
	}
	return mach0_eh_type_name (bf, type_addr);
}

static void mach0_eh_add_action(RBinFile *bf, RList *result, const Mach0EhReader *lsda,
		const ut8 *action_table, const ut8 *type_table, ut8 type_encoding, ut64 action,
		ut64 source, ut64 from, ut64 to, ut64 handler) {
	if (!action) {
		RBinTrycatch *tc = r_bin_trycatch_new (source, from, to, handler, 0);
		if (tc) {
			tc->kind = R_BIN_TRYCATCH_CLEANUP;
			r_list_append (result, tc);
		}
		return;
	}
	if (action > (ut64)(lsda->end - action_table)) {
		return;
	}
	const ut8 *record = action_table + action - 1;
	for (size_t depth = 0; record >= action_table && record < lsda->end && depth < 64; depth++) {
		Mach0EhReader action_reader = *lsda;
		action_reader.p = record;
		st64 type_filter;
		if (!mach0_eh_sleb (&action_reader, &type_filter)) {
			break;
		}
		const ut8 *next_field = action_reader.p;
		st64 next;
		if (!mach0_eh_sleb (&action_reader, &next)) {
			break;
		}
		RBinTrycatch *tc = r_bin_trycatch_new (source, from, to, handler, 0);
		if (!tc) {
			break;
		}
		tc->kind = type_filter < 0? R_BIN_TRYCATCH_FILTER: R_BIN_TRYCATCH_CATCH;
		tc->type_filter = type_filter;
		tc->type = mach0_eh_read_type (bf, lsda, type_table, type_encoding,
			type_filter, &tc->catch_all);
		r_list_append (result, tc);
		if (!next) {
			break;
		}
		st64 next_index = (next_field - action_table) + next;
		if (next_index < 0 || (ut64)next_index >= (ut64)(lsda->end - action_table)) {
			break;
		}
		record = action_table + next_index;
	}
}

static void mach0_eh_parse_lsda(RBinFile *bf, RList *result, ut64 source, ut64 lsda_addr) {
	RBinSection *section = mach0_section_at (bf, lsda_addr);
	if (!section || section->size > ST32_MAX) {
		return;
	}
	ut64 section_offset = lsda_addr - section->vaddr;
	ut64 bytes_size = section->size - section_offset;
	if (!bytes_size || bytes_size > ST32_MAX) {
		return;
	}
	ut8 *bytes = malloc (bytes_size);
	if (!bytes || r_buf_read_at (bf->buf, section->paddr + section_offset, bytes, bytes_size) != bytes_size) {
		free (bytes);
		return;
	}
	struct MACH0_(obj_t) *mo = bf->bo->bin_obj;
	Mach0EhReader r = {
		.buf = bytes,
		.p = bytes,
		.end = bytes + bytes_size,
		.vaddr = lsda_addr,
		.baddr = baddr (bf),
		.function = source,
		.bits = bf->bo->info? bf->bo->info->bits: R_SYS_BITS,
		.big_endian = mo->big_endian,
	};
	ut8 lp_encoding = *r.p++;
	ut64 lpstart = source;
	if (lp_encoding != DW_EH_PE_OMIT && !mach0_eh_encoded (&r, lp_encoding, &lpstart, true)) {
		free (bytes);
		return;
	}
	if (r.p >= r.end) {
		free (bytes);
		return;
	}
	ut8 type_encoding = *r.p++;
	const ut8 *type_table = NULL;
	if (type_encoding != DW_EH_PE_OMIT) {
		ut64 type_offset;
		if (!mach0_eh_uleb (&r, &type_offset) || type_offset > (ut64)(r.end - r.p)) {
			free (bytes);
			return;
		}
		type_table = r.p + type_offset;
	}
	if (r.p >= r.end) {
		free (bytes);
		return;
	}
	ut8 callsite_encoding = *r.p++;
	ut64 callsite_size;
	if (!mach0_eh_uleb (&r, &callsite_size) || callsite_size > (ut64)(r.end - r.p)) {
		free (bytes);
		return;
	}
	const ut8 *callsite_end = r.p + callsite_size;
	const ut8 *action_table = callsite_end;
	while (r.p < callsite_end) {
		ut64 start;
		ut64 length;
		ut64 landing_pad;
		ut64 action;
		if (!mach0_eh_encoded (&r, callsite_encoding, &start, false)
				|| !mach0_eh_encoded (&r, callsite_encoding, &length, false)
				|| !mach0_eh_encoded (&r, callsite_encoding, &landing_pad, false)
				|| !mach0_eh_uleb (&r, &action) || r.p > callsite_end) {
			break;
		}
		if (landing_pad && start <= UT64_MAX - lpstart && length <= UT64_MAX - start - lpstart) {
			mach0_eh_add_action (bf, result, &r, action_table, type_table, type_encoding,
				action, source, lpstart + start, lpstart + start + length,
				lpstart + landing_pad);
		}
	}
	free (bytes);
}

static RList *trycatch(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	RList *result = r_list_newf ((RListFree)r_bin_trycatch_free);
	if (!result) {
		return NULL;
	}
	RBinSection *section = mach0_section_named (bf, ".__unwind_info");
	if (!section || section->size < 28 || section->size > ST32_MAX) {
		return result;
	}
	ut8 *bytes = malloc (section->size);
	if (!bytes || r_buf_read_at (bf->buf, section->paddr, bytes, section->size) != section->size) {
		free (bytes);
		return result;
	}
	struct MACH0_(obj_t) *mo = bf->bo->bin_obj;
	bool be = mo->big_endian;
	ut32 version = r_read_ble32 (bytes, be);
	ut32 index_offset = r_read_ble32 (bytes + 20, be);
	ut32 index_count = r_read_ble32 (bytes + 24, be);
	if (version != 1 || index_count < 2 || index_count > section->size / 12
			|| index_offset > section->size - (index_count * 12)) {
		free (bytes);
		return result;
	}
	ut64 base = baddr (bf);
	for (ut32 i = 0; i + 1 < index_count; i++) {
		const ut8 *index = bytes + index_offset + (i * 12);
		const ut8 *next_index = index + 12;
		ut32 lsda_offset = r_read_ble32 (index + 8, be);
		ut32 next_lsda_offset = r_read_ble32 (next_index + 8, be);
		if (lsda_offset > next_lsda_offset || next_lsda_offset > section->size
				|| (next_lsda_offset - lsda_offset) % 8) {
			continue;
		}
		for (ut32 at = lsda_offset; at < next_lsda_offset; at += 8) {
			ut32 function_offset = r_read_ble32 (bytes + at, be);
			ut32 lsda = r_read_ble32 (bytes + at + 4, be);
			mach0_eh_parse_lsda (bf, result, base + function_offset, base + lsda);
		}
	}
	free (bytes);
	return result;
}

#if !R_BIN_MACH064

RBinPlugin r_bin_plugin_mach0 = {
	.meta = {
		.name = "mach0",
		.desc = "32bit Mach Objects",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.get_sdb = &get_sdb,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.signature = &entitlements,
	.load_resources = &load_resources,
	.sections_vec = &sections_vec,
	.symbols_vec = &symbols_vec,
	.imports_vec = &imports_vec,
	.size = &size,
	.info = &info,
	.header = MACH0_(mach_headerfields),
	.fields = MACH0_(mach_fields),
	.libs = &libs,
	.relocs = &relocs,
	.patch_relocs = &patch_relocs,
	.create = &create,
	.classes = &classes,
	.trycatch = &trycatch,
	.write = &r_bin_write_mach0,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_mach0,
	.version = R2_VERSION
};
#endif
#endif
