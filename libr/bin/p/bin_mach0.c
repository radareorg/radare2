/* radare - LGPL - Copyright 2009-2025 - pancake */

#include <r_core.h>
#include "../i/private.h"
#include "mach0/mach0.h"
#include "objc/mach0_classes.h"
#include <sdb/ht_uu.h>

typedef struct {
	ut8 *buf;
	int count;
	ut64 off;
	RIO *io;
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
	if (mo) {
		const char *s = (const char *)mo->signature;
		if (s) {
			if (json) {
				PJ *pj = pj_new ();
				pj_s (pj, s);
				return pj_drain (pj);
			}
			return strdup (s);
		}
	}
	return NULL;
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
				r_buf_free (bf->buf);
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

// R2_600 return RVecSegment
static RList *sections(RBinFile *bf) {
	struct MACH0_(obj_t) *mo = bf->bo->bin_obj;
	return MACH0_(get_segments) (bf, mo); // TODO split up sections and segments?
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

static void process_constructors(RBinFile *bf, RList *ret, int bits) {
	RList *secs = sections (bf);
	RListIter *iter;
	RBinSection *sec;
	int i, type;
	r_list_foreach (secs, iter, sec) {
		type = -1;
		if (strstr (sec->name, "_mod_fini_func")) {
			type  = R_BIN_ENTRY_TYPE_FINI;
		} else if (strstr (sec->name, "_mod_init_func")) {
			type  = R_BIN_ENTRY_TYPE_INIT;
		}
		if (type != -1) {
			ut8 *buf = calloc (sec->size, 1);
			if (!buf) {
				continue;
			}
			int read = r_buf_read_at (bf->buf, sec->paddr, buf, sec->size);
			if (read < sec->size) {
				R_LOG_ERROR ("process_constructors: cannot process section %s", sec->name);
				continue;
			}
			if (bits == 32) {
				for (i = 0; i + 3 < sec->size; i += 4) {
					ut32 addr32 = r_read_le32 (buf + i);
					RBinAddr *ba = newEntry (sec->paddr + i, (ut64)addr32, type, bits);
					if (ba) {
						r_list_append (ret, ba);
					}
				}
			} else {
				for (i = 0; i + 7 < sec->size; i += 8) {
					ut64 addr64 = r_read_le64 (buf + i);
					RBinAddr *ba = newEntry (sec->paddr + i, addr64, type, bits);
					if (ba) {
						r_list_append (ret, ba);
					}
				}
			}
			free (buf);
		}
	}
	r_list_free (secs);
}

static RList *entries(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, NULL);

	RBinAddr *ptr = NULL;
	struct addr_t *entry = NULL;

	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}

	int bits = MACH0_(get_bits) (bf->bo->bin_obj);
	if (!(entry = MACH0_(get_entrypoint) (bf->bo->bin_obj))) {
		return ret;
	}
	if ((ptr = R_NEW0 (RBinAddr))) {
		ptr->paddr = entry->offset + bf->bo->boffset;
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
	}

	process_constructors (bf, ret, bits);
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
	if (imports_by_name) {
		bool found = false;
		RBinImport *ptr = ht_pp_find (imports_by_name, orig_name, &found);
		if (found) {
			return ptr;
		}
	}

	RBinImport *ptr = R_NEW0 (RBinImport);
	if (!ptr) {
		return NULL;
	}

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

	if (imports_by_name) {
		ht_pp_insert (imports_by_name, orig_name, ptr);
	}

	return ptr;
}

static RList *imports(RBinFile *bf) {
	RBinObject *obj = bf? bf->bo: NULL;
	const RPVector *imports = MACH0_(load_imports) (bf, obj->bin_obj);
	if (!imports) {
		return NULL;
	}

	RList *list = r_list_newf ((RListFree) r_bin_import_free);
	void **it;
	r_pvector_foreach (imports, it) {
		// need to clone here, in bobj.c the list free function is forced to `r_bin_import_free`
		// otherwise, a list with no free function could be returned here..
		RBinImport *import = r_bin_import_clone (*it);
		r_list_append (list, import);
	}
	return list;
}

static void _r_bin_reloc_free(RBinReloc *reloc) {
	if (reloc) {
		// XXX also need to free or unref RBinSymbol?
		r_bin_import_free (reloc->import);
		free (reloc);
	}
}

static RList *relocs(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	struct MACH0_(obj_t) *mo = bf->bo->bin_obj;
	const RSkipList *relocs = MACH0_(load_relocs) (bf->bo->bin_obj);
	if (!relocs) {
		return NULL;
	}
	RList *ret = r_list_newf ((RListFree)_r_bin_reloc_free);

	RSkipListNode *it;
	struct reloc_t *reloc;
	r_skiplist_foreach (relocs, it, reloc) {
		if (reloc->external) {
			continue;
		}
		RBinReloc *ptr = R_NEW0 (RBinReloc);
		ptr->type = reloc->type;
		ptr->ntype = reloc->ntype;
		ptr->additive = 0;
		if (reloc->name[0]) {
			ptr->import = import_from_name (bf->rbin, (char*) reloc->name, mo->imports_by_name);
		} else if (reloc->ord >= 0 && mo->imports_by_ord && reloc->ord < mo->imports_by_ord_size) {
			ptr->import = mo->imports_by_ord[reloc->ord];
		}
		ptr->addend = reloc->addend;
		ptr->vaddr = reloc->addr;
		ptr->paddr = reloc->offset;
		r_list_append (ret, ptr);
	}
	if (mo->reloc_fixups) {
		RBinReloc *r;
		RListIter *iter;

		r_list_foreach (mo->reloc_fixups, iter, r) {
			RBinReloc *ptr = R_NEW0 (RBinReloc);
			ptr->type = R_BIN_RELOC_64;
			ut64 paddr = r->paddr + mo->baddr;
			ptr->vaddr = paddr;
			ptr->paddr = r->vaddr;
			ptr->addend = r->vaddr;
			r_list_append (ret, ptr);
		}
	}

	return ret;
}

static RList *libs(RBinFile *bf) {
	RBinObject *obj = bf ? bf->bo : NULL;
	if (!obj) {
		return NULL;
	}

	const RPVector *libs = MACH0_(load_libs) (obj->bin_obj);
	if (!libs) {
		return NULL;
	}

	RList *result = r_list_new ();
	void **it;
	r_pvector_foreach (libs, it) {
		r_list_append (result, *it);
	}
	return result;
}

static RBinInfo *info(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, NULL);
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	struct MACH0_(obj_t) *mo = bf->bo->bin_obj;
	if (bf->file) {
		ret->file = strdup (bf->file);
	}

	char *str = MACH0_(get_class) (mo);
	if (str) {
		ret->bclass = str;
	}
	if (mo) {
		ret->has_canary = mo->has_canary;
		ret->has_retguard = -1;
		ret->has_sanitizers = mo->has_sanitizers;
		ret->has_libinjprot = mo->has_libinjprot;
		ret->dbg_info = mo->dbg_info;
		ret->lang = mo->lang;
		if (mo->dyld_info) {
			ut64 allbinds = 0;
			if ((int)mo->dyld_info->bind_size > 0) {
				allbinds += mo->dyld_info->bind_size;
			}
			if ((int)mo->dyld_info->lazy_bind_size > 0) {
				allbinds += mo->dyld_info->lazy_bind_size;
			}
			if ((int)mo->dyld_info->weak_bind_size > 0) {
				allbinds += mo->dyld_info->weak_bind_size;
			}
			if (allbinds > 0) {
				ret->dbg_info |= R_BIN_DBG_RELOCS;
			}
		}
	}
	const char *intrp = MACH0_(get_intrp)(mo);
	ret->intrp = intrp? strdup (intrp): NULL;
	ret->compiler = strdup ("clang");
	ret->rclass = strdup ("mach0");
	ret->os = strdup (MACH0_(get_os)(mo));
	ret->subsystem = strdup ("darwin");
	ret->arch = strdup (MACH0_(get_cputype) (mo));
	ret->machine = MACH0_(get_cpusubtype) (mo);
	ret->has_lit = true;
	ret->type = MACH0_(get_filetype) (mo);
	ret->big_endian = MACH0_(is_big_endian) (mo);
	ret->bits = 32;
	if (mo) {
		ret->has_crypto = mo->has_crypto;
		ret->bits = MACH0_(get_bits) (mo);
	}
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

static RList* patch_relocs(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin, NULL);

	RList *ret = NULL;
	RIOMap *g = NULL;
	HtUU *relocs_by_sym = NULL;
	RIODesc *gotr2desc = NULL;

	RBin *b = bf->rbin;
	RIO *io = b->iob.io;
	if (!io || !io->desc) {
		return NULL;
	}

	RBinObject *obj = r_bin_cur_object (b);
	if (!obj) {
		return NULL;
	}
	struct MACH0_(obj_t) *mo = obj->bin_obj;

	const RSkipList *all_relocs = MACH0_(load_relocs)(mo);
	if (!all_relocs) {
		return NULL;
	}
	RPVector ext_relocs;
	r_pvector_init (&ext_relocs, NULL);
	RSkipListNode *it;
	struct reloc_t *reloc;
	r_skiplist_foreach (all_relocs, it, reloc) {
		if (!reloc->external) {
			continue;
		}
		r_pvector_push (&ext_relocs, reloc);
	}
#if 1
	// XXX for some reason we are patching this twice as relocs and fixups
	// may be good to find out why and comment back this code with an if0
	int relocs_count = 0;
	// fixups are now considered part of the relocs listing
	if (mo->reloc_fixups != NULL) {
		relocs_count = r_list_length (mo->reloc_fixups);
	}
	if (mo->reloc_fixups && relocs_count > 0) {
		ut8 buf[8], obuf[8];
		RBinReloc *r;
		RListIter *iter2;

		int count = relocs_count;
		if (mo->limit > 0) {
			if (relocs_count > mo->limit) {
				R_LOG_WARN ("mo.limit for relocs");
			}
			count = mo->limit;
		}
		r_list_foreach (mo->reloc_fixups, iter2, r) {
			if (count-- < 0) {
				break;
			}
			ut64 paddr = r->paddr + mo->baddr;
			r_write_ble64 (buf, r->vaddr, false);
			b->iob.read_at (b->iob.io, paddr, obuf, 8);
			if (memcmp (buf, obuf, 8)) {
				if (!b->iob.overlay_write_at (b->iob.io, paddr, buf, 8)) {
					R_LOG_ERROR ("write error at 0x%"PFMT64x, paddr);
				}
			}
		}
	}
#endif
	ut64 num_ext_relocs = r_pvector_length (&ext_relocs);
	if (!num_ext_relocs) {
		goto beach;
	}

	const int cdsz = obj->info ? obj->info->bits / 8 : 8;

	ut64 offset = 0;
	RIOBank *bank = b->iob.bank_get (io, io->bank);
	RListIter *iter;
	RIOMapRef *mapref;
	r_list_foreach (bank->maprefs, iter, mapref) {
		RIOMap *map = b->iob.map_get (io, mapref->id);
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
	gotr2desc = b->iob.open_at (io, muri, R_PERM_R, 0664, n_vaddr);
	free (muri);
	if (!gotr2desc) {
		goto beach;
	}

	RIOMap *gotr2map = b->iob.map_get_at (io, n_vaddr);
	if (!gotr2map) {
		R_LOG_WARN ("no maps for 0x%"PFMT64x, n_vaddr);
		goto beach;
	}
	gotr2map->name = strdup (".got.r2");

	if (!(ret = r_list_newf ((RListFree)free))) {
		goto beach;
	}
	if (!(relocs_by_sym = ht_uu_new0 ())) {
		goto beach;
	}
	ut64 vaddr = n_vaddr;
	void **ext_reloc_iter;
	r_pvector_foreach (&ext_relocs, ext_reloc_iter) {
		reloc = *ext_reloc_iter;
		bool found = false;
		ut64 sym_addr = ht_uu_find (relocs_by_sym, reloc->ord, &found);
		if (!found || !sym_addr) {
			sym_addr = vaddr;
			ht_uu_insert (relocs_by_sym, reloc->ord, vaddr);
			vaddr += cdsz;
		}
		if (!_patch_reloc (mo, &b->iob, reloc, sym_addr)) {
			continue;
		}
		RBinReloc *ptr = R_NEW0 (RBinReloc);
		ptr->type = reloc->type;
		ptr->additive = 0;
		RBinImport *imp = import_from_name (b, (char*) reloc->name, mo->imports_by_name);
		if (R_LIKELY (imp)) {
			ptr->vaddr = sym_addr;
			ptr->import = imp;
			r_list_append (ret, ptr);
		} else {
			free (ptr);
		}
	}
	if (r_list_empty (ret)) {
		goto beach;
	}
	ht_uu_free (relocs_by_sym);
	r_pvector_fini (&ext_relocs);
	// XXX r_io_desc_free (gotr2desc);
	return ret;

beach:
	r_pvector_fini (&ext_relocs);
	r_io_desc_free (gotr2desc);
	r_list_free (ret);
	ht_uu_free (relocs_by_sym);
	return NULL;
}

static RBuffer *swizzle_io_read(RBinFile *bf, struct MACH0_(obj_t) *obj, RIO *io) {
	R_RETURN_VAL_IF_FAIL (io && io->desc && io->desc->plugin, NULL);
	RFixupRebaseContext ctx = {0};
	RBuffer *nb = r_buf_new_with_cache (obj->b, false);
	RBuffer *ob = obj->b;
	obj->b = nb;
	ut64 count = r_buf_size (obj->b);
	ctx.io = io;
	ctx.obj = obj;
	ut64 off = 0;
	ctx.off = off;
	MACH0_(iterate_chained_fixups) (obj, off, off + count,
		R_FIXUP_EVENT_MASK_ALL, &rebase_buffer_callback2, &ctx);
	obj->b = ob;
//	bf->buf = nb; // ???
	return nb;
}

static void add_fixup(RList *list, ut64 addr, ut64 value) {
	RBinReloc *r = R_NEW0 (RBinReloc);
	r->vaddr = value;
	r->paddr = addr;
	r_list_append (list, r);
}

static bool rebase_buffer_callback2(void *context, RFixupEventDetails * event_details) {
	RFixupRebaseContext *ctx = context;
	ut64 in_buf = event_details->offset - ctx->off;
	RList *rflist = ctx->obj->reloc_fixups;
	if (!rflist) {
		rflist = r_list_newf (free);
		ctx->obj->reloc_fixups = rflist;
	}
	// r_buf_write_at (ctx->obj->b, 0x000a36780, "\x00\x00\x00\x10", 4);
	switch (event_details->type) {
	case R_FIXUP_EVENT_BIND:
	case R_FIXUP_EVENT_BIND_AUTH:
		{
			ut8 data[8] = {0};
			r_buf_write_at (ctx->obj->b, in_buf, (const ut8*)"\x00\x00\x00\x00\x00\x00\x00", event_details->ptr_size);
			r_buf_read_at (ctx->obj->b, in_buf, data, event_details->ptr_size);
			add_fixup (rflist, in_buf, 0);
			if (data[0]) {
				R_LOG_ERROR ("DATA0 write has failed");
			}
		}
		break;
	case R_FIXUP_EVENT_REBASE:
	case R_FIXUP_EVENT_REBASE_AUTH:
		{
			ut8 data[8] = {0};
			ut64 v = ((RFixupRebaseEventDetails *) event_details)->ptr_value;
			add_fixup (rflist, in_buf, v);
			memcpy (&data, &v, event_details->ptr_size);
			r_buf_write_at (ctx->obj->b, in_buf, data, event_details->ptr_size);
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
	switch (sym) {
	case R_BIN_SYM_MAIN:
		{
			struct MACH0_(obj_t) *mo = R_UNWRAP3 (bf, bo, bin_obj);
			ut64 addr = MACH0_(get_main) (mo);
			if (addr != UT64_MAX && addr != 0) {
				ret = R_NEW0 (RBinAddr);
				ret->vaddr = ((addr >> 1) << 1);
				ret->paddr = ret->vaddr;
			}
		}
		break;
	}
	return ret;
}

static ut64 size(RBinFile *bf) {
	ut64 off = 0;
	ut64 len = 0;
	if (!bf->bo->sections) {
		RListIter *iter;
		RBinSection *section;
		bf->bo->sections = sections (bf);
		r_list_foreach (bf->bo->sections, iter, section) {
			if (section->paddr > off) {
				off = section->paddr;
				len = section->size;
			}
		}
	}
	return off + len;
}

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
	.sections = &sections,
	.symbols_vec = &symbols_vec,
	.imports = &imports,
	.size = &size,
	.info = &info,
	.header = MACH0_(mach_headerfields),
	.fields = MACH0_(mach_fields),
	.libs = &libs,
	.relocs = &relocs,
	.patch_relocs = &patch_relocs,
	.create = &create,
	.classes = &classes,
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
