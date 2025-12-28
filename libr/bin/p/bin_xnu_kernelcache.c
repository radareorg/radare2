/* radare2 - LGPL - Copyright 2019-2025 - mrmacete */

#include <r_core.h>

#define R_BIN_MACH064 1
#include "../format/mach0/mach0.h"

#include "../format/xnu/r_cf_dict.h"
#include "../format/xnu/mig_index.h"
#include "../format/mach0/mach064_is_kernelcache.c"

typedef bool (*ROnRebaseFunc) (ut64 offset, ut64 decorated_addr, void *user_data);

typedef struct _RKernelCacheObj {
	RBuffer *cache_buf;
	RCFValueDict *prelink_info;
	ut64 pa2va_exec;
	ut64 pa2va_data;
	struct _RKextIndex *kexts;
	struct MACH0_(obj_t) *mach0;
	struct _RRebaseInfo *rebase_info;
	int (*original_io_read)(RIO *io, RIODesc *fd, ut8 *buf, int count);
	bool rebase_info_populated;
	bool rebasing_buffer;
	bool kexts_initialized;
	ut8 *internal_buffer;
	int internal_buffer_size;
	ut64 kernel_base;
	HtUP *class_by_handle;
} RKernelCacheObj;

typedef struct _RFileRange {
	ut64 offset;
	ut64 size;
} RFileRange;

typedef struct _RPrelinkRange {
	RFileRange range;
	ut64 pa2va_exec;
	ut64 pa2va_data;
} RPrelinkRange;

typedef struct _RStubsInfo {
	RFileRange got;
	RFileRange stubs;
	ut64 got_addr;
} RStubsInfo;

typedef struct _RKext {
	RFileRange range;
	RFileRange text_range;
	char *name;
	ut64 mod_info;
	ut64 vaddr;
	struct MACH0_(obj_t) *mach0;
	bool own_name;
	ut64 pa2va_exec;
	ut64 pa2va_data;
	RList /*<RIOKitClass>*/ *classes;
} RKext;

typedef struct _RKextIndex {
	ut64 length;
	RKext **entries;
} RKextIndex;

typedef struct {
	ut8 *buf;
	ut64 va;
	ut64 size;
} RKextTextBlob;

typedef struct _RRebaseInfo {
	RFileRange *ranges;
	ut64 n_ranges;
	ut64 multiplier;
	ut64 kernel_base;
} RRebaseInfo;

typedef struct _RRebaseCtx {
	ut64 off, eob;
	ut8 *buf;
	int count;
	RKernelCacheObj *obj;
} RRebaseCtx;

typedef struct _RParsedPointer {
	ut64 address;
} RParsedPointer;

typedef struct _RKmodInfo {
	char name[0x41];
	ut64 start;
} RKmodInfo;

typedef struct {
	ut64 va;
	ut32 slots_total;
	ut32 slots_own;
} RIOKitVTable;

typedef struct {
	RIOKitVTable instance;
	RIOKitVTable metaclass;
} RIOKitVTables;

typedef struct {
	char *name;
	ut64 size;
	ut64 meta_va;
	ut64 supermeta_va;
	RIOKitVTables vt;
} RIOKitClass;

#define KEXT_SHORT_NAME_FROM_SECTION(io_section) ({\
	char *result = NULL;\
	char *clone = strdup (io_section->name);\
	char *cursor = strstr (clone, "__");\
	if (cursor) {\
		cursor--;\
		*cursor = 0;\
		cursor--;\
		cursor = strrchr (cursor, '.');\
		if (cursor) {\
			*cursor = 0;\
			cursor = strrchr (cursor, '.');\
			if (cursor) {\
				result = strdup (cursor + 1);\
				R_FREE (clone);\
			}\
		}\
	}\
	result ? result : clone;\
})

#define KEXT_INFER_VSIZE(index, i)\
	((i+1 < index->length) ? index->entries[i+1]->vaddr - index->entries[i]->vaddr : UT64_MAX)

#define KEXT_INFER_PSIZE(index, i)\
	((i+1 < index->length) ? index->entries[i+1]->range.offset - index->entries[i]->range.offset : UT64_MAX)

#define R_K_CONSTRUCTOR_TO_ENTRY 0
#define R_K_CONSTRUCTOR_TO_SYMBOL 1

#define K_PPTR(p) p_ptr (p, obj)
#define K_RPTR(buf) r_ptr (buf, obj)

#define IS_KERNEL_ADDR(x) ((x & 0XFFFFFFF000000000ULL) == 0XFFFFFFF000000000ULL)

#define IS_PTR_AUTH(x) ((x & (1ULL << 63)) != 0)
#define IS_PTR_BIND(x) ((x & (1ULL << 62)) != 0)

#define ARM64_BL_MASK        0xFC000000u
#define ARM64_BL_BASE        0x94000000u

#define ARM64_RET_MASK       0xFFFFFC1Fu
#define ARM64_RET_BASE       0xD65F0000u

#define ARM64_RET_AUTH_MASK  0xFFFFFC00u
#define ARM64_RET_AUTH_BASE  0xD65F0C00u

#define ARM64_ADRP_MASK      0x9F000000u
#define ARM64_ADRP_BASE      0x90000000u

#define ARM64_ADDI64_MASK    0xFF000000u
#define ARM64_ADDI64_BASE    0x91000000u

#define ARM64_LDRX_UOFF_MASK 0xFFC00000u
#define ARM64_LDRX_UOFF_BASE 0xF9400000u

static ut64 p_ptr(ut64 decorated_addr, RKernelCacheObj *obj);
static ut64 r_ptr(ut8 *buf, RKernelCacheObj *obj);

static RRebaseInfo *r_rebase_info_new_from_mach0(RBuffer *cache_buf, struct MACH0_(obj_t) *mach0);
static void r_rebase_info_free(RRebaseInfo *info);
static void r_rebase_info_populate(RRebaseInfo *info, RKernelCacheObj *obj);
static ut64 iterate_rebase_list(RBuffer *cache_buf, ut64 multiplier, ut64 start_offset, ROnRebaseFunc func, void *user_data);
static ut64 r_rebase_offset_to_paddr(RKernelCacheObj *obj, const RVecSection *sections, ut64 offset);
static void swizzle_io_read(RKernelCacheObj *obj, RIO *io);
static int kernelcache_io_read(RIO *io, RIODesc *fd, ut8 *buf, int count);
static void rebase_buffer(RKernelCacheObj *obj, ut64 off, RIODesc *fd, ut8 *buf, int count);
static void rebase_buffer_fixup(RKernelCacheObj *kobj, ut64 off, RIODesc *fd, ut8 *buf, int count);

static RPrelinkRange *get_prelink_info_range_from_mach0(struct MACH0_(obj_t) *mach0);
static RList *filter_kexts(RKernelCacheObj *obj, RBinFile *bf);
static RList *carve_kexts(RKernelCacheObj *obj, RBinFile *bf);
static RList *kexts_from_load_commands(RKernelCacheObj *obj, RBinFile *bf);

static void sections_from_mach0(RList *ret, struct MACH0_(obj_t) *mach0, RBinFile *bf, ut64 paddr, char *prefix, RKernelCacheObj *obj);
static void handle_data_sections(RBinSection *sect);
static RList *resolve_syscalls(RKernelCacheObj *obj, ut64 enosys_addr);
static RList *resolve_mig_subsystem(RKernelCacheObj *obj);
static void symbols_from_stubs_vec(RVecRBinSymbol *symbols, RBinFile *bf, HtPP *kernel_syms_by_addr, RKext *kext, int ordinal);
static RStubsInfo *get_stubs_info(struct MACH0_(obj_t) *mach0, ut64 paddr, RKernelCacheObj *obj);
static int prot2perm(int x);
static RList *resolve_iokit_classes(RVecRBinSymbol *symbols, ut64 start_offset, RBinFile *bf, RKext *kext);
static RList *find_class_registrations(RVecRBinSymbol *symbols, ut64 start_offset, RBinFile *bf, RKext *kext);
static void r_iokit_class_free(void *_c);
static void find_class_vtables(RList *classes, RBinFile *bf, RKext *kext);
static void compute_class_vtable_sizes(RList *classes, RBinFile *bf, RKext *kext);
static void compute_vtable_sizes_for_class(RBinFile *bf, RKext *kext, RIOKitClass *c, const ut64 *vt_sorted, size_t n_sorted);
static void compute_metaclass_vtable_sizes_for_class(RBinFile *bf, RKext *kext, RIOKitClass *c, const ut64 *vt_sorted, size_t n_sorted);
static ut32 scan_vtable_total_slots(RBinFile *bf, RKext *kext, ut64 start, const ut64 *vt_sorted, size_t n_sorted);
static ut64 *build_sorted_vtable_starts(RList *classes, size_t *out_n);
static int ut64_compare(const void *pa, const void *pb);
static ut64 next_vtable_after(const ut64 *arr, size_t n, ut64 self_start);
static bool load_kext_text_blob(RBinFile *bf, RKext *kext, RKextTextBlob *blob);
static const ut8 *text_ptr(const RKextTextBlob *tb, ut64 va);
static bool try_read_exec_va(RBinFile *bf, RKext *kext, ut64 va, void *dst, size_t len);
static bool try_read_data_va(RBinFile *bf, RKext *kext, ut64 va, void *dst, size_t len);
static bool try_read_printable_cstr(RBinFile *bf, RKext *kext, ut64 va, char **cstr);
static bool is_bl(ut32 insn);
static bool is_ret_like(ut32 insn);
static bool try_parse_movz_w_imm(ut32 insn, int *dst_reg, ut32 *imm);
static bool try_parse_adrp_add_pair(const ut8 *ptr, ut64 va, int *reg, ut64 *addr);
static bool try_parse_adrp_ldr_pair(const ut8 *ptr, ut64 va, RBinFile *bf, RKext *kext, int *dst_reg, ut64 *loaded_val);
static bool try_parse_adrp_base(ut32 insn, ut64 va, ut32 *rd, ut64 *adrp_base);
static bool try_parse_addi64_same_reg(ut32 insn, int *reg, ut32 *imm12, bool *sh_is_12);
static bool try_parse_mov_reg_reg(ut32 insn, int *dst_reg, int *src_reg);

static void r_kext_free(RKext *kext);
static void r_kext_fill_text_range(RKext *kext);
static int kexts_sort_vaddr_func(const void *a, const void *b);
static struct MACH0_(obj_t) *create_kext_mach0(RKernelCacheObj *obj, RKext *kext, RBinFile *bf);
static struct MACH0_(obj_t) *create_kext_shared_mach0(RKernelCacheObj *obj, RKext *kext, RBinFile *bf);

#define r_kext_index_foreach(index, i, item)\
	if (index) for (i = 0; i < index->length && (item = index->entries[i], 1); i++)

static RKextIndex *r_kext_index_new(RList *kexts);
static void r_kext_index_free(RKextIndex *index);
static RKext *r_kext_index_vget(RKextIndex *index, ut64 vaddr);

static void process_kmod_init_term_vec(RVecRBinSymbol *symbols, RBinFile *bf, RKext *kext, ut64 **inits, ut64 **terms);
static void create_initterm_syms_vec(RVecRBinSymbol *symbols, RBinFile *bf, RKext *kext, int type, ut64 *pointers);
static void process_constructors(RKernelCacheObj *obj, struct MACH0_(obj_t) *mach0, RList *ret, ut64 paddr, bool is_first, int mode, const char *prefix);
static void process_constructors_vec(RVecRBinSymbol *symbols, RBinFile *bf, RKernelCacheObj *obj, struct MACH0_(obj_t) *mach0, ut64 paddr, bool is_first, int mode, const char *prefix);
static RBinAddr *newEntry(ut64 haddr, ut64 vaddr, int type);
static bool is_30bit_decorated(ut64 p);
static ut64 undecorate_30bit(ut64 p, const RKernelCacheObj *obj);
static ut64 undecorate_ios12(ut64 p, const RKernelCacheObj *obj);
static void ensure_kexts_initialized(RKernelCacheObj *obj, RBinFile *bf);

static void r_kernel_cache_free(RKernelCacheObj *obj);

static R_TH_LOCAL RList *pending_bin_files = NULL;

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	RBuffer *fbuf = r_buf_ref (buf);
	struct MACH0_(opts_t) opts;
	MACH0_(opts_set_default) (&opts, bf);
	struct MACH0_(obj_t) *main_mach0 = MACH0_(new_buf) (bf, fbuf, &opts);
	if (!main_mach0) {
		return false;
	}

	RRebaseInfo *rebase_info = r_rebase_info_new_from_mach0 (fbuf, main_mach0);

	RPrelinkRange *prelink_range = get_prelink_info_range_from_mach0 (main_mach0);
	if (!prelink_range) {
		goto beach;
	}

	RKernelCacheObj *obj = R_NEW0 (RKernelCacheObj);
	const bool is_modern = main_mach0->hdr.filetype == MH_FILESET ||
		(main_mach0->hdr.cputype == CPU_TYPE_ARM64 && main_mach0->hdr.cpusubtype == 0xc0000002);

	RCFValueDict *prelink_info = NULL;
	if (!is_modern && prelink_range->range.size) {
		prelink_info = r_cf_value_dict_parse (fbuf, prelink_range->range.offset,
				prelink_range->range.size, R_CF_OPTION_SKIP_NSDATA | R_CF_OPTION_SUPPORT_IDREF);
		if (!prelink_info) {
			R_FREE (prelink_range);
			R_FREE (obj);
			goto beach;
		}
	}

	if (!pending_bin_files) {
		pending_bin_files = r_list_new ();
		if (!pending_bin_files) {
			R_FREE (prelink_range);
			R_FREE (obj);
			R_FREE (prelink_info);
			goto beach;
		}
	}

	obj->mach0 = main_mach0;
	obj->rebase_info = rebase_info;
	obj->prelink_info = prelink_info;
	obj->cache_buf = fbuf;
	obj->pa2va_exec = prelink_range->pa2va_exec;
	obj->pa2va_data = prelink_range->pa2va_data;
	obj->class_by_handle = ht_up_new0 ();
	R_FREE (prelink_range);
	bf->bo->bin_obj = obj;
	r_list_push (pending_bin_files, bf);

	if (rebase_info) {
		obj->kernel_base = rebase_info->kernel_base;
	} else {
		struct MACH0_(segment_command) *seg;
		int nsegs = R_MIN (main_mach0->nsegs, 128);
		int i;
		for (i = 0; i < nsegs; i++) {
			char segname[17];
			seg = &main_mach0->segs[i];
			r_str_ncpy (segname, seg->segname, 17);
			if (!strncmp (segname, "__TEXT", 6) && segname[6] == '\0') {
				obj->kernel_base = seg->vmaddr;
				break;
			}
		}
	}

	if (rebase_info || main_mach0->chained_starts) {
		RIO *io = bf->rbin->iob.io;
		swizzle_io_read (obj, io);
	}

	return true;

beach:
	r_buf_free (fbuf);
	r_rebase_info_free (rebase_info);
	MACH0_(mach0_free) (main_mach0);
	return false;
}

static void r_ptr_undecorate(RParsedPointer *ptr, ut64 p, RKernelCacheObj *obj) {
	if (!p || IS_KERNEL_ADDR (p)) {
		ptr->address = p;
		return;
	}

	if (is_30bit_decorated (p)) {
		ut64 a = undecorate_30bit (p, obj);
		if (IS_KERNEL_ADDR (a)) {
			ptr->address = a;
			return;
		}
	}

	ut64 a = undecorate_ios12 (p, obj);
	if (IS_KERNEL_ADDR (a)) {
		ptr->address = a;
		return;
	}

	a = undecorate_30bit (p, obj);
	ptr->address = IS_KERNEL_ADDR (a) ? a : p;
}

static bool is_30bit_decorated(ut64 p) {
	return (p & (1ULL << 61)) && !IS_KERNEL_ADDR (p);
}

static ut64 undecorate_30bit(ut64 p, const RKernelCacheObj *obj) {
	return obj->kernel_base + (p & ((1ULL << 30) - 1));
}

static ut64 undecorate_ios12(ut64 p, const RKernelCacheObj *obj) {
	/*
	 * Logic taken from:
	 * https://github.com/Synacktiv/kernelcache-laundering/blob/master/ios12_kernel_cache_helper.py
	 */

	if (p & (1ULL << 62)) {
		return p;
	}

	if (p & (1ULL << 63)) {
		return obj->kernel_base + (p & 0xffffffffULL);
	}

	ut64 r = ((p << 13) & 0xff00000000000000ULL) | (p & 0x7ffffffffffULL);
	if (p & 0x40000000000ULL) {
		r |= 0xfffc0000000000ULL;
	}
	return r;
}

static void ensure_kexts_initialized(RKernelCacheObj *obj, RBinFile *bf) {
	if (obj->kexts_initialized) {
		return;
	}
	obj->kexts_initialized = true;

	RList *kexts = NULL;

	if (obj->prelink_info) {
		kexts = filter_kexts (obj, bf);
	}

	if (kexts && !r_list_length (kexts)) {
		r_list_free (kexts);
		kexts = NULL;
	}

	if (!kexts) {
		kexts = kexts_from_load_commands (obj, bf);
	}

	if (kexts && r_list_empty (kexts)) {
		r_list_free (kexts);
		kexts = NULL;
	}
	if (!kexts) {
		kexts = carve_kexts (obj, bf);
	}

	obj->kexts = r_kext_index_new (kexts);

	if (kexts) {
		kexts->free = NULL;
		r_list_free (kexts);
	}
}

static RPrelinkRange *get_prelink_info_range_from_mach0(struct MACH0_(obj_t) *mach0) {
	const RVecSection *sections = MACH0_(load_sections) (mach0);
	if (!sections) {
		return NULL;
	}

	RPrelinkRange *prelink_range = R_NEW0 (RPrelinkRange);

	int incomplete = 3;
	struct section_t *section;
	R_VEC_FOREACH (sections, section) {
		if (strstr (section->name, "__PRELINK_INFO.__info")) {
			prelink_range->range.offset = section->paddr;
			prelink_range->range.size = section->size;
			if (!--incomplete) {
				break;
			}
		}

		if (strstr (section->name, "__PRELINK_TEXT.__text")) {
			prelink_range->pa2va_exec = section->vaddr - section->paddr;
			if (!--incomplete) {
				break;
			}
		}

		if (strstr (section->name, "__PRELINK_DATA.__data")) {
			prelink_range->pa2va_data = section->vaddr - section->paddr;
			if (!--incomplete) {
				break;
			}
		}
	}

	if (incomplete == 1 && !prelink_range->pa2va_data) {
		struct MACH0_(segment_command) *seg;
		int nsegs = R_MIN (mach0->nsegs, 128);
		size_t i;
		for (i = 0; i < nsegs; i++) {
			seg = &mach0->segs[i];
			if (!strcmp (seg->segname, "__DATA")) {
				prelink_range->pa2va_data = seg->vmaddr - seg->fileoff;
				incomplete--;
				break;
			}
		}
	}

	if (incomplete) {
		R_FREE (prelink_range);
	}

	return prelink_range;
}

static RList *filter_kexts(RKernelCacheObj *obj, RBinFile *bf) {
	RCFValueArray *kext_array = NULL;
	RListIter *iter;
	RCFKeyValue *item;
	r_list_foreach (obj->prelink_info->pairs, iter, item) {
		if (!strcmp (item->key, "_PrelinkInfoDictionary")) {
			kext_array = (RCFValueArray*) item->value;
			break;
		}
	}

	if (!kext_array) {
		return NULL;
	}

	RList *kexts = r_list_newf ((RListFree) &r_kext_free);
	if (!kexts) {
		return NULL;
	}

	bool is_sorted = true;
	RKext *prev_kext = NULL;
	RCFValueDict *kext_item;
	r_list_foreach (kext_array->values, iter, kext_item) {
		RKext *kext = R_NEW0 (RKext);
		int kext_incomplete = 5;
		RListIter *internal_iter;
		r_list_foreach (kext_item->pairs, internal_iter, item) {
			if (!strcmp (item->key, "CFBundlePackageType")) {
				if (item->value->type != R_CF_STRING) {
					break;
				}
				RCFValueString *type = (RCFValueString*) item->value;
				if (strcmp (type->value, "KEXT")) {
					break;
				}
				kext_incomplete--;
			}

			if (!strcmp (item->key, "_PrelinkExecutableLoadAddr")) {
				if (item->value->type == R_CF_INTEGER) {
					kext_incomplete--;
					kext->vaddr = ((RCFValueInteger*) item->value)->value;
					kext->range.offset = kext->vaddr - obj->pa2va_exec;
				}
			}

			if (!strcmp (item->key, "_PrelinkExecutableSize")) {
				kext_incomplete--;
				if (item->value->type == R_CF_INTEGER) {
					kext->range.size = ((RCFValueInteger*) item->value)->value;
				} else {
					kext->range.size = 0;
				}
			}

			if (!strcmp (item->key, "_PrelinkKmodInfo")) {
				if (item->value->type == R_CF_INTEGER) {
					kext_incomplete--;
					kext->mod_info = ((RCFValueInteger*) item->value)->value;
					kext->mod_info -= obj->pa2va_data;
				}
			}

			if (!strcmp (item->key, "CFBundleIdentifier")) {
				if (item->value->type == R_CF_STRING) {
					kext_incomplete--;
					kext->name = ((RCFValueString*) item->value)->value;
				}
			}
		}

		if (kext_incomplete) {
			r_kext_free (kext);
			continue;
		}

		if (prev_kext && kext->vaddr < prev_kext->vaddr) {
			is_sorted = false;
		}
		prev_kext = kext;

		kext->mach0 = create_kext_mach0 (obj, kext, bf);
		if (!kext->mach0) {
			r_kext_free (kext);
			continue;
		}

		r_kext_fill_text_range (kext);

		r_list_push (kexts, kext);
	}

	if (!is_sorted) {
		R_LOG_DEBUG ("Sorting KEXTs");
		r_list_sort (kexts, kexts_sort_vaddr_func);
	}
	return kexts;
}

static ut64 p_ptr(ut64 decorated_addr, RKernelCacheObj *obj) {
	RParsedPointer ptr;
	r_ptr_undecorate (&ptr, decorated_addr, obj);
	return ptr.address;
}

static ut64 r_ptr(ut8 *buf, RKernelCacheObj *obj) {
	ut64 decorated_addr = r_read_le64 (buf);
	return K_PPTR (decorated_addr);
}

static RList *carve_kexts(RKernelCacheObj *obj, RBinFile *bf) {
	const RVecSection *sections = MACH0_(load_sections) (obj->mach0);
	if (!sections) {
		return NULL;
	}

	ut64 pa2va_exec = 0;
	ut64 pa2va_data = 0;
	ut64 kmod_start = 0, kmod_end = 0;
	ut64 kmod_info = 0, kmod_info_end = 0;
	int incomplete = 4;
	RKmodInfo *all_infos = NULL;

	struct section_t *section;
	R_VEC_FOREACH (sections, section) {
		if (incomplete == 0) {
			break;
		}
		if (strstr (section->name, "__TEXT_EXEC.__text")) {
			pa2va_exec = section->vaddr - section->paddr;
			incomplete--;
		}
		if (strstr (section->name, "__DATA.__data")) {
			pa2va_data = section->vaddr - section->paddr;
			incomplete--;
		}
		if (strstr (section->name, "__PRELINK_INFO.__kmod_start")) {
			kmod_start = section->paddr;
			kmod_end = kmod_start + section->size;
			incomplete--;
		}
		if (strstr (section->name, "__PRELINK_INFO.__kmod_info")) {
			kmod_info = section->paddr;
			kmod_info_end = kmod_info + section->size;
			incomplete--;
		}
	}

	if (incomplete) {
		return NULL;
	}

	RList *kexts = r_list_newf ((RListFree) &r_kext_free);
	if (!kexts) {
		return NULL;
	}

	int n_kmod_info = (kmod_info_end - kmod_info) / 8;
	if (n_kmod_info == 0) {
		goto beach;
	}

	all_infos = R_NEWS0 (RKmodInfo, n_kmod_info);
	if (!all_infos) {
		goto beach;
	}

	ut8 bytes[8];
	int j = 0;
	for (; j < n_kmod_info; j++) {
		ut64 entry_offset = j * 8 + kmod_info;

		if (r_buf_read_at (obj->cache_buf, entry_offset, bytes, 8) < 8) {
			goto beach;
		}

		ut64 kmod_info_paddr = K_RPTR (bytes) - pa2va_data;

		ut64 field_name = kmod_info_paddr + 0x10;
		ut64 field_start = kmod_info_paddr + 0xb4;

		if (r_buf_read_at (obj->cache_buf, field_start, bytes, 8) < 8) {
			goto beach;
		}

		all_infos[j].start = K_RPTR (bytes);

		if (r_buf_read_at (obj->cache_buf, field_name, (ut8 *) all_infos[j].name, 0x40) < 0x40) {
			goto beach;
		}

		all_infos[j].name[0x40] = 0;
	}

	ut64 cursor = kmod_start;
	for (; cursor < kmod_end; cursor += 8) {
		ut8 bytes[8];
		if (r_buf_read_at (obj->cache_buf, cursor, bytes, 8) < 8) {
			goto beach;
		}
		RKext *kext = R_NEW0 (RKext);
		kext->vaddr = K_RPTR (bytes);
		kext->range.offset = kext->vaddr - pa2va_exec;

		kext->mach0 = create_kext_mach0 (obj, kext, bf);
		if (!kext->mach0) {
			r_kext_free (kext);
			continue;
		}

		r_kext_fill_text_range (kext);
		kext->vaddr = K_PPTR (kext->vaddr);
		kext->pa2va_exec = pa2va_exec;
		kext->pa2va_data = pa2va_data;

		ut64 text_start = kext->vaddr;
		ut64 text_end = text_start + kext->text_range.size;

		if (text_start == text_end) {
			r_kext_free (kext);
			continue;
		}

		for (j = 0; j < n_kmod_info; j++) {
			if (text_start > all_infos[j].start || all_infos[j].start >= text_end) {
				continue;
			}

			kext->name = strdup (all_infos[j].name);
			kext->own_name = true;
			break;
		}

		if (!kext->name) {
			r_kext_free (kext);
			continue;
		}

		r_list_push (kexts, kext);
	}

	R_FREE (all_infos);
	return kexts;

beach:
	r_list_free (kexts);
	R_FREE (all_infos);
	return NULL;
}

static RList *kexts_from_load_commands(RKernelCacheObj *obj, RBinFile *bf) {
	RList *kexts = r_list_newf ((RListFree) &r_kext_free);
	if (!kexts) {
		return NULL;
	}

	RBuffer *cache_buf = r_buf_ref (obj->cache_buf);
	if (!cache_buf) {
		r_list_free (kexts);
		return NULL;
	}

	ut32 i, ncmds = r_buf_read_le32_at (cache_buf, 16);
	ut64 length = r_buf_size (cache_buf);

	ut32 cursor = sizeof (struct MACH0_(mach_header));
	for (i = 0; i < ncmds && cursor < length; i++) {
		ut32 cmdtype = r_buf_read_le32_at (cache_buf, cursor);
		ut32 cmdsize = r_buf_read_le32_at (cache_buf, cursor + 4);
		if (!cmdsize || cmdsize + cursor < cursor) {
			break;
		}
		if (cmdtype != LC_KEXT) {
			cursor += cmdsize;
			continue;
		}

		ut64 vaddr = r_buf_read_le64_at (cache_buf, cursor + 8);
		ut64 paddr = r_buf_read_le64_at (cache_buf, cursor + 16);
		st32 padded_name_length = (st32)cmdsize - 32;
		if (padded_name_length <= 0 || cmdsize - 32 + cursor >= length || padded_name_length > 0x1000) {
			cursor += cmdsize;
			continue;
		}

		char *padded_name = calloc (1, padded_name_length);
		if (!padded_name) {
			goto beach;
		}
		if (r_buf_read_at (cache_buf, cursor + 32, (ut8 *)padded_name, padded_name_length)
				!= padded_name_length) {
			free (padded_name);
			goto early;
		}

		RKext *kext = R_NEW0 (RKext);
		kext->vaddr = vaddr;
		kext->range.offset = paddr;

		kext->mach0 = create_kext_shared_mach0 (obj, kext, bf);
		if (!kext->mach0) {
			free (padded_name);
			r_kext_free (kext);
			cursor += cmdsize;
			continue;
		}

		r_kext_fill_text_range (kext);
		kext->pa2va_exec = obj->pa2va_exec;
		kext->pa2va_data = obj->pa2va_data;
		kext->name = strdup (padded_name);
		kext->own_name = true;
		free (padded_name);
		r_list_push (kexts, kext);

		cursor += cmdsize;
	}
early:
	r_buf_free (cache_buf);
	return kexts;
beach:
	r_buf_free (cache_buf);
	r_list_free (kexts);
	return NULL;
}

static void r_kext_free(RKext *kext) {
	if (!kext) {
		return;
	}

	r_list_free (kext->classes);

	if (kext->mach0) {
		MACH0_(mach0_free) (kext->mach0);
		kext->mach0 = NULL;
	}

	if (kext->own_name && kext->name) {
		R_FREE (kext->name);
		kext->name = NULL;
	}

	R_FREE (kext);
}

static void r_kext_fill_text_range(RKext *kext) {
	const RVecSection *sections = MACH0_(load_sections) (kext->mach0);
	if (!sections) {
		return;
	}

	struct section_t *section;
	R_VEC_FOREACH (sections, section) {
		if (strstr (section->name, "__TEXT_EXEC.__text")) {
			kext->text_range.offset = section->paddr;
			kext->text_range.size = section->size;
			kext->vaddr = section->vaddr;
			break;
		}
	}
}

static int kexts_sort_vaddr_func(const void *a, const void *b) {
	RKext *A = (RKext *) a;
	RKext *B = (RKext *) b;
	int vaddr_compare = A->vaddr - B->vaddr;
	if (vaddr_compare == 0) {
		return A->text_range.size - B->text_range.size;
	}
	return vaddr_compare;
}

static RKextIndex *r_kext_index_new(RList *kexts) {
	if (!kexts) {
		return NULL;
	}

	int length = r_list_length (kexts);
	if (!length) {
		return NULL;
	}

	RKextIndex *index = R_NEW0 (RKextIndex);
	index->entries = calloc (length, sizeof (RKext*));
	if (!index->entries) {
		R_FREE (index);
		return NULL;
	}

	RListIter *iter;
	RKext *kext;
	int i = 0;
	r_list_foreach (kexts, iter, kext) {
		index->entries[i++] = kext;
	}
	index->length = i;

	return index;
}

static void r_kext_index_free(RKextIndex *index) {
	if (!index) {
		return;
	}

	int i = 0;
	RKext *kext;
	r_kext_index_foreach (index, i, kext) {
		r_kext_free (kext);
		index->entries[i] = NULL;
	}

	index->length = 0;
	R_FREE (index);
}

static RKext *r_kext_index_vget(RKextIndex *index, ut64 vaddr) {
	int imid;
	int imin = 0;
	int imax = index->length - 1;

	while (imin < imax) {
		imid = (imin + imax) / 2;
		RKext *entry = index->entries[imid];
		if ((entry->vaddr + entry->text_range.size) <= vaddr || (entry->vaddr == vaddr && entry->text_range.size == 0)) {
			imin = imid + 1;
		} else {
			imax = imid;
		}
	}

	RKext *minEntry = index->entries[imin];
	if ((imax == imin) && (minEntry->vaddr <= vaddr) && ((minEntry->vaddr + minEntry->text_range.size) > vaddr)) {
		return minEntry;
	}
	return NULL;
}

static struct MACH0_(obj_t) *create_kext_mach0(RKernelCacheObj *obj, RKext *kext, RBinFile *bf) {
	RBuffer *buf = r_buf_new_slice (obj->cache_buf, kext->range.offset, r_buf_size (obj->cache_buf) - kext->range.offset);
	struct MACH0_(opts_t) opts;
	MACH0_(opts_set_default) (&opts, bf);
	opts.verbose = true;
	opts.header_at = 0;
	struct MACH0_(obj_t) *mach0 = MACH0_(new_buf) (bf, buf, &opts);
	r_buf_free (buf);
	return mach0;
}

static struct MACH0_(obj_t) *create_kext_shared_mach0(RKernelCacheObj *obj, RKext *kext, RBinFile *bf) {
	RBuffer *buf = r_buf_ref (obj->cache_buf);
	struct MACH0_(opts_t) opts;
	MACH0_(opts_set_default) (&opts, bf);
	opts.verbose = false;
	opts.header_at = kext->range.offset;
	struct MACH0_(obj_t) *mach0 = MACH0_(new_buf) (bf, buf, &opts);
	// RESULTS IN UAF we should ref and unref instead r_buf_free (buf);
	return mach0;
}

static RList *entries(RBinFile *bf) {
	RList *ret;
	RBinObject *obj = bf ? bf->bo : NULL;

	if (!obj || !obj->bin_obj || !(ret = r_list_newf (free))) {
		return NULL;
	}

	RKernelCacheObj *kobj = (RKernelCacheObj*) obj->bin_obj;
	ut64 entry_vaddr = kobj->mach0->entry;
	if (kobj->pa2va_exec <= entry_vaddr) {
		ut64 entry_paddr = entry_vaddr - kobj->pa2va_exec;
		RBinAddr *ba = newEntry (entry_paddr, entry_vaddr, 0);
		if (ba) {
			r_list_append (ret, ba);
		}
	}

	process_constructors (kobj, kobj->mach0, ret, 0, true, R_K_CONSTRUCTOR_TO_ENTRY, NULL);

	return ret;
}

static void process_kmod_init_term_vec(RVecRBinSymbol *symbols, RBinFile *bf, RKext *kext, ut64 **inits, ut64 **terms) {
	RKernelCacheObj *obj = (RKernelCacheObj*) bf->bo->bin_obj;
	if (!*inits || !*terms) {
		const RVecSection *sections = MACH0_(load_sections) (obj->mach0);
		if (!sections) {
			return;
		}

		struct section_t *section;
		R_VEC_FOREACH (sections, section) {
			if (section->size == 0) {
				continue;
			}

			ut64 start_paddr = 0;
			ut64 *target = NULL;
			int n_ptrs = 0;

			if (!*inits && strstr (section->name, "__kmod_init")) {
				int n_inits = section->size / 8;
				if (n_inits <= 0) {
					continue;
				}
				*inits = R_NEWS0 (ut64, n_inits + 1);
				target = *inits;
				n_ptrs = n_inits;
			}
			if (!*terms && strstr (section->name, "__kmod_term")) {
				int n_terms = section->size / 8;
				if (n_terms <= 0) {
					continue;
				}
				*terms = R_NEWS0 (ut64, n_terms + 1);
				target = *terms;
				n_ptrs = n_terms;
			}
			if (!target || !n_ptrs) {
				continue;
			}
			start_paddr = section->paddr;
			int j = 0;
			ut8 bytes[8];
			for (; j < n_ptrs; j++) {
				if (r_buf_read_at (obj->cache_buf, start_paddr + j * 8, bytes, 8) < 8) {
					break;
				}
				target[j] = K_RPTR (bytes);
			}
			target[j] = 0;
		}
	}

	if (*inits) {
		create_initterm_syms_vec (symbols, bf, kext, R_BIN_ENTRY_TYPE_INIT, *inits);
	}
	if (*terms) {
		create_initterm_syms_vec (symbols, bf, kext, R_BIN_ENTRY_TYPE_FINI, *terms);
	}
}

/*
 * com.apple.driver.AppleMesaSEPDriver.3.__TEXT_EXEC.__text
 *                       |
 *                       |
 * AppleMesaSEPDriver <--+
 */
static const char *kext_short_name(RKext *kext) {
	const char *sn = strrchr (kext->name, '.');
	return sn ? sn + 1 : kext->name;
}

static void create_initterm_syms_vec(RVecRBinSymbol *symbols, RBinFile *bf, RKext *kext, int type, ut64 *pointers) {
	// RKernelCacheObj *obj = (RKernelCacheObj*) bf->bo->bin_obj;
	int i = 0;
	int count = 0;
	for (; pointers[i]; i++) {
		ut64 func_vaddr = pointers[i];
		ut64 text_start = kext->vaddr;
		ut64 text_end = text_start + kext->text_range.size;

		if (text_start == text_end) {
			continue;
		}

		if (text_start > func_vaddr || func_vaddr >= text_end) {
			continue;
		}

		RBinSymbol *sym = R_NEW0 (RBinSymbol);
		sym->name = r_bin_name_new_from (
				r_str_newf ("%s.%s.%d", kext_short_name (kext), (type == R_BIN_ENTRY_TYPE_INIT) ? "init" : "fini", count++)
			);
		sym->vaddr = func_vaddr;
		sym->paddr = func_vaddr - kext->pa2va_exec;
		sym->size = 0;
		sym->forwarder = "NONE";
		sym->bind = "GLOBAL";
		sym->type = "FUNC";

		RVecRBinSymbol_push_back (symbols, sym);
	}
}

static void process_constructors(RKernelCacheObj *obj, struct MACH0_(obj_t) *mach0, RList *ret, ut64 paddr, bool is_first, int mode, const char *prefix) {
// TODO: derpecate and use only a vector
	const RVecSection *sections = MACH0_(load_sections) (mach0);
	if (!sections) {
		return;
	}
	int type;
	struct section_t *section;
	R_VEC_FOREACH (sections, section) {
		if (section->size == 0) {
			continue;
		}

		if (strstr (section->name, "_mod_fini_func") || strstr (section->name, "_mod_term_func")) {
			type  = R_BIN_ENTRY_TYPE_FINI;
		} else if (strstr (section->name, "_mod_init_func")) {
			type  = is_first ? 0 : R_BIN_ENTRY_TYPE_INIT;
			is_first = false;
		} else {
			continue;
		}

		ut8 *buf = calloc (section->size, 1);
		if (!buf) {
			break;
		}
		if (r_buf_read_at (obj->cache_buf, section->paddr + paddr, buf, section->size) < section->size) {
			free (buf);
			break;
		}
		int j;
		int count = 0;
		for (j = 0; j + 7 < section->size; j += 8) {
			ut64 addr64 = K_RPTR (buf + j);
			ut64 paddr64 = section->paddr + paddr + j;
			if (mode == R_K_CONSTRUCTOR_TO_ENTRY) {
				RBinAddr *ba = newEntry (paddr64, addr64, type);
				r_list_append (ret, ba); // XXX rbinaddr != rbinsymbol
				// eprintf ("entry point is wrong here.. \n");
				// XXX RVecRBinSymbol_push_back (&(bf->bo->symbols_vec), ba);
			} else if (mode == R_K_CONSTRUCTOR_TO_SYMBOL) {
				RBinSymbol *sym = R_NEW0 (RBinSymbol);
				sym->name = r_bin_name_new_from (
						r_str_newf ("%s.%s.%d", prefix, (type == R_BIN_ENTRY_TYPE_INIT) ? "init" : "fini", count++)
					);
				sym->vaddr = addr64;
				sym->paddr = paddr64;
				sym->size = 0;
				sym->forwarder = "NONE";
				sym->bind = "GLOBAL";
				sym->type = "FUNC";
				r_list_append (ret, sym);
			}
		}
		free (buf);
	}
}

static void process_constructors_vec(RVecRBinSymbol *symbols, RBinFile *bf, RKernelCacheObj *obj, struct MACH0_(obj_t) *mo, ut64 paddr, bool is_first, int mode, const char *prefix) {
	const RVecSection *sections = MACH0_(load_sections) (mo);
	if (!sections) {
		return;
	}
	int type;
	struct section_t *section;
	R_VEC_FOREACH (sections, section) {
		if (section->size == 0) {
			continue;
		}

		if (strstr (section->name, "_mod_fini_func") || strstr (section->name, "_mod_term_func")) {
			type  = R_BIN_ENTRY_TYPE_FINI;
		} else if (strstr (section->name, "_mod_init_func")) {
			type  = is_first ? 0 : R_BIN_ENTRY_TYPE_INIT;
			is_first = false;
		} else {
			continue;
		}

		ut8 *buf = calloc (section->size, 1);
		if (!buf) {
			break;
		}
		if (r_buf_read_at (obj->cache_buf, section->paddr, buf, section->size) < section->size) {
			free (buf);
			break;
		}
		int j;
		int count = 0;
		for (j = 0; j + 7 < section->size; j += 8) {
			ut64 addr64 = K_RPTR (buf + j);
			ut64 paddr64 = addr64 - obj->pa2va_exec;

			if (mode == R_K_CONSTRUCTOR_TO_ENTRY) {
				R_LOG_WARN ("wrong entrypoint entry not registered");
				// RBinAddr *ba = newEntry (paddr64, addr64, type);
				// r_list_append (ret, ba);
				// XXX RVecRBinSymbol_push_back (&(bf->bo->symbols_vec), ba);
			} else if (mode == R_K_CONSTRUCTOR_TO_SYMBOL) {
				RBinSymbol sym = {0};
				sym.name = r_bin_name_new_from (
							r_str_newf ("%s.%s.%d", prefix, (type == R_BIN_ENTRY_TYPE_INIT) ? "init" : "fini", count++)
					);
				sym.vaddr = addr64;
				sym.paddr = paddr64;
				sym.size = 0;
				sym.forwarder = "NONE";
				sym.bind = "GLOBAL";
				sym.type = "FUNC";
				RVecRBinSymbol_push_back (symbols, &sym);
			}
		}
		free (buf);
	}
}

static void bin_symbol_copy(RBinSymbol *dst, const RBinSymbol *src) {
	memcpy (dst, src, sizeof (RBinSymbol));
	dst->name = r_bin_name_clone (src->name);
	if (src->libname) {
		dst->libname = strdup (src->libname);
	}
	if (src->classname) {
		dst->classname = strdup (src->classname);
	}
}

static RBinAddr *newEntry(ut64 haddr, ut64 vaddr, int type) {
	RBinAddr *ptr = R_NEW0 (RBinAddr);
	ptr->paddr = haddr;
	ptr->vaddr = vaddr;
	ptr->hpaddr = haddr;
	ptr->bits = 64;
	ptr->type = type;
	return ptr;
}

static bool check(RBinFile *bf, RBuffer *b) {
	if (r_buf_size (b) > 4) {
		ut8 buf[4];
		r_buf_read_at (b, 0, buf, sizeof (buf));
		if (!memcmp (buf, "\xcf\xfa\xed\xfe", 4)) {
			return is_kernelcache_buffer (b);
		}
	}
	return false;
}

static RList *sections(RBinFile *bf) {
	RList *ret = NULL;
	RBinObject *obj = bf ? bf->bo : NULL;

	if (!obj || !obj->bin_obj || !(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}

	RKernelCacheObj *kobj = (RKernelCacheObj*) obj->bin_obj;
	ensure_kexts_initialized (kobj, bf);
	RBuffer *cache_buf = r_buf_ref (kobj->cache_buf);
	if (!cache_buf) {
		r_list_free (ret);
		return NULL;
	}

	int iter;
	RKext *kext;
	r_kext_index_foreach (kobj->kexts, iter, kext) {
		ut8 magicbytes[4];

		r_buf_read_at (cache_buf, kext->range.offset, magicbytes, 4);
		int magic = r_read_le32 (magicbytes);
		switch (magic) {
		case MH_MAGIC_64:
			sections_from_mach0 (ret, kext->mach0, bf, kext->range.offset, kext->name, kobj);
			break;
		default:
			R_LOG_ERROR ("Unknown sub-bin");
			break;
		}
	}

	sections_from_mach0 (ret, kobj->mach0, bf, 0, NULL, kobj);

	struct MACH0_(segment_command) *seg;
	int nsegs = R_MIN (kobj->mach0->nsegs, 128);
	int i;
	for (i = 0; i < nsegs; i++) {
		char segname[17];
		RBinSection *ptr = R_NEW0 (RBinSection);
		seg = &kobj->mach0->segs[i];
		r_str_ncpy (segname, seg->segname, 17);
		r_str_filter (segname, -1);
		ptr->name = r_str_newf ("%d.%s", i, segname);
		ptr->size = seg->vmsize;
		ptr->vsize = seg->vmsize;
		ptr->paddr = seg->fileoff + bf->bo->boffset;
		ptr->vaddr = seg->vmaddr;
		ptr->add = true;
		ptr->is_segment = true;
		if (!ptr->vaddr) {
			ptr->vaddr = ptr->paddr;
		}
			ptr->perm = prot2perm (seg->initprot);
		r_list_append (ret, ptr);
	}

	r_buf_free (cache_buf);
	return ret;
}

static int prot2perm(int x) {
	int r = 0;
	if (x&1) r |= 4;
	if (x&2) r |= 2;
	if (x&4) r |= 1;
	return r;
}

static void sections_from_mach0(RList *ret, struct MACH0_(obj_t) *mach0, RBinFile *bf, ut64 paddr, char *prefix, RKernelCacheObj *obj) {
	const RVecSection *sections = MACH0_(load_sections) (mach0);
	if (!sections) {
		return;
	}

	struct section_t *section;
	bool is_paddr_global = true;
	R_VEC_FOREACH (sections, section) {
		if (section->paddr != 0 && section->paddr + bf->bo->boffset < paddr) {
			is_paddr_global = false;
			break;
		}
	}
	R_VEC_FOREACH (sections, section) {
		RBinSection *ptr = R_NEW0 (RBinSection);
		if (prefix) {
			ptr->name = r_str_newf ("%s.%s", prefix, (char*)section->name);
		} else {
			ptr->name = r_str_newf ("%s", (char*)section->name);
		}
		if (strstr (ptr->name, "la_symbol_ptr")) {
			int len = section->size / 8;
			ptr->format = r_str_newf ("Cd %d[%d]", 8, len);
		}
		handle_data_sections (ptr);
		ptr->size = section->size;
		ptr->vsize = section->vsize;
		ptr->paddr = section->paddr + bf->bo->boffset;
		if (!is_paddr_global) {
			ptr->paddr += paddr;
		}
		ptr->vaddr = K_PPTR (section->vaddr);
		if (!ptr->vaddr) {
			ptr->vaddr = ptr->paddr;
		}
		ptr->perm = section->perm;
		if (!ptr->perm && strstr (section->name, "__TEXT_EXEC.__text")) {
			ptr->perm = 1 | 4;
		}
		r_list_append (ret, ptr);
	}
}

static void handle_data_sections(RBinSection *sect) {
	if (strstr (sect->name, "_cstring")) {
		sect->is_data = true;
	} else if (strstr (sect->name, "_os_log")) {
		sect->is_data = true;
	} else if (strstr (sect->name, "_objc_methname")) {
		sect->is_data = true;
	} else if (strstr (sect->name, "_objc_classname")) {
		sect->is_data = true;
	} else if (strstr (sect->name, "_objc_methtype")) {
		sect->is_data = true;
	}
}

static bool symbols_vec(RBinFile *bf) {
	RKernelCacheObj *obj = (RKernelCacheObj*) bf->bo->bin_obj;

	struct MACH0_(obj_t) *mo = obj->mach0;
	RVecRBinSymbol symbols;
	RVecRBinSymbol_init (&symbols);
	if (MACH0_(load_symbols) (mo)) {
		RVecRBinSymbol_append (&symbols, mo->symbols_vec, &bin_symbol_copy);
		RVecRBinSymbol_fini (mo->symbols_vec);
	}

	HtPP *kernel_syms_by_addr = sdb_ht_new ();
	if (!kernel_syms_by_addr) {
		return false;
	}

	RBinSymbol *sym;
	ut64 enosys_addr = 0;
	R_VEC_FOREACH (&symbols, sym) {
		r_strf_var (key, 64, "%"PFMT64x, sym->vaddr);
		const char *oname = r_bin_name_tostring (sym->name);
		sdb_ht_insert (kernel_syms_by_addr, key, oname);
		if (!enosys_addr && strstr (oname, "enosys")) {
			enosys_addr = sym->vaddr;
		}
	}

	ensure_kexts_initialized (obj, bf);
	RList *syscalls = resolve_syscalls (obj, enosys_addr);
	if (syscalls) {
		RListIter *iter;
		r_list_foreach (syscalls, iter, sym) {
			const char *oname = r_bin_name_tostring (sym->name);
			r_strf_var (key, 32, "%"PFMT64x, sym->vaddr);
			sdb_ht_insert (kernel_syms_by_addr, key, oname);
			RVecRBinSymbol_push_back (&symbols, sym);
		}
		syscalls->free = NULL;
		r_list_free (syscalls);
	}

	RList *subsystem = resolve_mig_subsystem (obj);
	if (subsystem) {
		RListIter *iter;
		r_list_foreach (subsystem, iter, sym) {
			r_strf_var (key, 64, "%"PFMT64x, sym->vaddr);
			const char *sym_name = r_bin_name_tostring (sym->name);
			sdb_ht_insert (kernel_syms_by_addr, key, sym_name);
			RVecRBinSymbol_push_back (&symbols, sym);
		}
		subsystem->free = NULL;
		r_list_free (subsystem);
	}

	char *filter = r_sys_getenv ("R_KERNELCACHE_FILTER");
	if (R_STR_ISEMPTY (filter)) {
		R_FREE (filter);
	}

	RKext *kext = NULL;
	int kiter;
	ut64 *inits = NULL;
	ut64 *terms = NULL;
	RCons *cons = r_cons_singleton ();
	r_cons_break_push (cons, NULL, NULL);
	r_kext_index_foreach (obj->kexts, kiter, kext) {
		if (r_cons_is_breaked (cons)) {
			eprintf ("Interrupted\n");
			break;
		}
		if (filter && !strstr (kext->name, filter)) {
			continue;
		}
		ut8 magicbytes[4];
		r_buf_read_at (obj->cache_buf, kext->range.offset, magicbytes, 4);
		// TODO: add a filter by name
		R_LOG_INFO ("Loading kEXT %s", kext->name);
		ut32 magic = r_read_le32 (magicbytes);
		switch (magic) {
		case MH_MAGIC_64:
			if (MACH0_(load_symbols) (kext->mach0)) {
				R_LOG_DEBUG ("--> %d / %d", RVecRBinSymbol_length (kext->mach0->symbols_vec), RVecRBinSymbol_length (&symbols));
				RVecRBinSymbol_append (&symbols, kext->mach0->symbols_vec, &bin_symbol_copy);
			}

			ut64 start_offset = RVecRBinSymbol_length (&symbols);

			{
				process_constructors_vec (&symbols, bf, obj, kext->mach0, kext->range.offset, false, R_K_CONSTRUCTOR_TO_SYMBOL, kext_short_name (kext));
				const ut32 last_ordinal = RVecRBinSymbol_length (&(bf->bo->symbols_vec));
				symbols_from_stubs_vec (&symbols, bf, kernel_syms_by_addr, kext, last_ordinal);
				process_kmod_init_term_vec (&symbols, bf, kext, &inits, &terms);
				RVecRBinSymbol_fini (kext->mach0->symbols_vec);
				kext->mach0->symbols_loaded = false;
#if 0
				// causes UAF, because symbols name is not copied in an ownery way, so better leak than crash
				// freeing this makes us lose the sections
				MACH0_(mach0_free)(kext->mach0);
				kext->mach0 = NULL;
#endif
			}

			kext->classes = resolve_iokit_classes (&symbols, start_offset, bf, kext);
			RListIter *iter;
			RIOKitClass *c;
			r_list_foreach (kext->classes, iter, c) {
				ht_up_insert (obj->class_by_handle, c->meta_va, c);
			}

			break;
		default:
			R_LOG_WARN ("Unknown sub-bin");
			break;
		}
	}
	r_cons_break_pop (cons);

	R_FREE (inits);
	R_FREE (terms);

	sdb_ht_free (kernel_syms_by_addr);
	// memcpy (kext->mach0->symbols_vec, &symbols, sizeof (symbols));
	memcpy (&(bf->bo->symbols_vec), &symbols, sizeof (symbols));

	return true;
}

static RList *classes(RBinFile *bf) {
	RKernelCacheObj *obj = (RKernelCacheObj*) bf->bo->bin_obj;
	RList *list = r_list_newf ((RListFree) r_bin_class_free);
	int i;
	RKext *kext;
	r_kext_index_foreach (obj->kexts, i, kext) {
		RListIter *iter;
		RIOKitClass *c;
		r_list_foreach (kext->classes, iter, c) {
			RIOKitClass *parent = ht_up_find (obj->class_by_handle, c->supermeta_va, NULL);
			RBinClass *klass = r_bin_class_new (c->name, parent ? parent->name : "", R_BIN_ATTR_PUBLIC);
			klass->instance_size = c->size;
			klass->addr = c->meta_va;
			klass->origin = R_BIN_CLASS_ORIGIN_BIN;
			r_list_append (list, klass);
		}
	}

	return list;
}

typedef struct _r_sysent {
	ut64 sy_call;
	ut64 sy_arg_munge32;
	st32 sy_return_type;
	st16 sy_narg;
	ut16 sy_arg_bytes;
} RSysEnt;

static RList *resolve_syscalls(RKernelCacheObj *obj, ut64 enosys_addr) {
	const RVecSection *sections = MACH0_(load_sections) (obj->mach0);
	if (!sections) {
		return NULL;
	}

	RList *syscalls = NULL;
	RSyscall *syscall = NULL;
	ut8 *data_const = NULL;
	ut64 data_const_offset = 0, data_const_size = 0, data_const_vaddr = 0;
	struct section_t *section;
	R_VEC_FOREACH (sections, section) {
		if (strstr (section->name, "__DATA_CONST.__const")) {
			data_const_offset = section->paddr;
			data_const_size = section->size;
			data_const_vaddr = K_PPTR (section->vaddr);
			break;
		}
	}

	if (!data_const_offset || !data_const_size || !data_const_vaddr) {
		RKext *kext = NULL;
		int kiter;
		r_kext_index_foreach (obj->kexts, kiter, kext) {
			if (strcmp (kext->name, "com.apple.kernel") == 0) {
				const RVecSection *sections = MACH0_(load_sections) (kext->mach0);
				if (sections) {
					R_VEC_FOREACH (sections, section) {
						if (strstr (section->name, "__DATA_CONST.__const")) {
							data_const_offset = section->paddr;
							data_const_size = section->size;
							data_const_vaddr = K_PPTR (section->vaddr);
							break;
						}
					}
				}
				break;
			}
		}
		if (!data_const_offset || !data_const_size || !data_const_vaddr) {
			goto beach;
		}
	}

	data_const = malloc (data_const_size);
	if (!data_const) {
		goto beach;
	}
	if (r_buf_read_at (obj->cache_buf, data_const_offset, data_const, data_const_size) < data_const_size) {
		goto beach;
	}

	ut8 *cursor = data_const;
	ut8 *end = data_const + data_const_size;
	ut64 offset = 24;
	ut64 array_offset = 24;
	ut64 pattern = enosys_addr;
	if (enosys_addr == 0) {
		pattern = 0x0004000100000000;
		offset += 40;
		array_offset += 24;
	}
	while (cursor < end) {
		ut64 test = r_read_le64 (cursor);
		if (test == pattern) {
			break;
		}
		cursor += 8;
	}

	if (cursor >= end) {
		goto beach;
	}

	cursor -= offset;
	if (enosys_addr) {
		while (cursor >= data_const) {
			ut64 addr = r_read_le64 (cursor);
			ut64 x = r_read_le64 (cursor + 8);
			ut64 y = r_read_le64 (cursor + 16);

			if (IS_KERNEL_ADDR (K_PPTR (addr)) &&
				(x == 0 || IS_KERNEL_ADDR (K_PPTR (x))) &&
				(y != 0 && !IS_KERNEL_ADDR (K_PPTR (y)))) {
				cursor -= 24;
				continue;
			}

			cursor += 24;
			break;
		}
	}

	if (cursor < data_const) {
		goto beach;
	}

	syscalls = r_list_newf (r_bin_symbol_free);
	if (!syscalls) {
		goto beach;
	}

	syscall = r_syscall_new ();
	if (!syscall) {
		goto beach;
	}
	r_syscall_setup (syscall, "arm", 64, NULL, "ios");
	if (!syscall->db) {
		r_syscall_free (syscall);
		goto beach;
	}

	ut64 sysent_vaddr = cursor - data_const + data_const_vaddr;

	RBinSymbol *sym = R_NEW0 (RBinSymbol);
	sym->name = r_bin_name_new ("sysent");
	sym->vaddr = sysent_vaddr;
	sym->paddr = cursor - data_const + data_const_offset;
	sym->size = 0;
	sym->forwarder = "NONE";
	sym->bind = "GLOBAL";
	sym->type = "OBJECT";
	r_list_append (syscalls, sym);

	int i = 1;
	cursor += array_offset;
	int num_syscalls = sdb_count (syscall->db);
	while (cursor < end && i < num_syscalls) {
		ut64 addr = K_PPTR (r_read_le64 (cursor));
		RSyscallItem *item = r_syscall_get (syscall, i, 0x80);
		if (item && item->name) {
			RBinSymbol *sym = R_NEW0 (RBinSymbol);
			sym->name = r_bin_name_new_from (r_str_newf ("syscall.%d.%s", i, item->name));
			sym->vaddr = addr;
			sym->paddr = addr;
			sym->size = 0;
			sym->forwarder = "NONE";
			sym->bind = "GLOBAL";
			sym->type = "FUNC";
			r_list_append (syscalls, sym);
		}
		r_syscall_item_free (item);
		cursor += 24;
		i++;
	}

	r_syscall_free (syscall);
	R_FREE (data_const);
	return syscalls;

beach:
	r_syscall_free (syscall);
	if (syscalls) {
		r_list_free (syscalls);
	}
	R_FREE (data_const);
	return NULL;
}

#define K_MIG_SUBSYSTEM_SIZE (4 * 8)
#define K_MIG_ROUTINE_SIZE (5 * 8)
#define K_MIG_MAX_ROUTINES 100

static HtPP *mig_hash_new(void) {
	HtPP *hash = sdb_ht_new ();
	if (!hash) {
		return NULL;
	}

	int i;
	for (i = 0; i < R_MIG_INDEX_LEN; i += 2) {
		const char *num = mig_index[i];
		const char *name = mig_index[i+1];
		sdb_ht_insert (hash, num, name);
	}

	return hash;
}

static RList *resolve_mig_subsystem(RKernelCacheObj *obj) {
	const RVecSection *sections = MACH0_(load_sections) (obj->mach0);
	if (!sections) {
		return NULL;
	}

	HtPP *mig_hash = NULL;
	RList *subsystem = NULL;
	ut8 *data_const = NULL;
	ut64 data_const_offset = 0, data_const_size = 0, data_const_vaddr = 0;
	ut64 text_exec_offset = 0, text_exec_size = 0, text_exec_vaddr = 0;
	int incomplete = 2;

	struct section_t *section;
	R_VEC_FOREACH (sections, section) {
		if (strstr (section->name, "__DATA_CONST.__const")) {
			data_const_offset = section->paddr;
			data_const_size = section->size;
			data_const_vaddr = K_PPTR (section->vaddr);
			incomplete--;
		}
		if (strstr (section->name, "__TEXT_EXEC.__text")) {
			text_exec_offset = section->paddr;
			text_exec_size = section->size;
			text_exec_vaddr = K_PPTR (section->vaddr);
			incomplete--;
		}
	}
	if (incomplete) {
		return NULL;
	}

	if (!data_const_offset || !data_const_size || !data_const_vaddr ||
		!text_exec_offset || !text_exec_size || !text_exec_vaddr) {
		goto beach;
	}

	data_const = malloc (data_const_size);
	if (!data_const) {
		goto beach;
	}
	if (r_buf_read_at (obj->cache_buf, data_const_offset, data_const, data_const_size) < data_const_size) {
		goto beach;
	}

	subsystem = r_list_newf (r_bin_symbol_free);
	if (!subsystem) {
		goto beach;
	}

	mig_hash = mig_hash_new ();
	if (!mig_hash) {
		goto beach;
	}

	ut8 *cursor = data_const;
	ut8 *end = data_const + data_const_size;
	while (cursor < end) {
		ut64 subs_p = K_PPTR (r_read_le64 (cursor));
		if (subs_p < text_exec_vaddr || subs_p >= text_exec_vaddr + text_exec_size) {
			cursor += 8;
			continue;
		}
		ut32 subs_min_idx = r_read_le32 (cursor + 8);
		ut32 subs_max_idx = r_read_le32 (cursor + 12);
		if (subs_min_idx >= subs_max_idx || (subs_max_idx - subs_min_idx) > K_MIG_MAX_ROUTINES) {
			cursor += 16;
			continue;
		}

		ut32 n_routines = (subs_max_idx - subs_min_idx);
		ut64 *routines = (ut64 *) calloc (n_routines, sizeof (ut64));
		if (!routines) {
			goto beach;
		}
		ut8 *array_cursor = cursor + K_MIG_SUBSYSTEM_SIZE;
		ut8 *end_array = array_cursor + n_routines * K_MIG_ROUTINE_SIZE;
		bool is_consistent = true;
		int idx = 0;
		while (array_cursor < end_array) {
			ut64 should_be_null = r_read_le64 (array_cursor);
			if (should_be_null != 0) {
				is_consistent = false;
				break;
			}

			ut64 routine_p = K_PPTR (r_read_le64 (array_cursor + 8));
			if (routine_p != 0 && (routine_p < text_exec_vaddr || routine_p >= text_exec_vaddr + text_exec_size)) {
				is_consistent = false;
				break;
			}

			routines[idx++] = routine_p;
			array_cursor += K_MIG_ROUTINE_SIZE;
		}

		if (is_consistent) {
			for (idx = 0; idx < n_routines; idx++) {
				ut64 routine_p = routines[idx];
				if (!routine_p) {
					continue;
				}

				RBinSymbol *sym = R_NEW0 (RBinSymbol);
				int num = idx + subs_min_idx;
				bool found = false;
				r_strf_var (key, 32, "%d", num);
				const char *name = sdb_ht_find (mig_hash, key, &found);
				if (found && name && *name) {
					sym->name = r_bin_name_new_from (r_str_newf ("mig.%d.%s", num, name));
				} else {
					sym->name = r_bin_name_new_from (r_str_newf ("mig.%d", num));
				}

				sym->vaddr = routine_p;
				sym->paddr = sym->vaddr - text_exec_vaddr + text_exec_offset;
				sym->size = 0;
				sym->forwarder = "NONE";
				sym->bind = "GLOBAL";
				sym->type = "OBJECT";
				r_list_append (subsystem, sym);
			}

			cursor += K_MIG_SUBSYSTEM_SIZE + n_routines * K_MIG_ROUTINE_SIZE;
		} else {
			cursor += 8;
		}

		R_FREE (routines);
	}

	sdb_ht_free (mig_hash);
	R_FREE (data_const);
	return subsystem;

beach:
	if (subsystem) {
		r_list_free (subsystem);
	}
	if (mig_hash) {
		sdb_ht_free (mig_hash);
	}
	R_FREE (data_const);
	return NULL;
}

static ut64 extract_addr_from_code(const ut8 *arm64_code, ut64 vaddr) {
	const ut64 page = vaddr & ~0xfffULL;

	const ut32 adrp = r_read_le32 (arm64_code);
	const ut64 immlo = (adrp >> 29) & 0x3;
	const ut64 immhi = (adrp >> 5) & 0x7ffffULL;
	ut64 imm21 = (immhi << 2) | immlo;
	int64_t simm21 = (int64_t) ((imm21 ^ 0x100000) - 0x100000);
	// Avoid shifting a negative value (which is undefined and flagged by Coverity).
	// Compute the page offset as a signed 64-bit multiply, then widen to ut64.
	int64_t page_off = simm21 * 4096; // 1 << 12
	const ut64 adrp_base = page + (ut64) page_off;

	const ut32 addi = r_read_le32 (arm64_code + 4);
	const ut64 imm12 = (addi >> 10) & 0xFFFULL;
	const ut64 sh = (addi >> 22) & 0x1ULL;
	const ut64 add_imm = imm12 << (sh ? 12 : 0);

	return adrp_base + add_imm;
}

static void symbols_from_stubs_vec(RVecRBinSymbol *symbols, RBinFile *bf, HtPP *kernel_syms_by_addr, RKext *kext, int ordinal) {
	RKernelCacheObj *obj = (RKernelCacheObj*) bf->bo->bin_obj;
	RStubsInfo *stubs_info = get_stubs_info (kext->mach0, kext->range.offset, obj);
	if (!stubs_info) {
		return;
	}
	RBuffer *cache_buf = r_buf_ref (obj->cache_buf);
	if (!cache_buf) {
		R_FREE (stubs_info);
		return;
	}
	ut64 stubs_cursor = stubs_info->stubs.offset;
	ut64 stubs_end = stubs_cursor + stubs_info->stubs.size;

	for (; stubs_cursor < stubs_end; stubs_cursor += 12) {
		ut8 arm64_code[8];
		if (r_buf_read_at (cache_buf, stubs_cursor, arm64_code, 8) < 8) {
			break;
		}

		ut64 vaddr = stubs_cursor + obj->pa2va_exec;
		ut64 addr_in_got = extract_addr_from_code (arm64_code, vaddr);

		bool found = false;
		int level = 3;

		ut64 target_addr = UT64_MAX;

		while (!found && level-- > 0) {
			ut64 offset_in_got = addr_in_got - obj->pa2va_exec;
			ut64 addr;
			if (r_buf_read_at (cache_buf, offset_in_got, (ut8*) &addr, 8) < 8) {
				break;
			}

			if (level == 2) {
				target_addr = addr;
			}

			r_strf_var (key, 32, "%"PFMT64x, addr);
			const char *name = sdb_ht_find (kernel_syms_by_addr, key, &found);

			if (found) {
				/* coverity[leaked_storage] ownership transferred into subsystem list */
				RBinSymbol *sym = R_NEW0 (RBinSymbol);
				sym->name = r_bin_name_new_from (r_str_newf ("stub.%s", name));
				sym->vaddr = vaddr;
				sym->paddr = stubs_cursor;
				sym->size = 12;
				sym->forwarder = "NONE";
				sym->bind = "LOCAL";
				sym->type = "FUNC";
				sym->ordinal = ordinal ++;
				RVecRBinSymbol_push_back (symbols, sym);
				break;
			}

			addr_in_got = addr;
		}

		if (found || target_addr == UT64_MAX) {
			continue;
		}

		ensure_kexts_initialized (obj, bf);
		RKext *remote_kext = r_kext_index_vget (obj->kexts, target_addr);
		if (!remote_kext) {
			continue;
		}

		RBinSymbol *remote_sym = R_NEW0 (RBinSymbol);
		remote_sym->name = r_bin_name_new_from (
				r_str_newf ("exp.%s.0x%"PFMT64x, kext_short_name (remote_kext), target_addr)
			);
		remote_sym->vaddr = target_addr;
		remote_sym->paddr = target_addr - obj->pa2va_exec;
		remote_sym->size = 0;
		remote_sym->forwarder = "NONE";
		remote_sym->bind = "GLOBAL";
		remote_sym->type = "FUNC";
		remote_sym->ordinal = ordinal ++;
		RVecRBinSymbol_push_back (symbols, remote_sym);

		RBinSymbol *local_sym = R_NEW0 (RBinSymbol);
		local_sym->name = r_bin_name_new_from (r_str_newf ("stub.%s.0x%"PFMT64x, kext_short_name (remote_kext), target_addr));
		local_sym->vaddr = vaddr;
		local_sym->paddr = stubs_cursor;
		local_sym->size = 12;
		local_sym->forwarder = "NONE";
		local_sym->bind = "GLOBAL";
		local_sym->type = "FUNC";
		local_sym->ordinal = ordinal ++;
		RVecRBinSymbol_push_back (symbols, local_sym);
	}

	r_buf_free (cache_buf);
	R_FREE (stubs_info);
}


static RStubsInfo *get_stubs_info(struct MACH0_(obj_t) *mach0, ut64 paddr, RKernelCacheObj *obj) {
	const RVecSection *sections = MACH0_(load_sections) (mach0);
	if (!sections) {
		return NULL;
	}

	RStubsInfo *stubs_info = R_NEW0 (RStubsInfo);
	int incomplete = 2;
	struct section_t *section;
	R_VEC_FOREACH (sections, section) {
		if (strstr (section->name, "__DATA_CONST.__got")) {
			stubs_info->got.offset = section->paddr + paddr;
			stubs_info->got.size = section->size;
			stubs_info->got_addr = K_PPTR (section->vaddr);
			if (!--incomplete) {
				break;
			}
		}

		if (strstr (section->name, "__TEXT_EXEC.__stubs")) {
			stubs_info->stubs.offset = section->paddr + paddr;
			stubs_info->stubs.size = section->size;
			if (!--incomplete) {
				break;
			}
		}
	}

	if (incomplete) {
		R_FREE (stubs_info);
	}

	return stubs_info;
}

static RList *resolve_iokit_classes(RVecRBinSymbol *symbols, ut64 start_offset, RBinFile *bf, RKext *kext) {
	RList *classes = find_class_registrations (symbols, start_offset, bf, kext);
	find_class_vtables (classes, bf, kext);
	compute_class_vtable_sizes (classes, bf, kext);

	RListIter *it;
	RIOKitClass *c;
	r_list_foreach (classes, it, c) {
		/* coverity[leaked_storage] ownership transferred into symbols vector */
		RBinSymbol *sym = R_NEW0 (RBinSymbol);
		sym->name = r_bin_name_new_from (r_str_newf ("%s::gMetaClass", c->name));
		sym->vaddr = c->meta_va;
		sym->paddr = c->meta_va - kext->pa2va_exec;
		sym->size = 8;
		sym->forwarder = "NONE";
		sym->bind = "GLOBAL";
		sym->type = "OBJECT";
		sym->ordinal = RVecRBinSymbol_length (symbols);
		RVecRBinSymbol_push_back (symbols, sym);

		if (c->vt.instance.va) {
			/* coverity[leaked_storage] ownership transferred into symbols vector */
			RBinSymbol *vsym = R_NEW0 (RBinSymbol);
			vsym->name = r_bin_name_new_from (r_str_newf ("%s::vtable", c->name));
			vsym->vaddr = c->vt.instance.va;
			vsym->paddr = c->vt.instance.va - kext->pa2va_exec;
			{
				/* avoid overflow-before-widen: promote before multiply */
				ut64 slots = (ut64) (c->vt.instance.slots_total ? c->vt.instance.slots_total : 1U);
				vsym->size = slots * 8ULL;
			}
			vsym->forwarder = "NONE";
			vsym->bind = "GLOBAL";
			vsym->type = "OBJECT";
			vsym->ordinal = RVecRBinSymbol_length (symbols);
			RVecRBinSymbol_push_back (symbols, vsym);
		}

		if (c->vt.metaclass.va) {
			/* coverity[leaked_storage] ownership transferred into symbols vector */
			RBinSymbol *msym = R_NEW0 (RBinSymbol);
			msym->name = r_bin_name_new_from (r_str_newf ("%s::MetaClass::vtable", c->name));
			msym->vaddr = c->vt.metaclass.va;
			msym->paddr = c->vt.metaclass.va - kext->pa2va_exec;
			{
				/* avoid overflow-before-widen: promote before multiply */
				ut64 slots = (ut64) (c->vt.metaclass.slots_total ? c->vt.metaclass.slots_total : 1U);
				msym->size = slots * 8ULL;
			}
			msym->forwarder = "NONE";
			msym->bind = "GLOBAL";
			msym->type = "OBJECT";
			msym->ordinal = RVecRBinSymbol_length (symbols);
			RVecRBinSymbol_push_back (symbols, msym);
		}
	}

	return classes;
}

static RList *find_class_registrations(RVecRBinSymbol *symbols, ut64 start_offset, RBinFile *bf, RKext *kext) {
	RList *classes = r_list_newf (r_iokit_class_free);

	ut64 i;
	ut64 end_offset = RVecRBinSymbol_length (symbols);
	for (i = start_offset; i != end_offset; i++) {
		RBinSymbol *sym = RVecRBinSymbol_at (symbols, i);
		if (!strstr (sym->name->oname, ".init.")) {
			continue;
		}

		ut64 func_vaddr = sym->vaddr;
		ut64 reg_values[29] = { 0, };
		ut64 w3_site = 0;

		ut64 pc;
		for (pc = func_vaddr; true; pc += 4) {
			ut8 bytes[8];
			if (!try_read_exec_va (bf, kext, pc, bytes, sizeof (bytes))) {
				break;
			}

			int reg;
			ut64 addr;
			if (try_parse_adrp_add_pair (bytes, pc, &reg, &addr) ||
					try_parse_adrp_ldr_pair (bytes, pc, bf, kext, &reg, &addr)) {
				if (reg < R_ARRAY_SIZE (reg_values)) {
					reg_values[reg] = addr;
				}
				continue;
			}

			const ut32 insn = r_read_le32 (bytes);

			int dst_reg, src_reg;
			if (try_parse_mov_reg_reg (insn, &dst_reg, &src_reg)) {
				if (dst_reg < R_ARRAY_SIZE (reg_values) &&
						src_reg < R_ARRAY_SIZE (reg_values)) {
					reg_values[dst_reg] = reg_values[src_reg];
				}
				continue;
			}

			ut32 imm16 = 0;
			if (try_parse_movz_w_imm (insn, &dst_reg, &imm16)) {
				if (dst_reg == 2) {
					reg_values[0] = 0;
					reg_values[1] = 0;
					reg_values[2] = 0;
				} else if (dst_reg == 3) {
					reg_values[3] = imm16;
					w3_site = pc;
				}
				continue;
			}

			if (is_ret_like (insn)) {
				break;
			}

			if (!is_bl (insn)) {
				continue;
			}

			ut64 meta_va = reg_values[0];
			ut64 name_va = reg_values[1];
			ut64 supermeta_va = reg_values[2];
			ut64 size = reg_values[3];
			reg_values[0] = 0;
			reg_values[1] = 0;
			reg_values[2] = 0;
			reg_values[3] = 0;

			if (meta_va == 0 || name_va == 0 || w3_site == 0) {
				w3_site = 0;
				continue;
			}
			w3_site = 0;

			/*
			 * const int off26 = (int) ((insn & 0x03FFFFFFu) << 6) >> 6;
			 * const ut64 bl_target = pc + ((ut64) off26 << 2);
			 * TODO: Implement renaming of bl_target.
			 */

			char *name = NULL;
			if (!try_read_printable_cstr (bf, kext, name_va, &name)) {
				continue;
			}

			RIOKitClass *c = R_NEW0 (RIOKitClass);
			c->name = name;
			c->size = size;
			c->meta_va = meta_va;
			c->supermeta_va = supermeta_va;
			r_list_append (classes, c);
		}
	}

	return classes;
}

static void r_iokit_class_free(void *_c) {
	RIOKitClass *c = _c;
	if (c) {
		free (c->name);
		free (c);
	}
}

static void find_class_vtables(RList *classes, RBinFile *bf, RKext *kext) {
	int num_classes = r_list_length (classes);
	if (num_classes == 0) {
		return;
	}

	RKextTextBlob tb;
	if (!load_kext_text_blob (bf, kext, &tb)) {
		return;
	}

	HtUP *class_by_handle = ht_up_new0 ();
	RListIter *it;
	RIOKitClass *c;
	r_list_foreach (classes, it, c) {
		ht_up_insert (class_by_handle, c->meta_va, c);
	}

	const int anchor_back = 8;
	const int meta_back = 256;

	ut64 pc;
	for (pc = tb.va; pc + 16 <= tb.va + tb.size; pc += 4) {
		const ut32 insn = r_read_le32 (text_ptr (&tb, pc));

		int reg_n;
		ut32 imm12;
		bool sh12;
		if (!try_parse_addi64_same_reg (insn, &reg_n, &imm12, &sh12)) {
			continue;
		}
		if (imm12 != 0x10 || sh12) {
			continue;
		}

		ut64 va = pc;
		int b;

		bool found_anchor = false;
		ut64 anchor = 0;
		ut64 vtable = 0;
		for (b = 1; b <= anchor_back; b++) {
			va -= 4;

			const ut8 *ptr = text_ptr (&tb, va);
			if (!ptr) {
				break;
			}

			int reg_x;
			ut64 addr;
			if (try_parse_adrp_add_pair (ptr, va, &reg_x, &addr) && reg_x == reg_n) {
				anchor = addr;
				vtable = anchor + 0x10;
				found_anchor = true;
				break;
			}
		}
		if (!found_anchor) {
			continue;
		}

		RIOKitClass *c_x0 = NULL;
		{
			int cur = 0;
			ut64 tva = pc + 4;
			int k;
			for (k = 1; k <= meta_back; k++) {
				if (tva < tb.va + 4) {
					break;
				}
				tva -= 4;

				const ut8 *ptr = text_ptr (&tb, tva);
				if (!ptr) {
					break;
				}

				const ut32 insn = r_read_le32 (ptr);

				if (is_ret_like (insn)) {
					break;
				}

				int rd, rs;
				if (try_parse_mov_reg_reg (insn, &rd, &rs) && rd == cur) {
					cur = rs;
					continue;
				}

				int rpair;
				ut64 a;
				if (try_parse_adrp_add_pair (ptr, tva, &rpair, &a) && rpair == cur) {
					c_x0 = ht_up_find (class_by_handle, a, NULL);
					if (c_x0) {
						break;
					}
					continue;
				}

				ut64 loaded;
				if (try_parse_adrp_ldr_pair (ptr, tva, bf, kext, &rpair, &loaded) && rpair == cur) {
					c_x0 = ht_up_find (class_by_handle, loaded, NULL);
					if (c_x0) {
						break;
					}
					continue;
				}
			}
		}

		if (c_x0) {
			if (!c_x0->vt.metaclass.va) {
				c_x0->vt.metaclass.va = vtable;
			}
			continue;
		}

		for (b = 1; b <= meta_back; b++) {
			va -= 4;

			const ut8 *ptr = text_ptr (&tb, va);
			if (!ptr) {
				break;
			}

			const ut32 insn = r_read_le32 (ptr);
			if (is_ret_like (insn)) {
				break;
			}

			ut64 addr;
			if (!try_parse_adrp_add_pair (ptr, va, NULL, &addr)) {
				continue;
			}

			c = ht_up_find (class_by_handle, addr, NULL);
			if (c) {
				if (!c->vt.instance.va) {
					c->vt.instance.va = vtable;
				}
				break;
			}
		}
	}

	ht_up_free (class_by_handle);
	free (tb.buf);
}

static void compute_class_vtable_sizes(RList *classes, RBinFile *bf, RKext *kext) {
	size_t n_sorted = 0;
	ut64 *vt_sorted = build_sorted_vtable_starts (classes, &n_sorted);
	if (!vt_sorted) {
		return;
	}

	RListIter *it;
	RIOKitClass *c;

	r_list_foreach (classes, it, c) {
		compute_vtable_sizes_for_class (bf, kext, c, vt_sorted, n_sorted);
	}

	r_list_foreach (classes, it, c) {
		compute_metaclass_vtable_sizes_for_class (bf, kext, c, vt_sorted, n_sorted);
	}

	R_FREE (vt_sorted);
}

static void compute_vtable_sizes_for_class(RBinFile *bf, RKext *kext, RIOKitClass *c, const ut64 *vt_sorted, size_t n_sorted) {
	if (!c->vt.instance.va || c->vt.instance.slots_total) {
		return;
	}

	ut32 total = scan_vtable_total_slots (bf, kext, c->vt.instance.va, vt_sorted, n_sorted);
	c->vt.instance.slots_total = total;

	RKernelCacheObj *obj = (RKernelCacheObj *) bf->bo->bin_obj;
	RIOKitClass *parent = ht_up_find (obj->class_by_handle, c->supermeta_va, NULL);

	ut32 parent_total = 0;
	if (parent && parent->vt.instance.va) {
		compute_vtable_sizes_for_class (bf, kext, parent, vt_sorted, n_sorted);
		parent_total = parent->vt.instance.slots_total;
	}

	c->vt.instance.slots_own = (total > parent_total) ? (total - parent_total) : 0;
}

static void compute_metaclass_vtable_sizes_for_class(RBinFile *bf, RKext *kext, RIOKitClass *c, const ut64 *vt_sorted, size_t n_sorted) {
	if (!c->vt.metaclass.va || c->vt.metaclass.slots_total) {
		return;
	}

	ut32 total = scan_vtable_total_slots (bf, kext, c->vt.metaclass.va, vt_sorted, n_sorted);
	c->vt.metaclass.slots_total = total;

	RKernelCacheObj *obj = (RKernelCacheObj *) bf->bo->bin_obj;
	RIOKitClass *parent = ht_up_find (obj->class_by_handle, c->supermeta_va, NULL);

	ut32 parent_total = 0;
	if (parent && parent->vt.metaclass.va) {
		compute_metaclass_vtable_sizes_for_class (bf, kext, parent, vt_sorted, n_sorted);
		parent_total = parent->vt.metaclass.slots_total;
	}

	c->vt.metaclass.slots_own = (total > parent_total) ? (total - parent_total) : 0;
}

static ut32 scan_vtable_total_slots(RBinFile *bf, RKext *kext, ut64 start, const ut64 *vt_sorted, size_t n_sorted) {
	if (!start) {
		return 0;
	}

	RKernelCacheObj *obj = (RKernelCacheObj*) bf->bo->bin_obj;
	const ut64 next_start = next_vtable_after (vt_sorted, n_sorted, start);
	const ut64 hard_end = next_start ? next_start : (kext->vaddr + kext->range.size);

	const ut64 start_off = start - kext->pa2va_data;
	const ut64 end_off = hard_end - kext->pa2va_data;
	ut64 span = end_off - start_off;

	const ut64 one_megabyte = (1ULL << 20);
	if (span > one_megabyte) {
		span = one_megabyte;
	}

	ut8 *buf = malloc (span);
	if (r_buf_read_at (obj->cache_buf, start_off, buf, span) < span) {
		free (buf);
		return 0;
	}

	ut32 count = 0;
	const ut8 *p = buf;
	const ut8 *end = buf + span;

	while (p + 8 <= end) {
		ut64 decorated = r_read_le64 (p);
		if (decorated == 0) {
			break;
		}

		ut64 fn = K_PPTR (decorated);
		if (!IS_KERNEL_ADDR (fn)) {
			break;
		}

		count++;
		p += 8;
	}

	free (buf);

	return count;
}

static ut64 *build_sorted_vtable_starts(RList *classes, size_t *out_n) {
	*out_n = 0;

	const size_t n = r_list_length (classes);
	if (!n) {
		return NULL;
	}

	ut64 *arr = R_NEWS0 (ut64, n * 2);

	size_t i = 0;
	RListIter *it;
	RIOKitClass *c;
	r_list_foreach (classes, it, c) {
		if (c->vt.instance.va) {
			arr[i++] = c->vt.instance.va;
		}
		if (c->vt.metaclass.va) {
			arr[i++] = c->vt.metaclass.va;
		}
	}
	if (!i) {
		R_FREE (arr);
		return NULL;
	}
	qsort (arr, i, sizeof (ut64), ut64_compare);

	*out_n = i;
	return arr;
}

static int ut64_compare(const void *pa, const void *pb) {
	const ut64 a = *(const ut64 *) pa;
	const ut64 b = *(const ut64 *) pb;
	return (a > b) - (a < b);
}

static ut64 next_vtable_after(const ut64 *arr, size_t n, ut64 self_start) {
	size_t lo = 0;
	size_t hi = n;
	while (lo < hi) {
		size_t mid = (lo + hi) >> 1;
		if (arr[mid] <= self_start) {
			lo = mid + 1;
		} else {
			hi = mid;
		}
	}
	return (lo < n) ? arr[lo] : 0;
}

static bool load_kext_text_blob(RBinFile *bf, RKext *kext, RKextTextBlob *blob) {
	RKernelCacheObj *obj = (RKernelCacheObj*) bf->bo->bin_obj;
	if (!kext->text_range.size) {
		return false;
	}

	ut8 *buf = malloc (kext->text_range.size);
	if (r_buf_read_at (obj->cache_buf, kext->text_range.offset, buf, kext->text_range.size) < kext->text_range.size) {
		free (buf);
		return false;
	}
	blob->buf = buf;
	blob->va = kext->vaddr;
	blob->size = kext->text_range.size;
	return true;
}

static const ut8 *text_ptr(const RKextTextBlob *tb, ut64 va) {
	if (va < tb->va || va + 4 > tb->va + tb->size) {
		return NULL;
	}
	return tb->buf + (va - tb->va);
}

static bool try_read_exec_va(RBinFile *bf, RKext *kext, ut64 va, void *dst, size_t len) {
	return r_buf_read_at (bf->buf, va - kext->pa2va_exec, dst, len) == len;
}

static bool try_read_data_va(RBinFile *bf, RKext *kext, ut64 va, void *dst, size_t len) {
	return r_buf_read_at (bf->buf, va - kext->pa2va_data, dst, len) == len;
}

static bool try_read_printable_cstr(RBinFile *bf, RKext *kext, ut64 va, char **cstr) {
	*cstr = NULL;

	ut8 buf[128];
	if (!try_read_exec_va (bf, kext, va, buf, sizeof (buf))) {
		return false;
	}

	int i = 0;
	for (; i < sizeof (buf); i++) {
		if (!buf[i]) {
			break;
		}
		if (buf[i] < 0x20 || buf[i] > 0x7e) {
			return false;
		}
	}
	if (i < 1 || i >= (int) sizeof (buf)) {
		return false;
	}

	*cstr = r_str_ndup ((char *) buf, i);
	return true;
}

static bool is_bl(ut32 insn) {
	return (insn & ARM64_BL_MASK) == ARM64_BL_BASE;
}

static bool is_ret_like(ut32 insn) {
	if ((insn & ARM64_RET_MASK) == ARM64_RET_BASE) {
		return true;
	}
	return (insn & ARM64_RET_AUTH_MASK) == ARM64_RET_AUTH_BASE;
}

static bool try_parse_movz_w_imm(ut32 insn, int *dst_reg, ut32 *imm) {
	if ((insn & 0xFF800000u) != 0x52800000u) {
		return false;
	}
	const ut32 rd = insn & 0x1Fu;
	const ut32 imm16 = (insn >> 5) & 0xFFFFu;
	const ut32 hw = (insn >> 21)  & 0x3u;

	*dst_reg = (int) rd;
	*imm = imm16 << (hw * 16);
	return true;
}

static bool try_parse_adrp_add_pair(const ut8 *ptr, ut64 va, int *reg, ut64 *addr) {
	const ut32 i0 = r_read_le32 (ptr);
	const ut32 i1 = r_read_le32 (ptr + 4);

	ut32 rd_adrp;
	ut64 adrp_base;
	if (!try_parse_adrp_base (i0, va, &rd_adrp, &adrp_base)) {
		return false;
	}

	int rd_add;
	if (!try_parse_addi64_same_reg (i1, &rd_add, NULL, NULL) || rd_add != rd_adrp) {
		return false;
	}

	if (reg) {
		*reg = (int) rd_adrp;
	}
	*addr = extract_addr_from_code (ptr, va);
	return true;
}

static bool try_parse_adrp_ldr_pair(const ut8 *ptr, ut64 va, RBinFile *bf, RKext *kext, int *dst_reg, ut64 *loaded_val) {
	*dst_reg = -1;
	*loaded_val = 0;

	const ut32 i0 = r_read_le32 (ptr);
	const ut32 i1 = r_read_le32 (ptr + 4);

	ut32 rd_adrp;
	ut64 adrp_base;
	if (!try_parse_adrp_base (i0, va, &rd_adrp, &adrp_base)) {
		return false;
	}

	if ((i1 & ARM64_LDRX_UOFF_MASK) != ARM64_LDRX_UOFF_BASE) {
		return false;
	}
	const ut32 rn_ldr = (i1 >> 5) & 0x1Fu;
	if (rn_ldr != rd_adrp) {
		return false;
	}

	const ut32 rd_ldr = i1 & 0x1Fu;
	const ut32 imm12 = (i1 >> 10) & 0xFFFu;
	const ut64 addr = adrp_base + ((ut64) imm12 << 3);

	ut64 decorated = 0;
	if (!try_read_data_va (bf, kext, addr, &decorated, sizeof (decorated))) {
		return false;
	}

	RKernelCacheObj *obj = (RKernelCacheObj *) bf->bo->bin_obj;
	*dst_reg = (int) rd_ldr;
	*loaded_val = K_PPTR (decorated);
	return true;
}

static bool try_parse_adrp_base(ut32 insn, ut64 va, ut32 *rd, ut64 *adrp_base) {
	if ((insn & ARM64_ADRP_MASK) != ARM64_ADRP_BASE) {
		return false;
	}
	const ut64 page  = va & ~0xfffULL;

	const ut64 immlo = (insn >> 29) & 0x3;
	const ut64 immhi = (insn >> 5) & 0x7ffffULL;
	const ut64 imm21 = (immhi << 2) | immlo;
	const int64_t simm21 = (int64_t) ((imm21 ^ 0x100000) - 0x100000);

	*rd = insn & 0x1Fu;
	*adrp_base = page + ((ut64) simm21 << 12);
	return true;
}

static bool try_parse_addi64_same_reg(ut32 insn, int *reg, ut32 *imm12, bool *sh_is_12) {
	if ((insn & ARM64_ADDI64_MASK) != ARM64_ADDI64_BASE) {
		return false;
	}

	const ut32 rd = (insn & 0x1Fu);
	const ut32 rn = (insn >> 5) & 0x1Fu;
	if (rd != rn) {
		return false;
	}

	*reg = (int) rd;
	if (imm12)
		*imm12 = (insn >> 10) & 0xFFFu;
	if (sh_is_12)
		*sh_is_12 = ((insn >> 22) & 1u) != 0;
	return true;
}

static bool try_parse_mov_reg_reg(ut32 insn, int *dst_reg, int *src_reg) {
	ut32 top = insn & 0xFF000000u;
	if (top != 0x2A000000u && top != 0xAA000000u) {
		return false;
	}
	if (((insn >> 21) & 1u) != 0) {
		return false;
	}
	if (((insn >> 22) & 3u) != 0) {
		return false;
	}
	if (((insn >> 10) & 0x3Fu) != 0) {
		return false;
	}
	if (((insn >> 5) & 0x1Fu) != 31u) {
		return false;
	}

	*dst_reg = (int) (insn & 0x1Fu);
	*src_reg = (int) ((insn >> 16) & 0x1Fu);
	return true;
}

static RBinInfo *info(RBinFile *bf) {
	bool big_endian = 0;
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = strdup (bf->file);
	ret->bclass = strdup ("kernelcache");
	ret->rclass = strdup ("ios");
	ret->os = strdup ("iOS");
	ret->arch = strdup ("arm"); // XXX
	ret->machine = strdup (ret->arch);
	ret->subsystem = strdup ("xnu");
	ret->type = strdup ("kernel-cache");
	ret->bits = 64;
	ret->has_va = true;
	ret->big_endian = big_endian;
	ret->dbg_info = 0;
	return ret;
}

static ut64 baddr(RBinFile *bf) {
	if (!bf || !bf->bo || !bf->bo->bin_obj) {
		return 0; // 8LL; // w t f
	}
	RKernelCacheObj *obj = (RKernelCacheObj*) bf->bo->bin_obj;
	return MACH0_(get_baddr)(obj->mach0);
}

static void destroy(RBinFile *bf) {
	r_kernel_cache_free ((RKernelCacheObj*) bf->bo->bin_obj);
}

static void r_kernel_cache_free(RKernelCacheObj *obj) {
	if (!obj) {
		return;
	}

	ht_up_free (obj->class_by_handle);

	if (obj->mach0) {
		MACH0_(mach0_free) (obj->mach0);
		obj->mach0 = NULL;
		obj->cache_buf = NULL;
	}

	if (obj->cache_buf) {
		r_buf_free (obj->cache_buf);
		obj->cache_buf = NULL;
	}

	if (obj->prelink_info) {
		r_cf_value_dict_free (obj->prelink_info);
		obj->prelink_info = NULL;
	}

	if (obj->kexts) {
		r_kext_index_free (obj->kexts);
		obj->kexts = NULL;
	}

	if (obj->rebase_info) {
		r_rebase_info_free (obj->rebase_info);
		obj->rebase_info = NULL;
	}

	R_FREE (obj);
}

static RRebaseInfo *r_rebase_info_new_from_mach0(RBuffer *cache_buf, struct MACH0_(obj_t) *mach0) {
	const RVecSection *sections = MACH0_(load_sections) (mach0);
	if (!sections) {
		return NULL;
	}

	ut64 starts_offset = 0, starts_size = 0;

	struct section_t *section;
	R_VEC_FOREACH (sections, section) {
		if (strstr (section->name, "__TEXT.__thread_starts")) {
			starts_offset = section->paddr;
			starts_size = section->size;
			break;
		}
	}

	ut64 kernel_base = 0;

	struct MACH0_(segment_command) *seg;
	int nsegs = R_MIN (mach0->nsegs, 128);
	int i;
	for (i = 0; i < nsegs; i++) {
		char segname[17];
		seg = &mach0->segs[i];
		r_str_ncpy (segname, seg->segname, 17);
		if (!strncmp (segname, "__TEXT", 6) && segname[6] == '\0') {
			kernel_base = seg->vmaddr;
			break;
		}
	}

	if (starts_offset == 0 || starts_size == 0 || kernel_base == 0) {
		return NULL;
	}

	int n_starts = starts_size / 4;
	if (n_starts <= 1) {
		return NULL;
	}
	RFileRange *rebase_ranges = R_NEWS0 (RFileRange, n_starts - 1);
	if (!rebase_ranges) {
		return NULL;
	}

	ut64 multiplier = 4;
	for (i = 0; i != n_starts; i++) {
		ut8 bytes[4];
		if (r_buf_read_at (cache_buf, starts_offset + i * 4, bytes, 4) < 4) {
			break;
		}

		if (i == 0) {
			multiplier += 4 * (r_read_le32 (bytes) & 1);
			continue;
		}

		rebase_ranges[i - 1].offset = r_read_le32 (bytes);
		rebase_ranges[i - 1].size = UT64_MAX;
	}
	if (i == n_starts) {
		RRebaseInfo *rebase_info = R_NEW0 (RRebaseInfo);
		rebase_info->ranges = rebase_ranges;
		rebase_info->n_ranges = n_starts - 1;
		rebase_info->multiplier = multiplier;
		rebase_info->kernel_base = kernel_base;
		return rebase_info;
	}
	R_FREE (rebase_ranges);
	return NULL;
}

static void r_rebase_info_free(RRebaseInfo *info) {
	if (info) {
		free (info->ranges);
		free (info);
	}
}

static void r_rebase_info_populate(RRebaseInfo *info, RKernelCacheObj *obj) {
	const RVecSection *sections = NULL;
	int i = 0;

	if (obj->rebase_info_populated) {
		return;
	}
	obj->rebase_info_populated = true;

	for (; i < info->n_ranges; i++) {
		if (info->ranges[i].size != UT64_MAX) {
			return;
		} else if (sections == NULL) {
			sections = MACH0_(load_sections) (obj->mach0);
			if (!sections) {
				return;
			}
		}
		info->ranges[i].offset = r_rebase_offset_to_paddr (obj, sections, info->ranges[i].offset);
		ut64 end = iterate_rebase_list (obj->cache_buf, info->multiplier, info->ranges[i].offset, NULL, NULL);
		if (end != UT64_MAX) {
			info->ranges[i].size = end - info->ranges[i].offset + 8;
		} else {
			info->ranges[i].size = 0;
		}
	}
}

static ut64 r_rebase_offset_to_paddr(RKernelCacheObj *obj, const RVecSection *sections, ut64 offset) {
	ut64 vaddr = obj->rebase_info->kernel_base + offset;
	struct section_t *section;
	R_VEC_FOREACH (sections, section) {
		if (section->vaddr <= vaddr && vaddr < (section->vaddr + section->vsize)) {
			return section->paddr + (vaddr - section->vaddr);
		}
	}
	return offset;
}

static ut64 iterate_rebase_list(RBuffer *cache_buf, ut64 multiplier, ut64 start_offset, ROnRebaseFunc func, void *user_data) {
	ut8 bytes[8];
	ut64 cursor = start_offset;

	while (true) {
		if (r_buf_read_at (cache_buf, cursor, bytes, 8) < 8) {
			return UT64_MAX;
		}

		ut64 decorated_addr = r_read_le64 (bytes);

		if (func) {
			bool carry_on = func (cursor, decorated_addr, user_data);
			if (!carry_on) {
				break;
			}
		}

		ut64 delta = ((decorated_addr >> 51) & 0x7ff) * multiplier;
		if (delta == 0) {
			break;
		}
		cursor += delta;
	}

	return cursor;
}

static void swizzle_io_read(RKernelCacheObj *obj, RIO *io) {
	R_RETURN_IF_FAIL (io && io->desc && io->desc->plugin);
	RIOPlugin *plugin = io->desc->plugin;
	obj->original_io_read = plugin->read;
	plugin->read = &kernelcache_io_read;
}

static int kernelcache_io_read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	R_RETURN_VAL_IF_FAIL (io, -1);
	RCore *core = (RCore*) io->coreb.core;

	if (!fd || !core || !core->bin || !core->bin->binfiles) {
		return -1;
	}

	RKernelCacheObj *cache = NULL;
	RListIter *iter;
	RBinFile *bf;
	r_list_foreach (core->bin->binfiles, iter, bf) {
		if (bf->fd == fd->fd && bf->bo && bf->bo->bin_obj) {
			cache = bf->bo->bin_obj;
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
			if (bf->fd == fd->fd && bf->bo) {
				cache = bf->bo->bin_obj;
				break;
			}
		}
	}
	if (!cache || !cache->original_io_read || cache->rebasing_buffer) {
		if (cache) {
			if ((!cache->rebasing_buffer && fd->plugin->read == &kernelcache_io_read) ||
					(cache->rebasing_buffer && !cache->original_io_read)) {
				return -1;
			}
			if (cache->rebasing_buffer) {
				return cache->original_io_read (io, fd, buf, count);
			}
		}
		if (fd->plugin->read == kernelcache_io_read) {
			if (core->bin->options.verbose) {
				R_LOG_ERROR ("Avoid recursive reads");
			}
			return -1;
		}
		return fd->plugin->read (io, fd, buf, count);
	}

	if (cache->rebase_info) {
		r_rebase_info_populate (cache->rebase_info, cache);
	}
	if (!cache->original_io_read) {
		return -1;
	}

	// move into
	if (count > cache->internal_buffer_size) {
		if (cache->internal_buffer) {
			R_FREE (cache->internal_buffer);
		}
		cache->internal_buffer_size = R_MAX (count, 8);
		cache->internal_buffer = (ut8 *) calloc (1, cache->internal_buffer_size);
		if (!cache->internal_buffer) {
			cache->internal_buffer_size = 0;
			return -1;
		}
	}
	ut64 io_off = io->off;
	int result = cache->original_io_read (io, fd, cache->internal_buffer, count);
	if (result == count) {
		if (cache->mach0->chained_starts) {
			rebase_buffer_fixup (cache, io_off, fd, cache->internal_buffer, count);
		} else if (cache->rebase_info) {
			rebase_buffer (cache, io_off, fd, cache->internal_buffer, count);
		}
		memcpy (buf, cache->internal_buffer, result);
	}

	return result;
}

static bool on_rebase_pointer(ut64 offset, ut64 decorated_addr, RRebaseCtx *ctx) {
	if (offset < ctx->off) {
		return true;
	}
	if (offset >= ctx->eob) {
		return false;
	}
	ut64 in_buf = offset - ctx->off;
	if (in_buf >= ctx->count || (in_buf + 8) > ctx->count) {
		return false;
	}

	RParsedPointer ptr;
	r_ptr_undecorate (&ptr, decorated_addr, ctx->obj);

	r_write_le64 (&ctx->buf[in_buf], ptr.address);

	return true;
}

static void rebase_buffer(RKernelCacheObj *obj, ut64 off, RIODesc *fd, ut8 *buf, int count) {
	if (obj->rebasing_buffer || !buf) {
		return;
	}
	obj->rebasing_buffer = true;

	ut64 eob = off + count;
	int i = 0;
	RRebaseCtx ctx;

	ctx.off = off;
	ctx.eob = eob;
	ctx.buf = buf;
	ctx.count = count;
	ctx.obj = obj;

	for (; i < obj->rebase_info->n_ranges; i++) {
		ut64 start = obj->rebase_info->ranges[i].offset;
		ut64 end = start + obj->rebase_info->ranges[i].size;
		if (end >= off && start <= eob) {
			iterate_rebase_list (obj->cache_buf, obj->rebase_info->multiplier, start,
				(ROnRebaseFunc) on_rebase_pointer, &ctx);
		}
	}

	obj->rebasing_buffer = false;
}

static void rebase_buffer_fixup(RKernelCacheObj *kobj, ut64 off, RIODesc *fd, ut8 *buf, int count) {
	if (kobj->rebasing_buffer) {
		return;
	}
	kobj->rebasing_buffer = true;
	struct MACH0_(obj_t) *obj = kobj->mach0;
	ut64 eob = off + count;
	size_t i = 0;
	for (; i < obj->segs_count; i++) {
		if (!obj->chained_starts[i]) {
			continue;
		}
		ut64 page_size = obj->chained_starts[i]->page_size;
		if (page_size < 1) {
			page_size = 4096;
		}
		ut64 start = obj->segs[i].fileoff;
		ut64 end = start + obj->segs[i].filesize;
		if (end >= off && start <= eob) {
			ut64 page_idx = (R_MAX (start, off) - start) / page_size;
			ut64 page_end_idx = (R_MIN (eob, end) - start) / page_size;
			for (; page_idx <= page_end_idx; page_idx++) {
				if (page_idx >= obj->chained_starts[i]->page_count) {
					break;
				}
				if (!obj->chained_starts[i]->page_start) {
					break;
				}
				ut16 page_start = obj->chained_starts[i]->page_start[page_idx];
				if (page_start == DYLD_CHAINED_PTR_START_NONE) {
					continue;
				}
				ut64 cursor = start + page_idx * page_size + page_start;
				while (cursor < eob && cursor < end) {
					ut8 tmp[8];
					if (r_buf_read_at (obj->b, cursor, tmp, 8) != 8) {
						break;
					}
					ut64 raw_ptr = r_read_le64 (tmp);
					ut64 ptr_value = raw_ptr;
					ut64 delta = 0;
					ut64 stride = 8;
					if (obj->chained_starts[i]->pointer_format == DYLD_CHAINED_PTR_ARM64E) {
						bool is_auth = IS_PTR_AUTH (raw_ptr);
						bool is_bind = IS_PTR_BIND (raw_ptr);
						if (is_auth && is_bind) {
							struct dyld_chained_ptr_arm64e_auth_bind *p =
									(struct dyld_chained_ptr_arm64e_auth_bind *) &raw_ptr;
							delta = p->next;
						} else if (!is_auth && is_bind) {
							struct dyld_chained_ptr_arm64e_bind *p =
									(struct dyld_chained_ptr_arm64e_bind *) &raw_ptr;
							delta = p->next;
						} else if (is_auth && !is_bind) {
							struct dyld_chained_ptr_arm64e_auth_rebase *p =
									(struct dyld_chained_ptr_arm64e_auth_rebase *) &raw_ptr;
							delta = p->next;
							ptr_value = p->target + obj->baddr;
						} else {
							struct dyld_chained_ptr_arm64e_rebase *p =
									(struct dyld_chained_ptr_arm64e_rebase *) &raw_ptr;
							delta = p->next;
							ptr_value = ((ut64)p->high8 << 56) | p->target;
							ptr_value += obj->baddr;
						}
					} else if (obj->chained_starts[i]->pointer_format == DYLD_CHAINED_PTR_64_KERNEL_CACHE ||
							obj->chained_starts[i]->pointer_format == DYLD_CHAINED_PTR_ARM64E_KERNEL) {
						bool is_auth = IS_PTR_AUTH (raw_ptr);
						stride = 4;
						if (is_auth) {
							struct dyld_chained_ptr_arm64e_cache_auth_rebase *p =
									(struct dyld_chained_ptr_arm64e_cache_auth_rebase *) &raw_ptr;
							delta = p->next;
							ptr_value = p->target + obj->baddr;
						} else {
							struct dyld_chained_ptr_arm64e_cache_rebase *p =
									(struct dyld_chained_ptr_arm64e_cache_rebase *) &raw_ptr;
							delta = p->next;
							ptr_value = ((ut64)p->high8 << 56) | p->target;
							ptr_value += obj->baddr;
						}
					} else {
						R_LOG_ERROR ("Unsupported pointer format: %u", obj->chained_starts[i]->pointer_format);
					}
					ut64 in_buf = cursor - off;
					if (cursor >= off && cursor <= eob - 8) {
						r_write_le64 (&buf[in_buf], ptr_value);
					}
					cursor += delta * stride;
					if (!delta) {
						break;
					}
				}
			}
		}
	}
	kobj->rebasing_buffer = false;
}

RBinPlugin r_bin_plugin_xnu_kernelcache = {
	.meta = {
		.name = "kernelcache",
		.desc = "iOS/macOS Kernel Cache",
		.author = "mrmacete",
		.license = "LGPL-3.0-only",
	},
	.destroy = &destroy,
	.load = &load,
	.entries = &entries,
	.baddr = &baddr,
	.symbols_vec = &symbols_vec,
	.sections = &sections,
	.classes = &classes,
	.check = &check,
	.info = &info
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_kernelcache,
	.version = R2_VERSION
};
#endif
