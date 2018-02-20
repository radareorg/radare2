/* radare2 - LGPL - Copyright 2018 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
// #include "../format/mach0/mach0_defines.h"
#define R_BIN_MACH064 1
#include "../format/mach0/mach0.h"

static void* addr2ptr(uint64_t addr, cache_hdr_t *hdr) {
	uint32_t i;
	cache_map_t *map = (cache_map_t*)((const ut8*)hdr + hdr->mappingOffset);
	for (i = 0; i < hdr->mappingCount; ++i) {
		if (addr >= map[i].address && addr < map[i].address + map[i].size) {
			return (void*)((const ut8*)hdr + map[i].fileOffset + (addr - map[i].address));
		}
	}
	return NULL;
}

static ut64 va2pa(uint64_t addr, void *cache) {
	uint32_t i;
	cache_hdr_t *hdr = (cache_hdr_t*)cache;
	cache_map_t *map = (cache_map_t*)((uintptr_t)cache + hdr->mappingOffset);
	for (i = 0; i < hdr->mappingCount; ++i) {
		if (addr >= map[i].address && addr < map[i].address + map[i].size) {
			return map[i].fileOffset + addr - map[i].address;
			// (void*)((uintptr_t)cache + map[i].fileOffset + (addr - map[i].address));
		}
	}
	return UT64_MAX;
}

static bool dyld64 = false;

static bool check_bytes(const ut8 *buf, ut64 length) {
	bool rc = false;
	if (buf && length >= 32) {
		char arch[9] = { 0 };
		strncpy (arch, (const char *) buf + 9, R_MIN (length, sizeof (arch) - 1));
		rc = !memcmp (buf, "dyld", 4);
		if (rc) {
			dyld64 = strstr (arch, "64") != NULL;
			if (*arch) {
				eprintf ("Arch: %s\n", arch);
			}
		}
	}
	return rc;
}

static void *load_bytes(RBinFile *bf, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	return (void *) (size_t) check_bytes (buf, sz);
}

static bool load(RBinFile *bf) {
	const ut8 *bytes = bf ? r_buf_buffer (bf->buf) : NULL;
	ut64 sz = bf ? r_buf_size (bf->buf): 0;
	ut64 la = (bf && bf->o) ? bf->o->loadaddr: 0;
	return load_bytes (bf, bytes, sz, la, bf? bf->sdb: NULL) != NULL;
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
	bool big_endian = 0;
	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->bclass = strdup ("dyldcache");
	ret->rclass = strdup ("ios");
	ret->os = strdup ("iOS");
	ret->arch = strdup ("arm"); // XXX
	ret->machine = strdup (ret->arch);
	ret->subsystem = strdup ("xnu");
	ret->type = strdup ("library-cache");
	ret->bits = dyld64? 64: 32;
	ret->has_va = true;
	ret->big_endian = big_endian;
	ret->dbg_info = 0;
	return ret;
}

#if 0
static void parse_mach0 (RList *ret, ut64 paddr, RBinFile *bf) {
	// TODO
}
#endif

static ut64 baddr(RBinFile *bf) {
	// XXX hardcoded
	return 0x180000000;
}

#define USE_R2_API 0

void parse_mach064 (RList *ret, ut64 paddr, RBinFile *bf) {
	// eprintf ("MACH0 AT 0x%"PFMT64x"\n", paddr);
	int sz = 0;
	void *ptr = r_buf_get_at (bf->buf, paddr, &sz);
#if USE_R2_API
	// XXX r2 api cannot load those mach0s because addresses are messed up
	sz = 1024*1024*1; // 1MB limit file size to 1MB to avoid slow copies.. this is a nice place to optimize unnecessary r_buf_new_from_bytes
	RBuffer *buf = r_buf_new_with_pointers (ptr, sz);
	struct MACH0_(obj_t) *res = MACH0_(new_buf) (buf, bf->rbin->verbose);
	if (!res) {
		return;
	}
	struct symbol_t *symbols = MACH0_(get_symbols) (res);
	eprintf ("mach0-64: b:%p r:%p s:%p\n", buf, res, symbols);
	if (!symbols) {
		return;
	}
	for (i = 0; !symbols[i].last; i++) {
		if (!symbols[i].name[0] || symbols[i].addr < 100) {
			continue;
		}
		RBinSymbol *sym = R_NEW0 (RBinSymbol);
		if (!sym) {
			break;
		}
		sym->name = strdup (symbols[i].name);
		sym->vaddr = symbols[i].addr;
		sym->paddr = symbols[i].offset + bf->o->boffset;
		sym->size = symbols[i].size;
		sym->ordinal = i;
		r_list_append (ret, sym);
	}
	free (symbols);
	r_buf_free (buf);
	MACH0_(free)(res);
#else
	const ut8 * root = r_buf_get_at (bf->buf, 0, NULL);
	//printf("f sym.imp.%s 0 0x%llx\n", &strs[syms[n].n_un.n_strx + 1], syms[n].n_value);
	struct MACH0_(mach_header) *h64 = ptr;
	struct load_command *cmd = (struct load_command*)((const ut8*)ptr + 0x20);
	struct load_command *end = (struct load_command*)((const ut8*)cmd + h64->sizeofcmds);
	for (; cmd < end; cmd = (void *)((const ut8*)cmd + cmd->cmdsize)) {
		// eprintf ("%p  0x%x (%02x)\n", (void*)cmd - (void*)ptr + (void*)(size_t)paddr, cmd->cmd, LC_SYMTAB);
		if (cmd->cmd == LC_SYMTAB) {
			struct symtab_command *stab = (struct symtab_command*)(cmd);
			struct MACH0_(nlist) *syms = (struct MACH0_(nlist)*)((uintptr_t)root + stab->symoff);
			char *strs = (char*)((uintptr_t)root + stab->stroff);
			size_t n;
			for (n = 0; n < stab->nsyms; n++) {
				if ((syms[n].n_type & N_TYPE) != N_UNDF && (syms[n].n_type & N_EXT)) {
					if (false) { // strs[syms[n].n_un.n_strx] != '_')
						// LOG("Not a C symbol: %s", &strs[syms[n].n_un.n_strx]);
					} else {
						RBinSymbol *sym = R_NEW0 (RBinSymbol);
						if (sym) {
							sym->name = strdup (&strs [ syms[n].n_strx + 1]);
							// eprintf ("Sym 0x%llx %s\n", (ut64)(syms[n].n_value), sym->name);
							sym->vaddr = syms[n].n_value;
							sym->paddr = syms[n].n_value;
							// XXX THIs is unnecessarily slow! must be enums
							sym->bind = "PUBLIC";
							sym->type = "SYM";
							r_list_append (ret, sym);
						}
						//printf("f sym.imp.%s 0 0x%llx\n", &strs[syms[n].n_un.n_strx + 1], syms[n].n_value);
					}
				}
			}
		}
		if ((int)cmd->cmdsize < 1) {
			eprintf ("CMD Size FAIL %d\n", cmd->cmdsize);
			break;
		}
	}
#endif
}

static RList* sections(RBinFile *bf) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	RBinObject *obj = bf ? bf->o : NULL;

	ut64 vaddr = 0x180000000;
	if (!obj || !obj->bin_obj || !(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}
	if (!(ptr = R_NEW0 (RBinSection))) {
		return NULL;
	}
	r_str_ncpy (ptr->name, (char*)"text", R_BIN_SIZEOF_STRINGS);
	ptr->size = r_buf_size (bf->buf);
	ptr->vsize = ptr->size;
	ptr->paddr = 0;
	ptr->vaddr = vaddr;
	ptr->add = true;
	if (!ptr->vaddr) {
		ptr->vaddr = ptr->paddr;
	}
	ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_WRITABLE | R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP;
	r_list_append (ret, ptr);
	return ret;
}

static RList* symbols(RBinFile *bf) {
	RList *ret = r_list_newf (free);
	int cache_size = 0;
	const ut8 *cache = r_buf_get_at (bf->buf, 0, &cache_size);
	cache_hdr_t *hdr = (cache_hdr_t *)cache;
	cache_img_t *img = (cache_img_t*)((uintptr_t)cache + hdr->imagesOffset);
	int i;
	for (i = 0; i < hdr->imagesCount; i++) {
		ut32 *ptr = addr2ptr (img[i].address, (cache_hdr_t*)cache);
		ut64 pa = va2pa (img[i].address, (cache_hdr_t*)cache);
		switch (*(uint32_t*)ptr) {
		case MH_MAGIC:
			// parse_mach0 (ret, *ptr, bf);
			break;
		case MH_MAGIC_64:
			parse_mach064 (ret, pa, bf);
			break;
		default:
			eprintf ("Unknown sub-bin\n");
			break;
		}
	}
	return ret;
}

RBinPlugin r_bin_plugin_dyldcache = {
	.name = "dyldcache",
	.desc = "dyldcache bin plugin",
	.license = "LGPL3",
	.load = &load,
	.load_bytes = &load_bytes,
	.entries = &entries,
	.baddr = &baddr,
	.symbols = &symbols,
	.sections = &sections,
	.check_bytes = &check_bytes,
	.info = &info,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_dyldcache,
	.version = R2_VERSION
};
#endif
