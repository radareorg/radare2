/* radare2 - LGPL - Copyright 2017 - pancake */

// TODO: Support NRR and MODF
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

// starting at 0
typedef struct {
	ut32 unused;
	ut32 mod_memoffset;
	ut64 padding;
} NROStart;

#define NRO_OFF(x) sizeof (NROStart) + r_offsetof (NROHeader, x)
#define NRO_OFFSET_MODMEMOFF r_offsetof (NROStart, mod_memoffset)

// starting at 0x10 (16th byte)
typedef struct {
	ut32 magic;  // NRO0
	ut32 unknown; // 4
	ut32 size; // 8
	ut32 unknown2; // 12
	ut32 text_memoffset; // 16
	ut32 text_size; // 20
	ut32 ro_memoffset; // 24
	ut32 ro_size; // 28
	ut32 data_memoffset; // 32
	ut32 data_size; // 36
	ut32 bss_size; // 40
	ut32 unknown3;
} NROHeader;

// ------------------------------
typedef struct {
	ut32 magic;
	ut32 dynamic;
	ut32 bss_start;
	ut32 bss_end;
	ut32 unwind_start;
	ut32 unwind_end;
	ut32 mod_object;
} MODHeader;

typedef struct {
	ut64 next;
	ut64 prev;
	ut64 relplt;
	ut64 reldyn;
	ut64 base;
	ut64 dynamic;
	ut64 is_rela;
	ut64 relplt_size;
	ut64 init;
	ut64 fini;
	ut64 bucket;
	ut64 chain;
	ut64 strtab;
	ut64 symtab;
	ut64 strtab_size;
	ut64 got;
	ut64 reladyn_size;
	ut64 reldyn_size;
	ut64 relcount;
	ut64 relacount;
	ut64 nchain;
	ut64 nbucket;
	ut64 got_value;
} MODObject;

typedef struct {
	ut32 mod_offset;
	ut32 text_offset;
	ut32 text_size;
	ut32 ro_offset;
	ut32 ro_size;
	ut32 data_offset;
	ut32 data_size;
	ut32 bss_size;
} MODMeta;

typedef struct {
	ut32 *strings;
	RList *methods_list;
	RList *imports_list;
	RList *classes_list;
} RBinNROObj;

static void parseMod (RBinFile *bf, RBinNROObj *bin, ut32 mod0, ut64 baddr);

static ut32 readLE32(RBuffer *buf, int off) {
	int left = 0;
	const ut8 *data = r_buf_get_at (buf, off, &left);
	return left > 3? r_read_le32 (data): 0;
}

static ut64 readLE64(RBuffer *buf, int off) {
	int left = 0;
	const ut8 *data = r_buf_get_at (buf, off, &left);
	return left > 7? r_read_le64 (data): 0;
}

static const char *readString(RBuffer *buf, int off) {
	int left = 0;
	const char *data = (const char *)r_buf_get_at (buf, off, &left);
	return left > 0 ? data: NULL;
}

static ut64 baddr(RBinFile *arch) {
	return arch? readLE32 (arch->buf, NRO_OFFSET_MODMEMOFF): 0;
}

static const char *fileType(const ut8 *buf) {
	if (!memcmp (buf, "NRO0", 4)) {
		return "nro0";
	}
	if (!memcmp (buf, "NRR0", 4)) {
		return "nrr0";
	}
	if (!memcmp (buf, "MOD0", 4)) {
		return "mod0";
	}
	return NULL;
}

static bool check_bytes(const ut8 *buf, ut64 length) {
	if (buf && length >= 0x20) {
		return fileType (buf + NRO_OFF (magic)) != NULL;
	}
	return false;
}

static void *load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	RBinNROObj *bin = R_NEW0 (RBinNROObj);
	if (!bin) {
		return NULL;
	}
	ut64 ba = baddr (arch);
	bin->methods_list = r_list_newf ((RListFree)free);
	bin->imports_list = r_list_newf ((RListFree)free);
	bin->classes_list = r_list_newf ((RListFree)free);
	ut32 mod0 = readLE32 (arch->buf, NRO_OFFSET_MODMEMOFF);
	parseMod (arch, bin, mod0, ba);
	return (void *) bin;//(size_t) check_bytes (buf, sz);
}

static bool load(RBinFile *arch) {
	if (!arch || !arch->buf || !arch->o) {
		return false;
	}
	const ut64 sz = r_buf_size (arch->buf);
	const ut64 la = arch->o->loadaddr;
	const ut8 *bytes = r_buf_buffer (arch->buf);
	arch->o->bin_obj = load_bytes (arch, bytes, sz, la, arch? arch->sdb: NULL);
	return arch->o->bin_obj != NULL;
}

static int destroy(RBinFile *arch) {
	return true;
}

static RBinAddr *binsym(RBinFile *arch, int type) {
	return NULL; // TODO
}

static RList *entries(RBinFile *arch) {
	RList *ret;
	RBinAddr *ptr = NULL;
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;
	if ((ptr = R_NEW0 (RBinAddr))) {
		ptr->paddr = 0x80;
		ptr->vaddr = ptr->paddr + baddr (arch);
		r_list_append (ret, ptr);
	}
	return ret;
}

static Sdb *get_sdb(RBinFile *bf) {
	Sdb *kv = sdb_new0 ();
	sdb_num_set (kv, "nro_start.offset", 0, 0);
	sdb_num_set (kv, "nro_start.size", 16, 0);
	sdb_set (kv, "nro_start.format", "xxq unused mod_memoffset padding", 0);
	sdb_num_set (kv, "nro_header.offset", 16, 0);
	sdb_num_set (kv, "nro_header.size", 0x70, 0);
	sdb_set (kv, "nro_header.format", "xxxxxxxxxxxx magic unk size unk2 text_offset text_size ro_offset ro_size data_offset data_size bss_size unk3", 0);
	sdb_ns_set (bf->sdb, "info", kv);
	return kv;
}

static void walkSymbols (RBinFile *bf, RBinNROObj *bin, ut64 symtab, ut64 strtab, ut64 strtab_size, ut64 relplt, ut64 baddr) {
	int i, import = 0;
	RBinSymbol *sym;
	RBinImport *imp;
	for (i = 8; i < 99999; i++) {
		ut64 addr = readLE64 (bf->buf, symtab + i);
		ut64 size = readLE64 (bf->buf, symtab + i + 8);
		i += 16; // NULL, NULL
		ut64 name = readLE32 (bf->buf, symtab + i);
		//ut64 type = readLE32 (bf->buf, symtab + i + 4);
		const char *symName = readString (bf->buf, strtab + name);
		if (!symName) {
			break;
		}
		sym = R_NEW0 (RBinSymbol);
		if (!sym) {
			break;
		}
		sym->type = r_str_const ("FUNC");
		sym->bind = r_str_const ("NONE");
		sym->size = size;

		if (addr == 0) {
			import ++;
			ut64 pltSym = readLE64 (bf->buf, relplt + (import * 24));
			imp = R_NEW0 (RBinImport);
			if (!imp) {
				R_FREE (sym);
				break;
			}
			imp->name  = strdup (symName);
			if (!imp->name) {
				goto out_walk_symbol;
			}
			imp->type = r_str_const ("FUNC");
			if (!imp->type) {
				goto out_walk_symbol;
			}
			imp->bind = r_str_const ("NONE");
			if (!imp->bind) {
				goto out_walk_symbol;
			}
			imp->ordinal = bin->imports_list->length;
			r_list_append (bin->imports_list, imp);
			sym->name = r_str_newf ("imp.%s", symName);
			if (!sym->name) {
				goto out_walk_symbol;
			}
			sym->paddr = pltSym - 8;
			sym->vaddr = sym->paddr + baddr;
			//eprintf ("f sym.imp.%s = 0x%"PFMT64x"\n", symName, pltSym - 8);
		} else {
			sym->name = strdup (symName);
			if (!sym->name) {
				R_FREE (sym);
				break;
			}
			sym->paddr = addr;
			sym->vaddr = sym->paddr + baddr;
			//eprintf ("f sym.%s %"PFMT64u "0x%"PFMT64x"\n", symName, size, addr);
		}
		r_list_append (bin->methods_list, sym);
		i += 8 - 1;
	}
    return;

out_walk_symbol:
	R_FREE (sym);
	R_FREE (imp);
	return;
}

static void parseMod (RBinFile *bf, RBinNROObj *bin, ut32 mod0, ut64 baddr) {
	ut32 ptr = readLE32 (bf->buf, mod0);
	eprintf ("magic %x at 0x%x\n", ptr, mod0);
	if (ptr == 0x30444f4d) { // MOD0
		eprintf ("is mode0\n");
		MODHeader mh = {
			.magic = readLE32 (bf->buf, mod0),
			.dynamic = readLE32 (bf->buf, mod0 + 4),
			.bss_start = readLE32 (bf->buf, mod0 + 8),
			.bss_end = readLE32 (bf->buf, mod0 + 12),
			.unwind_start = readLE32 (bf->buf, mod0 + 16),
			.unwind_end = readLE32 (bf->buf, mod0 + 20),
			.mod_object = readLE32 (bf->buf, mod0 + 24),
		};
		mh.mod_object += mod0;
		eprintf ("magic 0x%x\n", mh.magic);
		eprintf ("dynamic 0x%x\n", mh.dynamic);
		eprintf ("bss 0x%x 0x%x\n", mh.bss_start, mh.bss_end);
		eprintf ("unwind 0x%x 0x%x\n", mh.unwind_start, mh.unwind_end);
		eprintf ("-------------\n");
		eprintf ("mod 0x%x\n", mh.mod_object);
#define MO_(x) readLE64(bf->buf, mh.mod_object + r_offsetof(MODObject, x))
		MODObject mo = {
			.next = MO_(next),
			.prev = MO_(prev),
			.relplt = MO_(relplt),
			.reldyn = MO_(reldyn),
			.base = MO_(base),
			.dynamic = MO_(dynamic),
			.is_rela = MO_(is_rela),
			.relplt_size = MO_(relplt_size),
			.init = MO_(init),
			.fini = MO_(fini),
			.bucket = MO_(bucket),
			.chain = MO_(chain),
			.strtab = MO_(strtab),
			.symtab = MO_(symtab),
			.strtab_size = MO_(strtab_size)
		};
		eprintf ("next 0x%llx\n", mo.next);
		eprintf ("prev 0x%llx\n", mo.prev);
		eprintf ("base 0x%llx\n", mo.base);
		eprintf ("init 0x%llx\n", mo.init);
		eprintf ("fini 0x%llx\n", mo.fini);
		eprintf ("relplt 0x%llx\n", mo.relplt - mo.base);
		eprintf ("symtab = 0x%llx\n", mo.symtab - mo.base);
		eprintf ("strtab = 0x%llx\n", mo.strtab - mo.base);
		eprintf ("strtabsz = 0x%llx\n", mo.strtab_size);
		//ut32 modo = mh.mod_object;
		ut64 strtab = mo.strtab - mo.base;
		ut64 symtab = mo.symtab - mo.base;
		walkSymbols (bf, bin, symtab, strtab, mo.strtab_size, mo.relplt - mo.base, baddr);
	}
}

static RList *sections(RBinFile *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	RBuffer *b = arch->buf;
	if (!arch->o->info) {
		return NULL;
	}
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;

	ut64 ba = baddr (arch);

	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	strncpy (ptr->name, "header", R_BIN_SIZEOF_STRINGS);
	ptr->size = 0x80;
	ptr->vsize = 0x80;
	ptr->paddr = 0;
	ptr->vaddr = 0;
	ptr->srwx = R_BIN_SCN_READABLE;
	ptr->add = false;
	r_list_append (ret, ptr);

	int bufsz = r_buf_size (arch->buf);

	ut32 mod0 = readLE32 (arch->buf, NRO_OFFSET_MODMEMOFF);
	if (mod0 && mod0 + 8 < bufsz) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}
		ut32 mod0sz = readLE32 (arch->buf, mod0 + 4);
		strncpy (ptr->name, "mod0", R_BIN_SIZEOF_STRINGS);
		ptr->size = mod0sz;
		ptr->vsize = mod0sz;
		ptr->paddr = mod0;
		ptr->vaddr = mod0 + ba;
		ptr->srwx = R_BIN_SCN_READABLE; // rw-
		ptr->add = false;
		r_list_append (ret, ptr);
	} else {
		eprintf ("Invalid MOD0 address\n");
	}

	ut32 sig0 = readLE32 (arch->buf, 0x18);
	if (sig0 && sig0 + 8 < bufsz) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}
		ut32 sig0sz = readLE32 (arch->buf, sig0 + 4);
		strncpy (ptr->name, "sig0", R_BIN_SIZEOF_STRINGS);
		ptr->size = sig0sz;
		ptr->vsize = sig0sz;
		ptr->paddr = sig0;
		ptr->vaddr = sig0 + ba;
		ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_MAP; // r--
		ptr->add = true;
		r_list_append (ret, ptr);
	} else {
		eprintf ("Invalid SIG0 address\n");
	}

	// add text segment
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	strncpy (ptr->name, "text", R_BIN_SIZEOF_STRINGS);
	ptr->vsize = readLE32 (b, NRO_OFF (text_size));
	ptr->size = ptr->vsize;
	ptr->paddr = readLE32 (b, NRO_OFF (text_memoffset));
	ptr->vaddr = ptr->paddr + ba;
	ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP; // r-x
	ptr->add = true;
	r_list_append (ret, ptr);

	// add ro segment
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	strncpy (ptr->name, "ro", R_BIN_SIZEOF_STRINGS);
	ptr->vsize = readLE32 (b, NRO_OFF (ro_size));
	ptr->size = ptr->vsize;
	ptr->paddr = readLE32 (b, NRO_OFF (ro_memoffset));
	ptr->vaddr = ptr->paddr + ba;
	ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_MAP; // r-x
	ptr->add = true;
	r_list_append (ret, ptr);

	// add data segment
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	strncpy (ptr->name, "data", R_BIN_SIZEOF_STRINGS);
	ptr->vsize = readLE32 (b, NRO_OFF (data_size));
	ptr->size = ptr->vsize;
	ptr->paddr = readLE32 (b, NRO_OFF (data_memoffset));
	ptr->vaddr = ptr->paddr + ba;
	ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_WRITABLE | R_BIN_SCN_MAP; // rw-
	ptr->add = true;
	eprintf ("Base Address 0x%08"PFMT64x "\n", ba);
	eprintf ("BSS Size 0x%08"PFMT64x "\n", (ut64)
			readLE32 (arch->buf, NRO_OFF (bss_size)));
	r_list_append (ret, ptr);
	return ret;
}

static RList *symbols(RBinFile *arch) {
	RBinNROObj *bin;
	if (!arch || !arch->o || !arch->o->bin_obj) {
		return NULL;
	}
	bin = (RBinNROObj*) arch->o->bin_obj;
	if (!bin) {
		return NULL;
	}
	return bin->methods_list;
}

static RList *imports(RBinFile *arch) {
	RBinNROObj *bin;
	if (!arch || !arch->o || !arch->o->bin_obj) {
		return NULL;
	}
	bin = (RBinNROObj*) arch->o->bin_obj;
	if (!bin) {
		return NULL;
	}
	return bin->imports_list;
}

static RList *libs(RBinFile *arch) {
	return NULL;
}

static RBinInfo *info(RBinFile *arch) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	const char *ft = fileType (r_buf_get_at (arch->buf, NRO_OFF (magic), NULL));
	if (!ft) {
		ft = "nro";
	}
	ret->file = strdup (arch->file);
	ret->rclass = strdup (ft);
	ret->os = strdup ("switch");
	ret->arch = strdup ("arm");
	ret->machine = strdup ("Nintendo Switch");
	ret->subsystem = strdup (ft);
	if (!strncmp (ft, "nrr", 3)) {
		ret->bclass = strdup ("program");
		ret->type = strdup ("EXEC (executable file)");
	} else if (!strncmp (ft, "nro", 3)) {
		ret->bclass = strdup ("object");
		ret->type = strdup ("OBJECT (executable code)");
	} else { // mod
		ret->bclass = strdup ("library");
		ret->type = strdup ("MOD (executable library)");
	}
	ret->bits = 64;
	ret->has_va = true;
	ret->has_lit = true;
	ret->big_endian = false;
	ret->dbg_info = 0;
	ret->dbg_info = 0;
	return ret;
}

#if !R_BIN_NRO

RBinPlugin r_bin_plugin_nro = {
	.name = "nro",
	.desc = "Nintendo Switch NRO0 binaries",
	.license = "MIT",
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.get_sdb = &get_sdb,
	.symbols = &symbols,
	.imports = &imports,
	.info = &info,
	.libs = &libs,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_nro,
	.version = R2_VERSION
};
#endif
#endif
