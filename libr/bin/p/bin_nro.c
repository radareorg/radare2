/* radare2 - LGPL - Copyright 2017-2019 - pancake */

// TODO: Support NRR and MODF
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "nxo/nxo.h"

#define NRO_OFF(x) (sizeof (NXOStart) + r_offsetof (NROHeader, x))
#define NRO_OFFSET_MODMEMOFF r_offsetof (NXOStart, mod_memoffset)

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

static ut64 baddr(RBinFile *bf) {
	return bf? readLE32 (bf->buf, NRO_OFFSET_MODMEMOFF): 0;
}

static bool check_buffer(RBuffer *b) {
	ut8 magic[4];
	if (r_buf_read_at (b, NRO_OFF (magic), magic, sizeof (magic)) == 4) {
		return fileType (magic) != NULL;
	}
	return false;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *b, ut64 loadaddr, Sdb *sdb) {
	// XX bf->buf vs b :D this load_b
	RBinNXOObj *bin = R_NEW0 (RBinNXOObj);
	if (bin) {
		ut64 ba = baddr (bf);
		bin->methods_list = r_list_newf ((RListFree)free);
		bin->imports_list = r_list_newf ((RListFree)free);
		bin->classes_list = r_list_newf ((RListFree)free);
		ut32 mod0 = readLE32 (b, NRO_OFFSET_MODMEMOFF);
		parseMod (b, bin, mod0, ba);
		*bin_obj = bin;
	}
	return true;
}

static RBinAddr *binsym(RBinFile *bf, int type) {
	return NULL; // TODO
}

static RList *entries(RBinFile *bf) {
	RList *ret;
	RBinAddr *ptr = NULL;
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;
	if ((ptr = R_NEW0 (RBinAddr))) {
		ptr->paddr = 0x80;
		ptr->vaddr = ptr->paddr + baddr (bf);
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

static RList *sections(RBinFile *bf) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	RBuffer *b = bf->buf;
	if (!bf->o->info) {
		return NULL;
	}
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;

	ut64 ba = baddr (bf);

	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("header");
	ptr->size = 0x80;
	ptr->vsize = 0x80;
	ptr->paddr = 0;
	ptr->vaddr = 0;
	ptr->perm = R_PERM_R;
	ptr->add = false;
	r_list_append (ret, ptr);

	int bufsz = r_buf_size (bf->buf);

	ut32 mod0 = readLE32 (bf->buf, NRO_OFFSET_MODMEMOFF);
	if (mod0 && mod0 + 8 < bufsz) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}
		ut32 mod0sz = readLE32 (bf->buf, mod0 + 4);
		ptr->name = strdup ("mod0");
		ptr->size = mod0sz;
		ptr->vsize = mod0sz;
		ptr->paddr = mod0;
		ptr->vaddr = mod0 + ba;
		ptr->perm = R_PERM_R; // rw-
		ptr->add = false;
		r_list_append (ret, ptr);
	} else {
		eprintf ("Invalid MOD0 address\n");
	}

	ut32 sig0 = readLE32 (bf->buf, 0x18);
	if (sig0 && sig0 + 8 < bufsz) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}
		ut32 sig0sz = readLE32 (bf->buf, sig0 + 4);
		ptr->name = strdup ("sig0");
		ptr->size = sig0sz;
		ptr->vsize = sig0sz;
		ptr->paddr = sig0;
		ptr->vaddr = sig0 + ba;
		ptr->perm = R_PERM_R; // r--
		ptr->add = true;
		r_list_append (ret, ptr);
	} else {
		eprintf ("Invalid SIG0 address\n");
	}

	// add text segment
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("text");
	ptr->vsize = readLE32 (b, NRO_OFF (text_size));
	ptr->size = ptr->vsize;
	ptr->paddr = readLE32 (b, NRO_OFF (text_memoffset));
	ptr->vaddr = ptr->paddr + ba;
	ptr->perm = R_PERM_RX; // r-x
	ptr->add = true;
	r_list_append (ret, ptr);

	// add ro segment
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("ro");
	ptr->vsize = readLE32 (b, NRO_OFF (ro_size));
	ptr->size = ptr->vsize;
	ptr->paddr = readLE32 (b, NRO_OFF (ro_memoffset));
	ptr->vaddr = ptr->paddr + ba;
	ptr->perm = R_PERM_R; // r-x
	ptr->add = true;
	r_list_append (ret, ptr);

	// add data segment
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("data");
	ptr->vsize = readLE32 (b, NRO_OFF (data_size));
	ptr->size = ptr->vsize;
	ptr->paddr = readLE32 (b, NRO_OFF (data_memoffset));
	ptr->vaddr = ptr->paddr + ba;
	ptr->perm = R_PERM_RW;
	ptr->add = true;
	eprintf ("Base Address 0x%08"PFMT64x "\n", ba);
	eprintf ("BSS Size 0x%08"PFMT64x "\n", (ut64)
			readLE32 (bf->buf, NRO_OFF (bss_size)));
	r_list_append (ret, ptr);
	return ret;
}

static RList *symbols(RBinFile *bf) {
	RBinNXOObj *bin;
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	bin = (RBinNXOObj*) bf->o->bin_obj;
	return bin->methods_list;
}

static RList *imports(RBinFile *bf) {
	RBinNXOObj *bin;
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	bin = (RBinNXOObj*) bf->o->bin_obj;
	return bin->imports_list;
}

static RList *libs(RBinFile *bf) {
	return NULL;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ut8 magic[4];
	r_buf_read_at (bf->buf, NRO_OFF (magic), magic, sizeof (magic));
	const char *ft = fileType (magic);
	if (!ft) {
		ft = "nro";
	}
	ret->file = strdup (bf->file);
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
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
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

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_nro,
	.version = R2_VERSION
};
#endif
#endif
