/* radare2 - LGPL - Copyright 2017 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

static bool check_bytes(const ut8 *buf, ut64 length) {
	if (buf && length >= 0x20) {
		return !memcmp (buf + 0x10, "NRO0", 4);
	}
	return false;
}

static bool check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	return (void*)(size_t)check_bytes (buf, sz);
}

static int load(RBinFile *arch) {
	return check(arch);
}

static int destroy (RBinFile *arch) {
	return true;
}

static ut64 baddr(RBinFile *arch) {
	return 0x1000000; // XXX
}

static RBinAddr* binsym(RBinFile *arch, int type) {
	return NULL; // TODO
}

static RList* entries(RBinFile *arch) {
	RList* ret;
	RBinAddr *ptr = NULL;
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;
	if ((ptr = R_NEW0 (RBinAddr))) {
		ptr->paddr = 0x80;
		ptr->vaddr = 0x80;
		r_list_append (ret, ptr);
	}
	return ret;
}

static RList* sections(RBinFile *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	ut64 textsize;

	if (!arch->o->info) {
		return NULL;
	}
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;

	const ut8 *buf = arch ? r_buf_buffer (arch->buf) : NULL;
	int bufsz = r_buf_size (arch->buf);

	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	strncpy (ptr->name, "header", R_BIN_SIZEOF_STRINGS);
	ptr->size = 0x80;
	ptr->vsize = 0x80;
	ptr->paddr = 0;
	ptr->vaddr = 0;
	ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_MAP; // r-x
	ptr->add = true;
	r_list_append (ret, ptr);

	ut32 mod0 = r_read_le32 (buf + 4);
	if (mod0 && mod0 + 8 < bufsz) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}
		ut32 mod0sz = r_read_le32 (buf + mod0 + 4);
		strncpy (ptr->name, "mod0", R_BIN_SIZEOF_STRINGS);
		ptr->size = mod0sz;
		ptr->vsize = mod0sz;
		ptr->paddr = mod0;
		ptr->vaddr = mod0;
		ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_WRITABLE | R_BIN_SCN_MAP; // rw-
		ptr->add = true;
		r_list_append (ret, ptr);
	} else {
		eprintf ("Invalid MOD0 address\n");
	}

	ut32 sig0 = r_read_le32 (buf + 0x18);
	if (sig0 && sig0 + 8 < bufsz) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}
		ut32 sig0sz = r_read_le32 (buf + sig0 + 4);
		strncpy (ptr->name, "sig0", R_BIN_SIZEOF_STRINGS);
		ptr->size = sig0sz;
		ptr->vsize = sig0sz;
		ptr->paddr = sig0;
		ptr->vaddr = sig0;
		ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_WRITABLE | R_BIN_SCN_MAP; // rw-
		ptr->add = true;
		r_list_append (ret, ptr);
	} else {
		eprintf ("Invalid SIG0 address\n");
	}

	// add text segment
	textsize = r_mem_get_num (arch->buf->buf + 4, 4);
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	strncpy (ptr->name, "text", R_BIN_SIZEOF_STRINGS);
	ptr->vsize = ptr->size = mod0 - 0x80;
	ptr->paddr = 0x80;
	ptr->vaddr = 0x80;
	ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP; // r-x
	ptr->add = true;
	r_list_append (ret, ptr);
	return ret;
}

static RList* symbols(RBinFile *arch) {
	// TODO: parse symbol table
	return NULL;
}

static RList* imports(RBinFile *arch) {
	return NULL;
}

static RList* libs(RBinFile *arch) {
	return NULL;
}

static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = strdup (arch->file);
	ret->bclass = strdup ("program");
	ret->rclass = strdup ("nro0");
	ret->os = strdup ("switch");
	ret->arch = strdup ("arm");
	ret->machine = strdup ("Nintendo Switch");
	ret->subsystem = strdup ("NRO");
	ret->type = strdup ("EXEC (executable file)");
	ret->bits = 64;
	ret->has_va = true;
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
	.check = &check,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
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
