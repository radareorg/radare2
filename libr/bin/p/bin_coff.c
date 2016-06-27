/* radare - LGPL - Copyright 2014-2015 - Fedor Sakharov */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#include "coff/coff.h"

static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

static Sdb* get_sdb (RBinObject *o) {
	if (!o) return NULL;
	struct r_bin_coff_obj *bin = (struct r_bin_coff_obj *) o->bin_obj;
	if (bin->kv) return bin->kv;
	return NULL;
}

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	void *res = NULL;
	RBuffer *tbuf = NULL;

	if (!buf || sz == 0 || sz == UT64_MAX) return NULL;
	tbuf = r_buf_new();
	r_buf_set_bytes (tbuf, buf, sz);
	res = r_bin_coff_new_buf(tbuf);
	r_buf_free (tbuf);
	return res;
}

static int load(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;

	if (!arch || !arch->o) return false;
	arch->o->bin_obj = load_bytes (arch, bytes, sz, arch->o->loadaddr, arch->sdb);
	return arch->o->bin_obj ? true: false;
}

static int destroy(RBinFile *arch) {
	r_bin_coff_free((struct r_bin_coff_obj*)arch->o->bin_obj);
	return true;
}

static ut64 baddr(RBinFile *arch) {
	return 0;
}

static RBinAddr *binsym(RBinFile *arch, int sym) {
	return NULL;
}

static RList *entries(RBinFile *arch) {
	struct r_bin_coff_obj *obj = (struct r_bin_coff_obj*)arch->o->bin_obj;
	RList *ret;
	RBinAddr *ptr = NULL;

	if (!(ret = r_list_new ()))
		return NULL;

	ret->free = free;

	ptr = r_coff_get_entry(obj);
	r_list_append(ret, ptr);

	return ret;
}

static RList *sections(RBinFile *arch) {
	const char *coffname;
	size_t i;
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	struct r_bin_coff_obj *obj = (struct r_bin_coff_obj*)arch->o->bin_obj;

	ret = r_list_new();

	if (!ret)
		return NULL;

	if (obj && obj->scn_hdrs)
	for (i = 0; i < obj->hdr.f_nscns; i++) {
		coffname = r_coff_symbol_name (obj, &obj->scn_hdrs[i]);
		if (!coffname) {
			r_list_free (ret);
			return NULL;
		}

		ptr = R_NEW0 (RBinSection);
		strncpy (ptr->name, coffname, R_BIN_SIZEOF_STRINGS);

		ptr->size = obj->scn_hdrs[i].s_size;
		ptr->vsize = obj->scn_hdrs[i].s_size;
		ptr->paddr = obj->scn_hdrs[i].s_scnptr;
		ptr->add = true;

		ptr->srwx = R_BIN_SCN_MAP;
		if (obj->scn_hdrs[i].s_flags&COFF_SCN_MEM_READ)
			ptr->srwx |= R_BIN_SCN_READABLE;
		if (obj->scn_hdrs[i].s_flags&COFF_SCN_MEM_WRITE)
			ptr->srwx |= R_BIN_SCN_WRITABLE;
		if (obj->scn_hdrs[i].s_flags&COFF_SCN_MEM_EXECUTE)
			ptr->srwx |= R_BIN_SCN_EXECUTABLE;

		r_list_append (ret, ptr);
	}

	return ret;
}

static RList *symbols(RBinFile *arch) {
	const char *coffname;
	size_t i;
	RList *ret = NULL;
	RBinSymbol *ptr = NULL;

	struct r_bin_coff_obj *obj = (struct r_bin_coff_obj*)arch->o->bin_obj;

	if (!(ret = r_list_new()))
		return ret;

	ret->free = free;

	if (obj->symbols)
	for (i = 0; i < obj->hdr.f_nsyms; i++) {
		if (!(ptr = R_NEW0 (RBinSymbol)))
			break;
		coffname = r_coff_symbol_name (obj, &obj->symbols[i]);
		if (!coffname) {
			free (ptr);
			break;
		}
		ptr->name = strdup (coffname);
		ptr->forwarder = r_str_const ("NONE");

		switch (obj->symbols[i].n_sclass) {
		case COFF_SYM_CLASS_FUNCTION:
			ptr->type = r_str_const ("FUNC");
			break;
		case COFF_SYM_CLASS_FILE:
			ptr->type = r_str_const ("FILE");
			break;
		case COFF_SYM_CLASS_SECTION:
			ptr->type = r_str_const ("SECTION");
			break;
		case COFF_SYM_CLASS_EXTERNAL:
			ptr->type = r_str_const ("EXTERNAL");
			break;
		case COFF_SYM_CLASS_STATIC:
			ptr->type = r_str_const ("STATIC");
			break;
		default:
			ptr->type = r_str_const (sdb_fmt(0, "%i", obj->symbols[i].n_sclass));
			break;
		}

		if (obj->symbols[i].n_scnum < obj->hdr.f_nscns) {
			ptr->paddr = obj->scn_hdrs[obj->symbols[i].n_scnum].s_scnptr +
				obj->symbols[i].n_value;
		}

		ptr->size = 4;
		ptr->ordinal = 0;

		r_list_append (ret, ptr);

		i += obj->symbols[i].n_numaux;
		free (ptr);
	}

	return ret;
}

static RList *imports(RBinFile *arch) {
	return NULL;
}

static RList *libs(RBinFile *arch) {
	return NULL;
}

static RList *relocs(RBinFile *arch) {
	return NULL;
}

static RBinInfo *info(RBinFile *arch) {
	RBinInfo *ret = R_NEW0(RBinInfo);
	struct r_bin_coff_obj *obj = (struct r_bin_coff_obj*)arch->o->bin_obj;

	ret->file = arch->file? strdup (arch->file): NULL;
	ret->rclass = strdup ("coff");
	ret->type = strdup ("COFF (Executable file)");
	ret->os = strdup ("any");
	ret->subsystem = strdup ("any");
	ret->big_endian = obj->endian;
	ret->has_va = false;
	ret->dbg_info = 0;

	if (r_coff_is_stripped (obj)) {
		ret->dbg_info |= R_BIN_DBG_STRIPPED;
	} else {
		if (!(obj->hdr.f_flags & COFF_FLAGS_TI_F_RELFLG))
			ret->dbg_info |= R_BIN_DBG_RELOCS;
		if (!(obj->hdr.f_flags & COFF_FLAGS_TI_F_LNNO))
			ret->dbg_info |= R_BIN_DBG_LINENUMS;
		if (!(obj->hdr.f_flags & COFF_FLAGS_TI_F_EXEC))
			ret->dbg_info |= R_BIN_DBG_SYMS;
	}

	switch (obj->hdr.f_magic) {
	case COFF_FILE_MACHINE_I386:
		ret->machine = strdup ("i386");
		ret->arch = strdup ("x86");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_AMD64:
		ret->machine = strdup ("AMD64");
		ret->arch = strdup ("x86");
		ret->bits = 64;
		break;
	case COFF_FILE_MACHINE_H8300:
		ret->machine = strdup ("H8300");
		ret->arch = strdup ("h8300");
		ret->bits = 16;
		break;
	case COFF_FILE_TI_COFF:
		switch (obj->target_id) {
		case COFF_FILE_MACHINE_TMS320C54:
			ret->machine = strdup ("c54x");
			ret->arch = strdup ("tms320");
			ret->bits = 32;
			break;
		case COFF_FILE_MACHINE_TMS320C55:
			ret->machine = strdup ("c55x");
			ret->arch = strdup ("tms320");
			ret->bits = 32;
			break;
		case COFF_FILE_MACHINE_TMS320C55PLUS:
			ret->machine = strdup ("c55x+");
			ret->arch = strdup ("tms320");
			ret->bits = 32;
			break;
		}
		break;
	default:
		ret->machine = strdup ("unknown");
	}

	return ret;
}

static RList *fields(RBinFile *arch) {
	return NULL;
}


static ut64 size(RBinFile *arch) {
	return 0;
}

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);

}

static int check_bytes(const ut8 *buf, ut64 length) {
#if 0
TODO: do more checks here to avoid false positives

ut16 MACHINE
ut16 NSECTIONS
ut32 DATE
ut32 PTRTOSYMTABLE
ut32 NUMOFSYMS
ut16 OPTHDRSIZE
ut16 CHARACTERISTICS
#endif
	if (buf && length >= 20)
		return r_coff_supported_arch (buf);
	return false;
}

RBinPlugin r_bin_plugin_coff = {
	.name = "coff",
	.desc = "COFF format r_bin plugin",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
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
	.fields = &fields,
	.size = &size,
	.libs = &libs,
	.relocs = &relocs,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_coff,
	.version = R2_VERSION
};
#endif
