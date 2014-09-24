/* radare - LGPL - Copyright 2014 - Fedor Sakharov */

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

static void * load_bytes(const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
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

	if (!arch || !arch->o) return R_FALSE;
	arch->o->bin_obj = load_bytes (bytes, sz, arch->o->loadaddr, arch->sdb);
	return arch->o->bin_obj ? R_TRUE: R_FALSE;
}

static int destroy(RBinFile *arch) {
	r_bin_coff_free((struct r_bin_coff_obj*)arch->o->bin_obj);
	return R_TRUE;
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
		ptr = R_NEW0 (RBinSection);

		coffname = r_coff_symbol_name (obj, &obj->scn_hdrs[i]);
		if (!coffname)
			return NULL;
		strncpy (ptr->name, coffname, R_BIN_SIZEOF_STRINGS); 

		ptr->size = obj->scn_hdrs[i].s_size;
		ptr->vsize = obj->scn_hdrs[i].s_size;
		ptr->paddr = obj->scn_hdrs[i].s_scnptr;

		ptr->srwx = 0;
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
		if (!coffname)
			break;
		strncpy (ptr->name, coffname, R_BIN_SIZEOF_STRINGS);

		strncpy (ptr->forwarder, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->bind, "", R_BIN_SIZEOF_STRINGS);

		switch (obj->symbols[i].n_sclass) {
			case COFF_SYM_CLASS_FUNCTION:
				strcpy (ptr->type, "FUNC"); break;
			case COFF_SYM_CLASS_FILE:
				strcpy (ptr->type, "FILE"); break;
			case COFF_SYM_CLASS_SECTION:
				strcpy (ptr->type, "SECTION"); break;
			case COFF_SYM_CLASS_EXTERNAL:
				strcpy (ptr->type, "EXTERNAL"); break;
			case COFF_SYM_CLASS_STATIC:
				strcpy (ptr->type, "STATIC"); break;
			default:
				snprintf (ptr->type, R_BIN_SIZEOF_STRINGS, "%i", obj->symbols[i].n_sclass);
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

	strncpy (ret->file, arch->file, R_BIN_SIZEOF_STRINGS);
	strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->bclass, "NONE", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->rclass, "coff", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->type, "COFF (Executable file)", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->os, "any", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->subsystem, "any", R_BIN_SIZEOF_STRINGS);
	ret->big_endian = obj->endian;
	ret->has_va = R_FALSE;
	ret->dbg_info = 0;

	if (r_coff_is_stripped (obj))
		ret->dbg_info |= R_BIN_DBG_STRIPPED;
	else {
		if (!!!(obj->hdr.f_flags & COFF_FLAGS_TI_F_RELFLG))
			ret->dbg_info |= R_BIN_DBG_RELOCS;
		if (!!!(obj->hdr.f_flags & COFF_FLAGS_TI_F_LNNO))
			ret->dbg_info |= R_BIN_DBG_LINENUMS;
		if (!!!(obj->hdr.f_flags & COFF_FLAGS_TI_F_EXEC))
			ret->dbg_info |= R_BIN_DBG_SYMS;
	}

	switch (obj->hdr.f_magic) {
	case COFF_FILE_MACHINE_I386:
		strncpy(ret->machine, "i386", R_BIN_SIZEOF_STRINGS);
		strncpy(ret->arch, "x86", R_BIN_SIZEOF_STRINGS);
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_AMD64:
		strncpy(ret->machine, "AMD 64", R_BIN_SIZEOF_STRINGS);
		strncpy(ret->arch, "x86", R_BIN_SIZEOF_STRINGS);
		ret->bits = 64;
		break;
	case COFF_FILE_MACHINE_H8300:
		strncpy(ret->machine, "H8300", R_BIN_SIZEOF_STRINGS);
		strncpy(ret->arch, "h8300", R_BIN_SIZEOF_STRINGS);
		ret->bits = 16;
		break;

	case COFF_FILE_TI_COFF:
		if (obj->target_id == COFF_FILE_MACHINE_TMS320C54) {
			strncpy(ret->machine, "c54x", R_BIN_SIZEOF_STRINGS);
			strncpy(ret->arch, "tms320", R_BIN_SIZEOF_STRINGS);
			ret->bits = 32;
		} else if (obj->target_id == COFF_FILE_MACHINE_TMS320C55) {
			strncpy(ret->machine, "c55x", R_BIN_SIZEOF_STRINGS);
			strncpy(ret->arch, "tms320", R_BIN_SIZEOF_STRINGS);
			ret->bits = 32;
		} else if (obj->target_id == COFF_FILE_MACHINE_TMS320C55PLUS) {
			strncpy(ret->machine, "c55x+", R_BIN_SIZEOF_STRINGS);
			strncpy(ret->arch, "tms320", R_BIN_SIZEOF_STRINGS);
			ret->bits = 32;
		}
		break;
	default:
		strncpy (ret->machine, "unknown", R_BIN_SIZEOF_STRINGS);
	}

	return ret;
}

static RList *fields(RBinFile *arch) {
	return NULL;
}


static int size(RBinFile *arch) {
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
	return R_FALSE;
}

RBinPlugin r_bin_plugin_coff = {
	.name = "coff",
	.desc = "COFF format r_bin plugin",
	.license = "LGPL3",
	.init = NULL,
	.fini = NULL,
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check = &check,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.boffset = NULL,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.strings = NULL,
	.info = &info,
	.fields = &fields,
	.size = &size,
	.libs = &libs,
	.relocs = &relocs,
	.dbginfo = NULL,
	.write = NULL,
	.get_vaddr = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_coff
};
#endif
