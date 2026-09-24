/* radare - LGPL - Copyright 2009-2023 - pancake */

#include <r_bin.h>
#include "elf/elf.h"

static ut64 scn_resize(RBinFile *bf, const char *name, ut64 size) {
	return Elf_(resize_section) (bf, name, size);
}

static bool scn_perms(RBinFile *bf, const char *name, int perms) {
	return Elf_(section_perms) (bf, name, perms);
}

static bool seg_perms(RBinFile *bf, const char *name, int perms) {
	return Elf_(segment_perms) (bf, name, perms);
}

static bool symbol_weak(RBinFile *bf, const char *symbol, bool weak) {
	if (!bf || !bf->bo || !bf->bo->bin_obj || !bf->buf || !R_STR_ISNOTEMPTY (symbol)) {
		return false;
	}
	struct Elf_(obj_t) *eo = bf->bo->bin_obj;
	RBinElfDynamicInfo *di = &eo->dyn_info;
	size_t namelen = strlen (symbol);
	if (namelen >= ELF_STRING_LENGTH || (eo->ehdr.e_type != ET_EXEC && eo->ehdr.e_type != ET_DYN)
		|| di->dt_symtab == R_BIN_ELF_ADDR_MAX || di->dt_strtab == R_BIN_ELF_ADDR_MAX
		|| di->dt_syment != sizeof (Elf_(Sym)) || !di->dt_strsz
		|| !Elf_(load_imports) (eo)) {
		return false;
	}
	ut64 size = r_buf_size (bf->buf);
	ut64 symtab = Elf_(v2p) (eo, di->dt_symtab);
	ut64 strtab = Elf_(v2p) (eo, di->dt_strtab);
	if (symtab == UT64_MAX || strtab == UT64_MAX || symtab > size
		|| strtab > size || di->dt_strsz > size - strtab) {
		return false;
	}
	char *name = malloc (namelen + 1);
	if (!name) {
		return false;
	}
	ut64 found_at = UT64_MAX;
	ut8 found_info = 0;
	bool big_endian = Elf_(is_big_endian) (eo);
	RBinElfSymbol *imp;
	R_VEC_FOREACH (eo->g_imports_vec, imp) {
		if (!imp->is_imported || strcmp (imp->name, symbol)) {
			continue;
		}
		if (di->dt_syment > size - symtab
			|| imp->ordinal > (size - symtab - di->dt_syment) / di->dt_syment) {
			goto fail;
		}
		ut64 entry = symtab + (ut64)imp->ordinal * di->dt_syment;
		ut8 raw[sizeof (Elf_(Sym))];
		if (r_buf_read_at (bf->buf, entry, raw, sizeof (raw)) != sizeof (raw)) {
			goto fail;
		}
		ut32 nameoff = r_read_ble32 (raw, big_endian);
		ut16 shndx = r_read_ble16 (raw + r_offsetof (Elf_(Sym), st_shndx), big_endian);
		ut8 info = raw[r_offsetof (Elf_(Sym), st_info)];
		ut8 bind = ELF_ST_BIND (info);
		if (shndx != SHN_UNDEF || (bind != STB_GLOBAL && bind != STB_WEAK)
			|| nameoff >= di->dt_strsz || namelen >= di->dt_strsz - nameoff
			|| r_buf_read_at (bf->buf, strtab + nameoff, (ut8 *)name, namelen + 1) != namelen + 1
			|| memcmp (name, symbol, namelen + 1)) {
			goto fail;
		}
		ut64 info_at = entry + r_offsetof (Elf_(Sym), st_info);
		if (found_at != UT64_MAX && found_at != info_at) {
			R_LOG_ERROR ("More than one ELF dynamic import matches %s", symbol);
			goto fail;
		}
		found_at = info_at;
		found_info = info;
	}
	free (name);
	if (found_at == UT64_MAX) {
		R_LOG_ERROR ("ELF dynamic import not found: %s", symbol);
		return false;
	}
	ut8 new_info = ELF_ST_INFO (weak? STB_WEAK: STB_GLOBAL, ELF_ST_TYPE (found_info));
	return new_info == found_info || r_buf_write_at (bf->buf, found_at, &new_info, 1) == 1;
fail:
	free (name);
	return false;
}

static int rpath_del(RBinFile *bf) {
	return Elf_(del_rpath) (bf);
}

static bool chentry(RBinFile *bf, ut64 addr) {
	return Elf_(entry_write) (bf, addr);
}
