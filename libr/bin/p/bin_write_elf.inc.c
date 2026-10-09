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

static void addlib_phdr(Elf_(Phdr) *ph, ut32 type, ut64 offset, ut64 addr, ut64 size, ut64 align, ut32 flags, bool be) {
	r_write_ble32 (&ph->p_type, type, be);
	r_write_ble32 (&ph->p_flags, flags, be);
	r_write_ble (&ph->p_offset, offset, be, R_BIN_ELF_WORDSIZE * 8);
	r_write_ble (&ph->p_vaddr, addr, be, R_BIN_ELF_WORDSIZE * 8);
	r_write_ble (&ph->p_paddr, addr, be, R_BIN_ELF_WORDSIZE * 8);
	r_write_ble (&ph->p_filesz, size, be, R_BIN_ELF_WORDSIZE * 8);
	r_write_ble (&ph->p_memsz, size, be, R_BIN_ELF_WORDSIZE * 8);
	r_write_ble (&ph->p_align, align, be, R_BIN_ELF_WORDSIZE * 8);
}

static bool addlib(RBinFile *bf, const char *lib) {
	if (!bf || !bf->bo || !bf->bo->bin_obj || !bf->buf || !R_STR_ISNOTEMPTY (lib)) {
		return false;
	}
	struct Elf_(obj_t) *eo = bf->bo->bin_obj;
	Elf_(Ehdr) *eh = &eo->ehdr;
	RBinElfDynamicInfo *di = &eo->dyn_info;
	ut64 size = r_buf_size (bf->buf);
	if (!eo->phdr || !eo->phnum || eo->phnum >= PN_XNUM - 2 || size > R_BIN_ELF_ADDR_MAX
		|| (eh->e_type != ET_EXEC && eh->e_type != ET_DYN)
		|| eh->e_phentsize != sizeof (Elf_(Phdr)) || eh->e_phoff > size
		|| eo->phnum > (size - eh->e_phoff) / sizeof (Elf_(Phdr))
		|| !eo->strtab || !di->dt_strsz || di->dt_strsz > eo->strtab_size
		|| di->dt_strtab == R_BIN_ELF_ADDR_MAX) {
		return false;
	}
	ut64 stroff = Elf_(v2p) (eo, di->dt_strtab);
	if (stroff > size || di->dt_strsz > size - stroff) {
		return false;
	}
	ut64 align = 0x1000, last = 0, i;
	int dynamic = -1, phdr = -1;
	for (i = 0; i < eo->phnum; i++) {
		Elf_(Phdr) *ph = &eo->phdr[i];
		if (ph->p_offset > size || ph->p_filesz > size - ph->p_offset) {
			return false;
		}
		if (ph->p_type == PT_LOAD) {
			if (ph->p_filesz > ph->p_memsz || ph->p_memsz > R_BIN_ELF_ADDR_MAX - ph->p_vaddr
				|| (ph->p_align && (ph->p_align & (ph->p_align - 1)))) {
				return false;
			}
			last = R_MAX (last, ph->p_vaddr + ph->p_memsz);
			align = R_MAX (align, ph->p_align);
		} else if (ph->p_type == PT_DYNAMIC) {
			if (dynamic != -1) {
				return false;
			}
			dynamic = i;
		} else if (ph->p_type == PT_PHDR) {
			if (phdr != -1) {
				return false;
			}
			phdr = i;
		}
	}
	if (dynamic < 0 || !last || align > R_BIN_ELF_ADDR_MAX - R_MAX (last, size)) {
		return false;
	}
	bool be = Elf_(is_big_endian) (eo);
	Elf_(Phdr) *dp = &eo->phdr[dynamic];
	ut64 dynsize = 0, strtab_at = UT64_MAX, strsz_at = UT64_MAX;
	bool terminated = false;
	for (i = 0; i + sizeof (Elf_(Dyn)) <= dp->p_filesz; i += sizeof (Elf_(Dyn))) {
		Elf_(Dyn) d;
		if (r_buf_read_at (bf->buf, dp->p_offset + i, (ut8 *)&d, sizeof (d)) != sizeof (d)) {
			return false;
		}
		ut64 tag = r_read_ble (&d.d_tag, be, R_BIN_ELF_WORDSIZE * 8);
		ut64 value = r_read_ble (&d.d_un, be, R_BIN_ELF_WORDSIZE * 8);
		if (tag == DT_NULL) {
			dynsize = i + 2 * sizeof (Elf_(Dyn));
			terminated = true;
			break;
		}
		if (tag == DT_STRTAB) {
			strtab_at = i;
		} else if (tag == DT_STRSZ) {
			strsz_at = i;
		} else if (tag == DT_MIPS_RLD_MAP_REL) {
			R_LOG_ERROR ("Cannot relocate a relative MIPS dynamic table");
			return false;
		} else if (tag == DT_NEEDED) {
			if (value >= di->dt_strsz || !memchr (eo->strtab + value, 0, di->dt_strsz - value)) {
				return false;
			}
			if (!strcmp (eo->strtab + value, lib)) {
				return true;
			}
		}
	}
	if (!terminated || strtab_at == UT64_MAX || strsz_at == UT64_MAX) {
		return false;
	}
	ut64 phnum = eo->phnum + 1 + (phdr < 0);
	ut64 phsize = phnum * sizeof (Elf_(Phdr));
	ut64 newoff = (size + align - 1) & ~(align - 1);
	ut64 newaddr = (last + align - 1) & ~(align - 1);
	ut64 strsize, payload;
	if (r_add_overflow_ut64 (di->dt_strsz, strlen (lib) + 1, &strsize)
		|| r_add_overflow_ut64 (phsize, dynsize, &payload)
		|| r_add_overflow_ut64 (payload, strsize, &payload)
		|| payload > SIZE_MAX || newoff > SIZE_MAX - payload
		|| payload > R_BIN_ELF_ADDR_MAX - R_MAX (newoff, newaddr)) {
		return false;
	}
	ut8 *data = calloc (1, payload);
	if (!data) {
		return false;
	}
	// Keep code, data and BSS in place; map the new metadata in a separate load segment.
	ut64 shift = phdr < 0? sizeof (Elf_(Phdr)): 0;
	bool ok = r_buf_read_at (bf->buf, eh->e_phoff, data + shift,
			eo->phnum * sizeof (Elf_(Phdr))) == eo->phnum * sizeof (Elf_(Phdr))
		&& r_buf_read_at (bf->buf, dp->p_offset, data + phsize, dynsize - sizeof (Elf_(Dyn))) == dynsize - sizeof (Elf_(Dyn))
		&& r_buf_read_at (bf->buf, stroff, data + phsize + dynsize, di->dt_strsz) == di->dt_strsz;
	Elf_(Phdr) *headers = (Elf_(Phdr) *)data;
	addlib_phdr (&headers[phdr < 0? 0: phdr], PT_PHDR, newoff, newaddr, phsize, R_BIN_ELF_WORDSIZE, PF_R, be);
	addlib_phdr (&headers[dynamic + (phdr < 0)], PT_DYNAMIC, newoff + phsize,
		newaddr + phsize, dynsize, R_BIN_ELF_WORDSIZE, PF_R | PF_W, be);
	addlib_phdr (&headers[phnum - 1], PT_LOAD, newoff, newaddr, payload, align, PF_R | PF_W, be);
	ut8 *dyn = data + phsize;
	r_write_ble (dyn + strtab_at + R_BIN_ELF_WORDSIZE, newaddr + phsize + dynsize, be, R_BIN_ELF_WORDSIZE * 8);
	r_write_ble (dyn + strsz_at + R_BIN_ELF_WORDSIZE, strsize, be, R_BIN_ELF_WORDSIZE * 8);
	r_write_ble (dyn + dynsize - 2 * sizeof (Elf_(Dyn)), DT_NEEDED, be, R_BIN_ELF_WORDSIZE * 8);
	r_write_ble (dyn + dynsize - 2 * sizeof (Elf_(Dyn)) + R_BIN_ELF_WORDSIZE, di->dt_strsz, be, R_BIN_ELF_WORDSIZE * 8);
	memcpy (data + phsize + dynsize + di->dt_strsz, lib, strlen (lib) + 1);
	RBuffer *out = ok? r_buf_new_with_buf (bf->buf): NULL;
	if (!out) {
		free (data);
		return false;
	}
	ok = r_buf_resize (out, newoff) && r_buf_append_bytes (out, data, payload);
	free (data);
	ut8 value[8];
	r_write_ble (value, newoff, be, R_BIN_ELF_WORDSIZE * 8);
	ok = ok && r_buf_write_at (out, r_offsetof (Elf_(Ehdr), e_phoff), value, R_BIN_ELF_WORDSIZE) == R_BIN_ELF_WORDSIZE;
	r_write_ble16 (value, phnum, be);
	ok = ok && r_buf_write_at (out, r_offsetof (Elf_(Ehdr), e_phnum), value, 2) == 2;
	// Section headers are optional, but keep them consistent when present.
	if (eh->e_shoff) {
		ok = ok && eh->e_shnum && eh->e_shentsize == sizeof (Elf_(Shdr)) && eh->e_shoff <= size
			&& eh->e_shnum <= (size - eh->e_shoff) / sizeof (Elf_(Shdr));
		for (i = 0; ok && i < eh->e_shnum; i++) {
			Elf_(Shdr) sh;
			if (r_buf_read_at (bf->buf, eh->e_shoff + i * sizeof (sh), (ut8 *)&sh, sizeof (sh)) != sizeof (sh)) {
				ok = false;
				break;
			}
			ut32 type = r_read_ble32 (&sh.sh_type, be);
			ut64 offset = r_read_ble (&sh.sh_offset, be, R_BIN_ELF_WORDSIZE * 8);
			ut64 at, len;
			if (type == SHT_DYNAMIC && offset == dp->p_offset) {
				at = phsize;
				len = dynsize;
			} else if (type == SHT_STRTAB && offset == stroff) {
				at = phsize + dynsize;
				len = strsize;
			} else {
				continue;
			}
			ut8 fields[3 * R_BIN_ELF_WORDSIZE];
			r_write_ble (fields, newaddr + at, be, R_BIN_ELF_WORDSIZE * 8);
			r_write_ble (fields + R_BIN_ELF_WORDSIZE, newoff + at, be, R_BIN_ELF_WORDSIZE * 8);
			r_write_ble (fields + 2 * R_BIN_ELF_WORDSIZE, len, be, R_BIN_ELF_WORDSIZE * 8);
			ok = r_buf_write_at (out, eh->e_shoff + i * sizeof (Elf_(Shdr)) + r_offsetof (Elf_(Shdr), sh_addr),
				fields, sizeof (fields)) == sizeof (fields);
		}
	}
	if (ok) {
		r_unref (bf->buf);
		bf->buf = out;
	} else {
		r_unref (out);
	}
	return ok;
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
