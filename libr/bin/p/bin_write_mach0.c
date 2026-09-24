/* radare - LGPL - Copyright 2016-2019 - pancake */

#include <r_types.h>
#include <r_bin.h>
#include "mach0/mach0.h"

typedef struct machoPointers_t {
	size_t ncmds;
	size_t ncmds_off;
	size_t sizeofcmds;
	size_t sizeofcmds_off;
	size_t lastcmd_off;
} MachoPointers;

static MachoPointers findLastCommand(RBinFile *bf) {
	struct MACH0_(obj_t) *bin = bf->bo->bin_obj;
	int i = 0;
	ut64 off;
	MachoPointers mp = {0};
	mp.ncmds = bin->hdr.ncmds;
	mp.ncmds_off = 0x10;
	mp.sizeofcmds = bin->hdr.sizeofcmds;
	mp.sizeofcmds_off = 0x14;

	for (i = 0, off = 0x20 + bin->header_at; i < mp.ncmds; i++) {
		ut32 loadc[2] = {0};
		r_buf_read_at (bin->b, off, (ut8*)&loadc, sizeof (loadc));
		//r_buf_seek (bin->b, off, R_BUF_SET);
		int len = loadc[1]; // r_buf_read_le32 (loadc[1]); // bin->b); //
		if (len < 1) {
			R_LOG_ERROR ("read (lc) at 0x%08"PFMT64x, off);
			break;
		}
		int size = r_read_ble32 (&loadc[1], bin->big_endian);
		off += size;
	}
	mp.lastcmd_off = off;
	return mp;
}

static const uint8_t sample_dylib[56] = {
	0x0c, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x18, 0x00,
	0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x0a, 0xca, 0x04,
	0x00, 0x00, 0x01, 0x00, 0x2f, 0x75, 0x73, 0x72, 0x2f, 0x6c,
	0x69, 0x62, 0x2f, 0x6c, 0x69, 0x6f, 0x75, 0x74, 0x69, 0x6c,
	0x2e, 0x64, 0x79, 0x6c, 0x69, 0x62, 0x00, 0x6c, 0x69, 0x62,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static bool MACH0_(write_addlib)(RBinFile *bf, const char *lib) {
	MachoPointers mp = findLastCommand (bf);
	size_t size_of_lib = 56;

	ut32 ncmds = mp.ncmds + 1;
	r_buf_write_at (bf->buf, mp.ncmds_off, (const ut8*)&ncmds, sizeof (ncmds));

	ut32 sizeofcmds = mp.sizeofcmds + size_of_lib; // , &ncmds, sizeof (ncmds));
	r_buf_write_at (bf->buf, mp.sizeofcmds_off, (ut8*)&sizeofcmds, sizeof (sizeofcmds));

	size_t lib_len = strlen (lib);
	if (lib_len > 22) {
		R_LOG_WARN ("Adjusting cmdsize too long libname");
		size_of_lib += lib_len + 1 - 22;
		size_of_lib += 8 - (size_of_lib % 8);
	}

	const size_t sample_dylib_name_off = 24;
	r_buf_write_at (bf->buf, mp.lastcmd_off, sample_dylib, 56);
	r_buf_write_at (bf->buf, mp.lastcmd_off + 4, (const ut8*)&size_of_lib, 4);
	r_buf_write_at (bf->buf, mp.lastcmd_off + sample_dylib_name_off, (const ut8*)lib, lib_len + 1);
	return true;
}

static bool addlib(RBinFile *bf, const char *lib) {
	return MACH0_(write_addlib) (bf, lib);
}

static bool lib_weak(RBinFile *bf, const char *lib, bool weak) {
	if (!bf || !bf->bo || !bf->bo->bin_obj || !bf->buf || !R_STR_ISNOTEMPTY (lib)) {
		return false;
	}
	struct MACH0_(obj_t) *mo = bf->bo->bin_obj;
	ut64 size = r_buf_size (bf->buf);
	ut64 off = mo->header_at + sizeof (struct MACH0_(mach_header));
	if (off > size || mo->hdr.sizeofcmds > size - off) {
		return false;
	}
	ut64 end = off + mo->hdr.sizeofcmds;
	size_t liblen = strlen (lib);
	ut64 found_at = UT64_MAX;
	ut32 found_cmd = 0;
	ut32 i;
	for (i = 0; i < mo->hdr.ncmds; i++) {
		ut8 lc[8];
		if (off > end || end - off < sizeof (lc)
			|| r_buf_read_at (bf->buf, off, lc, sizeof (lc)) != sizeof (lc)) {
			return false;
		}
		ut32 cmd = r_read_ble32 (lc, mo->big_endian);
		ut32 cmdsize = r_read_ble32 (lc + 4, mo->big_endian);
		if (cmdsize < sizeof (lc) || cmdsize > end - off) {
			return false;
		}
		if (cmd == LC_LOAD_DYLIB || cmd == LC_LOAD_WEAK_DYLIB) {
			ut8 name_field[4];
			if (cmdsize < sizeof (struct dylib_command)
				|| r_buf_read_at (bf->buf, off + 8, name_field, sizeof (name_field)) != sizeof (name_field)) {
				return false;
			}
			ut32 nameoff = r_read_ble32 (name_field, mo->big_endian);
			if (nameoff < sizeof (struct dylib_command) || nameoff >= cmdsize) {
				return false;
			}
			if (liblen < cmdsize - nameoff) {
				char *name = malloc (liblen + 1);
				if (!name) {
					return false;
				}
				bool match = r_buf_read_at (bf->buf, off + nameoff, (ut8 *)name, liblen + 1) == liblen + 1
					&& !memcmp (name, lib, liblen + 1);
				free (name);
				if (match) {
					if (found_at != UT64_MAX) {
						R_LOG_ERROR ("More than one Mach-O library load command matches %s", lib);
						return false;
					}
					found_at = off;
					found_cmd = cmd;
				}
			}
		}
		off += cmdsize;
	}
	if (found_at == UT64_MAX) {
		R_LOG_ERROR ("Mach-O library load command not found: %s", lib);
		return false;
	}
	ut32 new_cmd = weak? LC_LOAD_WEAK_DYLIB: LC_LOAD_DYLIB;
	if (found_cmd == new_cmd) {
		return true;
	}
	ut8 value[4];
	r_write_ble32 (value, new_cmd, mo->big_endian);
	return r_buf_write_at (bf->buf, found_at, value, sizeof (value)) == sizeof (value);
}

typedef struct {
	ut64 symtab;
	ut64 fixups;
	ut64 dyldinfo;
} MachWeakCommands;

typedef struct {
	ut64 sym_at;
	ut16 sym_desc;
	ut32 target_ordinal;
	bool have_ordinal;
	ut64 chain_at;
	ut64 chain_value;
	int chain_width;
	ut64 bind_at;
	ut8 bind_value;
	ut64 lazy_at;
	ut8 lazy_value;
} MachWeakEdit;

static bool mach_weak_commands(RBinFile *bf, struct MACH0_(obj_t) *mo, MachWeakCommands *cmds) {
	ut64 size = r_buf_size (bf->buf);
	ut64 off = mo->header_at + sizeof (struct MACH0_(mach_header));
	if (off > size || mo->hdr.sizeofcmds > size - off) {
		return false;
	}
	ut64 end = off + mo->hdr.sizeofcmds;
	ut32 i;
	for (i = 0; i < mo->hdr.ncmds; i++) {
		ut8 lc[8];
		if (off > end || end - off < sizeof (lc)
			|| r_buf_read_at (bf->buf, off, lc, sizeof (lc)) != sizeof (lc)) {
			return false;
		}
		ut32 cmd = r_read_ble32 (lc, mo->big_endian);
		ut32 cmdsize = r_read_ble32 (lc + 4, mo->big_endian);
		if (cmdsize < sizeof (lc) || cmdsize > end - off) {
			return false;
		}
		ut64 *slot = NULL;
		ut32 minimum = 0;
		switch (cmd) {
		case LC_SYMTAB:
			slot = &cmds->symtab;
			minimum = sizeof (struct symtab_command);
			break;
		case LC_DYLD_CHAINED_FIXUPS:
			slot = &cmds->fixups;
			minimum = 16;
			break;
		case LC_DYLD_INFO:
		case LC_DYLD_INFO_ONLY:
			slot = &cmds->dyldinfo;
			minimum = sizeof (struct dyld_info_command);
			break;
		}
		if (slot) {
			if (*slot != UT64_MAX || cmdsize < minimum) {
				return false;
			}
			*slot = off;
		}
		off += cmdsize;
	}
	return true;
}

static bool mach_weak_name_matches(RBuffer *buf, ut64 off, ut64 available,
		const char *name, size_t namelen, ut8 *scratch) {
	if (namelen < available
		&& r_buf_read_at (buf, off, scratch, namelen + 1) == namelen + 1
		&& !memcmp (scratch, name, namelen + 1)) {
		return true;
	}
	return namelen + 1 < available
		&& r_buf_read_at (buf, off, scratch, namelen + 2) == namelen + 2
		&& scratch[0] == '_'
		&& !memcmp (scratch + 1, name, namelen + 1);
}

static bool mach_weak_symtab(RBinFile *bf, struct MACH0_(obj_t) *mo,
		ut64 cmd, const char *name, size_t namelen, ut8 *scratch, MachWeakEdit *edit) {
	if (cmd == UT64_MAX) {
		return true;
	}
	ut8 fields[16];
	if (r_buf_read_at (bf->buf, cmd + 8, fields, sizeof (fields)) != sizeof (fields)) {
		return false;
	}
	bool be = mo->big_endian;
	ut64 symoff = r_read_ble32 (fields, be);
	ut64 nsyms = r_read_ble32 (fields + 4, be);
	ut64 stroff = r_read_ble32 (fields + 8, be);
	ut64 strsize = r_read_ble32 (fields + 12, be);
	ut64 size = r_buf_size (bf->buf);
#if R_BIN_MACH064
	const ut64 entry_size = sizeof (struct nlist_64);
#else
	const ut64 entry_size = sizeof (struct nlist);
#endif
	if (symoff > size || nsyms > (size - symoff) / entry_size
		|| stroff > size || strsize > size - stroff) {
		return false;
	}
	ut64 i;
	for (i = 0; i < nsyms; i++) {
		ut64 at = symoff + i * entry_size;
		ut8 nlist[8];
		if (r_buf_read_at (bf->buf, at, nlist, sizeof (nlist)) != sizeof (nlist)) {
			return false;
		}
		ut32 strx = r_read_ble32 (nlist, be);
		ut8 type = nlist[4];
		if ((type & N_STAB) || (type & N_TYPE) != N_UNDF || strx >= strsize) {
			continue;
		}
		if (!mach_weak_name_matches (bf->buf, stroff + strx, strsize - strx,
				name, namelen, scratch)) {
			continue;
		}
		if (edit->sym_at != UT64_MAX) {
			R_LOG_ERROR ("More than one Mach-O undefined symbol matches %s", name);
			return false;
		}
		edit->sym_at = at + 6;
		edit->sym_desc = r_read_ble16 (nlist + 6, be);
		edit->target_ordinal = edit->sym_desc >> 8;
		edit->have_ordinal = true;
	}
	return true;
}

static bool mach_weak_fixups(RBinFile *bf, struct MACH0_(obj_t) *mo,
		ut64 cmd, const char *name, size_t namelen, ut8 *scratch, MachWeakEdit *edit) {
	if (cmd == UT64_MAX) {
		return true;
	}
	ut8 linkedit[8];
	if (r_buf_read_at (bf->buf, cmd + 8, linkedit, sizeof (linkedit)) != sizeof (linkedit)) {
		return false;
	}
	ut64 dataoff = r_read_ble32 (linkedit, mo->big_endian);
	ut64 datasize = r_read_ble32 (linkedit + 4, mo->big_endian);
	ut64 size = r_buf_size (bf->buf);
	if (dataoff > size || datasize > size - dataoff || datasize < 28) {
		return false;
	}
	ut8 header[28];
	if (r_buf_read_at (bf->buf, dataoff, header, sizeof (header)) != sizeof (header)) {
		return false;
	}
	ut64 imports_off = r_read_le32 (header + 8);
	ut64 symbols_off = r_read_le32 (header + 12);
	ut64 count = r_read_le32 (header + 16);
	ut32 format = r_read_le32 (header + 20);
	ut32 symbols_format = r_read_le32 (header + 24);
	int width = format == DYLD_CHAINED_IMPORT_ADDEND64? 16:
		(format == DYLD_CHAINED_IMPORT_ADDEND? 8:
		(format == DYLD_CHAINED_IMPORT? 4: 0));
	if (!width || symbols_format || imports_off > datasize || symbols_off > datasize
		|| count > (datasize - imports_off) / width) {
		return false;
	}
	ut64 i;
	for (i = 0; i < count; i++) {
		ut64 at = dataoff + imports_off + i * width;
		ut8 raw[8];
		int headsize = width == 16? 8: 4;
		if (r_buf_read_at (bf->buf, at, raw, headsize) != headsize) {
			return false;
		}
		ut64 value = width == 16? r_read_le64 (raw): r_read_le32 (raw);
		ut32 ordinal = width == 16? (value & 0xffff): (value & 0xff);
		ut64 nameoff = width == 16? (value >> 32): (value >> 9);
		if (nameoff >= datasize - symbols_off) {
			return false;
		}
		if (!mach_weak_name_matches (bf->buf, dataoff + symbols_off + nameoff,
				datasize - symbols_off - nameoff, name, namelen, scratch)) {
			continue;
		}
		if (edit->chain_at != UT64_MAX
			|| (edit->have_ordinal && ordinal != edit->target_ordinal)) {
			R_LOG_ERROR ("Ambiguous Mach-O chained import: %s", name);
			return false;
		}
		edit->chain_at = at;
		edit->chain_value = value;
		edit->chain_width = headsize;
		edit->target_ordinal = ordinal;
		edit->have_ordinal = true;
	}
	return true;
}

static bool mach_weak_skip_leb(RBuffer *buf, ut64 *off, ut64 end) {
	int i;
	for (i = 0; i < 10 && *off < end; i++) {
		ut8 byte;
		if (r_buf_read_at (buf, (*off)++, &byte, 1) != 1) {
			return false;
		}
		if (!(byte & 0x80)) {
			return true;
		}
	}
	return false;
}

static bool mach_weak_read_uleb(RBuffer *buf, ut64 *off, ut64 end, ut64 *value) {
	*value = 0;
	int i;
	for (i = 0; i < 10 && *off < end; i++) {
		ut8 byte;
		if (r_buf_read_at (buf, (*off)++, &byte, 1) != 1
			|| (i == 9 && byte > 1)) {
			return false;
		}
		*value |= (ut64)(byte & 0x7f) << (7 * i);
		if (!(byte & 0x80)) {
			return true;
		}
	}
	return false;
}

static bool mach_weak_bind_stream(RBinFile *bf, ut64 off, ut64 length,
		const char *name, size_t namelen, ut8 *scratch, MachWeakEdit *edit,
		ut64 *found_at, ut8 *found_value) {
	ut64 size = r_buf_size (bf->buf);
	if (off > size || length > size - off) {
		return false;
	}
	ut64 end = off + length;
	ut32 ordinal = 0;
	while (off < end) {
		ut64 opcode_at = off;
		ut8 byte;
		if (r_buf_read_at (bf->buf, off++, &byte, 1) != 1) {
			return false;
		}
		ut8 op = byte & BIND_OPCODE_MASK;
		ut8 imm = byte & BIND_IMMEDIATE_MASK;
		switch (op) {
		case BIND_OPCODE_DONE:
		case BIND_OPCODE_SET_TYPE_IMM:
		case BIND_OPCODE_DO_BIND:
		case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
			break;
		case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
			ordinal = imm;
			break;
		case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
			ordinal = imm? (0xf0 | imm): 0;
			break;
		case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
			{
				ut64 value;
				if (!mach_weak_read_uleb (bf->buf, &off, end, &value) || value > UT16_MAX) {
					return false;
				}
				ordinal = value;
			}
			break;
		case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
			{
				ut64 str_at = off;
				ut8 ch;
				do {
					if (off == end || r_buf_read_at (bf->buf, off++, &ch, 1) != 1) {
						return false;
					}
				} while (ch);
				if (mach_weak_name_matches (bf->buf, str_at, off - str_at,
						name, namelen, scratch)) {
					if (*found_at != UT64_MAX
						|| (edit->have_ordinal && edit->target_ordinal != ordinal)) {
						R_LOG_ERROR ("Ambiguous Mach-O bind import: %s", name);
						return false;
					}
					*found_at = opcode_at;
					*found_value = byte;
					edit->target_ordinal = ordinal;
					edit->have_ordinal = true;
				}
			}
			break;
		case BIND_OPCODE_SET_ADDEND_SLEB:
		case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
		case BIND_OPCODE_ADD_ADDR_ULEB:
		case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
			if (!mach_weak_skip_leb (bf->buf, &off, end)) {
				return false;
			}
			break;
		case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
			if (!mach_weak_skip_leb (bf->buf, &off, end)
				|| !mach_weak_skip_leb (bf->buf, &off, end)) {
				return false;
			}
			break;
		case BIND_OPCODE_THREADED:
			if (imm == BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB) {
				if (!mach_weak_skip_leb (bf->buf, &off, end)) {
					return false;
				}
			} else if (imm != BIND_SUBOPCODE_THREADED_APPLY) {
				return false;
			}
			break;
		default:
			return false;
		}
	}
	return true;
}

static bool mach_weak_dyldinfo(RBinFile *bf, struct MACH0_(obj_t) *mo,
		ut64 cmd, const char *name, size_t namelen, ut8 *scratch, MachWeakEdit *edit) {
	if (cmd == UT64_MAX) {
		return true;
	}
	ut8 fields[40];
	if (r_buf_read_at (bf->buf, cmd + 8, fields, sizeof (fields)) != sizeof (fields)) {
		return false;
	}
	bool be = mo->big_endian;
	ut64 bind_off = r_read_ble32 (fields + 8, be);
	ut64 bind_size = r_read_ble32 (fields + 12, be);
	ut64 lazy_off = r_read_ble32 (fields + 24, be);
	ut64 lazy_size = r_read_ble32 (fields + 28, be);
	return (!bind_size || mach_weak_bind_stream (bf, bind_off, bind_size,
			name, namelen, scratch, edit, &edit->bind_at, &edit->bind_value))
		&& (!lazy_size || mach_weak_bind_stream (bf, lazy_off, lazy_size,
			name, namelen, scratch, edit, &edit->lazy_at, &edit->lazy_value));
}

static bool symbol_weak_raw(RBinFile *bf, const char *symbol, bool weak) {
	if (!bf || !bf->bo || !bf->bo->bin_obj || !bf->buf || !R_STR_ISNOTEMPTY (symbol)) {
		return false;
	}
	struct MACH0_(obj_t) *mo = bf->bo->bin_obj;
	MachWeakCommands cmds = { UT64_MAX, UT64_MAX, UT64_MAX };
	MachWeakEdit edit = {
		.sym_at = UT64_MAX,
		.chain_at = UT64_MAX,
		.bind_at = UT64_MAX,
		.lazy_at = UT64_MAX,
	};
	size_t namelen = strlen (symbol);
	if (namelen > SIZE_MAX - 2) {
		return false;
	}
	ut8 *scratch = malloc (namelen + 2);
	if (!scratch) {
		return false;
	}
	bool ok = mach_weak_commands (bf, mo, &cmds)
		&& mach_weak_symtab (bf, mo, cmds.symtab, symbol, namelen, scratch, &edit)
		&& mach_weak_fixups (bf, mo, cmds.fixups, symbol, namelen, scratch, &edit)
		&& mach_weak_dyldinfo (bf, mo, cmds.dyldinfo, symbol, namelen, scratch, &edit);
	free (scratch);
	if (!ok) {
		return false;
	}
	if (edit.sym_at == UT64_MAX && edit.chain_at == UT64_MAX
		&& edit.bind_at == UT64_MAX && edit.lazy_at == UT64_MAX) {
		R_LOG_ERROR ("Mach-O import not found: %s", symbol);
		return false;
	}
	if (edit.sym_at != UT64_MAX) {
		ut16 desc = weak? edit.sym_desc | N_WEAK_REF: edit.sym_desc & ~N_WEAK_REF;
		ut8 raw[2];
		r_write_ble16 (raw, desc, mo->big_endian);
		if (r_buf_write_at (bf->buf, edit.sym_at, raw, sizeof (raw)) != sizeof (raw)) {
			return false;
		}
	}
	if (edit.chain_at != UT64_MAX) {
		ut64 mask = edit.chain_width == 8? (ut64)1 << 16: (ut64)1 << 8;
		ut64 value = weak? edit.chain_value | mask: edit.chain_value & ~mask;
		ut8 raw[8];
		if (edit.chain_width == 8) {
			r_write_le64 (raw, value);
		} else {
			r_write_le32 (raw, value);
		}
		if (r_buf_write_at (bf->buf, edit.chain_at, raw, edit.chain_width) != edit.chain_width) {
			return false;
		}
	}
	if (edit.bind_at != UT64_MAX) {
		ut8 value = weak? edit.bind_value | BIND_SYMBOL_FLAGS_WEAK_IMPORT:
			edit.bind_value & ~BIND_SYMBOL_FLAGS_WEAK_IMPORT;
		if (r_buf_write_at (bf->buf, edit.bind_at, &value, 1) != 1) {
			return false;
		}
	}
	if (edit.lazy_at != UT64_MAX) {
		ut8 value = weak? edit.lazy_value | BIND_SYMBOL_FLAGS_WEAK_IMPORT:
			edit.lazy_value & ~BIND_SYMBOL_FLAGS_WEAK_IMPORT;
		if (r_buf_write_at (bf->buf, edit.lazy_at, &value, 1) != 1) {
			return false;
		}
	}
	return true;
}

static bool symbol_weak(RBinFile *bf, const char *symbol, bool weak) {
	if (!bf || !bf->bo || !bf->bo->bin_obj || !bf->buf) {
		return false;
	}
	struct MACH0_(obj_t) *mo = bf->bo->bin_obj;
	RBuffer *swizzled = NULL;
	if (mo->chained_starts && mo->b != bf->buf) {
		RBuffer *raw = r_buf_new_with_buf (mo->b);
		if (!raw) {
			return false;
		}
		swizzled = bf->buf;
		bf->buf = raw;
	}
	bool ok = symbol_weak_raw (bf, symbol, weak);
	if (swizzled) {
		if (ok) {
			r_unref (swizzled);
		} else {
			r_unref (bf->buf);
			bf->buf = swizzled;
		}
	}
	return ok;
}

static bool seg_name_matches(const char *segname, const char *user) {
	size_t nlen = strlen (user);
	if (nlen > 16) {
		return false;
	}
	if (memcmp (segname, user, nlen)) {
		return false;
	}
	return (nlen == 16) || segname[nlen] == 0;
}

static bool seg_perms(RBinFile *bf, const char *name, int perms) {
	struct MACH0_(obj_t) *mo = bf->bo->bin_obj;
	if (!mo || !mo->segs || mo->nsegs <= 0) {
		return false;
	}
	/* VM_PROT_READ/WRITE/EXECUTE (0x1/0x2/0x4) match R_PERM_R/W/X. */
	const ut32 seg_lc =
#if R_BIN_MACH064
		LC_SEGMENT_64;
#else
		LC_SEGMENT;
#endif
	/* walk load commands to locate the on-disk offset of each segment_command
	 * so we can patch the initprot/maxprot fields in place. */
	ut64 off = sizeof (struct MACH0_(mach_header)) + mo->header_at;
	ut32 ncmds = mo->hdr.ncmds;
	int seg_idx = 0;
	ut32 i;
	for (i = 0; i < ncmds; i++) {
		ut32 loadc[2] = {0};
		if (r_buf_read_at (bf->buf, off, (ut8*)loadc, sizeof (loadc)) != sizeof (loadc)) {
			return false;
		}
		ut32 cmd = r_read_ble32 (&loadc[0], mo->big_endian);
		ut32 cmdsize = r_read_ble32 (&loadc[1], mo->big_endian);
		if (cmdsize == 0) {
			return false;
		}
		if (cmd == seg_lc) {
			if (seg_idx >= mo->nsegs) {
				return false;
			}
			if (seg_name_matches (mo->segs[seg_idx].segname, name)) {
				/* ensure maxprot is not more restrictive than the new
				 * initprot, or the kernel will silently cap our request. */
				ut32 new_initprot = (ut32)(perms & 7);
				ut32 new_maxprot = mo->segs[seg_idx].maxprot | new_initprot;
				ut8 le_max[4], le_init[4];
				r_write_ble32 (le_max, new_maxprot, mo->big_endian);
				r_write_ble32 (le_init, new_initprot, mo->big_endian);
				ut64 maxprot_off = off + r_offsetof (struct MACH0_(segment_command), maxprot);
				ut64 initprot_off = off + r_offsetof (struct MACH0_(segment_command), initprot);
				r_buf_write_at (bf->buf, maxprot_off, le_max, 4);
				r_buf_write_at (bf->buf, initprot_off, le_init, 4);
				mo->segs[seg_idx].initprot = new_initprot;
				mo->segs[seg_idx].maxprot = new_maxprot;
				R_LOG_DEBUG ("wv4 0x%x @ 0x%"PFMT64x" (initprot)", new_initprot, initprot_off);
				return true;
			}
			seg_idx++;
		}
		off += cmdsize;
	}
	return false;
}

#if !R_BIN_MACH064
RBinWrite r_bin_write_mach0 = {
#if 0
	.scn_resize = &scn_resize,
	.scn_perms = &scn_perms,
	.rpath_del = &rpath_del,
	.entry = &chentry,
#endif
	.seg_perms = &seg_perms,
	.addlib = &addlib,
	.lib_weak = &lib_weak,
	.symbol_weak = &symbol_weak,
};
#endif
