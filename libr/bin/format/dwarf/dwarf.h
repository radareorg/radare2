/* radare - LGPL - Copyright 2012-2025 - pancake, Fedor Sakharov */

#ifndef R2_BIN_DWARF_PRIVATE_H
#define R2_BIN_DWARF_PRIVATE_H

#include <r_bin.h>
#include <r_bin_dwarf.h>

#define READ8(buf) \
	(((buf) + sizeof (ut8) <= buf_end)? ((ut8 *)buf)[0]: 0); \
	(buf) += sizeof (ut8)
#define READ16(buf) \
	(((buf) + sizeof (ut16) <= buf_end)? r_read_ble16 (buf, be): 0); \
	(buf) += sizeof (ut16)
#define READ32(buf) \
	(((buf) + sizeof (ut32) <= buf_end)? r_read_ble32 (buf, be): 0); \
	(buf) += sizeof (ut32)
#define READ64(buf) \
	(((buf) + sizeof (ut64) <= buf_end)? r_read_ble64 (buf, be): 0); \
	(buf) += sizeof (ut64)

enum {
	DWARF_SN_ABBREV,
	DWARF_SN_INFO,
	DWARF_SN_FRAME,
	DWARF_SN_LINE,
	DWARF_SN_LOC,
	DWARF_SN_LOCLISTS,
	DWARF_SN_STR,
	DWARF_SN_LINE_STR,
	DWARF_SN_STR_OFFSETS,
	DWARF_SN_ADDR,
	DWARF_SN_RANGES,
	DWARF_SN_ARANGES,
	DWARF_SN_PUBNAMES,
	DWARF_SN_PUBTYPES,

	DWARF_SN_MAX
};

static inline ut64 dwarf_read_address(RBin *bin, size_t size, const ut8 **buf, const ut8 *buf_end) {
	const bool be = r_bin_is_big_endian (bin);
	ut64 result;
	switch (size) {
	case 2: result = READ16 (*buf); break;
	case 4: result = READ32 (*buf); break;
	case 8: result = READ64 (*buf); break;
	default:
		result = 0;
		*buf += size;
		R_LOG_WARN ("Unsupported dwarf address size: %u", (int)size);
	}
	return result;
}

typedef enum {
	DWARF_INDEX_RESOLUTION_OK,
	DWARF_INDEX_RESOLUTION_UNAVAILABLE,
	DWARF_INDEX_RESOLUTION_MALFORMED,
} DwarfIndexResolution;

typedef struct {
	size_t base; // the offset table
	size_t lists; // the first list
	size_t end;
	ut32 count;
	ut8 address_size;
	ut8 offset_size;
} DwarfLoclistsContribution;

R_IPI RBinSection *dwarf_get_section(RBinFile *bf, int sn);
R_IPI const ut8 *dwarf_get_section_bytes(RBinFile *bf, RBinSection *section);
R_IPI const char *dwarf_get_section_string(RBinFile *bf, RBinSection *section, size_t offset);
R_IPI const ut8 *dwarf_read_index(const ut8 *buf, const ut8 *buf_end, bool be, ut8 size, ut64 *value);
R_IPI const ut8 *dwarf_read_uleb_index(const ut8 *buf, const ut8 *buf_end, ut64 *value);
R_IPI bool dwarf_relocate_address(RBinFile *bf, ut64 address, ut64 *relocated);
R_IPI bool dwarf_is_zero_padding(const ut8 *buf, const ut8 *buf_end);
R_IPI bool dwarf_is_breaked(RBin *bin);
R_IPI void dwarf_line_files_add(RList *files, HtPP *seen, const char *file);
R_IPI void dwarf_print_comp_unit(const RBinDwarfCompUnit *unit, RStrBuf *sb);
R_IPI bool dwarf_index_entry_offset(ut64 base, ut64 index, ut8 entry_size, size_t section_size, size_t *entry_offset);
R_IPI bool dwarf_index_contribution_end(const ut8 *data, size_t size, bool be, ut64 base, bool is_64bit, bool is_address_table, ut8 address_size, size_t *contribution_end);
R_IPI bool dwarf_address_base(const ut8 *data, size_t section_size, bool be, ut64 base, ut8 address_size, size_t *end);
R_IPI bool dwarf_comp_unit_index_bases(const RBinDwarfCompUnit *unit, bool need_str, bool need_addr, bool need_loclists, ut64 *str_base, bool *has_str_base, ut64 *addr_base, bool *has_addr_base, ut64 *loclists_base, bool *has_loclists_base);
R_IPI bool dwarf_loclists_contribution_base(const ut8 *sec, size_t len, bool be, ut64 base, DwarfLoclistsContribution *c);
R_IPI DwarfIndexResolution dwarf_resolve_comp_unit_indexes(RBinFile *bf, RBinDwarfCompUnit *unit);

#endif
