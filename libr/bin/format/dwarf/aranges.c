/* radare - LGPL - Copyright 2012-2025 - pancake, Fedor Sakharov */

#include "dwarf.h"

#define READ_BUF(x, y) \
	if (idx + sizeof (y) >= len) { \
		return false; \
	} \
	(x) = *(y *)buf; \
	idx += sizeof (y); \
	buf += sizeof (y)

#define READ_BUF64(x) \
	if (idx + sizeof (ut64) >= len) { \
		return false; \
	} \
	(x) = r_read_ble64 (buf, be); \
	idx += sizeof (ut64); \
	buf += sizeof (ut64)
#define READ_BUF32(x) \
	if (idx + sizeof (ut32) >= len) { \
		return false; \
	} \
	(x) = r_read_ble32 (buf, be); \
	idx += sizeof (ut32); \
	buf += sizeof (ut32)
#define READ_BUF16(x) \
	if (idx + sizeof (ut16) >= len) { \
		return false; \
	} \
	(x) = r_read_ble16 (buf, be); \
	idx += sizeof (ut16); \
	buf += sizeof (ut16)

static int parse_aranges_raw(RBin *bin, const ut8 *obuf, int len, RStrBuf *sb) {
	bool be = r_bin_is_big_endian (bin);
	ut32 length, offset;
	ut16 version;
	ut32 debug_info_offset;
	ut8 address_size, segment_size;
	const ut8 *buf = obuf;
	int idx = 0;

	if (!buf || len < 4) {
		return false;
	}

	READ_BUF32 (length);
	if (sb) {
		r_strbuf_append (sb, "parse_aranges\n");
		r_strbuf_appendf (sb, "length 0x%x\n", length);
	}

	if (idx + 12 >= len) {
		return false;
	}
	READ_BUF16 (version);
	if (sb) {
		r_strbuf_appendf (sb, "Version %d\n", version);
	}
	READ_BUF32 (debug_info_offset);
	if (sb) {
		r_strbuf_appendf (sb, "Debug info offset %d\n", debug_info_offset);
	}
	READ_BUF (address_size, ut8);
	if (sb) {
		r_strbuf_appendf (sb, "address size %d\n", (int)address_size);
	}
	READ_BUF (segment_size, ut8);
	if (sb) {
		r_strbuf_appendf (sb, "segment size %d\n", (int)segment_size);
	}
	offset = segment_size + address_size * 2;
	if (offset) {
		ut64 n = (offset - (idx % offset)) % offset;
		if ((idx + n) >= len) {
			return false;
		}
		buf += n;
		idx += n;
	}

	while ((buf - obuf) < len) {
		ut64 adr, length;
		if ((idx + 8) >= len) {
			break;
		}
		READ_BUF64 (adr);
		READ_BUF64 (length);
		if (sb) {
			r_strbuf_appendf (sb, "length 0x%" PFMT64x " address 0x%" PFMT64x "\n", length, adr);
		}
	}

	return 0;
}

R_API R_OWNED char *r_bin_dwarf_print_aranges(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin, NULL);
	RBinSection *section = dwarf_get_section (bf, DWARF_SN_ARANGES);
	if (!section) {
		return NULL;
	}
	const ut8 *buf = dwarf_get_section_bytes (bf, section);
	if (!buf || section->bytes.len < 1 || section->bytes.len > ST32_MAX) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new (NULL);
	parse_aranges_raw (bf->rbin, buf, section->bytes.len, sb);
	return r_strbuf_drain (sb);
}
