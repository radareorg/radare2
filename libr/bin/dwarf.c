/* radare - LGPL - Copyright 2012 - pancake */

#define D0 if(0)
#define D1 if(1)

#include <r_bin.h>
#include <r_bin_dwarf.h>

#define STANDARD_OPERAND_COUNT_DWARF2 9
#define STANDARD_OPERAND_COUNT_DWARF3 12
#define R_BIN_DWARF_INFO 1

#define READ(x,y) *((y *)x); x += sizeof (y)

R_API RList *r_bin_dwarf_parse_line(RBin *a);

// XXX wtf
R_API RList *r_bin_dwarf_parse(RBin *bin, int type) {
	return r_bin_dwarf_parse_line (bin);
}

#if 0
R_API RBinDwarfRow *r_bin_dwarf_line_new (ut64 addr, const char *file, int line) {
	RBinDwarfRow *bdl = R_NEW (RBinDwarfRow);
	bdl->address = addr;
	bdl->file = strdup (file); // use unique pointer
	bdl->line = line;
	bdl->column = 0;
	return bdl;
}
#endif

struct Line_Table_File_Entry_s {
	ut8 *lte_filename;
	ut32 lte_directory_index;
	ut32 lte_last_modification_time;
	ut32 lte_length_of_file;
};

R_API int r_bin_dwarf_parse_info_raw(const ut8 *obuf) {
	int i;
	const char *buf = (const char *)obuf;
	ut32 len, version, addr_size, abbr_offset;

	len = READ (buf, ut32);
	version = READ (buf, ut16);
	abbr_offset = READ (buf, ut32);
	addr_size = READ (buf, ut8);
	//nextcu = READ (buf, ut8);

	D0 {
		eprintf ("Compile unit: 0x%x\n", len);
		eprintf ("Version: %d\n", version);
		eprintf ("abbr offset: 0x%x\n", abbr_offset);
		eprintf ("addr size: 0x%x\n", addr_size);
		//eprintf ("nextcu: 0x%x\n", nextcu);

		for (i=0;i<256; i++) { eprintf ("%02x ", buf[i]); } eprintf("\n");

		eprintf ("Compile Unit: length = 0x000000f1  version = 0x0002\n");
		eprintf ("abbr_offset = 0x00000000  addr_size = 0x04  (next CU at 0x000000f5)\n");
	}
	return R_TRUE;
}

static const ut8 *r_bin_dwarf_parse_header (const ut8 *buf, RBinDwarfInfoHeader *hdr) {
	int count, i;
	hdr->total_length = READ (buf, ut32);
	hdr->version = READ (buf, ut16);
	hdr->plen = READ (buf, ut32); // end of payload is buf + plen
	hdr->mininstlen = READ (buf, ut8);
	hdr->is_stmt = READ (buf, ut8);
	hdr->line_base = READ (buf, char);
	hdr->line_range = READ (buf, ut8);
	hdr->opcode_base = READ (buf, ut8);

	D0 {
		eprintf ("DWARF LINE HEADER\n");
		eprintf ("  payload length: %d\n", hdr->total_length);
		eprintf ("  version: %d\n", hdr->version);
		eprintf ("  plen: %d\n", hdr->plen);
		eprintf ("  mininstlen: %d\n", hdr->mininstlen);
		eprintf ("  is_stmt: %d\n", hdr->is_stmt);
		eprintf ("  line_base: %d\n", hdr->line_base);
		eprintf ("  line_range: %d\n", hdr->line_range);
		eprintf ("  opcode_base: %d\n", hdr->opcode_base);
	}

	count = hdr->opcode_base - 1;
	D0 eprintf ("-opcode arguments:\n");
	/* parse opcode lengths table */
	for (i = 0; i<count; i++) {
		hdr->oplentable[i] = READ (buf, ut8);
		D0 eprintf (" op %d %d\n", i, hdr->oplentable[i]);
	}
	/* parse include dirs */
	while (*buf++) {
		int len = strlen ((const char*)buf);
		if (!len) {
			buf += 3;
			break;
		}
		D0 eprintf ("INCLUDEDIR (%s)\n", buf);
		buf += len+3;
	}
	/* parse filenames */
#if 0
	- null-terminated string
		- uleb128 with directory index
		- leb128 with last modification time
		- uleb128 with length of file
#endif
	i = 0;
	while (*buf) {
		const char *filename = (const char *)buf;
		ut32 didx, flen;
		int tmod;
		int len = strlen (filename);
		if (!len) {
			buf++;
			break;
		}
		buf += len+1;
		buf = r_uleb128 (buf, &didx);
		buf = r_leb128 (buf, &tmod);
		buf = r_uleb128 (buf, &flen);
		D0 eprintf ("FILE (%s)\n", filename);
		hdr->file[i++] = filename;
		D0 eprintf ("| dir idx %d\n", didx);
		D0 eprintf ("| lastmod %d\n", tmod);
		D0 eprintf ("| filelen %d\n", flen);
	}
	hdr->file[i] = 0;
	return buf;
}

R_API int r_bin_dwarf_parse_line_raw(const ut8 *obuf, RList *list) {
	RBinDwarfInfoHeader hdr;
	ut64 address = 0;
	int line = 1;
	const ut8 *buf_end, *buf, *code;
	int type;
	ut8 opcode;
	const char *types[] = {
		"dw_extended_opcode", "extended",
		"discard", "standard", "special"
	};

	buf = r_bin_dwarf_parse_header (obuf, &hdr);
	code = obuf+hdr.total_length;

	buf_end = obuf + hdr.total_length;
	while (buf < buf_end) {
		opcode = *buf++;
		if (opcode == 0) {
			type = 0; // extended!
		} else
		if (opcode < hdr.opcode_base) {
			if (opcode == DW_EXTENDED_OPCODE)
				type = LOP_EXTENDED;
			else type = LOP_STANDARD;
		} else type = LOP_SPECIAL;

		D0	printf ("------ 0x%x type %d (%s) opcode %d\n",
				(int)(size_t)(buf-obuf-1), type, types[type], opcode);
		switch (type) {
		case DW_EXTENDED_OPCODE: // 0
			{ // extended (type=2)
			ut8 oplen = *buf++;
			opcode = *buf++;
			D0 eprintf ("Next opcode %d is extended of size %d\n", opcode, oplen);
			switch (opcode) {
			case DW_LNE_set_discriminator:
			case DW_LNE_define_file:
				eprintf ("extended opcode %d not supported\n", opcode);
				break;
			case DW_LNE_end_sequence:
				eprintf ("end_sequence\n");
				break;
			case DW_LNE_set_address:
				if (oplen == 9) {
					address = READ (buf, ut64);
				} else {
					address = (ut32) READ (buf, ut32);
				}
				D0 eprintf ("set address\n");
				//eprintf ("0x%08"PFMT64x"\t%s:%d\n", address, hdr.file[0], line);
				if (list) {
					RBinDwarfRow *row = R_NEW (RBinDwarfRow);
					r_bin_dwarf_line_new (row, address, hdr.file[0], line);
					r_list_append (list, row);
				}
				break;
			default:
				eprintf ("Invalid extended opcode %d in dwarf's debug_line\n", opcode);
				break;
			}
			} break;
		case LOP_STANDARD: // 1?
			switch (opcode) {
			case DW_LNS_advance_pc:
				{
				int didx;
				//buf = r_leb128 (buf, &didx);
				didx = *buf++;
				D0 eprintf ("advance pc %d\n", didx);
				address += didx;
				}
				break;
			default:
				eprintf ("XXX : unimplemented dwarf opcode '%02x'\n", opcode);
				break;
			}
			break;
		case LOP_SPECIAL: // 4
			{
				/*
				   int adjop = opcode - opcode_base
				   int opadv = adjop / line_range
				   new_address = address + mininstlen * (opidx + opadvance) % maxopsperinst
				   new_opidx = (op_idx + opadv) % maopsperinst;
				 */
				int maxopsperinst = 1; //
				int opidx = 0;
				int adjop = opcode - hdr.opcode_base;
				int opadv = adjop / hdr.line_range;
				address += hdr.mininstlen * (opidx + opadv) % maxopsperinst;
				int new_opidx = (opidx + opadv) % maxopsperinst;

				int addr = (opcode / hdr.line_range) * hdr.mininstlen-1;
				int delt = hdr.line_base + (adjop % hdr.line_range);

				address += addr;
				line += delt;
				//eprintf ("0x%08"PFMT64x"\t%s:%d\n", address, hdr.file[0], line);
				if (list && hdr.file[0]) {
					RBinDwarfRow *row = R_NEW (RBinDwarfRow);
					r_bin_dwarf_line_new (row, address, hdr.file[0], line);
					r_list_append (list, row);
				}
				D0 {
					eprintf ("LINE += %d  ADDR += %d\n", delt, addr);
					D0	eprintf ("opcode=%d ADJOP %d opadv=%d opidx=%d\n",
							opcode, adjop, opadv, new_opidx);
				}
			} 
			break;
		case LOP_DISCARD: // 2
			eprintf ("DISCARD!\n");
			break;
		}
	}
#if 0
	case LOP_STANDARD:
		eprintf ("standard opcode\n");
		switch (opcode) {
		case DW_LNS_copy:
			break;
		case DW_LNS_advance_pc:

			break;
		case DW_LNS_advance_line:
			st32 *b = ptr; // little endian foo
			line = line + *b;
			break;
		case DW_LNS_set_file:
			ut32 *b = ptr; // little endian foo
			file = *b;
			break;
		case DW_LNS_set_column:
			ut32 *b = ptr; // little endian foo
			column = *b;
			break;
		case DW_LNS_negate_stmt:
			is_stmt = !is_stmt;
			break;
		case DW_LNS_set_basic_block:
			bb = 1;
			break;
		case DW_LNS_const_add_pc:
			opcode = MAX_LINE_OP_CODE - opcode_base;
			address = address + mininslen * (opcode / line_range);
			break;
		case DW_LNS_fixed_advance_pc:
			ut16 *w = ptr;
			opcode = MAX_LINE_OP_CODE - opcode_base;
			address = address + mininslen * (opcode / line_range);
			break;
		case DW_LNS_set_prologue_end:
			prologue_end = 1;
			break;
		case DW_LNS_set_prologue_begin:
			epilogue_begin = 1;
			break;
		case DW_LNS_set_isa:
			break;
		}
		break;
	}
#endif
	return R_TRUE;
}

RBinSection *getsection(RBin *a, const char *sn) {
	RListIter *iter;
	RBinSection *section;

	if (a->cur.o->sections) {
		r_list_foreach (a->cur.o->sections, iter, section) {
			if (strstr (section->name, sn))
				return section;
		}
	}
	return NULL;
}

R_API int r_bin_dwarf_parse_info(RBin *a) {
	ut8 *buf;
	int len, ret;
	RBinSection *section = getsection (a, "debug_info");
	if (section) {
		len = section->size;
		buf = malloc (len);
		r_buf_read_at (a->cur.buf, section->offset, buf, len);
		ret = r_bin_dwarf_parse_info_raw (buf);
		free (buf);
		return ret;
	}
	return R_FALSE;
}

R_API RList *r_bin_dwarf_parse_line(RBin *a) {
	ut8 *buf;
	int len;
	RBinSection *section = getsection (a, "debug_line");
	if (section) {
		RList *list = r_list_new ();
		len = section->size;
		buf = malloc (len);
		r_buf_read_at (a->cur.buf, section->offset, buf, len);
		r_bin_dwarf_parse_line_raw (buf, list);
		free (buf);
		return list;
	}
	return NULL;
}
