/* radare - LGPL - Copyright 2012 pancake<nopcode.org> */

#include <r_bin.h>
#include <r_bin_dwarf.h>

#define STANDARD_OPERAND_COUNT_DWARF2 9
#define STANDARD_OPERAND_COUNT_DWARF3 12
#define R_BIN_DWARF_INFO 1

#define READ(x,y) *((y *)x); x += sizeof (y)

R_API int r_bin_dwarf_parse_line(RBin *a);

R_API int r_bin_dwarf_parse(RBin *bin, int type) {
	//RBinSection *s = NULL;
	ut8 *p;
	// find debug_line section //
	r_bin_dwarf_parse_line (p);
}

struct Line_Table_File_Entry_s {
	ut8 *lte_filename;
	ut32 lte_directory_index;
	ut32 lte_last_modification_time;
	ut32 lte_length_of_file;
};

static const ut8 *r_bin_dwarf_info(const ut8 *buf, RBinDwarfInfoHeader *hdr) {
	eprintf ("PARSE INFO!\n");
	return buf;
}

R_API int r_bin_dwarf_parse_info_raw(const ut8 *obuf) {
int i;
	const char *buf = obuf;
	ut32 len, version, addr_size, abbr_offset, nextcu;

	len = READ (buf, ut32);
	version = READ (buf, ut16);
	abbr_offset = READ (buf, ut32);
	addr_size = READ (buf, ut8);
	//nextcu = READ (buf, ut8);

	eprintf ("Compile unit: 0x%x\n", len);
	eprintf ("Version: %d\n", version);
	eprintf ("abbr offset: 0x%x\n", abbr_offset);
	eprintf ("addr size: 0x%x\n", addr_size);
	//eprintf ("nextcu: 0x%x\n", nextcu);

for (i=0;i<256; i++) {
	eprintf ("%02x ", buf[i]);
}
eprintf("\n");

eprintf ("Compile Unit: length = 0x000000f1  version = 0x0002\n");
eprintf ("abbr_offset = 0x00000000  addr_size = 0x04  (next CU at 0x000000f5)\n");
#if 0
0x00004197 |f100 0000 0200 0000 0000 0401 0100 0000| ................               
0x000041a7 |0125 0000 0030 0000 00fa 1d00 004d 1f00| .%...0.......M..               
0x000041b7 |0000 0000 0002 015a 0000 0001 013d 0000| .......Z.....=..               
0x000041c7 |00fa 1d00 001b 1e00 0000 0000 0003 0405| ................   
#endif
	eprintf ("PARSE INFO\n");
}

static const ut8 *r_bin_dwarf_parse_header (const ut8 *buf, RBinDwarfInfoHeader *hdr) {
	int count, i;
	hdr->len = READ (buf, ut32);
	hdr->version = READ (buf, ut16);
	hdr->plen = READ (buf, ut32);
	hdr->minislen = READ (buf, ut8);
	hdr->is_stmt = READ (buf, ut8);
	hdr->line_base = READ (buf, char);
	hdr->line_range = READ (buf, ut8);
	hdr->opcode_base = READ (buf, ut8);

	printf ("DWARF LINE HEADER\n");
	printf ("  payload length: %d\n", hdr->len);
	printf ("  version: %d\n", hdr->version);
	printf ("  plen: %d\n", hdr->plen);
	printf ("  minislen: %d\n", hdr->minislen);
	printf ("  is_stmt: %d\n", hdr->is_stmt);
	printf ("  line_base: %d\n", hdr->line_base);
	printf ("  line_range: %d\n", hdr->line_range);
	printf ("  opcode_base: %d\n", hdr->opcode_base);

	count = hdr->opcode_base - 1;
	printf ("-opcode arguments:\n");
	for (i = 0; i<count; i++) {
		ut8 n = READ (buf, ut8);
		printf (" op %d %d\n", i, n);
		hdr->oplentable[i] = n;
	}
	return buf;
}

R_API int r_bin_dwarf_parse_line_raw(const ut8 *obuf) {
	RBinDwarfInfoHeader hdr;
	const char *buf, *code;
	int type, opi, i;
	int opcount = 12; // TODO must autodetect if 9 or 12 coz versioning is crap
	ut8 opcode;

	buf = r_bin_dwarf_parse_header (obuf, &hdr);
	code = obuf+hdr.len;

	// parse filenames
	while (*buf++ == 0) {
		int len = strlen (buf);
		if (!len) {
			buf += 3;
			break;
		}
		eprintf ("FILE (%s)\n", buf);
		buf += len+3;
	}
#if 0
	for (i=0;i<20;i++) {
		printf ("%02x %c\n", buf[i], buf[i]);
	}
file_names[  1]    0 0x00000000 0x00000000 backtest.c
0x0000002b: DW_LNE_set_address( 0x0000000100000cf0 )
0x00000036: address += 0,  line += 6
            0x0000000100000cf0      1      7      0 is_stmt
#endif
// parse opcodes

for (opi= 0; opi<8;opi++) {
	opcode = *buf++;
	if (opcode < hdr.opcode_base) {
		if (opcode == DW_EXTENDED_OPCODE)
			type = LOP_EXTENDED;
		else if (opcount >= hdr.opcode_base)
		//else if ((pf_std_op_count+1) >= base)
			type = LOP_STANDARD;
		else type = LOP_DISCARD;
	} else type = LOP_SPECIAL;

printf ("type %d opcode %d\n", type, opcode);
	switch (type) {
	case LOP_DISCARD:
		{ int i;
		ut32 n = 0;
		int opcnt = hdr.oplentable[opcode];

		for (i=0; i<opcnt; i++) {
			buf = r_uleb128 (buf, &n);
		}
eprintf ("num %d\n", n);
		}
#if 0
		switch (opcode) {
		case DW_LNS_copy:
			eprintf ("COPY\n");
READ(buf, ut16);
			break;
		case DW_LNE_set_address:
			{
				ut32 addr = READ (buf, ut32);
				eprintf ("set address 0x%08x\n", addr);
				buf = code;
				for (i=0;i<10;i++) {
					printf ("%d %c\n", buf[i], buf[i]);
				}
			}
			break;
		default:
			eprintf ("UNKNOWN %d\n", opcode);
//buf = code;
		}
#if 0
		int i, opcnt = oplentable[opcode];
			// discard operands
		for (i=0; i<opcnt; i++) {
			//decode_leb128_uword;
		}
#endif
#endif
		break;
	case LOP_SPECIAL:
eprintf ("special opcode\n");
#if 0
buf += 2;
	for (i=0;i<20;i++) {
		printf ("%02x %c\n", buf[i], buf[i]);
	}
		opcode = opcode - hdr.opcode_base;
eprintf ("--> %d\n", opcode);
{
	// hardcoded set_lie
	ut32 a = READ (buf, ut32);
	ut32 l = READ (buf, ut32);
	eprintf ("addr += %d  line += %d\n", a, l);
}
//		address = address+ mininslen * (opcode / line_range);
//		line = line + line_base + opcode % line_range;
//		bb = 0;
#endif
		break;
	case LOP_STANDARD:
eprintf ("standard opcode\n");
#if 0
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
#endif
	case LOP_EXTENDED:
		{
			int inslen = READ (buf, int);
			ut8 ext_opcode = *buf++;
			printf ("ext op %d\n", ext_opcode);
			switch (ext_opcode) {
			case 1: // end seq
				break;
			case 2: // set addr
				{ ut32 addr = READ (buf, ut32);
				eprintf ("set address 0x%08x\n", addr);
}
				break;
			case 3: // define file
				break;
			case 4: // set discriminator
				break;
			default:
				eprintf ("Invalid extended opcode %d in dwarf's debug_line\n", ext_opcode);
				break;
			}
		}
		// TODO
		break;
	}
}
	return R_TRUE;
}

RBinSection *getsection(RBin *a, const char *sn) {
	RListIter *iter;
	RBinSection *section;

	if (a->curarch.sections) {
		r_list_foreach (a->curarch.sections, iter, section) {
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
		r_buf_read_at (a->curarch.buf, section->offset, buf, len);
		ret = r_bin_dwarf_parse_info_raw (buf);
		free (buf);
		return ret;
	}
	return R_FALSE;
}

R_API int r_bin_dwarf_parse_line(RBin *a) {
	ut8 *buf;
	int len, ret;
	RBinSection *section = getsection (a, "debug_line");
	if (section) {
		len = section->size;
		buf = malloc (len);
		r_buf_read_at (a->curarch.buf, section->offset, buf, len);
		ret = r_bin_dwarf_parse_line_raw (buf);
		free (buf);
		return ret;
	}
	return R_FALSE;
}
