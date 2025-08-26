/* radare - Copyright 2025 - pancake */

#define R_LOG_ORIGIN "writedwarf"

#include <r_core.h>

typedef struct {
	ut64 addr;
	char *symbol;
} SymEntry;

typedef struct {
	ut64 addr;
	char *file;
	int line;
} LineEntry;

// Macros for writing to RBuffer (little-endian)
#define B(x,y) r_buf_append_bytes (buf, (const ut8*)(x), (y))
#define U8(x) do { ut8 _v = (ut8)(x); r_buf_append_bytes (buf, &_v, 1); } while (0)
#define U16(x) r_buf_append_ut16 (buf, (ut16)(x))
#define U32(x) r_buf_append_ut32 (buf, (ut32)(x))
#define U64(x) do { ut64 _vv = (ut64)(x); r_buf_append_ut32 (buf, (ut32)_vv); r_buf_append_ut32 (buf, (ut32)(_vv >> 32)); } while (0)
#define Z(n) r_buf_append_nbytes (buf, (n))
#define W(off, data, len) r_buf_write_at (buf, (off), (const ut8*)(data), (len))


// Create a Mach-O 64-bit object with minimal DWARF v2 debug info
RBuffer *create_macho_with_dwarf(RList *lines, RList *symbols) {
	RBuffer *buf = r_buf_new ();
	if (!buf) {
		return NULL;
	}

	// Mach-O 64-bit Header (mach_header_64)
	U32(0xFEEDFACF);                // magic MH_MAGIC_64 [oai_citation:0‡mikeash.com](https://www.mikeash.com/pyblog/friday-qa-2012-11-30-lets-build-a-mach-o-executable.html#:~:text=%2F,NXSwapInt%28MH_MAGIC_64%29)
	U32(0x01000007);                // cputype (CPU_TYPE_X86_64 | CPU_ARCH_ABI64)
	U32(0x80000003);                // cpusubtype (CPU_SUBTYPE_X86_64_ALL | CPU_SUBTYPE_LIB64)
	U32(0x1);                       // filetype (MH_OBJECT)
	U32(3);                         // ncmds = 3 (two LC_SEGMENT_64 + one LC_SYMTAB)
	U32(152 + 312 + 24);            // sizeofcmds = 488 bytes (sum of all load commands)
	U32(0x2000);                    // flags (MH_SUBSECTIONS_VIA_SYMBOLS)
	U32(0);                        // reserved (unused in 64-bit header)

	// Load Command 1: __TEXT segment (contains __text section)
	U32(0x19);                     // LC_SEGMENT_64
	U32(152);                      // cmdsize (72 bytes cmd + 80 bytes section)
	B("__TEXT", 6); Z(10);         // segname[16] = "__TEXT"
	U64(0x0);                      // vmaddr
	U64(0x1);                      // vmsize (segment size in memory, 1 byte for code)
	U64(0x210);                    // fileoff = 0x210 (528) where __text section starts in file
	U64(0x1);                      // filesize = 1 (one byte of section data in file)
	U32(0x05);                     // maxprot = VM_PROT_READ | VM_PROT_EXECUTE
	U32(0x05);                     // initprot = VM_PROT_READ | VM_PROT_EXECUTE
	U32(1);                        // nsects = 1
	U32(0);                        // flags (none)
				       // Section 1: __text
	B("__text", 6); Z(10);         // sectname[16] = "__text"
	B("__TEXT", 6); Z(10);         // segname[16]  = "__TEXT"
	U64(0x0);                      // addr (0 since not linked)
	U64(0x1);                      // size = 1 byte
	U32(0x210);                    // offset = 528 (file offset of section)
	U32(4);                        // align = 2^4 (16-byte alignment)
	U32(0x0);                      // reloff (no relocations)
	U32(0x0);                      // nreloc
	U32(0x80000400);               // flags = S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
	U32(0x0);                      // reserved1
	U32(0x0);                      // reserved2
	U32(0x0);                      // reserved3

	// Load Command 2: __DWARF segment (contains 3 debug sections)
	U32(0x19);                     // LC_SEGMENT_64
	U32(312);                      // cmdsize (72 + 3*80)
	B("__DWARF", 7); Z(9);         // segname[16] = "__DWARF"
	U64(0x0);                      // vmaddr
	ut64 dwarf_vmsize_off = r_buf_size (buf);
	U64(0x0);                      // vmsize (placeholder, to patch later)
	U64(0x211);                    // fileoff = 0x211 (529) where first debug section starts
	ut64 dwarf_filesz_off = r_buf_size (buf);
	U64(0x0);                      // filesize (placeholder, to patch later)
	U32(0x0);                      // maxprot = VM_PROT_NONE (debug section not loaded into memory)
	U32(0x0);                      // initprot = VM_PROT_NONE
	U32(3);                        // nsects = 3
	U32(0x0);                      // flags (none)
				       // Section 2: __debug_info
	B("__debug_info", 12); Z(4);   // sectname[16] = "__debug_info"
	B("__DWARF", 7); Z(9);         // segname[16]  = "__DWARF"
	U64(0x0);                      // addr (0 within __DWARF segment)
	ut64 debug_info_size_off = r_buf_size (buf);
	U64(0x0);                      // size (placeholder, to patch with .debug_info length)
	U32(0x211);                    // offset = 529 (file offset of .debug_info)
	U32(0);                        // align = 2^0 (1-byte alignment)
	U32(0x0);                      // reloff
	U32(0x0);                      // nreloc
	U32(0x0);                      // flags = S_REGULAR | S_ATTR_DEBUG [oai_citation:1‡wiki.dwarfstd.org](https://wiki.dwarfstd.org/Best_Practices.md#:~:text=section%20name%20dwarf%20name%20%E2%80%9C__debug_abbrev%E2%80%9D,debug_macinfo%E2%80%9D)
	U32(0x0);                      // reserved1
	U32(0x0);                      // reserved2
	U32(0x0);                      // reserved3
				       // Section 3: __debug_abbrev
	B("__debug_abbrev", 14); Z(2); // sectname[16] = "__debug_abbrev"
	B("__DWARF", 7); Z(9);         // segname[16]  = "__DWARF"
	ut64 abbrev_addr_off = r_buf_size (buf);
	U64(0x0);                      // addr (placeholder, to patch: start address in segment)
	ut64 debug_abbrev_size_off = r_buf_size (buf);
	U64(0x0);                      // size (placeholder, to patch with .debug_abbrev length)
	ut64 debug_abbrev_offset_off = r_buf_size (buf);
	U32(0x0);                      // offset (placeholder, to patch with file offset of .debug_abbrev)
	U32(0);                        // align = 1
	U32(0x0);                      // reloff
	U32(0x0);                      // nreloc
	U32(0x0);                      // flags = S_REGULAR | S_ATTR_DEBUG
	U32(0x0);                      // reserved1
	U32(0x0);                      // reserved2
	U32(0x0);                      // reserved3
				       // Section 4: __debug_line
	B("__debug_line", 12); Z(4);     // sectname[16] = "__debug_line"
	B("__DWARF", 7); Z(9);           // segname[16]  = "__DWARF"
	ut64 line_addr_off = r_buf_size (buf);
	U64(0x0);                      // addr (placeholder, to patch: start address in segment)
	ut64 debug_line_size_off = r_buf_size (buf);
	U64(0x0);                      // size (placeholder, to patch with .debug_line length)
	ut64 debug_line_offset_off = r_buf_size (buf);
	U32(0x0);                      // offset (placeholder, to patch with file offset of .debug_line)
	U32(0);                        // align = 1
	U32(0x0);                      // reloff
	U32(0x0);                      // nreloc
	U32(0x0);                      // flags = S_REGULAR | S_ATTR_DEBUG
	U32(0x0);                      // reserved1
	U32(0x0);                      // reserved2
	U32(0x0);                      // reserved3

	// Load Command 3: Symtab (symbol table and string table)
	U32(0x02);                     // LC_SYMTAB
	U32(24);                       // cmdsize
	ut64 symoff_field_off = r_buf_size (buf);
	U32(0x0);                      // symoff (placeholder)
	ut64 nsyms_field_off = r_buf_size (buf);
	U32(0x0);                      // nsyms (placeholder)
	ut64 stroff_field_off = r_buf_size (buf);
	U32(0x0);                      // stroff (placeholder)
	ut64 strsize_field_off = r_buf_size (buf);
	U32(0x0);                      // strsize (placeholder)

	// Pad to align the first section’s file offset (528) as specified
	Z(8);  // pad from end of load commands (520) to 528

	// Section content: __text (code bytes)
	U8(0xC3);  // 0xC3 = RET instruction (our dummy function body)

	// Section content: .debug_info
	ut64 debug_info_start = r_buf_size (buf);
	// Write compilation unit header
	ut64 cu_length_off = r_buf_size (buf);
	if (cu_length_off == (ut64)-1) {
		return NULL;
	}
	U32(0);                         // unit_length (placeholder)
	U16(2);                         // DWARF version 2
	U32(0);                         // debug_abbrev_offset (0 for first CU)
	U8(8);                          // address_size = 8 bytes
					// Compile Unit DIE (DW_TAG_compile_unit) [oai_citation:2‡wiki.osdev.org](https://wiki.osdev.org/DWARF#:~:text=Number%20TAG%20,DW_AT_stmt_list%20%20%20%20DW_FORM_sec_offset)
	U8(0x01);                       // Abbrev code 1 (compile_unit)
					// DW_AT_language  (DW_FORM_data1)
	U8(0x0c);                       // e.g., DW_LANG_C99 (0x0C) [oai_citation:3‡wiki.osdev.org](https://wiki.osdev.org/DWARF#:~:text=,ANSI%20C99) [oai_citation:4‡dwarfstd.org](https://dwarfstd.org/languages.html#:~:text=Language%20Codes%20in%20DWARF%205,1%20%3B%20DW_LANG_PLI%2C%200x000f%2C%201)
					// DW_AT_name      (DW_FORM_string)
	B("main.c", 6); U8(0x00);       // Name of source file + NULL
					// DW_AT_comp_dir  (DW_FORM_string)
	B(".", 1); U8(0x00);           // Compilation directory "." + NULL
				       // DW_AT_low_pc    (DW_FORM_addr)
	U64(0x0);                      // low PC (0x0 in object file)
				       // DW_AT_high_pc   (DW_FORM_addr)
	U64(0x1);                      // high PC (end address of function range)
				       // DW_AT_stmt_list (DW_FORM_data4)
	U32(0x0);                      // offset in .debug_line (0 for this CU)
				       // Children DIEs: DW_TAG_subprogram entries for each symbol
	{
		RListIter *sym_it;
		SymEntry *sym;
		r_list_foreach (symbols, sym_it, sym) {
			// DW_TAG_subprogram (subprogram)
			U8(0x02);
			// DW_AT_name (DW_FORM_string)
			B(sym->symbol, strlen (sym->symbol));
			U8(0x00);
			// DW_AT_low_pc (DW_FORM_addr)
			U64(sym->addr);
			// DW_AT_high_pc (DW_FORM_addr)
			U64(sym->addr + 1);
		}
	}
	// End of children
	U8(0x00);

	// Patch the compile unit length
	ut64 cu_end = r_buf_size (buf);
	if (cu_end == (ut64)-1 || cu_length_off == (ut64)-1) {
		r_buf_free (buf);
		return NULL;
	}
	ut32 cu_length_val = (ut32)(cu_end - (cu_length_off + 4));
	W(cu_length_off, &cu_length_val, 4);  // write unit_length

	// Section content: .debug_abbrev (DWARF abbreviation table)
	ut64 debug_abbrev_start = r_buf_size(buf);
	// Abbreviation for DW_TAG_compile_unit (code 1) [oai_citation:5‡wiki.osdev.org](https://wiki.osdev.org/DWARF#:~:text=Number%20TAG%20,DW_AT_stmt_list%20%20%20%20DW_FORM_sec_offset)
	U8(0x01);                       // Abbrev code 1
	U8(0x11);                       // DW_TAG_compile_unit (0x11)
	U8(0x01);                       // has children (true)
					// Attribute specifications for compile_unit DIE:
	U8(0x13); U8(0x0b);             // DW_AT_language (0x13), DW_FORM_data1 (0x0b) [oai_citation:6‡wiki.osdev.org](https://wiki.osdev.org/DWARF#:~:text=DW_AT_producer%20%20%20%20,DW_AT_stmt_list%20%20%20%20DW_FORM_sec_offset)
	U8(0x03); U8(0x08);             // DW_AT_name     (0x03), DW_FORM_string  (0x08)
	U8(0x1b); U8(0x08);             // DW_AT_comp_dir (0x1b), DW_FORM_string  (0x08)
	U8(0x11); U8(0x01);             // DW_AT_low_pc   (0x11), DW_FORM_addr    (0x01)
	U8(0x12); U8(0x01);             // DW_AT_high_pc  (0x12), DW_FORM_addr    (0x01)
	U8(0x10); U8(0x06);             // DW_AT_stmt_list(0x10), DW_FORM_data4   (0x06) [oai_citation:7‡wiki.osdev.org](https://wiki.osdev.org/DWARF#:~:text=DW_AT_low_pc%20%20%20%20,DW_FORM%20value%3A%200)
	U8(0x00); U8(0x00);             // end of attribute list
					// Abbreviation for DW_TAG_subprogram (code 2)
	U8(0x02);                       // Abbrev code 2
	U8(0x2e);                       // DW_TAG_subprogram (0x2e)
	U8(0x00);                       // has children (false)
					// Attribute specifications for subprogram DIE:
	U8(0x03); U8(0x08);             // DW_AT_name    (0x03), DW_FORM_string (0x08)
	U8(0x11); U8(0x01);             // DW_AT_low_pc  (0x11), DW_FORM_addr   (0x01)
	U8(0x12); U8(0x01);             // DW_AT_high_pc (0x12), DW_FORM_addr   (0x01)
	U8(0x00); U8(0x00);             // end of attribute list
					// End of abbreviations
	U8(0x00);                       // abbreviation table terminator

	// Section content: .debug_line (DWARF line number program)
	ut64 debug_line_start = r_buf_size(buf);
	ut64 line_length_off = r_buf_size(buf);
	U32(0x0);                       // unit_length (placeholder)
	U16(2);                         // DWARF version 2
	ut64 header_length_off = r_buf_size(buf);
	U32(0x0);                       // header_length (placeholder)
					// Write .debug_line prologue fields [oai_citation:8‡wiki.osdev.org](https://wiki.osdev.org/DWARF#:~:text=Offset%3A%20%20%20%20,13)
	U8(1);                          // minimum_instruction_length
	U8(1);                          // default_is_stmt (true for line 1)
	U8((ut8)0xFB);                  // line_base = -5 (two’s complement 0xFB)
	U8(14);                         // line_range = 14
	U8(13);                         // opcode_base = 13
					// Standard opcode lengths (for opcodes 1 through 12)
	ut8 standard_opcode_lengths[12] = {0,1,1,1,1,0,0,0,1,0,0,1};
	{
		int i;
		for (i = 0; i < 12; i++) {
			U8(standard_opcode_lengths[i]);
		}
	}
	// Include directories table (empty, just terminator)
	RList *dirs = r_list_newf (free);
	RListIter *dir_it;
	char *dir;
	r_list_foreach (dirs, dir_it, dir) {
		B(dir, strlen (dir)); U8(0x00);
	}
	U8(0x00);  // end of directories
		   // File names table from unique files in lines list
	RList *files = r_list_newf (free);
	{
		RListIter *lit;
		LineEntry *le;
		r_list_foreach (lines, lit, le) {
			RListIter *fit;
			char *fn;
			int found = 0;
			r_list_foreach (files, fit, fn) {
				if (!strcmp (fn, le->file)) {
					found = 1;
					break;
				}
			}
			if (!found) {
				r_list_append (files, strdup (le->file));
			}
		}
	}
	RListIter *file_it;
	char *filename;
	r_list_foreach (files, file_it, filename) {
		B(filename, strlen (filename)); U8(0x00);  // file name + NULL
		U8(0x00);  // directory index
		U8(0x00);  // modification time
		U8(0x00);  // file length
	}
	U8(0x00);  // end of file names table
		   // Line number program instructions based on lines list
	{
		ut64 prev_line = 1;
		int prev_file_idx = 1;
		RListIter *lit;
		LineEntry *le;
		r_list_foreach (lines, lit, le) {
			// Extended DW_LNE_set_address
			U8(0x00); U8(1 + sizeof (ut64)); U8(0x02);
			U64(le->addr);
			// DW_LNS_set_file if changed
			int file_idx = 1;
			RListIter *fit;
			char *fname;
			r_list_foreach (files, fit, fname) {
				if (!strcmp (fname, le->file)) {
					break;
				}
				file_idx++;
			}
			if (file_idx != prev_file_idx) {
				U8(0x04);
				{ ut32 val = file_idx;
					do {
						ut8 byte = val & 0x7f; val >>= 7;
						if (val) {
							byte |= 0x80;
						}
						U8(byte);
					} while (val);
				}
				prev_file_idx = file_idx;
			}
			// DW_LNS_advance_line (SLEB128)
			U8(0x03);
			{
				int64_t delta = (int64_t)le->line - (int64_t)prev_line;
				ut64 val = (ut64)delta;
				int more = 1;
				while (more) {
					ut8 byte = val & 0x7f;
					val >>= 7;
					int32_t sign = (delta < 0) ? 1 : 0;
					if ((val == 0 && !sign) || ((int64_t)val == -1 && sign)) {
						more = 0;
					} else {
						byte |= 0x80;
					}
					U8(byte);
				}
				prev_line = le->line;
			}
			// DW_LNS_copy
			U8(0x01);
		}
	}
	// Extended DW_LNE_end_sequence
	U8(0x00); U8(0x01); U8(0x01);

	// Patch header_length in .debug_line prologue
	ut64 line_ops_start = r_buf_size(buf);
	ut32 header_length_val = (ut32)(line_ops_start - (header_length_off + 4));
	W(header_length_off, &header_length_val, 4);
	// Patch unit_length in .debug_line header
	ut64 line_end = r_buf_size (buf);
	ut32 line_length_val = (ut32)(line_end - (line_length_off + 4));
	W(line_length_off, &line_length_val, 4);

	// Free the RLists used for dirs and files
	r_list_free (files);
	r_list_free (dirs);

	// Now that all sections are written, patch section header values and load command sizes
	// Calculate section sizes
	ut64 debug_info_size = debug_abbrev_start - debug_info_start;
	ut64 debug_abbrev_size = debug_line_start - debug_abbrev_start;
	ut64 debug_line_size = line_end - debug_line_start;
	// Patch section sizes
	W(debug_info_size_off, &debug_info_size, 8);
	W(debug_abbrev_size_off, &debug_abbrev_size, 8);
	W(debug_line_size_off, &debug_line_size, 8);
	// Patch section file offsets
	ut32 debug_abbrev_fileoff = (ut32)debug_abbrev_start;
	ut32 debug_line_fileoff = (ut32)debug_line_start;
	W(debug_abbrev_offset_off, &debug_abbrev_fileoff, 4);
	W(debug_line_offset_off, &debug_line_fileoff, 4);
	// Patch section addresses within __DWARF segment (assign sequential addresses)
	ut64 debug_abbrev_addr = debug_info_size;
	ut64 debug_line_addr = debug_info_size + debug_abbrev_size;
	W(abbrev_addr_off, &debug_abbrev_addr, 8);
	W(line_addr_off, &debug_line_addr, 8);
	// Patch __DWARF segment vmsize and filesize (total debug segment size)
	ut64 dwarf_segment_size = debug_info_size + debug_abbrev_size + debug_line_size;
	W(dwarf_vmsize_off, &dwarf_segment_size, 8);
	W(dwarf_filesz_off, &dwarf_segment_size, 8);

	// Now prepare and patch symbol table info
	{   // Build offsets for each symbol string in the string table
		size_t sym_count = r_list_length (symbols);
		ut32 *str_offsets = malloc (sizeof (ut32) * sym_count);
		ut32 cur_offset = 1;
		RListIter *sit;
		SymEntry *se;
		int i = 0;
		r_list_foreach (symbols, sit, se) {
			str_offsets[i++] = cur_offset;
			cur_offset += (ut32)strlen(se->symbol) + 1;
		}
		// Patch symbol table offset and count
		ut32 symoff_val = (ut32)r_buf_size(buf);
		W(symoff_field_off, &symoff_val, 4);
		ut32 nsyms_val = (ut32)sym_count;
		W(nsyms_field_off, &nsyms_val, 4);
		// Emit nlist_64 entries
		i = 0;
		r_list_foreach (symbols, sit, se) {
			U32(str_offsets[i]);   // n_strx
			U8(0x0f);              // n_type = N_SECT | N_EXT
			U8(0x01);              // n_sect = __text (1)
			U16(0x0000);           // n_desc = 0
			U64(se->addr);         // n_value = address
			i++;
		}
		free (str_offsets);
	}
	// Emit string table
	{
		ut32 stroff_val = (ut32)r_buf_size (buf);
		W(stroff_field_off, &stroff_val, 4);
		// empty string
		U8(0x00);
		RListIter *sit2;
		SymEntry *se2;
		r_list_foreach (symbols, sit2, se2) {
			B(se2->symbol, strlen(se2->symbol)); U8(0x00);
		}
		ut32 strsize_val = (ut32)(r_buf_size(buf) - stroff_val);
		W(strsize_field_off, &strsize_val, 4);
	}

	// Final RBuffer contains the complete Mach-O file in memory
	return buf;
}

RBuffer *create_elf_with_dwarf(RList *lines, RList *symbols) {
	RBuffer *buf = r_buf_new ();
	if (!buf) {
		return NULL;
	}
	// ELF header
	B("\x7f""ELF", 4);
	U8(2); U8(1); U8(1); U8(0); U8(0); Z(7);
	U16(1); U16(0x3E); U32(1);
	U64(0); U64(0);
	ut64 shoff_off = r_buf_size(buf);
	U64(0);
	U32(0); U16(64); U16(0); U16(0); U16(64); U16(8); U16(7);
	// .text
	ut64 text_off = r_buf_size(buf); U8(0xC3);
	ut64 text_sz = r_buf_size(buf) - text_off;
	// .debug_info
	ut64 debug_info_start = r_buf_size(buf);
	ut64 cu_len_off = r_buf_size(buf);
	if (cu_len_off == (ut64)-1) {
		return NULL;
	}
	U32(0); U16(2); U32(0); U8(8);
	U8(0x01); U8(0x0c); B("main.c",6); U8(0); B(".",1); U8(0);
	U64(0); U64(1); U32(0);
	{
		RListIter *sym_it; SymEntry *sym;
		r_list_foreach (symbols, sym_it, sym) {
			U8(0x02);
			B(sym->symbol, strlen (sym->symbol));
			U8(0);
			U64(sym->addr);
			U64(sym->addr + 1);
		}
	}
	U8(0);
	ut64 cu_end = r_buf_size (buf);
	if (cu_end == (ut64)-1 || cu_len_off == (ut64)-1) {
		r_buf_free (buf);
		return NULL;
	}
	ut32 cu_len = (ut32)(cu_end - (cu_len_off + 4));
	W(cu_len_off, &cu_len, 4);
	// .debug_abbrev
	ut64 debug_abbrev_start = r_buf_size (buf);
	U8(0x01); U8(0x11); U8(0x01);
	U8(0x13); U8(0x0b);
	U8(0x03); U8(0x08);
	U8(0x1b); U8(0x08);
	U8(0x11); U8(0x01);
	U8(0x12); U8(0x01);
	U8(0x10); U8(0x06);
	U8(0x00); U8(0x00);
	U8(0x02); U8(0x2e); U8(0x00);
	U8(0x03); U8(0x08);
	U8(0x11); U8(0x01);
	U8(0x12); U8(0x01);
	U8(0x00); U8(0x00);
	U8(0x00);
	// .debug_line
	ut64 debug_line_start = r_buf_size (buf);
	ut64 line_len_off = r_buf_size(buf); U32(0); U16(2);
	ut64 hdr_len_off = r_buf_size(buf); U32(0);
	U8(1); U8(1); U8((ut8)0xFB); U8(14); U8(13);
	ut8 std_op_len[12] = {0,1,1,1,1,0,0,0,1,0,0,1};
	{
		int i;
		for (i = 0; i < 12; i++) {
			U8(std_op_len[i]);
		}
	}
	RList *dirs = r_list_newf (free);
	RListIter *dir_it; char *dir;
	r_list_foreach (dirs, dir_it, dir) {
		B(dir, strlen(dir)); U8(0);
	}
	U8(0);
	RList *files = r_list_newf(free);
	{
		RListIter *lit;
		LineEntry *le;
		r_list_foreach (lines, lit, le) {
			RListIter *fit;
			char *fn;
			bool found = false;
			r_list_foreach (files, fit, fn) {
				if (!strcmp (fn, le->file)) {
					found = true;
					break;
				}
			}
			if (!found) {
				r_list_append (files, strdup (le->file));
			}
		}
	}
	RListIter *file_it;
	char *filename;
	r_list_foreach (files, file_it, filename) {
		B(filename, strlen (filename));
		U8(0); U8(0); U8(0); U8(0);
	}
	U8(0);
	{
		ut64 prev_line = 1; int prev_file_idx = 1;
		RListIter *lit; LineEntry *le;
		r_list_foreach (lines, lit, le) {
			U8(0x00); U8(1 + sizeof (ut64)); U8(0x02); U64(le->addr);
			int file_idx = 1; RListIter *fit; char *fname;
			r_list_foreach (files, fit, fname) {
				if (!strcmp (fname, le->file)) {
					break;
				}
				file_idx++;
			}
			if (file_idx != prev_file_idx) {
				U8(0x04);
				ut32 v = file_idx;
				do {
					ut8 b = v & 0x7f;
					v >>= 7;
					if (v) {
						b |= 0x80;
					}
					U8(b);
				} while (v);
				prev_file_idx = file_idx;
			}
			U8(0x03);
			{
				int64_t d = (int64_t)le->line - (int64_t)prev_line;
				ut64 v = (ut64)d; int more = 1;
				while (more) {
					ut8 b = v & 0x7f; v >>= 7;
					int32_t s = (d < 0) ? 1 : 0;
					if ((v == 0 && s == 0) || ((int64_t)v == -1 && s == 1)) {
						more = 0;
					} else {
						b |= 0x80;
					}
					U8(b);
				}
				prev_line = le->line;
			}
			U8(0x01);
		}
	}
	U8(0); U8(1); U8(1);
	ut64 line_ops_end = r_buf_size(buf);
	ut32 hdr_len = (ut32)(line_ops_end - (hdr_len_off + 4)); W(hdr_len_off, &hdr_len, 4);
	ut64 line_end = r_buf_size(buf);
	ut32 line_len = (ut32)(line_end - (line_len_off + 4)); W(line_len_off, &line_len, 4);
	r_list_free(files); r_list_free(dirs);
	// Symbol table
	size_t sym_count = r_list_length (symbols);
	ut32 *str_offsets = calloc (sizeof (ut32), sym_count);
	ut32 cur_off = 1;
	RListIter *sit; SymEntry *se; int i;
	i = 0;
	r_list_foreach (symbols, sit, se) {
		str_offsets[i++] = cur_off;
		cur_off += strlen (se->symbol) + 1;
	}
	ut64 symtab_off = r_buf_size (buf);
	// NULL symbol
	U32(0); U8(0); U8(0); U16(0); U64(0); U64(0);
	i = 0;
	r_list_foreach (symbols, sit, se) {
		U32(str_offsets[i]);
		U8(0x12); U8(0); U16(1); U64(se->addr); U64(1);
		i++;
	}
	ut64 symtab_end = r_buf_size (buf);
	ut32 symtab_sz = (ut32)(symtab_end - symtab_off);
	free (str_offsets);
	// String table
	ut64 strtab_off = r_buf_size (buf);
	U8(0);
	r_list_foreach (symbols, sit, se) {
		B(se->symbol, strlen(se->symbol)); U8(0);
	}
	ut64 strtab_end = r_buf_size (buf);
	ut32 strtab_sz = (ut32)(strtab_end - strtab_off);
	// Section header string table
	ut64 shstr_off = r_buf_size (buf);
	ut32 sh_names[8];
	U8(0);
	sh_names[1] = (ut32)(r_buf_size(buf) - shstr_off); B(".text",5); U8(0);
	sh_names[2] = (ut32)(r_buf_size(buf) - shstr_off); B(".debug_info",11); U8(0);
	sh_names[3] = (ut32)(r_buf_size(buf) - shstr_off); B(".debug_abbrev",13); U8(0);
	sh_names[4] = (ut32)(r_buf_size(buf) - shstr_off); B(".debug_line",11); U8(0);
	sh_names[5] = (ut32)(r_buf_size(buf) - shstr_off); B(".symtab",7); U8(0);
	sh_names[6] = (ut32)(r_buf_size(buf) - shstr_off); B(".strtab",7); U8(0);
	sh_names[7] = (ut32)(r_buf_size(buf) - shstr_off); B(".shstrtab",9); U8(0);
	ut64 shstr_end = r_buf_size (buf);
	ut32 shstr_sz = (ut32)(shstr_end - shstr_off);
	// Patch section header table offset
	ut64 shdrs_off = r_buf_size (buf);
	W(shoff_off, &shdrs_off, 8);
	// Section headers
	Z(64);
	// .text
	U32(sh_names[1]); U32(1); U64(6); U64(0); U64(text_off); U64(text_sz); U32(0); U32(0); U64(16); U64(0);
	// .debug_info
	U32(sh_names[2]); U32(1); U64(0); U64(0); U64(debug_info_start); U64((ut64)(debug_abbrev_start - debug_info_start)); U32(0); U32(0); U64(1); U64(0);
	// .debug_abbrev
	U32(sh_names[3]); U32(1); U64(0); U64(0); U64(debug_abbrev_start); U64((ut64)(debug_line_start - debug_abbrev_start)); U32(0); U32(0); U64(1); U64(0);
	// .debug_line
	U32(sh_names[4]); U32(1); U64(0); U64(0); U64(debug_line_start); U64((ut64)(symtab_off - debug_line_start)); U32(0); U32(0); U64(1); U64(0);
	// .symtab
	U32(sh_names[5]); U32(2); U64(0); U64(0); U64(symtab_off); U64(symtab_sz); U32(6); U32(1); U64(8); U64(24);
	// .strtab
	U32(sh_names[6]); U32(3); U64(0); U64(0); U64(strtab_off); U64(strtab_sz); U32(0); U32(0); U64(1); U64(0);
	// .shstrtab
	U32(sh_names[7]); U32(3); U64(0); U64(0); U64(shstr_off); U64(shstr_sz); U32(0); U32(0); U64(1); U64(0);
	return buf;
}

// (create_macho_with_dwarf and main remain unchanged)
#if 0
int main() {
	RList *lines = r_list_newf (free);
	RList *symbols = r_list_newf (free);

	// Populate line entries
	{
		LineEntry *le1 = R_NEW0 (LineEntry);
		le1->addr = 0x1000;
		le1->file = strdup ("main.c");
		le1->line = 42;
		r_list_append (lines, le1);
		LineEntry *le2 = R_NEW0 (LineEntry);
		le2->addr = 0x2000;
		le2->file = strdup ("main.c");
		le2->line = 53;
		r_list_append (lines, le2);
		LineEntry *le3 = R_NEW0 (LineEntry);
		le3->addr = 0x3000;
		le3->file = strdup ("foo.c");
		le3->line = 63;
		r_list_append (lines, le3);
	}

	// Populate symbol entries
	{
		SymEntry *se1 = R_NEW0 (SymEntry);
		se1->addr = 0x1000;
		se1->symbol = strdup ("main");
		r_list_append (symbols, se1);
		SymEntry *se2 = R_NEW0 (SymEntry);
		se2->addr = 0x2000;
		se2->symbol = strdup ("check");
		r_list_append (symbols, se2);
	}

	RBuffer *b = create_macho_with_dwarf (lines, symbols);
	int sz;
	ut8 *outbuf = r_buf_read_all (b, &sz);
	r_file_dump ("gen", outbuf, sz, false);
	free (outbuf);
	r_buf_free (b);
	return 0;
}
#endif

static bool addrline_cb(void *user, RBinAddrline *al) {
	RList *lines = (RList *)user;
	if (!al || !al->file) {
		return true;
	}
	LineEntry *le = R_NEW0 (LineEntry);
	le->addr = al->addr;
	le->file = strdup (al->file);
	le->line = al->line;
	r_list_append (lines, le);
	return true;
}

static void populate_lines_from_addrline(RBin *bin, RList *lines) {
	if (bin && bin->cur && bin->cur->addrline.used) {
		r_bin_addrline_foreach (bin, addrline_cb, lines);
	} else {
		if (bin && bin->cur && bin->cur->sdb_addrinfo) {
			R_LOG_INFO ("Falling back to legacy sdb_addrinfo");
			// Legacy method - to be removed
			sdb_foreach (bin->cur->sdb_addrinfo, NULL, NULL);
		}
	}
}

static void writedwarf(RCore *core, const char *format, const char *arg) {
	const char *filename = arg;
	R_LOG_INFO ("Writing to %s", filename);

	RList *lines = r_list_newf (free);
	RList *symbols = r_list_newf (free);

	// Populate line entries from debug info
	populate_lines_from_addrline (core->bin, lines);

#if 0
	// Populate line entries
	{
		LineEntry *le1 = R_NEW0 (LineEntry);
		le1->addr = 0x1000;
		le1->file = strdup ("main.c");
		le1->line = 42;
		r_list_append(lines, le1);
		LineEntry *le2 = R_NEW0 (LineEntry);
		le2->addr = 0x2000;
		le2->file = strdup ("main.c");
		le2->line = 53;
		r_list_append(lines, le2);
		LineEntry *le3 = R_NEW0 (LineEntry);
		le3->addr = 0x3000;
		le3->file = strdup ("foo.c");
		le3->line = 63;
		r_list_append(lines, le3);
	}
#endif
	{
		RListIter *it;
		RAnalFunction *fcn;
		r_list_foreach (core->anal->fcns, it, fcn) {
			SymEntry *se = R_NEW0 (SymEntry);
			se->addr = fcn->addr;
			se->symbol = strdup (fcn->name);
			r_list_append (symbols, se);
		}
	}
#if 0
	// Populate symbol entries
	{
		SymEntry *se1 = R_NEW0 (SymEntry);
		se1->addr = 0x1000;
		se1->symbol = strdup ("main");
		r_list_append (symbols, se1);
		SymEntry *se2 = R_NEW0 (SymEntry);
		se2->addr = 0x2000;
		se2->symbol = strdup ("check");
		r_list_append(symbols, se2);
	}
#endif

	RBuffer *b = NULL;
	if (!strcmp (format, "elf")) {
		b = create_elf_with_dwarf (lines, symbols);
	} else if (!strcmp (format, "mac")) {
		b = create_macho_with_dwarf (lines, symbols);
	} else {
		R_LOG_ERROR ("Only macho and elf formats are supported");
	}
	int sz;
	ut8 *outbuf = r_buf_read_all (b, &sz);
	if (!r_file_dump (filename, outbuf, sz, false)) {
		R_LOG_ERROR ("Cannot write to %s", filename);
	}
	free (outbuf);
	r_buf_free (b);
	// Free the RLists
	RListIter *it;
	void *item;
	r_list_foreach (symbols, it, item) {
		SymEntry *se = (SymEntry *)item;
		free (se->symbol);
	}
	r_list_free (symbols);
	r_list_foreach (lines, it, item) {
		LineEntry *le = (LineEntry *)item;
		free (le->file);
	}
	r_list_free (lines);
}

static bool cmd_writedwarf(RCorePluginSession *cps, const char *input) {
	RCore *core = cps->core;
	if (r_str_startswith (input, "writedwarf")) {
		char *arg = strchr (input, ' ');
		const char *format = "macho";
		if (!arg) {
			R_LOG_INFO ("Usage: writedwarf [filename]");
			return true;
		}
		if (*arg == '-') {
			if (r_str_startswith (arg, "-elf")) {
				format = "elf";
			} else if (r_str_startswith (arg, "-mac")) {
				format = "mac";
			} else {
				R_LOG_ERROR ("Invalid format: use -elf or -mac");
				return true;
			}
			arg = strchr (arg, ' ');
		}
		if (arg && *arg != '?') {
			writedwarf (core, format, r_str_trim_head_ro (arg + 1));
		} else {
			R_LOG_INFO ("Usage: writedwarf [filename]");
		}
		return true;
	}
	return false;
}

RCorePlugin r_core_plugin_writedwarf = {
	.meta = {
		.name = "writedwarf",
		.desc = "Write a dwarf with the symbols and source line information",
		.author = "pancake",
		.license = "MIT",
	},
	.call = cmd_writedwarf,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_writedwarf,
	.version = R2_VERSION
};
#endif
