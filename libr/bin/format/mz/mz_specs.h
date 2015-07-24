/* radare - LGPL - Copyright 2015 nodepad */

typedef struct {
	ut16 signature; /* == 'MZ' or 'ZM' */
	ut16 bytes_in_last_block;
	ut16 blocks_in_file;
	ut16 num_relocs;
	ut16 header_paragraphs;
	ut16 min_extra_paragraphs;
	ut16 max_extra_paragraphs;
	ut16 ss;
	ut16 sp;
	ut16 checksum;
	ut16 ip;
	ut16 cs;
	ut16 reloc_table_offset;
	ut16 overlay_number;
} MZ_image_dos_header;

typedef struct {
	ut16 offset;
	ut16 segment;
} MZ_image_relocation_entry;
