#include "types.h"
#include "stream_pe.h"
#include "stream_file.h"

void parse_pe_stream(STpiStream *ss, void *stream, R_STREAM_FILE *stream_file) {
	int data_size = stream_file_get_size (stream_file);
	if (data_size < 1) {
		return;
	}
	char *data = (char *)malloc (data_size);
	if (!data) {
		return;
	}
	stream_file_get_data (stream_file, data);

	SPEStream *pe_stream = (SPEStream *)stream;
	int sctn_header_size = sizeof (SIMAGE_SECTION_HEADER);
	char *ptmp = data;
	pe_stream->sections_hdrs = r_list_newf (free);
	int read_bytes = 0;
	while (read_bytes + sctn_header_size <= data_size) {
		SIMAGE_SECTION_HEADER *sctn_header = R_NEW0 (SIMAGE_SECTION_HEADER);
		if (!sctn_header) {
			break;
		}
		memcpy (sctn_header->name, ptmp, PDB_SIZEOF_SECTION_NAME);
		sctn_header->misc.virtual_address = r_read_le32 (ptmp + 8);
		sctn_header->virtual_address = r_read_le32 (ptmp + 12);
		sctn_header->size_of_raw_data = r_read_le32 (ptmp + 16);
		sctn_header->pointer_to_raw_data = r_read_le32 (ptmp + 20);
		sctn_header->pointer_to_relocations = r_read_le32 (ptmp + 24);
		sctn_header->pointer_to_line_numbers = r_read_le32 (ptmp + 28);
		sctn_header->number_of_relocations = r_read_le16 (ptmp + 32);
		sctn_header->number_of_line_numbers = r_read_le16 (ptmp + 34);
		sctn_header->charactestics = r_read_le32 (ptmp + 36);
		ptmp += sctn_header_size;
		r_list_append (pe_stream->sections_hdrs, sctn_header);
		read_bytes += sctn_header_size;
	}
	free (data);
}

void free_pe_stream(STpiStream *ss, void *stream) {
	SPEStream *pe_stream = (SPEStream *)stream;
	r_list_free (pe_stream->sections_hdrs);
}
