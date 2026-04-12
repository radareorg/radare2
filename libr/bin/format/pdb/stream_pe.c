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
		SIMAGE_SECTION_HEADER *sctn_header = malloc (sctn_header_size);
		if (!sctn_header) {
			break;
		}
		memcpy (sctn_header, ptmp, sctn_header_size);
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
