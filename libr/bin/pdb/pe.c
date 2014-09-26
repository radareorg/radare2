#include "pe.h"

#include "stream_file.h"

///////////////////////////////////////////////////////////////////////////////
void parse_pe_stream(void *stream, R_STREAM_FILE *stream_file)
{
	int data_size = 0;
	char *data = 0, *ptmp = 0;
	int read_bytes = 0;
	SIMAGE_SECTION_HEADER *sctn_header = 0;
	SPEStream *pe_stream = (SPEStream *) stream;
	int sctn_header_size =0;

	stream_file_get_size(stream_file, &data_size);
	data = (char *) malloc(data_size);
	stream_file_get_data(stream_file, data);

	sctn_header_size = sizeof(SIMAGE_SECTION_HEADER);
	ptmp = data;
	pe_stream->sections_hdrs = r_list_new();
	while (read_bytes < data_size) {
		sctn_header = (SIMAGE_SECTION_HEADER *) malloc (sctn_header_size);
		memcpy(sctn_header, ptmp, sctn_header_size);
		ptmp += sctn_header_size;
		r_list_append(pe_stream->sections_hdrs, sctn_header);
		read_bytes += sctn_header_size;
	}

	free(data);
}

///////////////////////////////////////////////////////////////////////////////
void free_pe_stream(void *stream)
{
	SPEStream *pe_stream = (SPEStream *) stream;
	SIMAGE_SECTION_HEADER *sctn_header = 0;
	RListIter *it = 0;

	it = r_list_iterator(pe_stream->sections_hdrs);
	while (r_list_iter_next(it)) {
		sctn_header = (SIMAGE_SECTION_HEADER *) r_list_iter_get(it);
		free(sctn_header);
	}
	r_list_free(pe_stream->sections_hdrs);
}
