#include "dbi.h"

#include "stream_file.h"

///////////////////////////////////////////////////////////////////////////////
void init_dbi_stream(SDbiStream *dbi_stream)
{
	dbi_stream->free_ = 0;
}

///////////////////////////////////////////////////////////////////////////////
static void parse_dbi_header(SDBIHeader *dbi_header, R_STREAM_FILE *stream_file)
{
	stream_file_read(stream_file, sizeof(unsigned int), (char *)&dbi_header->magic);
	stream_file_read(stream_file, sizeof(unsigned int), (char *)&dbi_header->version);
	stream_file_read(stream_file, sizeof(unsigned int), (char *)&dbi_header->age);
	stream_file_read(stream_file, sizeof(short), (char *)&dbi_header->gssymStream);
	stream_file_read(stream_file, sizeof(unsigned short), (char *)&dbi_header->vers);
	stream_file_read(stream_file, sizeof(short), (char *)&dbi_header->pssymStream);
	stream_file_read(stream_file, sizeof(unsigned short), (char *)&dbi_header->pdbver);
	stream_file_read(stream_file, sizeof(short), (char *)&dbi_header->symrecStream);
	stream_file_read(stream_file, sizeof(unsigned short), (char *)&dbi_header->pdbver2);
	stream_file_read(stream_file, sizeof(unsigned int), (char *)&dbi_header->module_size);
	stream_file_read(stream_file, sizeof(unsigned int), (char *)&dbi_header->seccon_size);
	stream_file_read(stream_file, sizeof(unsigned int), (char *)&dbi_header->secmap_size);
	stream_file_read(stream_file, sizeof(unsigned int), (char *)&dbi_header->filinf_size);
	stream_file_read(stream_file, sizeof(unsigned int), (char *)&dbi_header->tsmap_size);
	stream_file_read(stream_file, sizeof(unsigned int), (char *)&dbi_header->mfc_index);
	stream_file_read(stream_file, sizeof(unsigned int), (char *)&dbi_header->dbghdr_size);
	stream_file_read(stream_file, sizeof(unsigned int), (char *)&dbi_header->ecinfo_size);
	stream_file_read(stream_file, sizeof(unsigned short), (char *)&dbi_header->flags);
	stream_file_read(stream_file, 2, (char *)&dbi_header->machine);
	stream_file_read(stream_file, sizeof(unsigned int), (char *)&dbi_header->resvd);
}

///////////////////////////////////////////////////////////////////////////////
void parse_dbi_stream(void *parsed_pdb_stream, R_STREAM_FILE *stream_file)
{
	SDbiStream *dbi_stream = (SDbiStream *) parsed_pdb_stream;
	int pos = 0;

	parse_dbi_header(&dbi_stream->dbi_header, stream_file);
	pos += sizeof(SDBIHeader) - 2;	// 2 because enum in C equal to 4, but
									// to read just 2;
	stream_file_seek(stream_file, pos, 0);

	int i = 0;
}
