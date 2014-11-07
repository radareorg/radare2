#include "dbi.h"

#include "stream_file.h"
#include "tpi.h"

#define _ALIGN 4

///////////////////////////////////////////////////////////////////////////////
static void free_dbi_stream(void *stream)
{
	SDbiStream *t = (SDbiStream *) stream;
	RListIter *it = 0;
	SDBIExHeader *dbi_ex_header = 0;

	it = r_list_iterator(t->dbiexhdrs);
	while (r_list_iter_next(it)) {
		dbi_ex_header = (SDBIExHeader *) r_list_iter_get(it);
		free(dbi_ex_header->modName.name);
		free(dbi_ex_header->objName.name);
		free(dbi_ex_header);
	}
	r_list_free(t->dbiexhdrs);
}

///////////////////////////////////////////////////////////////////////////////
static void parse_dbi_header(SDBIHeader *dbi_header, R_STREAM_FILE *stream_file)
{
	stream_file_read(stream_file, sizeof(ut32), (char *)&dbi_header->magic);
	stream_file_read(stream_file, sizeof(ut32), (char *)&dbi_header->version);
	stream_file_read(stream_file, sizeof(ut32), (char *)&dbi_header->age);
	stream_file_read(stream_file, sizeof(ut16), (char *)&dbi_header->gssymStream);
	stream_file_read(stream_file, sizeof(ut16), (char *)&dbi_header->vers);
	stream_file_read(stream_file, sizeof(st16), (char *)&dbi_header->pssymStream);
	stream_file_read(stream_file, sizeof(ut16), (char *)&dbi_header->pdbver);
	stream_file_read(stream_file, sizeof(st16), (char *)&dbi_header->symrecStream);
	stream_file_read(stream_file, sizeof(ut16), (char *)&dbi_header->pdbver2);
	stream_file_read(stream_file, sizeof(ut32), (char *)&dbi_header->module_size);
	stream_file_read(stream_file, sizeof(ut32), (char *)&dbi_header->seccon_size);
	stream_file_read(stream_file, sizeof(ut32), (char *)&dbi_header->secmap_size);
	stream_file_read(stream_file, sizeof(ut32), (char *)&dbi_header->filinf_size);
	stream_file_read(stream_file, sizeof(ut32), (char *)&dbi_header->tsmap_size);
	stream_file_read(stream_file, sizeof(ut32), (char *)&dbi_header->mfc_index);
	stream_file_read(stream_file, sizeof(ut32), (char *)&dbi_header->dbghdr_size);
	stream_file_read(stream_file, sizeof(ut32), (char *)&dbi_header->ecinfo_size);
	stream_file_read(stream_file, sizeof(ut16), (char *)&dbi_header->flags);
	stream_file_read(stream_file, 2, (char *)&dbi_header->machine);
	stream_file_read(stream_file, sizeof(ut32), (char *)&dbi_header->resvd);
}

///////////////////////////////////////////////////////////////////////////////
static int parse_ssymbol_range(char *data, int max_len, SSymbolRange *symbol_range)
{
	int read_bytes = 0;

	READ(read_bytes, 2, max_len, symbol_range->section, data, short);
	READ(read_bytes, 2, max_len, symbol_range->padding1, data, short);
	READ(read_bytes, 4, max_len, symbol_range->offset, data, int);
	READ(read_bytes, 4, max_len, symbol_range->size, data, int);
	READ(read_bytes, 4, max_len, symbol_range->flags, data, ut32);
	READ(read_bytes, 4, max_len, symbol_range->module, data, int);

// TODO: why not need to read this padding?
//	READ(read_bytes, 2, max_len, symbol_range->padding2, data, short);
	READ(read_bytes, 4, max_len, symbol_range->data_crc, data, ut32);
	READ(read_bytes, 4, max_len, symbol_range->reloc_crc, data, ut32);

	return read_bytes;
}

///////////////////////////////////////////////////////////////////////////////
static int parse_dbi_ex_header(char *data, int max_len, SDBIExHeader *dbi_ex_header)
{
	ut32 read_bytes = 0, before_read_bytes = 0;

	READ(read_bytes, 4, max_len, dbi_ex_header->opened, data, ut32);

	before_read_bytes = read_bytes;
	read_bytes += parse_ssymbol_range (data, max_len, &dbi_ex_header->range);
	data += (read_bytes - before_read_bytes);

	READ(read_bytes, 2, max_len, dbi_ex_header->flags, data, ut16);
	READ(read_bytes, 2, max_len, dbi_ex_header->stream, data, short);
	READ(read_bytes, 4, max_len, dbi_ex_header->symSize, data, ut32);
	READ(read_bytes, 4, max_len, dbi_ex_header->oldLineSize, data, ut32);
	READ(read_bytes, 4, max_len, dbi_ex_header->lineSize, data, ut32);
	READ(read_bytes, 2, max_len, dbi_ex_header->nSrcFiles, data, short);
	READ(read_bytes, 2, max_len, dbi_ex_header->padding1, data, short);
	READ(read_bytes, 4, max_len, dbi_ex_header->offsets, data, ut32);
	READ(read_bytes, 4, max_len, dbi_ex_header->niSource, data, ut32);
	READ(read_bytes, 4, max_len, dbi_ex_header->niCompiler, data, ut32);

	before_read_bytes = read_bytes;
	parse_sctring(&dbi_ex_header->modName, (unsigned char *)data, &read_bytes, max_len);
	data += (read_bytes - before_read_bytes);

	before_read_bytes = read_bytes;
	parse_sctring(&dbi_ex_header->objName, (unsigned char *)data, &read_bytes, max_len);
	data += (read_bytes - before_read_bytes);

	return read_bytes;
}

///////////////////////////////////////////////////////////////////////////////
static void parse_dbg_header(SDbiDbgHeader *dbg_header, R_STREAM_FILE *stream_file)
{
	stream_file_read(stream_file, sizeof(short), (char *)&dbg_header->sn_fpo);
	stream_file_read(stream_file, sizeof(short), (char *)&dbg_header->sn_exception);
	stream_file_read(stream_file, sizeof(short), (char *)&dbg_header->sn_fixup);
	stream_file_read(stream_file, sizeof(short), (char *)&dbg_header->sn_omap_to_src);
	stream_file_read(stream_file, sizeof(short), (char *)&dbg_header->sn_omap_from_src);
	stream_file_read(stream_file, sizeof(short), (char *)&dbg_header->sn_section_hdr);
	stream_file_read(stream_file, sizeof(short), (char *)&dbg_header->sn_token_rid_map);
	stream_file_read(stream_file, sizeof(short), (char *)&dbg_header->sn_xdata);
	stream_file_read(stream_file, sizeof(short), (char *)&dbg_header->sn_pdata);
	stream_file_read(stream_file, sizeof(short), (char *)&dbg_header->sn_new_fpo);
	stream_file_read(stream_file, sizeof(short), (char *)&dbg_header->sn_section_hdr_orig);
}

///////////////////////////////////////////////////////////////////////////////
void init_dbi_stream(SDbiStream *dbi_stream)
{
	dbi_stream->free_ = free_dbi_stream;
}

///////////////////////////////////////////////////////////////////////////////
void parse_dbi_stream(void *parsed_pdb_stream, R_STREAM_FILE *stream_file)
{
	SDbiStream *dbi_stream = (SDbiStream *) parsed_pdb_stream;
	SDBIExHeader *dbi_ex_header = 0;
	int pos = 0;
	char *dbiexhdr_data = 0, *p_tmp = 0;
	int size = 0, sz = 0;
	int i = 0;

	parse_dbi_header(&dbi_stream->dbi_header, stream_file);
	pos += sizeof(SDBIHeader) - 2;	// 2 because enum in C equal to 4, but
									// to read just 2;
	stream_file_seek(stream_file, pos, 0);

	size = dbi_stream->dbi_header.module_size;
	dbiexhdr_data = (char *) malloc(size);
	stream_file_read(stream_file, size, dbiexhdr_data);

	dbi_stream->dbiexhdrs = r_list_new();
	p_tmp = dbiexhdr_data;
	while (i < size) {
		dbi_ex_header = (SDBIExHeader *) malloc(sizeof(SDBIExHeader));
		// TODO: rewrite for signature where can to do chech CAN_READ true?
		sz = parse_dbi_ex_header(p_tmp, size, dbi_ex_header);
		if ((sz % _ALIGN)) {
			sz = sz + (_ALIGN - (sz % _ALIGN));
		}
		i += sz;
		p_tmp += sz;
		r_list_append(dbi_stream->dbiexhdrs, dbi_ex_header);
	}

	free(dbiexhdr_data);

	// "Section Contribution"
	stream_file_seek(stream_file, dbi_stream->dbi_header.seccon_size, 1);
	// "Section Map"
	stream_file_seek(stream_file, dbi_stream->dbi_header.secmap_size, 1);
	// "File Info"
	stream_file_seek(stream_file, dbi_stream->dbi_header.filinf_size, 1);
	// "TSM"
	stream_file_seek(stream_file, dbi_stream->dbi_header.tsmap_size, 1);
	// "EC"
	stream_file_seek(stream_file, dbi_stream->dbi_header.ecinfo_size, 1);

	parse_dbg_header(&dbi_stream->dbg_header, stream_file);
}
