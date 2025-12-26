#include "types.h"
#include "dbi.h"
#include "stream_file.h"
#include "tpi.h"

#define PDB_ALIGN 4

///////////////////////////////////////////////////////////////////////////////
static void free_dbi_stream(STpiStream *ss, void *stream) {
	SDbiStream *t = (SDbiStream *)stream;
	SDBIExHeader *dbi_ex_header = NULL;
	RListIter *it = r_list_iterator (t->dbiexhdrs);
	while (r_list_iter_next (it)) {
		dbi_ex_header = (SDBIExHeader *)r_list_iter_get (it);
		free (dbi_ex_header->modName.name);
		free (dbi_ex_header->objName.name);
		free (dbi_ex_header);
	}
	r_list_free (t->dbiexhdrs);
}

///////////////////////////////////////////////////////////////////////////////
static void parse_dbi_header(SDBIHeader *dbi_header, R_STREAM_FILE *stream_file) {
	stream_file_read (stream_file, sizeof (ut32), (char *)&dbi_header->magic);
	stream_file_read (stream_file, sizeof (ut32), (char *)&dbi_header->version);
	stream_file_read (stream_file, sizeof (ut32), (char *)&dbi_header->age);
	stream_file_read (stream_file, sizeof (ut16), (char *)&dbi_header->gssymStream);
	stream_file_read (stream_file, sizeof (ut16), (char *)&dbi_header->vers);
	stream_file_read (stream_file, sizeof (st16), (char *)&dbi_header->pssymStream);
	stream_file_read (stream_file, sizeof (ut16), (char *)&dbi_header->pdbver);
	stream_file_read (stream_file, sizeof (st16), (char *)&dbi_header->symrecStream);
	stream_file_read (stream_file, sizeof (ut16), (char *)&dbi_header->pdbver2);
	stream_file_read (stream_file, sizeof (ut32), (char *)&dbi_header->module_size);
	stream_file_read (stream_file, sizeof (ut32), (char *)&dbi_header->seccon_size);
	stream_file_read (stream_file, sizeof (ut32), (char *)&dbi_header->secmap_size);
	stream_file_read (stream_file, sizeof (ut32), (char *)&dbi_header->filinf_size);
	stream_file_read (stream_file, sizeof (ut32), (char *)&dbi_header->tsmap_size);
	stream_file_read (stream_file, sizeof (ut32), (char *)&dbi_header->mfc_index);
	stream_file_read (stream_file, sizeof (ut32), (char *)&dbi_header->dbghdr_size);
	stream_file_read (stream_file, sizeof (ut32), (char *)&dbi_header->ecinfo_size);
	stream_file_read (stream_file, sizeof (ut16), (char *)&dbi_header->flags);
	stream_file_read (stream_file, 2, (char *)&dbi_header->machine);
	stream_file_read (stream_file, sizeof (ut32), (char *)&dbi_header->resvd);
}

static int parse_ssymbol_range(const ut8 *data, ut32 max_len, SSymbolRange *symbol_range) {
	const ut32 size = 28;
	if (!can_read (0, size, max_len)) {
		return 0;
	}
	symbol_range->section = r_read_le16 (data);
	symbol_range->padding1 = r_read_le16 (data + 2);
	symbol_range->offset = (st32)r_read_le32 (data + 4);
	symbol_range->size = (st32)r_read_le32 (data + 8);
	symbol_range->flags = r_read_le32 (data + 12);
	symbol_range->module = (st32)r_read_le32 (data + 16);
	symbol_range->data_crc = r_read_le32 (data + 20);
	symbol_range->reloc_crc = r_read_le32 (data + 24);
	return size;
}

static int parse_dbi_ex_header(ut8 *data, ut32 max_len, SDBIExHeader *dbi_ex_header) {
	const ut32 fixed_size = 64;
	if (!can_read (0, fixed_size, max_len)) {
		return 0;
	}
	dbi_ex_header->opened = r_read_le32 (data);
	const int range_sz = parse_ssymbol_range (data + 4, max_len - 4, &dbi_ex_header->range);
	if (range_sz == 0) {
		return 0;
	}
	const ut8 *p = data + 4 + range_sz;
	dbi_ex_header->flags = r_read_le16 (p);
	dbi_ex_header->stream = (st16)r_read_le16 (p + 2);
	dbi_ex_header->symSize = r_read_le32 (p + 4);
	dbi_ex_header->oldLineSize = r_read_le32 (p + 8);
	dbi_ex_header->lineSize = r_read_le32 (p + 12);
	dbi_ex_header->nSrcFiles = (st16)r_read_le16 (p + 16);
	dbi_ex_header->padding1 = (st16)r_read_le16 (p + 18);
	dbi_ex_header->offsets = r_read_le32 (p + 20);
	dbi_ex_header->niSource = r_read_le32 (p + 24);
	dbi_ex_header->niCompiler = r_read_le32 (p + 28);
	ut32 read_bytes = fixed_size;
	ut8 *str_data = data + fixed_size;
	ut32 before = read_bytes;
	parse_sctring (&dbi_ex_header->modName, str_data, &read_bytes, max_len);
	str_data += (read_bytes - before);
	parse_sctring (&dbi_ex_header->objName, str_data, &read_bytes, max_len);
	return read_bytes;
}

///////////////////////////////////////////////////////////////////////////////
static void parse_dbg_header(SDbiDbgHeader *dbg_header, R_STREAM_FILE *stream_file) {
	stream_file_read (stream_file, sizeof (short), (char *)&dbg_header->sn_fpo);
	stream_file_read (stream_file, sizeof (short), (char *)&dbg_header->sn_exception);
	stream_file_read (stream_file, sizeof (short), (char *)&dbg_header->sn_fixup);
	stream_file_read (stream_file, sizeof (short), (char *)&dbg_header->sn_omap_to_src);
	stream_file_read (stream_file, sizeof (short), (char *)&dbg_header->sn_omap_from_src);
	stream_file_read (stream_file, sizeof (short), (char *)&dbg_header->sn_section_hdr);
	stream_file_read (stream_file, sizeof (short), (char *)&dbg_header->sn_token_rid_map);
	stream_file_read (stream_file, sizeof (short), (char *)&dbg_header->sn_xdata);
	stream_file_read (stream_file, sizeof (short), (char *)&dbg_header->sn_pdata);
	stream_file_read (stream_file, sizeof (short), (char *)&dbg_header->sn_new_fpo);
	stream_file_read (stream_file, sizeof (short), (char *)&dbg_header->sn_section_hdr_orig);
}

///////////////////////////////////////////////////////////////////////////////
void init_dbi_stream(SDbiStream *dbi_stream) {
	dbi_stream->free_ = free_dbi_stream;
}

///////////////////////////////////////////////////////////////////////////////
void parse_dbi_stream(void *parsed_pdb_stream, R_STREAM_FILE *stream_file) {
	SDbiStream *dbi_stream = (SDbiStream *)parsed_pdb_stream;
	SDBIExHeader *dbi_ex_header = NULL;
	int pos = 0;
	ut8 *dbiexhdr_data = NULL, *p_tmp = NULL;
	int size = 0, sz = 0;
	int i = 0;

	parse_dbi_header (&dbi_stream->dbi_header, stream_file);
	pos += sizeof (SDBIHeader) - 2; // 2 because enum in C equal to 4, but
				// to read just 2;
	stream_file_seek (stream_file, pos, 0);

	size = dbi_stream->dbi_header.module_size;
	dbiexhdr_data = malloc (size);
	if (!dbiexhdr_data) {
		return;
	}
	stream_file_read (stream_file, size, (char *)dbiexhdr_data);

	dbi_stream->dbiexhdrs = r_list_new ();
	p_tmp = dbiexhdr_data;
	while (i < size) {
		dbi_ex_header = (SDBIExHeader *)malloc (sizeof (SDBIExHeader));
		if (!dbi_ex_header) {
			break;
		}
		// TODO: rewrite for signature where can to do chech CAN_READ true?
		sz = parse_dbi_ex_header (p_tmp, size, dbi_ex_header);
		if ((sz % PDB_ALIGN)) {
			sz = sz + (PDB_ALIGN - (sz % PDB_ALIGN));
		}
		i += sz;
		p_tmp += sz;
		r_list_append (dbi_stream->dbiexhdrs, dbi_ex_header);
	}

	free (dbiexhdr_data);

	// "Section Contribution"
	stream_file_seek (stream_file, dbi_stream->dbi_header.seccon_size, 1);
	// "Section Map"
	stream_file_seek (stream_file, dbi_stream->dbi_header.secmap_size, 1);
	// "File Info"
	stream_file_seek (stream_file, dbi_stream->dbi_header.filinf_size, 1);
	// "TSM"
	stream_file_seek (stream_file, dbi_stream->dbi_header.tsmap_size, 1);
	// "EC"
	stream_file_seek (stream_file, dbi_stream->dbi_header.ecinfo_size, 1);

	parse_dbg_header (&dbi_stream->dbg_header, stream_file);
}
