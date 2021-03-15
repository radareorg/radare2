/* radare - LGPL - Copyright 2014-2020 - inisider */

#include <r_pdb.h>
#include <r_bin.h>
#include <string.h>

#include "types.h"
#include "stream_pe.h"
#include "stream_file.h"
#include "tpi.h"
#include "dbi.h"
#include "fpo.h"
#include "gdata.h"
#include "omap.h"

#define PDB2_SIGNATURE "Microsoft C/C++ program database 2.00\r\n\032JG\0\0"
#define PDB2_SIGNATURE_LEN 51

#define PDB7_SIGNATURE "Microsoft C/C++ MSF 7.00\r\n\x1A" "DS\0\0\0"
#define PDB7_SIGNATURE_LEN 32

typedef void (*parse_stream_)(void *stream, R_STREAM_FILE *stream_file);

typedef struct {
	int indx;
	parse_stream_ parse_stream;
	void *stream;
	EStream type;
	free_func free;
} SStreamParseFunc;

///////////////////////////////////////////////////////////////////////////////
static void free_pdb_stream(void *stream) {
	R_PDB_STREAM *pdb_stream = (R_PDB_STREAM *) stream;
	if (pdb_stream) {
		// R_FREE (pdb_stream->pages);
		if (pdb_stream->pages) {
// free(pdb_stream->pages);
			pdb_stream->pages = 0;
		}
	}
}

/**
 * @brief Create a type name from offset
 *
 * @param offset
 * @return char* Name or NULL if error
 */
static char *create_type_name_from_offset(ut64 offset) {
	int offset_length = snprintf (NULL, 0, "type_0x%" PFMT64x, offset);
	char *str = malloc (offset_length + 1);
	snprintf (str, offset_length + 1, "type_0x%" PFMT64x, offset);
	return str;
}

// static void pdb_stream_get_data(R_PDB_STREAM *pdb_stream, char *data)
// {
// int pos = stream_file_tell(&pdb_stream->stream_file);
// stream_file_seek(&pdb_stream->stream_file, 0, 0);
// stream_file_read(&pdb_stream->stream_file, -1, data);
// stream_file_seek(&pdb_stream->stream_file, pos, 0);
// }

///////////////////////////////////////////////////////////////////////////////
/// size - default value = -1
/// page_size - default value = 0x1000
///////////////////////////////////////////////////////////////////////////////
static int init_r_pdb_stream(R_PDB_STREAM *pdb_stream, RBuffer *buf /*FILE *fp*/, int *pages,
			     int pages_amount, int index, int size, int page_size) {
	pdb_stream->buf = buf;
	pdb_stream->pages = pages;
	pdb_stream->indx = index;
	pdb_stream->page_size = page_size;
	pdb_stream->pages_amount = pages_amount;
	if (size == -1) {
		pdb_stream->size = pages_amount * page_size;
	} else {
		pdb_stream->size = size;
	}
	init_r_stream_file (&(pdb_stream->stream_file), buf, pages, pages_amount, size, page_size);
	pdb_stream->free_ = free_pdb_stream;

	return 1;
}

///////////////////////////////////////////////////////////////////////////////
static int read_int_var(char *var_name, int *var, RPdb *pdb) {
	if (var) {
		*var = 0;
	}
	int bytes_read = r_buf_read (pdb->buf, (ut8 *) var, 4);
	if (bytes_read != 4) {
		eprintf ("Error while reading from file '%s'\n", var_name);
		return 0;
	}
	return bytes_read;
}

///////////////////////////////////////////////////////////////////////////////
static int count_pages(int length, int page_size) {
	int num_pages = 0;
	if (page_size > 0) {
		num_pages = length / page_size;
		if (length % page_size) {
			num_pages++;
		}
	}
	return num_pages;
}

///////////////////////////////////////////////////////////////////////////////
static int init_pdb7_root_stream(RPdb *pdb, int *root_page_list, int pages_amount,
				 EStream indx, int root_size, int page_size) {
	R_PDB_STREAM *pdb_stream = 0;
	int tmp_data_max_size = 0;
	char *tmp_data = NULL, *data_end;
	int stream_size = 0;
	int num_streams = 0;
	int *sizes = NULL;
	int num_pages = 0;
	int data_size = 0;
	char *data = NULL;
	int i = 0;
	int pos = 0;

	R_PDB7_ROOT_STREAM *root_stream7;

	pdb->root_stream = R_NEW0 (R_PDB7_ROOT_STREAM);
	init_r_pdb_stream (&pdb->root_stream->pdb_stream, pdb->buf, root_page_list, pages_amount,
		indx, root_size, page_size);

	root_stream7 = pdb->root_stream;
	pdb_stream = &(root_stream7->pdb_stream);

	stream_file_get_size (&pdb_stream->stream_file, &data_size);
	data = (char *) calloc (1, data_size);
	if (!data) {
		return 0;
	}
	stream_file_get_data (&pdb_stream->stream_file, data);

	num_streams = *(int *) data;
	tmp_data = data;
	tmp_data += 4;

	root_stream7->num_streams = num_streams;

	tmp_data_max_size = (data_size - (num_streams * 4 - 4));
	data_end = data + tmp_data_max_size;
	if (tmp_data_max_size > data_size) {
		R_FREE (data);
		eprintf ("Invalid max tmp data size.\n");
		return 0;
	}
	if (num_streams < 0 || tmp_data_max_size <= 0) {
		R_FREE (data);
		eprintf ("Too many streams: current PDB file is incorrect.\n");
		return 0;
	}

	sizes = (int *) calloc (num_streams, 4);
	if (!sizes) {
		R_FREE (data);
		eprintf ("Size too big: current PDB file is incorrect.\n");
		return 0;
	}

	for (i = 0; i < num_streams && (tmp_data + 4 < data_end); i++) {
		stream_size = *(int *) (tmp_data);
		tmp_data += 4;
		if (stream_size == UT32_MAX) {
			stream_size = 0;
		}
		memcpy (sizes + i, &stream_size, 4);
	}

// char *tmp_file_name = (char *) malloc(strlen("/root/test.pdb.000") + 1);
// short ii;
// FILE *tmp_file;
	tmp_data = ((char *) data + num_streams * 4 + 4);
	root_stream7->streams_list = r_list_new ();
	RList *pList = root_stream7->streams_list;
	SPage *page = 0;
	for (i = 0; i < num_streams; i++) {
		num_pages = count_pages (sizes[i], page_size);

		if ((pos + num_pages) > tmp_data_max_size) {
			R_FREE (data);
			R_FREE (sizes);
			eprintf ("Warning: looks like there is no correct values of stream size in PDB file.\n");
			return 0;
		}

		ut32 size = num_pages * 4;
		ut8 *tmp = (ut8 *) calloc (num_pages, 4);
		page = R_NEW0 (SPage);
		if (num_pages != 0) {
			if ((pos + size) > tmp_data_max_size) {
				eprintf ("Data overrun by num_pages.\n");
				R_FREE (data);
				R_FREE (sizes);
				R_FREE (tmp);
				R_FREE (page);
				return 0;
			}
			memcpy (tmp, tmp_data + pos, num_pages * 4);
			pos += size;
// sprintf(tmp_file_name, "%s%d", "/root/test.pdb", i);
// tmp_file = fopen(tmp_file_name, "wb");
// fwrite(tmp, num_pages * 4, 1, tmp_file);
// fclose(tmp_file);
			page->stream_size = sizes[i];
			if (sizes[i] == 0) {
				//eprintf ("Warning: stream_size (%d) is 0\n", i);
			}
			page->stream_pages = tmp;
			page->num_pages = num_pages;
		} else {
			page->stream_size = 0;
			page->stream_pages = 0;
			page->num_pages = 0;
			//eprintf ("Warning: stream_size (%d) is 0\n", i);
			free (tmp);
		}

		r_list_append (pList, page);
	}
	free (sizes);
	free (data);
// printf("init_pdb7_root_stream()\n");
	return 1;
}

///////////////////////////////////////////////////////////////////////////////
// R2: ugly indentation
// static void init_parsed_pdb_stream(SParsedPDBStream *pdb_stream, FILE *fp, int *pages,
// int pages_amount, int index, int size,
// int page_size, f_load pLoad)
// {
// pdb_stream->pdb_stream = (R_PDB_STREAM *) malloc(sizeof(R_PDB_STREAM));
// init_r_pdb_stream(pdb_stream->pdb_stream, fp, pages, pages_amount, index, size, page_size);
// pdb_stream->load = pLoad;
// if (pLoad != NULL) {
// pLoad(pdb_stream, &(pdb_stream->pdb_stream->stream_file));
// }
// }

///////////////////////////////////////////////////////////////////////////////
static void parse_pdb_info_stream(void *parsed_pdb_stream, R_STREAM_FILE *stream) {
	SPDBInfoStream *tmp = (SPDBInfoStream *) parsed_pdb_stream;

	tmp->names = 0;

	stream_file_read (stream, 4, (char *) &tmp->/*data.*/ version);
	stream_file_read (stream, 4, (char *) &tmp->/*data.*/ time_date_stamp);
	stream_file_read (stream, 4, (char *) &tmp->/*data.*/ age);
	stream_file_read (stream, 4, (char *) &tmp->/*data.*/ guid.data1);
	stream_file_read (stream, 2, (char *) &tmp->/*data.*/ guid.data2);
	stream_file_read (stream, 2, (char *) &tmp->/*data.*/ guid.data3);
	stream_file_read (stream, 8, (char *) &tmp->/*data.*/ guid.data4);
	stream_file_read (stream, 4, (char *) &tmp->/*data.*/ cb_names);

	tmp->/*data.*/ names = (char *) calloc (1, tmp->/*data.*/ cb_names);
	stream_file_read (stream, tmp->/*data.*/ cb_names, tmp->/*data.*/ names);
}

///////////////////////////////////////////////////////////////////////////////
static void free_info_stream(void *stream) {
	SPDBInfoStream *info_stream = (SPDBInfoStream *) stream;
	free (info_stream->names);
}

///////////////////////////////////////////////////////////////////////////////
#define ADD_INDX_TO_LIST(list, index, stream_size, stream_type, free_func, parse_func) {\
		if ((index) != -1) {							\
			SStreamParseFunc *stream_parse_func = R_NEW0 (SStreamParseFunc);\
			if (!stream_parse_func) { return; }				\
			stream_parse_func->indx = (index);				\
			stream_parse_func->type = (stream_type);			\
			stream_parse_func->parse_stream = (parse_func);			\
			stream_parse_func->free = (free_func);				\
			if (stream_size) {						\
				stream_parse_func->stream = calloc (1, stream_size);	\
				if (!stream_parse_func->stream) {			\
					R_FREE (stream_parse_func);			\
					return;						\
				}							\
			} else {							\
				stream_parse_func->stream = 0;				\
			}								\
			r_list_append ((list), stream_parse_func);			\
		}									\
}

///////////////////////////////////////////////////////////////////////////////
static void fill_list_for_stream_parsing(RList *l, SDbiStream *dbi_stream) {
	ADD_INDX_TO_LIST (l, dbi_stream->dbi_header.symrecStream, sizeof (SGDATAStream),
		ePDB_STREAM_GSYM, free_gdata_stream, parse_gdata_stream);
	ADD_INDX_TO_LIST (l, dbi_stream->dbg_header.sn_section_hdr, sizeof (SPEStream),
		ePDB_STREAM_SECT_HDR, free_pe_stream, parse_pe_stream);
	ADD_INDX_TO_LIST (l, dbi_stream->dbg_header.sn_section_hdr_orig, sizeof(SPEStream),
		ePDB_STREAM_SECT__HDR_ORIG, free_pe_stream, parse_pe_stream);
	ADD_INDX_TO_LIST (l, dbi_stream->dbg_header.sn_omap_to_src, sizeof(SOmapStream),
		ePDB_STREAM_OMAP_TO_SRC, free_omap_stream, parse_omap_stream);
	ADD_INDX_TO_LIST (l, dbi_stream->dbg_header.sn_omap_from_src, sizeof(SOmapStream),
		ePDB_STREAM_OMAP_FROM_SRC, free_omap_stream, parse_omap_stream);
	ADD_INDX_TO_LIST (l, dbi_stream->dbg_header.sn_fpo, sizeof(SFPOStream),
		ePDB_STREAM_FPO, free_fpo_stream, parse_fpo_stream);
	ADD_INDX_TO_LIST (l, dbi_stream->dbg_header.sn_new_fpo, sizeof(SFPONewStream),
		ePDB_STREAM_FPO_NEW, free_fpo_stream, parse_fpo_new_stream);

	// unparsed, but know their names
	ADD_INDX_TO_LIST (l, dbi_stream->dbg_header.sn_xdata, 0, ePDB_STREAM_XDATA, 0, 0);
	ADD_INDX_TO_LIST (l, dbi_stream->dbg_header.sn_pdata, 0, ePDB_STREAM_PDATA, 0, 0);
	ADD_INDX_TO_LIST (l, dbi_stream->dbg_header.sn_token_rid_map, 0, ePDB_STREAM_TOKEN_RID_MAP, 0, 0);
}

///////////////////////////////////////////////////////////////////////////////
static void find_indx_in_list(RList *l, int index, SStreamParseFunc **res) {
	SStreamParseFunc *stream_parse_func = 0;
	RListIter *it = 0;

	*res = 0;
	it = r_list_iterator (l);
	while (r_list_iter_next (it)) {
		stream_parse_func = (SStreamParseFunc *) r_list_iter_get (it);
		if (index == stream_parse_func->indx) {
			*res = stream_parse_func;
			return;
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
static int pdb_read_root(RPdb *pdb) {
	int i = 0;
	RList *pList = pdb->pdb_streams;
	R_PDB7_ROOT_STREAM *root_stream = pdb->root_stream;
	R_PDB_STREAM *pdb_stream = 0;
	SPDBInfoStream *pdb_info_stream = 0;
	STpiStream *tpi_stream = 0;
	R_STREAM_FILE stream_file;
	RListIter *it;
	SPage *page = 0;
	SStreamParseFunc *stream_parse_func = 0;

	it = r_list_iterator (root_stream->streams_list);
	while (r_list_iter_next (it)) {
		page = (SPage *) r_list_iter_get (it);
		if (page->stream_pages == 0) {
			//eprintf ("Warning: no stream pages. Skipping.\n");
			r_list_append (pList, NULL);
			i++;
			continue;
		}
		init_r_stream_file (&stream_file, pdb->buf, (int *) page->stream_pages,
			page->num_pages	/*root_stream->pdb_stream.pages_amount*/,
			page->stream_size,
			root_stream->pdb_stream.page_size);
		switch (i) {
		// TODO: rewrite for style like for streams from dbg stream
		// look default
		case ePDB_STREAM_PDB:
			pdb_info_stream = R_NEW0 (SPDBInfoStream);
			if (!pdb_info_stream) {
				return 0;
			}
			pdb_info_stream->free_ = free_info_stream;
			parse_pdb_info_stream (pdb_info_stream, &stream_file);
			r_list_append (pList, pdb_info_stream);
			break;
		case ePDB_STREAM_TPI:
			tpi_stream = R_NEW0 (STpiStream);
			if (!tpi_stream) {
				return 0;
			}
			init_tpi_stream (tpi_stream);
			if (!parse_tpi_stream (tpi_stream, &stream_file)) {
				free (tpi_stream);
				return 0;
			}
			r_list_append (pList, tpi_stream);
			break;
		case ePDB_STREAM_DBI:
		{
			SDbiStream *dbi_stream = R_NEW0 (SDbiStream);
			if (!dbi_stream) {
				return 0;
			}
			init_dbi_stream (dbi_stream);
			parse_dbi_stream (dbi_stream, &stream_file);
			r_list_append (pList, dbi_stream);
			pdb->pdb_streams2 = r_list_new ();
			fill_list_for_stream_parsing (pdb->pdb_streams2, dbi_stream);
			break;
		}
		default:
			find_indx_in_list (pdb->pdb_streams2, i, &stream_parse_func);
			if (stream_parse_func && stream_parse_func->parse_stream) {
				stream_parse_func->parse_stream (stream_parse_func->stream, &stream_file);
				break;
			}

			pdb_stream = R_NEW0 (R_PDB_STREAM);
			if (!pdb_stream) {
				return 0;
			}
			init_r_pdb_stream (pdb_stream, pdb->buf, (int *) page->stream_pages,
				root_stream->pdb_stream.pages_amount, i,
				page->stream_size, root_stream->pdb_stream.page_size);
			r_list_append (pList, pdb_stream);
			break;
		}
		if (stream_file.error) {
			return 0;
		}
		i++;
	}
	return 1;
}

static bool pdb7_parse(RPdb *pdb) {
	char signature[PDB7_SIGNATURE_LEN + 1];
	int num_root_index_pages = 0;
	int *root_index_pages = 0;
	void *root_page_data = 0;
	int *root_page_list = 0;
	int num_root_pages = 0;
	int num_file_pages = 0;
	int alloc_tbl_ptr = 0;
	int bytes_read = 0;
	int page_size = 0;
	int root_size = 0;
	int reserved = 0;
	void *p_tmp;
	int i = 0;

	bytes_read = r_buf_read (pdb->buf, (unsigned char *) signature, PDB7_SIGNATURE_LEN);
	if (bytes_read != PDB7_SIGNATURE_LEN) {
		//eprintf ("Error while reading PDB7_SIGNATURE.\n");
		goto error;
	}
	if (!read_int_var ("page_size", &page_size, pdb)) {
		goto error;
	}
	if (!read_int_var ("alloc_tbl_ptr", &alloc_tbl_ptr, pdb)) {
		goto error;
	}
	if (!read_int_var ("num_file_pages", &num_file_pages, pdb)) {
		goto error;
	}
	if (!read_int_var ("root_size", &root_size, pdb)) {
		goto error;
	}
	if (!read_int_var ("reserved", &reserved, pdb)) {
		goto error;
	}
	if (memcmp (signature, PDB7_SIGNATURE, PDB7_SIGNATURE_LEN) != 0) {
		eprintf ("Invalid signature for PDB7 format.\n");
		goto error;
	}

	num_root_pages = count_pages (root_size, page_size);
	num_root_index_pages = count_pages ((num_root_pages * 4), page_size);
	root_index_pages = (int *) calloc (sizeof (int), R_MAX (num_root_index_pages, 1));
	if (!root_index_pages) {
		eprintf ("Error memory allocation.\n");
		goto error;
	}

	bytes_read = r_buf_read (pdb->buf, (unsigned char *) root_index_pages, 4 * num_root_index_pages);
	// fread(root_index_pages, 4, num_root_index_pages, pdb->fp);
	if (bytes_read != 4 * num_root_index_pages) {
		eprintf ("Error while reading root_index_pages.\n");
		goto error;
	}
	if (page_size < 1 || num_root_index_pages < 1) {
		eprintf ("Invalid root index pages size.\n");
		goto error;
	}
	root_page_data = (int *) calloc (page_size, num_root_index_pages);
	if (!root_page_data) {
		eprintf ("Error: memory allocation of root_page_data.\n");
		goto error;
	}
	p_tmp = root_page_data;
	for (i = 0; i < num_root_index_pages; i++) {
		if (UT64_MUL_OVFCHK (root_index_pages[i], page_size)) {
			break;
		}
		r_buf_seek (pdb->buf, root_index_pages[i] * page_size,
			   R_BUF_SET);
		r_buf_read (pdb->buf, p_tmp, page_size);
		p_tmp = (char *) p_tmp + page_size;
	}
	root_page_list = (int *) calloc (sizeof(int), num_root_pages);
	if (!root_page_list) {
		eprintf ("Error: memory allocation of root page.\n");
		goto error;
	}

	p_tmp = root_page_data;
	for (i = 0; i < num_root_pages; i++) {
		root_page_list[i] = *((int *) p_tmp);
		p_tmp = (int *) p_tmp + 1;
	}

	pdb->pdb_streams2 = NULL;
	if (!init_pdb7_root_stream (pdb, root_page_list, num_root_pages,
		    ePDB_STREAM_ROOT, root_size, page_size)) {
		eprintf ("Could not initialize root stream.\n");
		goto error;
	}
	if (!pdb_read_root (pdb)) {
		eprintf ("PDB root was not initialized.\n");
		goto error;
	}

	R_FREE (root_page_list);
	R_FREE (root_page_data);
	R_FREE (root_index_pages);
	return true;
error:
	R_FREE (root_page_list);
	R_FREE (root_page_data);
	R_FREE (root_index_pages);
	return false;
}

static void finish_pdb_parse(RPdb *pdb) {
	R_PDB7_ROOT_STREAM *p = pdb->root_stream;
	RListIter *it;
	SPage *page = 0;

	if (!p) {
		return;
	}
	it = r_list_iterator (p->streams_list);
	while (r_list_iter_next (it)) {
		page = (SPage *) r_list_iter_get (it);
		free (page->stream_pages);
		page->stream_pages = 0;
		free (page);
		page = 0;
	}
	r_list_free (p->streams_list);
	p->streams_list = 0;
	free (p);
	p = 0;
	// end of free of R_PDB7_ROOT_STREAM

	// TODO: maybe create some kind of destructor?
	// free of pdb->pdb_streams
// SParsedPDBStream *parsed_pdb_stream = 0;
	SPDBInfoStream *pdb_info_stream = 0;
	STpiStream *tpi_stream = 0;
	SDbiStream *dbi_stream = 0;
	SStreamParseFunc *stream_parse_func;
	R_PDB_STREAM *pdb_stream = 0;
	int i = 0;
#if 1
/* r_list_free should be enough, all the items in a list should be freeable using a generic destructor
   hacking up things like that may only produce problems. so it is better to not assume that a specific
   element in a list is of a specific type and just store this info in the type struct or so.
*/
// XXX: this loop is fucked up. i prefer to leak than crash
	it = r_list_iterator (pdb->pdb_streams);
	while (r_list_iter_next (it)) {
		switch (i) {
		case 1:
			pdb_info_stream = (SPDBInfoStream *) r_list_iter_get (it);
			free_pdb_stream (pdb_info_stream);
			free (pdb_info_stream);
			break;
		case 2:
			tpi_stream = (STpiStream *) r_list_iter_get (it);
			free_pdb_stream (tpi_stream);
			free (tpi_stream);
			break;
		case 3:
			dbi_stream = (SDbiStream *) r_list_iter_get (it);
			free_pdb_stream (dbi_stream);
			free (dbi_stream);
			break;
		default:
			find_indx_in_list (pdb->pdb_streams2, i, &stream_parse_func);
			if (stream_parse_func) {
				break;
			}
			pdb_stream = (R_PDB_STREAM *) r_list_iter_get (it);
			free_pdb_stream (pdb_stream);
			free (pdb_stream);
			break;
		}
		i++;
	}
#endif
	r_list_free (pdb->pdb_streams);
	// enf of free of pdb->pdb_streams

#if 1
	// start of free pdb->pdb_streams2
	it = r_list_iterator (pdb->pdb_streams2);
	while (r_list_iter_next (it)) {
		stream_parse_func = (SStreamParseFunc *) r_list_iter_get (it);
		if (stream_parse_func->free) {
			stream_parse_func->free (stream_parse_func->stream);
			free (stream_parse_func->stream);
		}
		free (stream_parse_func);
	}
#endif
	r_list_free (pdb->pdb_streams2);
	// end of free pdb->streams2

	free (pdb->stream_map);
	r_buf_free (pdb->buf);

// fclose(pdb->fp);
// printf("finish_pdb_parse()\n");
}

static SimpleTypeMode get_simple_type_mode (PDB_SIMPLE_TYPES type) {
	ut32 value = type; // cast to unsigned for defined bitwise operations
	/*   https://llvm.org/docs/PDB/TpiStream.html#type-indices
        .---------------------------.------.----------.
        |           Unused          | Mode |   Kind   |
        '---------------------------'------'----------'
        |+32                        |+12   |+8        |+0
	*/
	// because mode is only number between 0-7, 1 byte is enough
	return (value & 0x00000000F0000);
}

static SimpleTypeKind get_simple_type_kind (PDB_SIMPLE_TYPES type) {
	ut32 value = type; // cast to unsigned for defined bitwise operations
	/*   https://llvm.org/docs/PDB/TpiStream.html#type-indices
        .---------------------------.------.----------.
        |           Unused          | Mode |   Kind   |
        '---------------------------'------'----------'
        |+32                        |+12   |+8        |+0
	*/
	return (value & 0x00000000000FF);
}

/**
 * @brief Maps simple type into a format string for `pf`
 *
 * @param simple_type
 * @param member_format pointer to assert member format to
 * @return int -1 if it's unparsable, -2 if it should be skipped, 0 if all is correct
 */
static int simple_type_to_format (const SLF_SIMPLE_TYPE *simple_type, char **member_format) {
	SimpleTypeMode mode = get_simple_type_mode (simple_type->simple_type);
	switch (mode) {
	case DIRECT: {
		SimpleTypeKind kind = get_simple_type_kind (simple_type->simple_type);
		switch (kind) {
		case PDB_NONE:
		case PDB_VOID:
		case PDB_NOT_TRANSLATED:
		case PDB_HRESULT:
			return -1;
			break;
		case PDB_SIGNED_CHAR:
		case PDB_NARROW_CHAR:
			*member_format = "c";
			break;
		case PDB_UNSIGNED_CHAR:
			*member_format = "b";
			break;
		case PDB_SBYTE:
			*member_format = "n1";
			break;
		case PDB_BOOL8:
		case PDB_BYTE:
			*member_format = "N1";
			break;
		case PDB_INT16_SHORT:
		case PDB_INT16:
			*member_format = "n2";
			break;
		case PDB_UINT16_SHORT:
		case PDB_UINT16:
		case PDB_WIDE_CHAR: // TODO what ideal format for wchar?
		case PDB_CHAR16:
		case PDB_BOOL16:
			*member_format = "N2";
			break;
		case PDB_INT32_LONG:
		case PDB_INT32:
			*member_format = "n4";
			break;
		case PDB_UINT32_LONG:
		case PDB_UINT32:
		case PDB_CHAR32:
		case PDB_BOOL32:
			*member_format = "N4";
			break;
		case PDB_INT64_QUAD:
		case PDB_INT64:
			*member_format = "n8";
			break;
		case PDB_UINT64_QUAD:
		case PDB_UINT64:
		case PDB_BOOL64:
			*member_format = "N8";
			break;
		// TODO these when formatting for them will exist
		case PDB_INT128_OCT:
		case PDB_UINT128_OCT:
		case PDB_INT128:
		case PDB_UINT128:
		case PDB_BOOL128:
			*member_format = "::::";
			return -2;
			////////////////////////////////////
			// TODO these when formatting for them will exist
			// I assume complex are made up by 2 floats
		case PDB_COMPLEX16:
			*member_format = "..";
			return -2;
		case PDB_COMPLEX32:
		case PDB_COMPLEX32_PP:
			*member_format = ":";
			return -2;
		case PDB_COMPLEX48:
			*member_format = ":.";
			return -2;
		case PDB_COMPLEX64:
			*member_format = "::";
			return -2;
		case PDB_COMPLEX80:
			*member_format = "::..";
			return -2;
		case PDB_COMPLEX128:
			*member_format = "::::";
			return -2;

		case PDB_FLOAT32:
		case PDB_FLOAT32_PP:
			*member_format = "f";
			break;
		case PDB_FLOAT64:
			*member_format = "F";
			break;
			////////////////////////////////////
			// TODO these when formatting for them will exist
		case PDB_FLOAT16:
			*member_format = "..";
			return -2;
		case PDB_FLOAT48:
			*member_format = ":.";
			return -2;
		case PDB_FLOAT80:
			*member_format = "::..";
			return -2;
		case PDB_FLOAT128:
			*member_format = "::::";
			return -2;
		default:
			r_warn_if_reached ();
			break;
		}
		break;
	}
	case NEAR_POINTER:
		*member_format = "p2";
		break;
	case FAR_POINTER:
		*member_format = "p4";
		break;
	case HUGE_POINTER:
		*member_format = "p4";
		break;
	case NEAR_POINTER32:
		*member_format = "p4";
		break;
	case FAR_POINTER32:
		*member_format = "p4";
		break;
	case NEAR_POINTER64:
		*member_format = "p8";
		break;
	case NEAR_POINTER128:
		*member_format = "p8::"; // TODO fix when support for 16 bytes
		break;
	default:
		// unknown mode ??
		r_warn_if_reached ();
		return -1;
	}
	return 0;
}

/**
 * @brief Creates the format string and puts it into format
 *
 * @param type_info Information about the member type
 * @param format buffer for the formatting string
 * @param names buffer for the member names
 * @return int -1 if it can't build the format
 */
static int build_member_format(STypeInfo *type_info, RStrBuf *format, RStrBuf *names) {
	r_return_val_if_fail (type_info && format && names && type_info->type_info, -1);
	// THOUGHT: instead of not doing anything for unknown types I can just skip the bytes
	// format is 2 chars tops + null terminator

	char *name = NULL;
	if (type_info->get_name) {
		type_info->get_name (type_info, &name);
	}
	if (!name) { // name should never be null, but malformed PDB exists
		return -1;
	}
	name = r_str_sanitize_sdb_key (name);

	SType *under_type = NULL;
	if (type_info->leaf_type == eLF_MEMBER ||
		type_info->leaf_type == eLF_NESTTYPE) {
		if (type_info->get_index) {
			type_info->get_index (type_info, (void **)&under_type);
		} else {
			r_warn_if_reached ();
		}
	} else if (type_info->leaf_type == eLF_METHOD ||
		type_info->leaf_type == eLF_ONEMETHOD) {
		return 0; // skip method member
	} else {
		r_warn_if_reached ();
		return -1;
	}
	type_info = &under_type->type_data;

	char *member_format = NULL;
	char tmp_format[5] = { 0 }; // used as writable format buffer

	switch (type_info->leaf_type) {
	case eLF_SIMPLE_TYPE: {
		int map_result = 0;
		if ((map_result = simple_type_to_format (type_info->type_info, &member_format)) != 0) {
			if (map_result == -1) { // unparsable
				goto error;
			} else if (map_result == -2) { // skip
				goto skip;
			}
		}
		r_strbuf_append (names, name);
		break;
	}
	case eLF_POINTER: {
		int size = 4;
		if (type_info->get_val) {
			type_info->get_val (type_info, &size);
		}
		snprintf (tmp_format, 5, "p%d", size);
		member_format = tmp_format;
		r_strbuf_append (names, name);
		break;
	}
	case eLF_CLASS:
	case eLF_UNION:
	case eLF_STRUCTURE: {
		member_format = "?";
		char *field_name = NULL;
		if (type_info->get_name) {
			type_info->get_name (type_info, &field_name);
		}
		if (!field_name) {
			field_name = create_type_name_from_offset (under_type->tpi_idx);
		} else {
			field_name = r_str_sanitize_sdb_key (field_name);
		}
		r_strbuf_appendf (names, "(%s)%s", field_name, name);
		free (field_name);
		break;
	}
	// TODO complete the type with additional info
	case eLF_BITFIELD: {
		member_format = "B";
		r_strbuf_appendf (names, "(uint)%s", name);
		break;
	}
	 // TODO complete the type with additional info
	case eLF_ENUM: {
		member_format = "E";
		r_strbuf_appendf (names, "(int)%s", name);
		break;
	}
	case eLF_ARRAY: {
		int size = 0;
		if (type_info->get_val) {
			type_info->get_val (type_info, &size);
		}
		snprintf (tmp_format, 5, "[%d]", size);
		member_format = tmp_format;
		r_strbuf_append (names, name); // TODO complete the type with additional info
		break;
	}

	default:
		r_warn_if_reached (); // Unhandled type format
		goto error;
	}

	if (!member_format) {
		r_warn_if_reached (); // Unhandled type format
		goto error;
	}
	r_strbuf_append (format, member_format);
skip: // shortcut for unknown types where we only skip the bytes
	free (name);
	return 0;
error:
	free (name);
	return -1;
}

static inline bool is_printable_type(ELeafType type) {
	return (type == eLF_STRUCTURE ||
		type == eLF_UNION ||
		type == eLF_ENUM ||
		type == eLF_CLASS);
}

/**
 * @brief Gets the name of the enum base type
 *
 * @param type_info Enum TypeInfo
 * @return char* name of the base type
 */
static char *get_enum_base_type_name(STypeInfo *type_info) {
	char *base_type_name = NULL;
	if (type_info->get_utype) {
		SType *base_type = NULL;
		type_info->get_utype (type_info, (void **)&base_type);
		if (base_type && base_type->type_data.leaf_type == eLF_SIMPLE_TYPE) {
			SLF_SIMPLE_TYPE *tmp = base_type->type_data.type_info;
			base_type_name = tmp->type;
		}
	}
	if (!base_type_name) {
		base_type_name = "unknown_t";
	}
	return base_type_name;
}

/**
 * @brief Prints out structure and class leaf types
 *
 * @param name Name of the structure/class
 * @param size Size of the structure/class
 * @param members List of members
 * @param printf Print function
 */
static void print_struct(const char *name, const int size, const RList *members, PrintfCallback printf) {
	r_return_if_fail (name && printf);
	printf ("struct %s { // size 0x%x\n", name, size);

	RListIter *member_iter = r_list_iterator (members);
	while (r_list_iter_next (member_iter)) {
		STypeInfo *type_info = r_list_iter_get (member_iter);
		char *member_name = NULL;
		if (type_info->get_name) {
			type_info->get_name (type_info, &member_name);
		}
		int offset = 0;
		if (type_info->get_val) {
			type_info->get_val (type_info, &offset);
		}
		char *type_name = NULL;
		if (type_info->get_print_type) {
			type_info->get_print_type (type_info, &type_name);
		}
		printf ("  %s %s; // offset +0x%x\n", type_name, member_name, offset);
		R_FREE (type_name);
	}
	printf ("};\n");
}

/**
 * @brief Prints out union leaf type
 *
 * @param name Name of the union
 * @param size Size of the union
 * @param members List of members
 * @param printf Print function
 */
static void print_union(const char *name, const int size, const RList *members, PrintfCallback printf) {
	r_return_if_fail (name && printf);
	printf ("union %s { // size 0x%x\n", name, size);

	RListIter *member_iter = r_list_iterator (members);
	while (r_list_iter_next (member_iter)) {
		STypeInfo *type_info = r_list_iter_get (member_iter);
		char *member_name = NULL;
		if (type_info->get_name) {
			type_info->get_name (type_info, &member_name);
		}
		int offset = 0;
		if (type_info->get_val) {
			type_info->get_val (type_info, &offset);
		}
		char *type_name = NULL;
		if (type_info->get_print_type) {
			type_info->get_print_type (type_info, &type_name);
		}
		printf ("  %s %s;\n", type_name, member_name);
		R_FREE (type_name);
	}
	printf ("};\n");
}

/**
 * @brief Prints out enum leaf type
 *
 * @param name Name of the enum
 * @param type type of the enum
 * @param members List of cases
 * @param printf Print function
 */
static void print_enum(const char *name, const char *type, const RList *members, PrintfCallback printf) {
	r_return_if_fail (name && printf);
	printf ("enum %s { // type: %s\n", name, type);

	RListIter *member_iter = r_list_iterator (members);
	while (r_list_iter_next (member_iter)) {
		STypeInfo *type_info = r_list_iter_get (member_iter);
		char *member_name = NULL;
		if (type_info->get_name) {
			type_info->get_name (type_info, &member_name);
		}
		int value = 0;
		if (type_info->get_val) {
			type_info->get_val (type_info, &value);
		}
		printf ("  %s = %d,\n", member_name, value);
	}
	printf ("};\n");
}

/**
 * @brief Prints out types in a default format "idpi" command
 *
 * @param pdb pdb structure for printing function
 * @param types List of types
 */
static void print_types_regular(const RPdb *pdb, const RList *types) {
	r_return_if_fail (pdb && types);
	RListIter *it = r_list_iterator (types);

	while (r_list_iter_next (it)) {
		SType *type = r_list_iter_get (it);
		STypeInfo *type_info = &type->type_data;
		// skip unprintable types
		if (!type || !is_printable_type (type_info->leaf_type)) {
			continue;
		}
		// skip forward references
		if (type_info->is_fwdref) {
			int is_fwdref = 0;
			type_info->is_fwdref (type_info, &is_fwdref);
			if (is_fwdref == 1) {
				continue;
			}
		}
		char *name = NULL;
		if (type_info->get_name) {
			type_info->get_name (type_info, &name);
		}
		int size = 0;
		if (type_info->get_val) {
			type_info->get_val (type_info, &size);
		}
		RList *members = NULL;
		if (type_info->get_members) { // do we wanna print empty types?
			type_info->get_members (type_info, &members);
		}

		switch (type_info->leaf_type) {
		case eLF_CLASS:
		case eLF_STRUCTURE:
			print_struct (name, size, members, pdb->cb_printf);
			break;
		case eLF_UNION:
			print_union (name, size, members, pdb->cb_printf);
			break;
		case eLF_ENUM:;
			print_enum (name, get_enum_base_type_name (type_info), members, pdb->cb_printf);
			break;
		default:
			// Unimplemented printing of printable type
			r_warn_if_reached ();
			break;
		}
	}
}

/**
 * @brief Prints out types in a json format - "idpij" command
 *
 * @param pdb pdb structure for printing function
 * @param types List of types
 */
static void print_types_json(const RPdb *pdb, PJ *pj, const RList *types) {
	r_return_if_fail (pdb && types && pj);

	RListIter *it = r_list_iterator (types);

	pj_ka (pj, "types");

	while (r_list_iter_next (it)) {
		SType *type = r_list_iter_get (it);
		STypeInfo *type_info = &type->type_data;
		// skip unprintable types
		if (!type || !is_printable_type (type_info->leaf_type)) {
			continue;
		}
		// skip forward references
		if (type_info->is_fwdref) {
			int is_fwdref = 0;
			type_info->is_fwdref (type_info, &is_fwdref);
			if (is_fwdref == 1) {
				continue;
			}
		}
		// get the necessary type information
		char *name = NULL;
		if (type_info->get_name) {
			type_info->get_name (type_info, &name);
		}
		int size = 0;
		if (type_info->get_val) {
			type_info->get_val (type_info, &size);
		}
		RList *members = NULL; // Should we print empty structures/enums?
		if (type_info->get_members) {
			type_info->get_members (type_info, &members);
		}

		// Maybe refactor these into their own functions aswell
		switch (type_info->leaf_type) {
		case eLF_CLASS:
		case eLF_STRUCTURE:
		case eLF_UNION: {
			pj_o (pj);
			pj_ks (pj, "type", "structure");
			pj_ks (pj, "name", name);
			pj_kn (pj, "size", size);
			pj_ka (pj, "members");

			if (members) {
				RListIter *member_iter = r_list_iterator (members);
				while (r_list_iter_next (member_iter)) {
					pj_o (pj);
					STypeInfo *type_info = r_list_iter_get (member_iter);
					char *member_name = NULL;
					if (type_info->get_name) {
						type_info->get_name (type_info, &member_name);
					}
					int offset = 0;
					if (type_info->get_val) {
						type_info->get_val (type_info, &offset);
					}
					char *type_name = NULL;
					if (type_info->get_print_type) {
						type_info->get_print_type (type_info, &type_name);
					}
					pj_ks (pj, "member_type", type_name);
					pj_ks (pj, "member_name", member_name);
					pj_kN (pj, "offset", offset);
					pj_end (pj);
					R_FREE (type_name);
				}
			}
			pj_end (pj);
			pj_end (pj);
			break;
		}
		case eLF_ENUM: {
			pj_o (pj);
			pj_ks (pj, "type", "enum");
			pj_ks (pj, "name", name);
			pj_ks (pj, "base_type", get_enum_base_type_name (type_info));
			pj_ka (pj, "cases");

			if (members) {
				RListIter *member_iter = r_list_iterator (members);
				while (r_list_iter_next (member_iter)) {
					pj_o (pj);
					STypeInfo *type_info = r_list_iter_get (member_iter);
					char *member_name = NULL;
					if (type_info->get_name) {
						type_info->get_name (type_info, &member_name);
					}
					int value = 0;
					if (type_info->get_val) {
						type_info->get_val (type_info, &value);
					}
					pj_ks (pj, "enum_name", member_name);
					pj_kn (pj, "enum_val", value);
					pj_end (pj);
				}
			}
			pj_end (pj);
			pj_end (pj);
			break;
		}
		default:
			// Unimplemented printing of printable type
			r_warn_if_reached ();
			break;
		}
	}
	pj_end (pj);
}

/**
 * @brief Creates pf commands from PDB types - "idpi*" command
 *
 * @param pdb pdb structure for printing function
 * @param types List of types
 */
static void print_types_format(const RPdb *pdb, const RList *types) {
	r_return_if_fail (pdb && types);
	RListIter *it = r_list_iterator (types);
	bool to_free_name = false;
	while (r_list_iter_next (it)) {
		SType *type = r_list_iter_get (it);
		STypeInfo *type_info = &type->type_data;
		// skip unprintable types and enums
		if (!type || !is_printable_type (type_info->leaf_type) || type_info->leaf_type == eLF_ENUM) {
			continue;
		}
		// skip forward references
		if (type_info->is_fwdref) {
			int is_fwdref = 0;
			type_info->is_fwdref (type_info, &is_fwdref);
			if (is_fwdref == 1) {
				continue;
			}
		}
		char *name = NULL;
		if (type_info->get_name) {
			type_info->get_name (type_info, &name);
		}
		if (!name) {
			name = create_type_name_from_offset (type->tpi_idx);
			to_free_name = true;
		}
		int size = 0;
		if (type_info->get_val) {
			type_info->get_val (type_info, &size);
		}
		RList *members = NULL;
		if (type_info->get_members) {
			type_info->get_members (type_info, &members);
		}
		// pf.name <format chars> <member names>
		RStrBuf format;
		r_strbuf_init (&format);
		RStrBuf member_names;
		r_strbuf_init (&member_names);

		if (type_info->leaf_type == eLF_UNION) {
			r_strbuf_append (&format, "0");	 // every type start from the offset 0
		}

		RListIter *member_iter = r_list_iterator (members);
		while (r_list_iter_next (member_iter)) {
			STypeInfo *member_info = r_list_iter_get (member_iter);
			switch (type_info->leaf_type) {
			case eLF_STRUCTURE:
			case eLF_CLASS:
			case eLF_UNION:
				if (build_member_format (member_info, &format, &member_names) == -1) { // if failed
					goto fail; // skip to the next one, we can't build format from this
				}
				break;
			default:
				r_warn_if_reached ();
			}
			r_strbuf_append (&member_names, " ");
		}
		if (format.len == 0) { // if it has no members, it's useless for us then?
			goto fail;
		}
		char *sanitized_name = r_str_sanitize_sdb_key (name);
		pdb->cb_printf ("pf.%s %s %s\n", sanitized_name, r_strbuf_get (&format), r_strbuf_get (&member_names));

		if (to_free_name) { // name can be generated or part of the PDB data
			R_FREE (name);
		}
		R_FREE (sanitized_name);
		r_strbuf_fini (&format);
		r_strbuf_fini (&member_names);

	fail: // if we can't print whole type correctly, don't print at all
		if (to_free_name) {
			R_FREE (name);
		}
		r_strbuf_fini (&format);
		r_strbuf_fini (&member_names);
	}
}

/**
 * @brief Prints out all the type information in regular,json or pf format
 *
 * @param pdb PDB information
 * @param mode printing mode
 */
static void print_types(const RPdb *pdb, PJ *pj, const int mode) {
	RList *plist = pdb->pdb_streams;
	STpiStream *tpi_stream = r_list_get_n (plist, ePDB_STREAM_TPI);

	if (!tpi_stream) {
		eprintf ("There is no tpi stream in current pdb\n");
		return;
	}
	switch (mode) {
	case 'd': print_types_regular (pdb, tpi_stream->types); return;
	case 'j': print_types_json (pdb, pj, tpi_stream->types); return;
	case 'r': print_types_format (pdb, tpi_stream->types); return;
	}
}

///////////////////////////////////////////////////////////////////////////////
static void print_gvars(RPdb *pdb, ut64 img_base, PJ *pj, int format) {
	SStreamParseFunc *omap = 0, *sctns = 0, *sctns_orig = 0, *gsym = 0, *tmp = 0;
	SIMAGE_SECTION_HEADER *sctn_header = 0;
	SGDATAStream *gsym_data_stream = 0;
	SPEStream *pe_stream = 0;
	SGlobal *gdata = 0;
	RListIter *it = 0;
	RList *l = 0;
	char *name;

	l = pdb->pdb_streams2;
	it = r_list_iterator (l);
	while (r_list_iter_next (it)) {
		tmp = (SStreamParseFunc *) r_list_iter_get (it);
		switch (tmp->type) {
		case ePDB_STREAM_SECT__HDR_ORIG:
			sctns_orig = tmp;
			break;
		case ePDB_STREAM_SECT_HDR:
			sctns = tmp;
			break;
		case ePDB_STREAM_OMAP_FROM_SRC:
			omap = tmp;
			break;
		case ePDB_STREAM_GSYM:
			gsym = tmp;
			break;
		default:
			break;
		}
	}
	if (!gsym) {
		eprintf ("There is no global symbols in current PDB.\n");
		return;
	}

	if (format == 'j') {
		pj_ka (pj, "gvars");
	}
	gsym_data_stream = (SGDATAStream *)gsym->stream;
	if ((omap != 0) && (sctns_orig != 0)) {
		pe_stream = (SPEStream *)sctns_orig->stream;
	} else {
		if (sctns) {
			pe_stream = (SPEStream *)sctns->stream;
		}
	}
	if (!pe_stream) {
		return;
	}
	it = r_list_iterator (gsym_data_stream->globals_list);
	while (r_list_iter_next (it)) {
		gdata = (SGlobal *)r_list_iter_get (it);
		sctn_header = r_list_get_n (pe_stream->sections_hdrs, (gdata->segment - 1));
		if (sctn_header) {
			char *filtered_name;
			name = r_bin_demangle_msvc (gdata->name.name);
			name = (name) ? name : strdup (gdata->name.name);
			switch (format) {
			case 2:
			case 'j': // JSON
				pj_o (pj);
				pj_kN (pj, "address", (img_base + omap_remap ((omap) ? (omap->stream) : 0, gdata->offset + sctn_header->virtual_address)));
				pj_kN (pj, "symtype", gdata->symtype);
				pj_ks (pj, "section_name", sctn_header->name);
				pj_ks (pj, "gdata_name", name);
				pj_end (pj);
				break;
			case 1:
			case '*':
			case 'r':
				filtered_name = r_name_filter2 (r_str_trim_head_ro (name));
				pdb->cb_printf ("f pdb.%s = 0x%" PFMT64x " # %d %.*s\n",
					filtered_name,
					(ut64) (img_base + omap_remap ((omap) ? (omap->stream) : 0, gdata->offset + sctn_header->virtual_address)),
					gdata->symtype, PDB_SIZEOF_SECTION_NAME, sctn_header->name);
				pdb->cb_printf ("\"fN pdb.%s %s\"\n", filtered_name, name);
				free (filtered_name);
				break;
			case 'd':
			default:
				pdb->cb_printf ("0x%08" PFMT64x "  %d  %.*s  %s\n",
					(ut64) (img_base + omap_remap ((omap) ? (omap->stream) : 0, gdata->offset + sctn_header->virtual_address)),
					gdata->symtype, PDB_SIZEOF_SECTION_NAME, sctn_header->name, name);
				break;
			}
			free (name);
		} else {
			//eprintf ("Skipping %s, segment %d does not exist\n",
			//gdata->name.name, (gdata->segment - 1));
		}
	}
	if (format == 'j') {
		pj_end (pj);
	}
}

///////////////////////////////////////////////////////////////////////////////
R_API bool init_pdb_parser_with_buf(RPdb *pdb, RBuffer* buf) {
	char *signature = NULL;
	int bytes_read = 0;

	if (!pdb) {
		eprintf ("R_PDB structure is incorrect.\n");
		goto error;
	}
	if (!pdb->cb_printf) {
		pdb->cb_printf = (PrintfCallback)printf;
	}
	pdb->buf = buf;
	if (!pdb->buf) {
		eprintf ("Invalid PDB buffer\n");
		goto error;
	}
	signature = (char *) calloc (1, PDB7_SIGNATURE_LEN);
	if (!signature) {
		eprintf ("Memory allocation error.\n");
		goto error;
	}

	bytes_read = r_buf_read (pdb->buf, (ut8 *) signature, PDB7_SIGNATURE_LEN);
	if (bytes_read != PDB7_SIGNATURE_LEN) {
		eprintf ("PDB reading error.\n");
		goto error;
	}

	r_buf_seek (pdb->buf, 0, R_BUF_SET);

	if (!memcmp (signature, PDB7_SIGNATURE, PDB7_SIGNATURE_LEN)) {
		pdb->pdb_parse = pdb7_parse;
	} else {
		goto error;
	}

	R_FREE (signature);

	pdb->pdb_streams = r_list_new ();
	pdb->stream_map = 0;
	pdb->finish_pdb_parse = finish_pdb_parse;
	pdb->print_types = print_types;
	pdb->print_gvars = print_gvars;
// printf("init_pdb_parser() finish with success\n");
	return true;
error:
	R_FREE (signature);
	return false;
}

R_API bool init_pdb_parser(RPdb *pdb, const char *filename) {
	RBuffer *buf = r_buf_new_slurp (filename);
	if (!buf) {
		eprintf ("%s: Error reading file \"%s\"\n", __func__, filename);
		return false;
	}
	return init_pdb_parser_with_buf (pdb, buf);
}
