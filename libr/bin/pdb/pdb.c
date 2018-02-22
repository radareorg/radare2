/* radare - LGPL - Copyright 2014 - inisider */

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
static int read_int_var(char *var_name, int *var, R_PDB *pdb) {
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
static int init_pdb7_root_stream(R_PDB *pdb, int *root_page_list, int pages_amount,
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

	char *tmp;

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
		tmp = (char *) calloc (num_pages, 4);
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
		if (index != -1) {							\
			SStreamParseFunc *stream_parse_func = R_NEW0 (SStreamParseFunc);\
			if (!stream_parse_func) { return; }				\
			stream_parse_func->indx = (index);				\
			stream_parse_func->type = (stream_type);			\
			stream_parse_func->parse_stream = (parse_func);			\
			stream_parse_func->free = (free_func);				\
			if (stream_size) {						\
				stream_parse_func->stream = malloc (stream_size);	\
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
	ADD_INDX_TO_LIST (l, dbi_stream->dbi_header.symrecStream, sizeof(SGDATAStream),
		ePDB_STREAM_GSYM, free_gdata_stream, parse_gdata_stream);
	ADD_INDX_TO_LIST (l, dbi_stream->dbg_header.sn_section_hdr, sizeof(SPEStream),
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
static int pdb_read_root(R_PDB *pdb) {
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

static bool pdb7_parse(R_PDB *pdb) {
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
		r_buf_seek (pdb->buf, root_index_pages[i] * page_size, 0);
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

static void finish_pdb_parse(R_PDB *pdb) {
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
			pdb_info_stream->free_(pdb_info_stream);
			free (pdb_info_stream);
			break;
		case 2:
			tpi_stream = (STpiStream *) r_list_iter_get (it);
			tpi_stream->free_(tpi_stream);
			free (tpi_stream);
			break;
		case 3:
			dbi_stream = (SDbiStream *) r_list_iter_get (it);
			dbi_stream->free_(dbi_stream);
			free (dbi_stream);
			break;
		default:
			find_indx_in_list (pdb->pdb_streams2, i, &stream_parse_func);
			if (stream_parse_func) {
				break;
			}
			pdb_stream = (R_PDB_STREAM *) r_list_iter_get (it);
			pdb_stream->free_(pdb_stream);
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

typedef enum EStates {
	ePointerState,
	eUnionState,
	eStructState,
	eMemberState,
	eUnsignedState,
	eTypeNameState,
	eShortState,
	eLongState,
	eCharState,
	eModifierState,
	eEnumState,
	eArrayState,
	eOneMethodState,
	eVoidState,
	eDoubleState,
	eBitfieldState,
	eStateMax
} EStates;

///////////////////////////////////////////////////////////////////////////////
static EStates convert_to_state(char *cstate) {
	EStates state = eStateMax;

	if (strstr (cstate, "member")) {
		state = eMemberState;
	} else if (strstr (cstate, "pointer")) {
		state = ePointerState;
	} else if (strstr (cstate, "union")) {
		state = eUnionState;
	} else if (strstr (cstate, "struct")) {
		state = eStructState;
	} else if (strstr (cstate, "unsigned")) {
		state = eUnsignedState;
	} else if (strstr (cstate, "short")) {
		state = eShortState;
	} else if (strstr (cstate, "long")) {
		state = eLongState;
	} else if (strstr (cstate, "char")) {
		state = eCharState;
	} else if (strstr (cstate, "modifier")) {
		state = eModifierState;
	} else if (strstr (cstate, "enum")) {
		state = eEnumState;
	} else if (strstr (cstate, "array")) {
		state = eArrayState;
	} else if (strstr (cstate, "onemethod")) {
		state = eOneMethodState;
	} else if (strstr (cstate, "void")) {
		state = eVoidState;
	} else if (strstr (cstate, "double")) {
		state = eDoubleState;
	} else if (strstr (cstate, "bitfield")) {
		state = eBitfieldState;
	}

	return state;
}

///////////////////////////////////////////////////////////////////////////////
/// TODO: rewrite this ?!
static int build_format_flags(R_PDB *pdb, char *type, int pos, char *res_field, char **name_field) {
	EStates curr_state;
	char *tmp = 0;
	char *name = 0;

	tmp = strtok (type, " ");
	while (tmp != NULL) {
		curr_state = convert_to_state (tmp);
		switch (curr_state) {
		case eMemberState:
			break;
		case ePointerState:
			if (res_field[pos] == 'p') {
				return 1;
			}
			res_field[pos] = 'p';
			break;
		case eUnionState:
		case eStructState:
			res_field[pos] = '?';
			tmp = strtok (NULL, " ");
			name = (char *) malloc (strlen (tmp) + strlen (*name_field) + 1 + 2);
			if (!name) {
				return 0;
			}
			r_name_filter (tmp, -1);
			r_name_filter (*name_field, -1);
			strcpy (name, tmp);

			sprintf (name, "(%s)%s", tmp, *name_field);
			free (*name_field);
			*name_field = name;

			return 1;
		case eUnsignedState:
			if (res_field[pos] == 'p') {
				return 1;
			}
			res_field[pos] = 'u';
			break;
		case eShortState:
			// TODO: where is short??
			// where is unsigned not in hex??
			// w word (2 bytes unsigned short in hex)
			if (res_field[pos] == 'p') {
				return 1;
			}
			res_field[pos] = 'w';
			return 1;
		case eCharState:
			if (res_field[pos] == 'p') {
				return 1;
			}
			if (res_field[pos] == 'u') {
				res_field[pos] = 'b';
			} else {
				res_field[pos] = 'c';
			}
			return 1;
		case eLongState:
			if (res_field[pos] == 'p') {
				return 1;
			}
			res_field[pos] = 'i';
			return 1;
		case eModifierState:
			if (res_field[pos] == 'p') {
				return 1;
			}
			res_field[pos] = 'w';
			break;
		case eEnumState:
			if (res_field[pos] == 'p') {
				return 1;
			}
			res_field[pos] = 'E';
			tmp = strtok (NULL, " ");
			name = (char *) malloc (strlen (tmp) + strlen (*name_field) + 1 + 2);
			if (!name) {
				return 0;
			}
			strcpy (name, tmp);
			sprintf (name, "(%s)%s", tmp, *name_field);
			free (*name_field);
			*name_field = name;
			return 1;
// case eDoubleState:
//// TODO: what is the flag for double in pf??
// res_field[pos] = 'q';
// return 1;
		case eBitfieldState:
			res_field[pos] = 'B';
			tmp = strtok (NULL, " ");
			name = (char *) malloc (strlen (tmp) + strlen (*name_field) + 1 + 2);
			if (!name) {
				return 0;
			}
			strcpy (name, tmp);
			sprintf (name, "(%s)%s", tmp, *name_field);
			free (*name_field);
			*name_field = name;
			return 1;
		case eVoidState:
		case eArrayState:
		case eOneMethodState:
			res_field[pos] = 'p';
			return 1;
		default:
			if (((!strcmp (tmp, "to"))) ||
			    (!strcmp (tmp, "nesttype")) ||
			    (!strcmp (tmp, "mfunction")) ||
			    (!strcmp (tmp, "proc")) ||
			    (!strcmp (tmp, "arglist"))) {
				break;
			} else {
				//eprintf ("There is no support for type \"%s\" in PF structs\n", tmp);
				res_field[pos] = 'A';
				return 0;
			}
		}

		tmp = strtok (NULL, " ");
	}

	return 1;
}

///////////////////////////////////////////////////////////////////////////////
void build_command_field(ELeafType lt, char **command_field) {
	switch (lt) {
	case eLF_STRUCTURE:
	case eLF_UNION:
		*command_field = (char *) malloc (strlen ("pf.") + 1);
		if (!(*command_field)) {
			break;
		}
		strcpy (*command_field, "pf.");
		break;
	case eLF_ENUM:
		*command_field = (char *) malloc (strlen ("\"td enum ") + 1);
		if (!(*command_field)) {
			break;
		}
		strcpy (*command_field, "\"td enum ");
		break;
	default:
		break;
	}
}

///////////////////////////////////////////////////////////////////////////////
void build_name_field(char *name, char **name_field) {
	if (name_field) {
		*name_field = name? strdup (name): NULL;
		r_name_filter (*name_field, -1);
		r_str_replace_char (*name_field, ':', '_');
	}
}

///////////////////////////////////////////////////////////////////////////////
int build_flags_format_and_members_field(R_PDB *pdb, ELeafType lt, char *name, char *type,
					 int i, int *pos, int offset, char *format_flags_field, char **members_field) {
	switch (lt) {
	case eLF_STRUCTURE:
	case eLF_UNION:
		members_field[i] = (char *) malloc (sizeof(char) * strlen (name) + 1);
		if (!members_field[i]) {
			return 0;
		}
		strcpy (members_field[i], name);
		if (build_format_flags (pdb, type, *pos, format_flags_field, &members_field[i]) == 0) {
			return 0;
		}
		*pos = *pos + 1;
		break;
	case eLF_ENUM:
		members_field[i] = r_str_newf ("%s=0x%"PFMT64x, name, offset);
#if 0
		members_field[i] = (char *) malloc (sizeof(char) * strlen (name) + 8 + 1 + 1);	// 8 - hex int, 1 - =
		if (!members_field[i]) {
			return 0;
		}
		sprintf (members_field[i], "%s=%08X", name, offset);
#endif
		break;
	default:
		return 0;
	}

	return 1;
}

int alloc_format_flag_and_member_fields(RList *ptmp, char **flags_format_field, int *members_amount, char ***members_name_field) {
	int i = 0, size = 0;

	RListIter *it2 = r_list_iterator (ptmp);
	while (r_list_iter_next (it2)) {
		(void) r_list_iter_get (it2);
		*members_amount = *members_amount + 1;
	}
	if (!*members_amount) {
		return 0;
	}
	*flags_format_field = (char *) malloc (*members_amount + 1);
	memset (*flags_format_field, 0, *members_amount + 1);

	size = sizeof *members_name_field * (*members_amount);
	*members_name_field = (char **) malloc (size);
	for (i = 0; i < *members_amount; i++) {
		(*members_name_field)[i] = 0;
	}
	return 1;
}

///////////////////////////////////////////////////////////////////////////////
// TODO: need refactor
static void print_types(R_PDB *pdb, int mode) {
	ELeafType lt = eLF_MAX;
	char *command_field = 0;
	char *name_field = 0;
	char *flags_format_field = 0;	// format for struct
	char **members_name_field = 0;
	char *type = 0;
	int members_amount = 0;
	int i = 0;
	int pos = 0;
	char sym = ' ';
	int is_first = 1;
	char *name = NULL;
	int val = 0;
	int offset = 0;
	SType *t = 0;
	STypeInfo *tf = 0;
	RListIter *it = 0, *it2 = 0;
	RList *plist = pdb->pdb_streams, *ptmp = NULL;
	STpiStream *tpi_stream = r_list_get_n (plist, ePDB_STREAM_TPI);

	if (!tpi_stream) {
		eprintf ("There is no tpi stream in current pdb\n");
		return;
	}

	if (mode == 'j') {
		pdb->cb_printf ("{\"%s\":[", "types");
	}

	it = r_list_iterator (tpi_stream->types);
	while (r_list_iter_next (it)) {
		pos = 0;
		i = 0;
		members_amount = 0;
		val = 0;
		t = (SType *) r_list_iter_get (it);
		tf = &t->type_data;
		lt = tf->leaf_type;
		if ((tf->leaf_type == eLF_STRUCTURE) || (tf->leaf_type == eLF_UNION) || (tf->leaf_type == eLF_ENUM)) {
			if (tf->is_fwdref) {
				tf->is_fwdref (tf, &val);
				if (val == 1) {
					continue;
				}
			}
			if ((mode == 'j') && (is_first == 0)) {
				pdb->cb_printf (",");
			}
			is_first = 0;
			if (tf->get_name) {
				tf->get_name (tf, &name);
			}
			// val for STRUCT or UNION mean size
			if (tf->get_val) {
				tf->get_val (tf, &val);
			}
			if (tf->get_members) {
				tf->get_members (tf, &ptmp);
			}
			// pdb->cb_printf ("%s: size 0x%x\n", name, val);
			switch (mode) {
			case 'd': pdb->cb_printf ("%s: size 0x%x\n", name, val); break;
			case 'r':
				build_command_field (lt, &command_field);
				build_name_field (name, &name_field);
				if (!alloc_format_flag_and_member_fields (ptmp, &flags_format_field,
					    &members_amount, &members_name_field)) {
					goto err;
				}
				break;
			case 'j':
				switch (lt) {
				case eLF_ENUM:
					pdb->cb_printf ("{\"type\":\"%s\", \"name\":\"%s\",\"%s\":[",
						"enum", name, "enums");
					break;
				case eLF_STRUCTURE:
				case eLF_UNION:
					pdb->cb_printf ("{\"type\":\"%s\",\"name\":\"%s\",\"%s\":[",
						"structure", name, "members");
					break;
				default:
					continue;
				}

				break;
			}

			it2 = r_list_iterator (ptmp);
			while (r_list_iter_next (it2)) {
				if ((mode == 'j') && (i)) {
					pdb->cb_printf (",");
				}
				tf = (STypeInfo *) r_list_iter_get (it2);
				if (tf->get_name) {
					tf->get_name (tf, &name);
				}
				if (tf->get_val) {
					tf->get_val (tf, &offset);
				} else {
					offset = 0;
				}
				if (tf->get_print_type) {
					tf->get_print_type (tf, &type);
				}
				switch (mode) {
				case 'd':
					pdb->cb_printf ("  0x%x: %s type:", offset, name);
					pdb->cb_printf ("%s\n", type);
					break;
				case 'r':
					if (!build_flags_format_and_members_field (pdb, lt, name, type, i,
						    &pos, offset, flags_format_field, members_name_field)) {
						R_FREE (type);
						goto err;
					}
					break;
				case 'j':	// JSON
					switch (lt) {
					case eLF_ENUM:
						pdb->cb_printf ("{\"%s\":\"%s\",\"%s\":%d}",
							"enum_name", name, "enum_val", offset);
						break;
					case eLF_STRUCTURE:
					case eLF_UNION:
						pdb->cb_printf ("{\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":%d}",
							"member_type", type + strlen ("(member)") + 1,
							"member_name", name, "offset", offset);
						break;
					default:
						break;
					}
					break;
				}
				R_FREE (type);
				i++;
			}

			if (mode == 'r') {
				pdb->cb_printf ("%s%s ", command_field, name_field);
				if (lt != eLF_ENUM) {
					pdb->cb_printf ("%s ", flags_format_field);
				} else {
					pdb->cb_printf ("%c ", '{');
				}
				sym = (lt == eLF_ENUM)? ',': ' ';
				for (i = 0; i < members_amount; i++) {
					pdb->cb_printf ("%s", members_name_field[i]);
					if ((i + 1) != members_amount) {
						pdb->cb_printf ("%c", sym);
					}
				}
				if (lt == eLF_ENUM) {
					pdb->cb_printf (" };\"\n");
				} else {
					pdb->cb_printf ("\n");
				}
			}
			if (mode == 'j') {
				pdb->cb_printf ("]}");
			}
err:
			if (mode == 'r') {
				R_FREE (command_field);
				R_FREE (name_field);
				R_FREE (flags_format_field);
				for (i = 0; i < members_amount; i++) {
					R_FREE (members_name_field[i]);
				}
				R_FREE (members_name_field);
			}
		}
	}

	if (mode == 'j') {
		pdb->cb_printf ("]}");
	}
}

///////////////////////////////////////////////////////////////////////////////
static void print_gvars(R_PDB *pdb, ut64 img_base, int format) {
	SStreamParseFunc *omap = 0, *sctns = 0, *sctns_orig = 0, *gsym = 0, *tmp = 0;
	SIMAGE_SECTION_HEADER *sctn_header = 0;
	SGDATAStream *gsym_data_stream = 0;
	SPEStream *pe_stream = 0;
	SGlobal *gdata = 0;
	RListIter *it = 0;
	RList *l = 0;
	char *name;
	int is_first = 1;

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
		pdb->cb_printf ("{\"%s\":[", "gvars");
	}
	gsym_data_stream = (SGDATAStream *) gsym->stream;
	if ((omap != 0) && (sctns_orig != 0)) {
		pe_stream = (SPEStream *) sctns_orig->stream;
	} else {
		if (sctns) {
			pe_stream = (SPEStream *) sctns->stream;
		}
	}
	if (!pe_stream) {
		return;
	}
	it = r_list_iterator (gsym_data_stream->globals_list);
	while (r_list_iter_next (it)) {
		gdata = (SGlobal *) r_list_iter_get (it);
		sctn_header = r_list_get_n (pe_stream->sections_hdrs, (gdata->segment - 1));
		if (sctn_header) {
			name = r_bin_demangle_msvc (gdata->name.name);
			name = (name)? name: strdup (gdata->name.name);
			if (name && format != 'd') {
				char *_name = name;
				name = r_name_filter2 (_name);
				free (_name);
			}
			switch (format) {
			case 2:
			case 'j':	// JSON
				if (!is_first) {
					pdb->cb_printf (",");
				}
				pdb->cb_printf ("{\"%s\":%d,\"%s\":%d,\"%s\":\"%s\",\"%s\":\"%s\"}",
					"address", (ut64) (img_base + omap_remap ((omap)? (omap->stream): 0, gdata->offset + sctn_header->virtual_address)),
					"symtype", gdata->symtype,
					"section_name", sctn_header->name,
					"gdata_name", name);
				break;
			case 1:
			case '*':
			case 'r':
				pdb->cb_printf ("f pdb.%s = 0x%"PFMT64x " # %d %s\n",
					name,
					(ut64) (img_base + omap_remap ((omap)? (omap->stream): 0,
							gdata->offset + sctn_header->virtual_address)),
					gdata->symtype, sctn_header->name);
				break;
			case 'd':
			default:
				pdb->cb_printf ("0x%08"PFMT64x "  %d  %s  %s\n",
					(ut64) (img_base + omap_remap ((omap)? (omap->stream): 0,
							gdata->offset + sctn_header->virtual_address)),
					gdata->symtype, sctn_header->name, name);
				break;
			}
			free (name);
		} else {
			//eprintf ("Skipping %s, segment %d does not exist\n",
				//gdata->name.name, (gdata->segment - 1));
		}
		is_first = 0;
	}
	if (format == 'j') {
		pdb->cb_printf ("]}");
	}
}

///////////////////////////////////////////////////////////////////////////////
R_API bool init_pdb_parser(R_PDB *pdb, const char *filename) {
	char *signature = NULL;
	int bytes_read = 0;

	if (!pdb) {
		eprintf ("R_PDB structure is incorrect.\n");
		goto error;
	}
	if (!pdb->cb_printf) {
		pdb->cb_printf = (PrintfCallback) printf;
	}
	pdb->buf = r_buf_new_slurp (filename);
	if (!pdb->buf) {
		eprintf ("File reading error/empty file\n");		
		goto error;
	}	
// pdb->fp = r_sandbox_fopen (filename, "rb");
// if (!pdb->fp) {
// eprintf ("file %s can not be open\n", filename);
// goto error;
// }
	signature = (char *) calloc (1, PDB7_SIGNATURE_LEN);
	if (!signature) {
		eprintf ("Memory allocation error.\n");
		goto error;
	}

	bytes_read = r_buf_read (pdb->buf, (ut8 *) signature, PDB7_SIGNATURE_LEN);
	if (bytes_read != PDB7_SIGNATURE_LEN) {
		eprintf ("File reading error.\n");
		goto error;
	}

	r_buf_seek (pdb->buf, 0, 0);

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
