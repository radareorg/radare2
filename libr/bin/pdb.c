#include <r_pdb.h>

#include <string.h>

#define PDB2_SIGNATURE "Microsoft C/C++ program database 2.00\r\n\032JG\0\0"
#define PDB7_SIGNATURE "Microsoft C/C++ MSF 7.00\r\n\x1ADS\0\0\0"
#define PDB7_SIGNATURE_LEN 32
#define PDB2_SIGNATURE_LEN 51

typedef struct {
	FILE *fp;
	int *pages;
	int page_size;
	int pages_amount;
	int end;
	int pos;
} R_STREAM_FILE;

typedef struct {
	FILE *fp;
	int *pages;
	int pages_amount;
	int indx;
	int page_size;
	int size;
	R_STREAM_FILE stream_file;
	// int fast_load;
	// ... parent;
} R_PDB_STREAM;

typedef struct {
	R_PDB_STREAM pdb_stream;
} R_PDB7_ROOT_STREAM;

typedef enum {
	ePDB_STREAM_ROOT = 0, // PDB_ROOT_DIRECTORY
	ePDB_STREAM_PDB, // PDB STREAM INFO
	ePDB_STREAM_TPI, // TYPE INFO
	ePDB_STREAM_DBI, // DEBUG INFO
	ePDB_STREAM_MAX
} EStream;

///////////////////////////////////////////////////////////////////////////////
/// size = -1 (default value)
/// pages_size = 0x1000 (default value)
////////////////////////////////////////////////////////////////////////////////
static int init_r_stream_file(R_STREAM_FILE *stream_file, FILE *fp, int *pages,
							  int pages_amount, int size, int page_size)
{
	stream_file->fp = fp;
	stream_file->pages = pages;
	stream_file->pages_amount = pages_amount;
	stream_file->page_size = page_size;

	if (size == -1) {
			stream_file->end = pages_amount * page_size;
	} else {
			stream_file->end = size;
	}

	stream_file->pos = 0;

	return 1;
}

#define GET_PAGE(pn, off, pos, page_size)	(pn) = (pos) / (page_size); \
											(off) = (pos) % (page_size);

///////////////////////////////////////////////////////////////////////////////
static char* stream_file_read(R_STREAM_FILE *stream, int size)
{
	int pn_start, off_start, pn_end, off_end;
	int i = 0;
	char *pdata = 0;
	char *tmp;
	char *ret = 0;

	if (size == -1) {
		pdata = (char *) malloc(stream->pages_amount * stream->page_size);
		GET_PAGE(pn_start, off_start, stream->pos, stream->page_size);
		tmp = pdata;
		// read_pages (...) {
		for (i = 0; i < stream->pages_amount; i++) {
			fseek(stream->fp, stream->pages[i] * stream->page_size, SEEK_SET);
			fread(tmp, stream->page_size, 1, stream->fp);
		}
		//}
		stream->pos = stream->end;
		tmp = pdata;
		ret = (char *) malloc(stream->end - off_start);
		memcpy(ret, tmp + off_start, stream->end - off_start);
		free(pdata);
	} else {
		GET_PAGE(pn_start, off_start, stream->pos, stream->page_size);
		GET_PAGE(pn_end, off_end, stream->pos + size, stream->page_size);

		pdata = (char *) malloc(pn_end + 1);
		tmp = pdata;
		for (i = pn_start; i < (pn_end + 1); i++) {
			fseek(stream->fp, stream->pages[i] * stream->page_size, SEEK_SET);
			fread(tmp, stream->page_size, 1, stream->fp);
		}
		stream->pos += size;
		ret = (char *) malloc(-(stream->page_size - off_end));
		tmp = pdata;
		memcpy(ret, tmp + off_start, -(stream->page_size - off_end));
		free(pdata);
	}

	return ret;
}

///////////////////////////////////////////////////////////////////////////////
//def seek(self, offset, whence=0):
//    if whence == 0:
//        self.pos = offset
//    elif whence == 1:
//        self.pos += offset
//    elif whence == 2:
//        self.pos = self.end + offset
static void stream_file_seek(R_STREAM_FILE *stream_file, int offset, int whence)
{
	switch (whence) {
	case 0:
		stream_file->pos = offset;
		break;
	case 1:
		stream_file->pos += offset;
		break;
	case 2:
		stream_file->pos = stream_file->end + offset;
		break;
	default:
		break;
	}
}

///////////////////////////////////////////////////////////////////////////////
static int stream_file_tell(R_STREAM_FILE *stream_file)
{
	return stream_file->pos;
}

static char* pdb_stream_get_data(R_PDB_STREAM *pdb_stream)
{
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
/// size - default value = -1
/// page_size - default value = 0x1000
///////////////////////////////////////////////////////////////////////////////
static int init_r_pdb_stream(R_PDB_STREAM *pdb_stream, FILE *fp, int *pages,
							 int pages_amount, int index, int size, int page_size)
{
	printf("init_r_pdb_stream()\n");

	pdb_stream->fp = fp;
	pdb_stream->pages = pages;
	pdb_stream->indx = index;
	pdb_stream->page_size = page_size;
	pdb_stream->pages_amount = pages_amount;

	if (size == -1) {
		pdb_stream->size =  pages_amount * page_size;
	} else {
		pdb_stream->size = size;
	}

	init_r_stream_file(&(pdb_stream->stream_file), fp, pages, pages_amount, size, page_size);

	return 1;
}

///////////////////////////////////////////////////////////////////////////////
static int read_int_var(char *var_name, int *var, FILE *fp)
{
	int bytes_read = fread(var, 4, 1, fp);
	if (bytes_read != 1) {
		printf("error while reading from file [%s]", var_name);
		return 0;
	}

	return 1;
}

///////////////////////////////////////////////////////////////////////////////
static int count_pages(int length, int page_size)
{
	int num_pages = 0;
	num_pages = length / page_size;
	if (length % page_size)
		num_pages++;
	return num_pages;
}

static int init_pdb7_root_stream(R_PDB *pdb, int *root_page_list, int pages_amount,
								 EStream indx, int root_size, int page_size)
{
	char *data;
	pdb->root_stream = (R_PDB7_ROOT_STREAM *)malloc(sizeof(R_PDB7_ROOT_STREAM));
	init_r_pdb_stream(pdb->root_stream, pdb->fp, root_page_list, pages_amount,
					  indx, root_size, page_size);

	// data = self.data

	printf("init_pdb7_root_stream()\n");
	return 1;
}

///////////////////////////////////////////////////////////////////////////////
static int pdb7_parse(R_PDB *pdb)
{
	printf("pdb7_parse()\n");

	char signature[PDB7_SIGNATURE_LEN + 1];
	int page_size = 0;
	int alloc_tbl_ptr = 0;
	int num_file_pages = 0;
	int root_size = 0;
	int reserved = 0;

	int num_root_pages = 0;
	int num_root_index_pages = 0;
	int *root_index_pages = 0;
	void *root_page_data = 0;
	int *root_page_list = 0;

	int i = 0;
	void *p_tmp;

	int bytes_read = 0;

	bytes_read = fread(signature, 1, PDB7_SIGNATURE_LEN, pdb->fp);
	if (bytes_read != PDB7_SIGNATURE_LEN) {
		printf("error while reading PDB7_SIGNATURE\n");
		goto error;
	}

	if (read_int_var("page_size", &page_size, pdb->fp) == 0) {
		goto error;
	}

	if (read_int_var("alloc_tbl_ptr", &alloc_tbl_ptr, pdb->fp) == 0) {
		goto error;
	}

	if (read_int_var("num_file_pages", &num_file_pages, pdb->fp) == 0) {
		goto error;
	}

	if (read_int_var("root_size", &root_size, pdb->fp) == 0) {
		goto error;
	}

	if (read_int_var("reserved", &reserved, pdb->fp) == 0) {
		goto error;
	}

	// FIXME: why they is not equal ????
	if (memcmp(signature, PDB7_SIGNATURE, PDB7_SIGNATURE_LEN) != 0) {
		printf("Invalid signature for PDB7 format\n");
		//goto error;
	}

	// TODO:
	// create stream of maps and names
	// ...

	num_root_pages = count_pages(root_size, page_size);
	num_root_index_pages = count_pages((num_root_pages * 4), page_size);

	root_index_pages = (int *)malloc(sizeof(int) * num_root_index_pages);
	if (!root_index_pages) {
		printf("error memory allocation\n");
		goto error;
	}

	bytes_read = fread(root_index_pages, 4, num_root_index_pages, pdb->fp);
	if (bytes_read != num_root_index_pages) {
		printf("error while reading root_index_pages\n");
		goto error;
	}

	root_page_data = (int *)malloc(page_size * num_root_index_pages);
	if (!root_page_data) {
		printf("error memory allocation of root_page_data\n");
		goto error;
	}

	p_tmp = root_page_data;
	for (i = 0; i < num_root_index_pages; i++) {
		fseek(pdb->fp, root_index_pages[i] * page_size, SEEK_SET);
		fread(p_tmp, page_size, 1, pdb->fp);
		p_tmp = (char *)p_tmp + page_size;
	}

	root_page_list = (int *)malloc(sizeof(int) * num_root_pages);
	if (!root_page_list) {
		printf("error: memory allocation of root page\n");
		goto error;
	}

	p_tmp = root_page_data;
	for (i = 0; i < num_root_pages; i++) {
		root_page_list[i] = *((int *)p_tmp);
		p_tmp = (int *)p_tmp + 1;
	}

	init_pdb7_root_stream(pdb, root_page_list, num_root_pages, ePDB_STREAM_ROOT, root_size, page_size);
	// TODO: get root stream
	// TODO: read root stream
//self.root_stream = PDB7RootStream(self.fp, root_page_list,
//    index=PDB_STREAM_ROOT, size=root_size, page_size=self.page_size)
//self.read_root(self.root_stream)

	if (root_page_list) {
		free(root_page_list);
		root_page_list = 0;
	}

	if (root_page_data) {
		free(root_page_data);
		root_page_data = 0;
	}

	if (root_index_pages) {
		free(root_index_pages);
		root_index_pages = 0;
	}

	return 1;

error:
	if (root_page_list) {
		free(root_page_list);
		root_page_list = 0;
	}

	if (root_page_data) {
		free(root_page_data);
		root_page_data = 0;
	}

	if (root_index_pages) {
		free(root_index_pages);
		root_index_pages = 0;
	}

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
static void finish_pdb_parse(R_PDB *pdb)
{
	fclose(pdb->fp);
	printf("finish_pdb_parse()\n");
}

///////////////////////////////////////////////////////////////////////////////
int init_pdb_parser(R_PDB *pdb)
{
	char *signature = 0;
	int bytes_read = 0;

	if (!pdb) {
		printf("struct R_PDB is not correct\n");
		goto error;
	}

	pdb->fp = fopen(pdb->file_name, "r");
	if (!pdb->fp) {
		printf("file %s can not be open\n", pdb->file_name);
		goto error;
	}

	signature = (char *)malloc(sizeof(char) * PDB7_SIGNATURE_LEN);
	if (!signature) {
		printf("memory allocation error\n");
		goto error;
	}

	bytes_read = fread(signature, 1, PDB7_SIGNATURE_LEN, pdb->fp);
	if (bytes_read != PDB7_SIGNATURE_LEN) {
		printf("file reading error\n");
		goto error;
	}

	fseek(pdb->fp, 0, SEEK_SET);

	if (memcmp(signature, PDB7_SIGNATURE, PDB7_SIGNATURE_LEN)) {
		pdb->pdb_parse =pdb7_parse;
	} else {
		printf("unsupported pdb format\n");
		goto error;
	}

	if (signature) {
		free(signature);
		signature = 0;
	}

	pdb->finish_pdb_parse = finish_pdb_parse;
	printf("init_pdb_parser() finish with success\n");
	return 1;

error:
	if (signature) {
		free(signature);
		signature = 0;
	}

	return 0;
}
