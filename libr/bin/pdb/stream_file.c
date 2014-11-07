#include "stream_file.h"

///////////////////////////////////////////////////////////////////////////////
/// size = -1 (default value)
/// pages_size = 0x1000 (default value)
////////////////////////////////////////////////////////////////////////////////
int init_r_stream_file(R_STREAM_FILE *stream_file, RBuffer *buf, int *pages,
							  int pages_amount, int size, int page_size)
{
	stream_file->error = 0;
	stream_file->buf = buf;
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

///////////////////////////////////////////////////////////////////////////////
static void stream_file_read_pages(R_STREAM_FILE *stream_file, int start_indx, int end_indx, char *res) {
	int i;
	int page_offset;
//	int tmp;
//	char buffer[1024];

	if ((end_indx - start_indx) > stream_file->end) {
		stream_file->error = READ_PAGE_FAIL;
		return;
	}
	end_indx = R_MIN (end_indx, stream_file->pages_amount);

	for (i = start_indx; i < end_indx; i++) {
//		tmp = stream_file->pages[i];
		page_offset = stream_file->pages[i] * stream_file->page_size;
		if (page_offset<1)
			return;
		stream_file->buf->cur = page_offset;
		r_buf_read_at (stream_file->buf, page_offset,
			(ut8*)res, stream_file->page_size);
//		fseek(stream_file->fp, page_offset, SEEK_SET);
//		curr_pos = ftell(stream_file->fp);
//		fread(res, stream_file->page_size, 1, stream_file->fp);
		res += stream_file->page_size;
	}
}

// size by default = -1
///////////////////////////////////////////////////////////////////////////////
void stream_file_read(R_STREAM_FILE *stream_file, int size, char *res)
{
	int pn_start, off_start, pn_end, off_end;
	char *pdata = 0;
	char *tmp;

	if (size == -1) {
		pdata = (char *) malloc(stream_file->pages_amount * stream_file->page_size);
		GET_PAGE(pn_start, off_start, stream_file->pos, stream_file->page_size);
		(void)off_end; // hack for remove unused warning
		tmp = pdata;
		stream_file_read_pages(stream_file, 0, stream_file->pages_amount, tmp);
		stream_file->pos = stream_file->end;
		memcpy(res, pdata + off_start, stream_file->end - off_start);
		free(pdata);
	} else {
		GET_PAGE(pn_start, off_start, stream_file->pos, stream_file->page_size);
		GET_PAGE(pn_end, off_end, stream_file->pos + size, stream_file->page_size);
		(void)off_end; // hack for remove unused warning
		pdata = (char *) malloc(stream_file->page_size * (pn_end + 1 - pn_start));
		if (!pdata)
			return;
		tmp = pdata;
		stream_file_read_pages(stream_file, pn_start, pn_end + 1, tmp);
		stream_file->pos += size;
		memcpy(res, pdata + off_start, size);
		free (pdata);
	}
}

///////////////////////////////////////////////////////////////////////////////
void stream_file_seek(R_STREAM_FILE *stream_file, int offset, int whence)
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

	if (stream_file->pos < 0) stream_file->pos = 0;
	if (stream_file->pos > stream_file->end) stream_file->pos = stream_file->end;
}

///////////////////////////////////////////////////////////////////////////////
int stream_file_tell(R_STREAM_FILE *stream_file)
{
	return stream_file->pos;
}

///////////////////////////////////////////////////////////////////////////////
void stream_file_get_data(R_STREAM_FILE *stream_file, char *data)
{
	int pos = 0;
	pos = stream_file_tell(stream_file);
	stream_file_seek(stream_file, 0, 0);
	stream_file_read(stream_file, -1, data);
	stream_file_seek(stream_file, pos, 0);
}

///////////////////////////////////////////////////////////////////////////////
void stream_file_get_size(R_STREAM_FILE *stream_file, int *data_size)
{
	int pn_start = 0, off_start = 0;
	GET_PAGE(pn_start, off_start, stream_file->pos, stream_file->page_size);
	(void)pn_start; // hack for remove unused warning
	*data_size = stream_file->end - off_start;
}
