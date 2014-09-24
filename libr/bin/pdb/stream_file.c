#include "stream_file.h"

///////////////////////////////////////////////////////////////////////////////
/// size = -1 (default value)
/// pages_size = 0x1000 (default value)
////////////////////////////////////////////////////////////////////////////////
int init_r_stream_file(R_STREAM_FILE *stream_file, FILE *fp, int *pages,
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

///////////////////////////////////////////////////////////////////////////////
static void stream_file_read_pages(R_STREAM_FILE *stream_file, int start_indx,
								   int end_indx, char *res)
{
	int i;
	int page_offset;
	int curr_pos;
	int tmp;
//	char buffer[1024];

	for (i = start_indx; i < end_indx; i++) {
		tmp = stream_file->pages[i];
		page_offset = stream_file->pages[i] * stream_file->page_size;
		fseek(stream_file->fp, page_offset, SEEK_SET);
//		curr_pos = ftell(stream_file->fp);
		fread(res, stream_file->page_size, 1, stream_file->fp);
		res += stream_file->page_size;
	}
}

// size by default = -1
///////////////////////////////////////////////////////////////////////////////
void stream_file_read(R_STREAM_FILE *stream_file, int size, char *res)
{
	int pn_start, off_start, pn_end, off_end;
	int i = 0;
	char *pdata = 0;
	char *tmp;
	int len = 0;

	if (size == -1) {
		pdata = (char *) malloc(stream_file->pages_amount * stream_file->page_size);
		GET_PAGE(pn_start, off_start, stream_file->pos, stream_file->page_size);
		tmp = pdata;
		stream_file_read_pages(stream_file, 0, stream_file->pages_amount, tmp);
		stream_file->pos = stream_file->end;
		memcpy(res, pdata + off_start, stream_file->end - off_start);
		free(pdata);
	} else {
		GET_PAGE(pn_start, off_start, stream_file->pos, stream_file->page_size);
		GET_PAGE(pn_end, off_end, stream_file->pos + size, stream_file->page_size);

		pdata = (char *) malloc(stream_file->page_size * (pn_end + 1 - pn_start));
		tmp = pdata;
		stream_file_read_pages(stream_file, pn_start, pn_end + 1, tmp);
		stream_file->pos += size;
		memcpy(res, pdata + off_start, size);
		free(pdata);
	}
}

///////////////////////////////////////////////////////////////////////////////
//def seek(seeLF, offset, whence=0):
//    if whence == 0:
//        seeLF.pos = offset
//    elif whence == 1:
//        seeLF.pos += offset
//    elif whence == 2:
//        seeLF.pos = seeLF.end + offset
//if seeLF.pos < 0: seeLF.pos = 0
//if seeLF.pos > seeLF.end: seeLF.pos = seeLF.end
// whence by default = 0
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
