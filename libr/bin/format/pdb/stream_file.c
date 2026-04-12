#include "types.h"
#include "stream_file.h"

// size = -1 (default value), pages_size = 0x1000 (default value)
int init_r_stream_file(R_STREAM_FILE *stream_file, RBuffer *buf, int *pages, int pages_amount, int size, int page_size) {
	stream_file->error = 0;
	stream_file->buf = buf;
	stream_file->pages = pages;
	stream_file->pages_amount = pages_amount;
	stream_file->page_size = page_size;
	stream_file->end = (size == -1)
		? (size_t)pages_amount * page_size
		: size;
	stream_file->pos = 0;
	return 1;
}

static void stream_file_read_pages(R_STREAM_FILE *stream_file, int start_indx, int end_indx, char *res) {
	if ((end_indx - start_indx) > stream_file->end) {
		stream_file->error = READ_PAGE_FAIL;
		return;
	}
	end_indx = R_MIN (end_indx, stream_file->pages_amount);
	int i;
	for (i = start_indx; i < end_indx; i++) {
		int page_offset = stream_file->pages[i] * stream_file->page_size;
		if (page_offset < 1) {
			return;
		}
		r_buf_read_at (stream_file->buf, page_offset, (ut8 *)res, stream_file->page_size);
		res += stream_file->page_size;
	}
}

void stream_file_read(R_STREAM_FILE *stream_file, int size, char *res) {
	size_t pn_start, off_start, pn_end, off_end;
	if (size == -1) {
		char *pdata = (char *)calloc (stream_file->pages_amount, stream_file->page_size);
		if (!pdata) {
			stream_file->error = READ_PAGE_FAIL;
			return;
		}
		GET_PAGE (pn_start, off_start, stream_file->pos, stream_file->page_size);
		stream_file_read_pages (stream_file, 0, stream_file->pages_amount, pdata);
		stream_file->pos = stream_file->end;
		if (res && stream_file->end > (int)off_start) {
			memcpy (res, pdata + off_start, stream_file->end - off_start);
		}
		free (pdata);
	} else {
		GET_PAGE (pn_start, off_start, stream_file->pos, stream_file->page_size);
		GET_PAGE (pn_end, off_end, stream_file->pos + size, stream_file->page_size);
		(void)off_end;
		size_t n_pages = pn_end + 1 - pn_start;
		size_t alloc_size;
		if (r_mul_overflow (n_pages, (size_t)stream_file->page_size, &alloc_size) || alloc_size > ST32_MAX) {
			stream_file->error = READ_PAGE_FAIL;
			return;
		}
		char *pdata = (char *)calloc (alloc_size, 1);
		if (!pdata) {
			stream_file->error = READ_PAGE_FAIL;
			return;
		}
		stream_file_read_pages (stream_file, pn_start, pn_end + 1, pdata);
		stream_file->pos += size;
		if (res && size > 0) {
			memcpy (res, pdata + off_start, size);
		}
		free (pdata);
	}
}

void stream_file_seek(R_STREAM_FILE *stream_file, int offset, int whence) {
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
	stream_file->pos = R_MAX (stream_file->pos, 0);
	stream_file->pos = R_MIN (stream_file->pos, stream_file->end);
}

int stream_file_tell(R_STREAM_FILE *stream_file) {
	return stream_file->pos;
}

void stream_file_get_data(R_STREAM_FILE *stream_file, char *data) {
	int pos = stream_file_tell (stream_file);
	stream_file_seek (stream_file, 0, 0);
	stream_file_read (stream_file, -1, data);
	stream_file_seek (stream_file, pos, 0);
}

int stream_file_get_size(R_STREAM_FILE *stream_file) {
	int pn_start = 0, off_start = 0;
	GET_PAGE (pn_start, off_start, stream_file->pos, stream_file->page_size);
	(void)pn_start;
	return stream_file->end - off_start;
}
