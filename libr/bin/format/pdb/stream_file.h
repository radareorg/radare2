#ifndef STREAM_FILE_H
#define STREAM_FILE_H

#include <stdio.h>

// size = -1 (default value), pages_size = 0x1000 (default value)
int init_r_stream_file(R_STREAM_FILE *stream_file, RBuffer *buf, int *pages, int pages_amount, int size, int page_size);

void stream_file_read(R_STREAM_FILE *stream_file, int size, char *res);
void stream_file_seek(R_STREAM_FILE *stream_file, int offset, int whence);
int stream_file_tell(R_STREAM_FILE *stream_file);
void stream_file_get_data(R_STREAM_FILE *stream_file, char *data);
int stream_file_get_size(R_STREAM_FILE *stream_file);

static inline ut16 stream_file_read_le16(R_STREAM_FILE *stream_file) {
	ut8 data[2] = {0};
	stream_file_read (stream_file, sizeof (data), (char *)data);
	return r_read_le16 (data);
}

static inline st16 stream_file_read_sle16(R_STREAM_FILE *stream_file) {
	return (st16)stream_file_read_le16 (stream_file);
}

static inline ut32 stream_file_read_le32(R_STREAM_FILE *stream_file) {
	ut8 data[4] = {0};
	stream_file_read (stream_file, sizeof (data), (char *)data);
	return r_read_le32 (data);
}

static inline st32 stream_file_read_sle32(R_STREAM_FILE *stream_file) {
	return (st32)stream_file_read_le32 (stream_file);
}

#endif // STREAM_FILE_H
