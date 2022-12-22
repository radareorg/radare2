#include <r_io.h>

typedef struct {
	bool host;
	ut8 *data;
	int size;
} RIOStreamItem;

typedef struct {
	RBuffer *buf;
	RList *log;
	int mode;
} RIOStream;

R_API void r_io_stream_log_free(RIOStreamItem *log);
R_API RIOStream *r_io_stream_new(void);
R_API bool r_io_stream_write(RIOStream *s, const ut8* data, size_t len);
R_API bool r_io_stream_read(RIOStream *s, const ut8* data, size_t len);
R_API char *r_io_stream_system(RIOStream *s, const char *cmd);
R_API void r_io_stream_free(RIOStream *s);
