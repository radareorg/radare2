#ifndef IO_MEMORY_H
#define IO_MEMORY_H

#include <r_io.h>

typedef struct {
	ut8 *buf;
	ut32 size;
	ut64 offset;
	void *data;
	ut32 cycle;
} RIOMalloc;

R_IPI bool io_memory_close(RIODesc *fd);
R_IPI int io_memory_read(RIO *io, RIODesc *fd, ut8 *buf, int count);
R_IPI ut64 io_memory_lseek(RIO* io, RIODesc *fd, ut64 offset, int whence);
R_IPI int io_memory_write(RIO *io, RIODesc *fd, const ut8 *buf, int count);
R_IPI bool io_memory_resize(RIO *io, RIODesc *fd, ut64 count);

#endif
