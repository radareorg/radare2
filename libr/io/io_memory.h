#ifndef IO_MEMORY_H
#define IO_MEMORY_H

#include "r_io.h"

typedef struct {
	ut8 *buf;
	ut32 size;
	ut64 offset;
} RIOMalloc;

int io_memory_close(RIODesc *fd);
int io_memory_read(RIO *io, RIODesc *fd, ut8 *buf, int count);
ut64 io_memory_lseek(RIO* io, RIODesc *fd, ut64 offset, int whence);
int io_memory_write(RIO *io, RIODesc *fd, const ut8 *buf, int count);
bool io_memory_resize(RIO *io, RIODesc *fd, ut64 count);

#endif
