#ifndef _IO_PRIVATE_H_
#define _IO_PRIVATE_H_

RIOMap *io_map_new(RIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size, bool do_skyline);
RIOMap *io_map_add(RIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size, bool do_skyline);
void io_map_calculate_skyline(RIO *io);

#endif
