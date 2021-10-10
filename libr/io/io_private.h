#ifndef _IO_PRIVATE_H_
#define _IO_PRIVATE_H_

void io_map_calculate_skyline(RIO *io);

bool io_bank_has_map(RIO *io, const ut32 bankid, const ut32 mapid);
#endif
