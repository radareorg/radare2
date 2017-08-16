/* radare - LGPLv3 - Copyright 2017 - xarkes */
#ifndef _AR_H
#define _AR_H

/* Offset passed is always the real io->off, the functions automatically
 * translate it to relative offset within the archive */
R_API RBuffer *ar_open_file(const char *arname, const char *filename);
R_API int ar_close(RBuffer *b);
R_API int ar_read_at(RBuffer *b, ut64 off, void *buf, int count);
R_API int ar_write_at(RBuffer *b, ut64 off, void *buf, int count);
int ar_read(RBuffer *b, void *dest, int len);
#endif // _AR_H
