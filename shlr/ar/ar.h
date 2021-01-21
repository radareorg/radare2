/* radare - LGPLv3 - Copyright 2017 - xarkes */
#ifndef _AR_H
#define _AR_H

typedef struct RARFP {
	char *name;
	ut64 start;
	ut64 end;
	RBuffer *buf;
	ut32 *refcount;
} RArFp;

typedef int (*RArOpenManyCB) (RArFp *arf, void *user);

/* Offset passed is always the real io->off of the inspected file,
 * the functions automatically translate it to relative offset within the archive */
R_API RArFp *ar_open_file(const char *arname, const char *filename);
R_API RList *ar_open_all(const char *arname);
R_API int ar_open_all_cb(const char *arname, RArOpenManyCB cb, void *user);
R_API int ar_close(RArFp *f);
R_API int ar_read_at(RArFp *f, ut64 off, void *buf, int count);
R_API int ar_write_at(RArFp *f, ut64 off, void *buf, int count);
#endif // _AR_H
