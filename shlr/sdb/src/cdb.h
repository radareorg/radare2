/* Public domain. */

#ifndef CDB_H
#define CDB_H

#include <string.h>
#include "types.h"

#define KVLSZ 4
#define CDB_MAX_KEY 0xff
#define CDB_MAX_VALUE 0xffffff

#define CDB_HASHSTART 5381

struct cdb {
	char *map;   /* 0 if no map is available */
	int fd;      /* filedescriptor */
	ut32 size;   /* initialized if map is nonzero */
	ut32 loop;   /* number of hash slots searched under this key */
	ut32 khash;  /* initialized if loop is nonzero */
	ut32 kpos;   /* initialized if loop is nonzero */
	ut32 hpos;   /* initialized if loop is nonzero */
	ut32 hslots; /* initialized if loop is nonzero */
	ut32 dpos;   /* initialized if cdb_findnext() returns 1 */
	ut32 dlen;   /* initialized if cdb_findnext() returns 1 */
};

/* TODO THIS MUST GTFO! */
bool cdb_getkvlen(struct cdb *db, ut32 *klen, ut32 *vlen, ut32 pos);
void cdb_free(struct cdb *);
bool cdb_init(struct cdb *, int fd);
void cdb_findstart(struct cdb *);
bool cdb_read(struct cdb *, char *, unsigned int, ut32);
int cdb_findnext(struct cdb *, ut32 u, const char *, ut32);

#define cdb_datapos(c) ((c)->dpos)
#define cdb_datalen(c) ((c)->dlen)

#endif
