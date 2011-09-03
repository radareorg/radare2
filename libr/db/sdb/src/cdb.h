/* Public domain. */

#ifndef CDB_H
#define CDB_H

#include <string.h>
#include "types.h"

#define KVLSZ 4

// GTFO!
int getkvlen(int fd, ut32 *klen, ut32 *vlen);
#define CDB_HASHSTART 5381
extern ut32 cdb_hashadd(ut32,unsigned char);
extern ut32 cdb_hash(const char *,unsigned int);
#define cdb_hashstr(x) (cdb_hash(x,strlen(x)))

struct cdb {
	char *map; /* 0 if no map is available */
	int fd;
	ut32 size; /* initialized if map is nonzero */
	ut32 loop; /* number of hash slots searched under this key */
	ut32 khash; /* initialized if loop is nonzero */
	ut32 kpos; /* initialized if loop is nonzero */
	ut32 hpos; /* initialized if loop is nonzero */
	ut32 hslots; /* initialized if loop is nonzero */
	ut32 dpos; /* initialized if cdb_findnext() returns 1 */
	ut32 dlen; /* initialized if cdb_findnext() returns 1 */
};

extern void cdb_free(struct cdb *);
extern void cdb_init(struct cdb *,int fd);

extern int cdb_read(struct cdb *,char *,unsigned int,ut32);

extern void cdb_findstart(struct cdb *);
extern int cdb_findnext(struct cdb *,ut32 u, const char *,unsigned int);
extern int cdb_find(struct cdb *,const char *,unsigned int);

#define cdb_datapos(c) ((c)->dpos)
#define cdb_datalen(c) ((c)->dlen)

#endif
