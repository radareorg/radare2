/* Public domain. */

#ifndef CDB_MAKE_H
#define CDB_MAKE_H

#include "buffer.h"
#include "types.h"

#define CDB_HPLIST 1000

struct cdb_hp { ut32 h; ut32 p; } ;

struct cdb_hplist {
  struct cdb_hp hp[CDB_HPLIST];
  struct cdb_hplist *next;
  int num;
} ;

struct cdb_make {
  char bspace[8192];
  char final[2048];
  ut32 count[256];
  ut32 start[256];
  struct cdb_hplist *head;
  struct cdb_hp *split; /* includes space for hash */
  struct cdb_hp *hash;
  ut32 numentries;
  buffer b;
  ut32 pos;
  int fd;
} ;

extern int cdb_make_start(struct cdb_make *,int);
extern int cdb_make_addbegin(struct cdb_make *,unsigned int,unsigned int);
extern int cdb_make_addend(struct cdb_make *,unsigned int,unsigned int,ut32);
extern int cdb_make_add(struct cdb_make *,const char *,unsigned int,const char *,unsigned int);
extern int cdb_make_finish(struct cdb_make *);

#endif
