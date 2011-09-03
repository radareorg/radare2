NAME=r_db
DEPS=r_util

OBJ=db.o table.o pair.o

PRE=sdb/src/libsdb.a
EXTRA_CLEAN=sdbclean

CFLAGS+=-Isdb/src
include ../rules.mk

# link against sdb
LINK+=${PRE}

sdbclean:
	cd sdb/src ; ${MAKE} clean

sdb/src/libsdb.a:
	cd sdb/src ; ${MAKE} CFLAGS=-fPIC libsdb.a

.PHONY: sdb-sync
SYNCFILES=sdb.hg/README sdb.hg/config.mk sdb.hg/src
#TODO SYNCFILES=$(addprefix )
sdb-sync:
	rm -rf sdb sdb.hg
	hg clone http://hg.youterm.com/sdb sdb.hg
	mkdir sdb
	cp -rf ${SYNCFILES} sdb
	hg add sdb
	rm -rf sdb.hg
