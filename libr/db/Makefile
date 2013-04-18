include ../config.mk

NAME=r_db
DEPS=r_util

OBJS=db.o table.o pair.o


SDBLIB=sdb/src/libsdb.a
EXTRA_CLEAN=sdbclean
EXTRA_TARGETS+=${SDBLIB}

OBJS+=sdb/src/buffer.o
OBJS+=sdb/src/cdb.o
OBJS+=sdb/src/cdb_make.o
OBJS+=sdb/src/ht.o
OBJS+=sdb/src/json/js0n.o
OBJS+=sdb/src/json/json.o
OBJS+=sdb/src/json/rangstr.o
OBJS+=sdb/src/json.o
OBJS+=sdb/src/lock.o
OBJS+=sdb/src/ls.o
OBJS+=sdb/src/ns.o
OBJS+=sdb/src/query.o
OBJS+=sdb/src/sdb.o
OBJS+=sdb/src/sdba.o
OBJS+=sdb/src/sdbn.o
OBJS+=sdb/src/util.o

CFLAGS+=-Isdb/src

URL=git://github.com/radare/sdb

F=README.md config.mk src Makefile
SYNCFILES=$(addprefix sdb.vc/,${F})

include ../rules.mk

# link against sdb
#LINK+=${SDBLIB}

sdbclean:
	cd sdb/src ; ${MAKE} clean

$(SDBLIB):
	cd sdb ; ${MAKE} src/sdb-version.h
	cd sdb/src ; ${MAKE} ARCH=xxx RANLIB="${RANLIB}" \
		CC="${CC}" CFLAGS="${CFLAGS}" LDFLAGS="${LDFLAGS}" libsdb.a

.PHONY: sdb-sync sync-sdb sdbclean
sdb-sync sync-sdb:
	rm -rf sdb sdb.vc
	git clone ${URL} sdb.vc
	mkdir -p sdb
	cp -rf ${SYNCFILES} sdb
	rm -rf sdb.vc ../include/sdb
	mkdir -p ../include/sdb
	cd sdb ; ${MAKE} src/sdb-version.h
	cp -f sdb/src/*.h ../include/sdb
	echo '#include <sdb/sdb.h>' > ../include/sdb.h
	git add ../include/sdb*
	git add sdb
