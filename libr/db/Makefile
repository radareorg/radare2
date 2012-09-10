NAME=r_db
DEPS=r_util

OBJ=db.o table.o pair.o

PRE=sdb/src/libsdb.a
EXTRA_CLEAN=sdbclean
EXTRA_TARGETS+=${PRE}

CFLAGS+=-Isdb/src

include ../rules.mk

# link against sdb
LINK+=${PRE}

sdbclean:
	cd sdb/src ; ${MAKE} clean

sdb/src/libsdb.a:
	#cd sdb/src ; ${MAKE} CFLAGS=-fPIC libsdb.a
	cd sdb ; ${MAKE} src/sdb-version.h
	cd sdb/src ; ${MAKE} ARCH=xxx \
		RANLIB="${RANLIB}" \
		CC="${CC}" CFLAGS="${CFLAGS}" LDFLAGS="${LDFLAGS}" libsdb.a

VC=git
URL=git://github.com/radare/sdb

F=README.md config.mk src Makefile
SYNCFILES=$(addprefix sdb.${VC}/,${F})

.PHONY: sdb-sync sync-sdb
sdb-sync sync-sdb:
	rm -rf sdb sdb.${VC}
	${VC} clone ${URL} sdb.${VC}
	mkdir sdb
	cp -rf ${SYNCFILES} sdb
	rm -rf sdb.${VC}
	rm -rf ../include/sdb
	mkdir -p ../include/sdb
	cd sdb ; ${MAKE} src/sdb-version.h
	cp -f sdb/src/*.h ../include/sdb
	echo '#include <sdb/sdb.h>' > ../include/sdb.h
	git add ../include/sdb*
	git add sdb
