MODS=udis86 java sdb
URL=git://github.com/radare/sdb
PWD=$(shell pwd)
SDB_CONFIG=${PWD}/sdb-config.mk

all:
	@for a in ${MODS} ; do \
		${MAKE} -C $$a HAVE_VALA= SDB_CONFIG=${SDB_CONFIG} ROOT=${PWD}/../ ; \
	done

clean mrproper:
	@for a in ${MODS} ; do ${MAKE} -C $$a clean ; done

$(SDBLIB):
	cd sdb ; ${MAKE} src/sdb-version.h
	cd sdb/src ; ${MAKE} ARCH=xxx RANLIB="${RANLIB}" \
		CC="${CC}" CFLAGS="${CFLAGS}" LDFLAGS="${LDFLAGS}" libsdb.a

.PHONY: sdb-sync sync-sdb sdbclean
F=README.md config.mk src Makefile
SYNCFILES=$(addprefix sdb.vc/,${F})
I=../libr/include

sdb-sync sync-sdb:
	rm -rf sdb sdb.vc
	git clone ${URL} sdb.vc
	mkdir -p sdb
	cp -rf ${SYNCFILES} sdb
	rm -rf sdb.vc $I/sdb
	mkdir -p $I/sdb
	cd sdb ; ${MAKE} src/sdb-version.h
	cp -f sdb/src/*.h $I/sdb
	echo '#include <sdb/sdb.h>' > $I/sdb.h
	mkdir -p sdb/test sdb/memcache
	sed -e 's,HAVE_VALA=,HAVE_VALA=#,' -i foo sdb/config.mk
	echo all clean mrproper: > sdb/memcache/Makefile
	echo all clean mrproper: > sdb/test/Makefile
	git add $I/sdb*
	git add sdb
