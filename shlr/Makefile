include ../config-user.mk
include ../mk/${COMPILER}.mk

HOST_CC?=gcc
MODS=udis86 java tcc
URL=git://github.com/radare/sdb
PWD=$(shell pwd)
SDB_CONFIG=${PWD}/sdb-config.mk

all: sdb/sdb
	@for a in ${MODS} ; do \
		echo ${MAKE} -C $$a ; \
		${MAKE} -C $$a HAVE_VALA= ROOT=${PWD}/../ ; \
	done

clean mrproper:
	rm -f sdb/src/.sdb sdb/sdb
	cd sdb ; ${MAKE} clean
	@for a in ${MODS} ; do ${MAKE} -C $$a clean ; done

$(SDBLIB) sdb/sdb:
	cd sdb ; ${MAKE} src/sdb-version.h
	cd sdb ; ${MAKE} clean
	cd sdb ; \
		${MAKE} clean && \
		${MAKE} CC=${HOST_CC} CFLAGS="${HOST_CFLAGS}" && \
		cp -f src/sdb src/.sdb
	cd sdb ; ${MAKE} clean
	cd sdb ; ${MAKE} src/sdb-version.h
	cd sdb/src ; ${MAKE} ARCH=xxx RANLIB="${RANLIB}" CFLAGS_SHARED=-fPIC \
		CC="${CC}" AR="${AR}" CFLAGS="${CFLAGS}" LDFLAGS="${LDFLAGS}" libsdb.a
	${RANLIB} sdb/src/libsdb.a
	cp -f sdb/src/.sdb sdb/sdb


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
	rm -f src/sdb-version.h
	cd sdb ; ${MAKE} src/sdb-version.h
	cp -f sdb/src/*.h $I/sdb
	echo '#include <sdb/sdb.h>' > $I/sdb.h
	mkdir -p sdb/test sdb/memcache
	sed -e 's,HAVE_VALA=,HAVE_VALA=#,' sdb/config.mk > .t
	mv .t sdb/config.mk
	echo all clean mrproper: | tee sdb/test/Makefile > sdb/memcache/Makefile
	git add $I/sdb*
	git add sdb

$(TCCLIB) libr_tcc/libr_tcc.a:
	cd libr_tcc ; ${MAKE}

udis-sync udis86-sync sync-udis sync-udis86:
	cd udis86 ; ${MAKE} sync

tcc-clean tccclean:
	cd libr_tcc ; ${MAKE} clean

CFILES=i386-asm.c i386-gen.c libtcc.c tccasm.c tccelf.c tccgen.c tccpp.c
HFILES=tcc.h i386-asm.h tcclib.h tcctok.h stab.h
HFILES+=elf.h libtcc.h config.h i386-tok.h

# TODO: use mob branch?

.PHONY: sdb-sync sync-sdb sdbclean
tcc-sync sync-tcc:
	rm -rf _
	git clone git://repo.or.cz/tinycc.git _
	cd _ ; ./configure --prefix=${PREFIX}
	mkdir -p tcc
	for a in ${CFILES} ${HFILES} ; do cp -f _/$$a tcc ; done
	cp -f _/VERSION _/COPYING _/stab.def tcc
	git add tcc
	rm -rf _

D=${DESTDIR}/${PREFIX}
install:
	mkdir -p ${D}/lib
	cp -f tcc/libr_tcc* ${D}/lib

install-symlink symstall:
	mkdir -p ${D}/lib
	cd tcc ; for a in libr_tcc* ; do \
		ln -fs `pwd`/$$a ${D}/lib/$$a ; done

uninstall deinstall:
	rm -f ${D}/lib/libr_tcc*
