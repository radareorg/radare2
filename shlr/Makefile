include ../config-user.mk
include ../mk/gcc.mk

MODS=udis86 java sdb tcc
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
	echo all clean mrproper: | tee sdb/test/Makefile > sdb/memcache/Makefile
	git add $I/sdb*
	git add sdb

$(TCCLIB) libr_tcc/libr_tcc.a:
	cd libr_tcc ; ${MAKE}

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

symstall:
	mkdir -p ${D}/lib
	for a in tcc/libr_tcc* ; do \
		ln -fs ${PWD}/$$a ${D}/lib/$$a ; done

uninstall deinstall:
	rm -f ${D}/lib/libr_tcc*
