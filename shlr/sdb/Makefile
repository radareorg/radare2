include config.mk
VALADIR=bindings/vala

PWD=$(shell pwd)
PFX=${DESTDIR}${PREFIX}
HGFILES=`find sdb-${SDBVER} -type f | grep -v hg | grep -v swp`
MKDIR=mkdir

all: pkgconfig src/sdb_version.h
	${MAKE} -C src
ifeq ($(BUILD_MEMCACHE),1)
	${MAKE} -C memcache
endif

vala:
ifneq (${HAVE_VALA},)
	$(MAKE) -C $(VALADIR)
	$(MAKE) -C $(VALADIR)/types
else
	@echo Nothing to do.
endif

.PHONY: test sdb.js pkgconfig dist w32dista asan

test:
	${MAKE} -C test

asan:
	${MAKE} src/sdb_version.h
	${MAKE} -C src CC="gcc -fsanitize=address" all

pkgconfig:
	[ -d pkgconfig ] && ${MAKE} -C pkgconfig || true

src/sdb_version.h:
	echo '#define SDB_VERSION "${SDBVER}"' > src/sdb_version.h

CFILES=cdb.c buffer.c cdb_make.c ls.c ht.c sdb.c num.c base64.c text.c
CFILES+=json.c ns.c lock.c util.c disk.c query.c array.c fmt.c main.c
EMCCFLAGS=-O2 -s EXPORTED_FUNCTIONS="['_sdb_querys','_sdb_new0']"
#EMCCFLAGS+=--embed-file sdb.data

sdb.js: src/sdb_version.h
	cd src ; emcc ${EMCCFLAGS} -I. -o ../sdb.js ${CFILES}

clean:
	rm -f src/sdb_version.h
	$(MAKE) -C src clean
	$(MAKE) -C memcache clean
	$(MAKE) -C test clean
ifneq (${HAVE_VALA},)
	${MAKE} -C $(VALADIR) clean
endif

dist:
	rm -f sdb-${SDBVER}.tar.gz
	rm -rf sdb-${SDBVER}
	git clone . sdb-${SDBVER}
	rm -rf sdb-${SDBVER}/.git*
	tar czvf sdb-${SDBVER}.tar.gz sdb-${SDBVER}
	pub sdb-${SDBVER}.tar.gz
	rm -rf sdb-${SDBVER}

w32dist:
	rm -f sdb-${SDBVER}.zip
	rm -rf sdb-${SDBVER}
	mkdir -p sdb-${SDBVER}
	cp src/sdb.exe sdb-${SDBVER}
	zip -r sdb-${SDBVER}.zip sdb-${SDBVER}
	rm -rf sdb-${SDBVER}

install-dirs:
	$(INSTALL_DIR) ${DESTDIR}${MANDIR} ${DESTDIR}${LIBDIR}/pkgconfig ${DESTDIR}${BINDIR} 
	$(INSTALL_DIR) ${DESTDIR}${DATADIR}/vala/vapi ${DESTDIR}${INCDIR}/sdb

INCFILES=src/sdb.h src/sdb_version.h src/cdb.h src/ht_uu.h src/ht_up.h src/ht_pp.h src/types.h
INCFILES+=src/ls.h src/cdb_make.h src/buffer.h src/config.h src/sdbht.h
INCFILES+=src/dict.h src/set.h src/ht_inc.h

install: pkgconfig install-dirs
	$(INSTALL_MAN) src/sdb.1 ${DESTDIR}${MANDIR}
	$(INSTALL_LIB) src/libsdb.${EXT_SO} ${DESTDIR}${LIBDIR}
	$(INSTALL_DATA) src/libsdb.a ${DESTDIR}${LIBDIR}
	-if [ "$(EXT_SO)" != "$(SOVER)" ]; then \
	  cd ${DESTDIR}${LIBDIR} ; \
	  mv libsdb.$(EXT_SO) libsdb.$(SOVER) ; \
	  ln -s libsdb.$(SOVER) libsdb.$(EXT_SO) ; \
	  ln -s libsdb.$(SOVER) libsdb.$(EXT_SO).$(SOVERSION) ; \
	fi
	$(INSTALL_DATA) $(INCFILES) ${DESTDIR}${INCDIR}/sdb
	$(INSTALL_PROGRAM) src/sdb ${DESTDIR}${BINDIR}
ifeq ($(BUILD_MEMCACHE),1)
	$(INSTALL_DATA) memcache/libmcsdb.a ${DESTDIR}${LIBDIR}
	$(INSTALL_DATA) memcache/mcsdb.h ${DESTDIR}${INCDIR}/sdb
	$(INSTALL_PROGRAM) memcache/mcsdbd ${DESTDIR}${BINDIR}
	$(INSTALL_PROGRAM) memcache/mcsdbc ${DESTDIR}${BINDIR}
	$(INSTALL_DATA) pkgconfig/mcsdb.pc ${DESTDIR}${LIBDIR}/pkgconfig
endif
	$(INSTALL_DATA) pkgconfig/sdb.pc ${DESTDIR}${LIBDIR}/pkgconfig
ifneq (${HAVE_VALA},)
	test -f ${VALADIR}/types/sdbtypes.h || $(MAKE) -C $(VALADIR)/types
	$(INSTALL_DATA) ${VALADIR}/sdb.vapi ${DESTDIR}${DATADIR}/vala/vapi
	cd ${VALADIR}/types && ${MAKE} install DESTDIR=${DESTDIR} PREFIX=${PREFIX}
ifeq ($(BUILD_MEMCACHE),1)
	$(INSTALL_DATA) ${VALADIR}/mcsdb.vapi ${DESTDIR}${DATADIR}/vala/vapi
endif
endif

deinstall uninstall:
	rm -rf ${DESTDIR}${INCDIR}/sdb
	rm -f ${DESTDIR}${BINDIR}/sdb
	rm -f ${DESTDIR}${BINDIR}/mcsdbc
	rm -f ${DESTDIR}${BINDIR}/mcsdbd
	rm -f ${DESTDIR}${LIBDIR}/libsdb.*
	rm -f ${DESTDIR}${LIBDIR}/libmcsdb.a
	rm -f ${DESTDIR}${LIBDIR}/pkgconfig/sdb.pc
	rm -f ${DESTDIR}${LIBDIR}/pkgconfig/mcsdb.pc
	rm -f ${DESTDIR}${MANDIR}/sdb.1
ifneq (${HAVE_VALA},)
	rm -f ${DESTDIR}${DATADIR}/vala/vapi/sdb.vapi
	rm -f ${DESTDIR}${DATADIR}/vala/vapi/mcsdb.vapi
	cd ${VALADIR}/types && ${MAKE} uninstall DESTDIR=${DESTDIR} PREFIX=${PREFIX}
endif

symstall: install-dirs
	cd src ; for a in libsdb.* ; do \
		ln -fs ${PWD}/src/$$a ${DESTDIR}${LIBDIR}/$$a ; done
	ln -fs ${PWD}/src/sdb.1 ${DESTDIR}${MANDIR}/sdb.1
	ln -fs ${PWD}/src/sdb ${DESTDIR}${BINDIR}
	ln -fs ${PWD}/src/sdb.h ${DESTDIR}${INCDIR}/sdb
	ln -fs ${PWD}/src/sdb_version.h ${DESTDIR}${INCDIR}/sdb
	ln -fs ${PWD}/src/cdb.h ${DESTDIR}${INCDIR}/sdb
	ln -fs ${PWD}/src/ht_uu.h ${DESTDIR}${INCDIR}/sdb
	ln -fs ${PWD}/src/ht_up.h ${DESTDIR}${INCDIR}/sdb
	ln -fs ${PWD}/src/ht_pp.h ${DESTDIR}${INCDIR}/sdb
	ln -fs ${PWD}/src/types.h ${DESTDIR}${INCDIR}/sdb
	ln -fs ${PWD}/src/ls.h ${DESTDIR}${INCDIR}/sdb
	ln -fs ${PWD}/src/cdb_make.h ${DESTDIR}${INCDIR}/sdb
	ln -fs ${PWD}/src/buffer.h ${DESTDIR}${INCDIR}/sdb
	ln -fs ${PWD}/src/config.h ${DESTDIR}${INCDIR}/sdb
	ln -fs ${PWD}/bindings/vala/sdb.pc ${DESTDIR}${LIBDIR}/pkgconfig
	ln -fs ${PWD}/bindings/vala/mcsdb.pc ${DESTDIR}${LIBDIR}/pkgconfig
ifneq (${HAVE_VALA},)
	$(MKDIR) -p ${DESTDIR}$(VAPIDIR)
	ln -fs ${PWD}/bindings/vala/sdb.vapi ${DESTDIR}$(VAPIDIR)
	ln -fs ${PWD}/bindings/vala/mcsdb.vapi ${DESTDIR}$(VAPIDIR)
	ln -fs ${PWD}/bindings/vala/sdb.vapi ${DESTDIR}$(VAPIDIR)
	ln -fs ${PWD}/bindings/vala/mcsdb.vapi ${DESTDIR}$(VAPIDIR)
	cd ${VALADIR}/types && ${MAKE} symstall DESTDIR=${DESTDIR} PREFIX=${PREFIX}
endif

# windows compiler prefix
# travis/debian
WCP=i386-mingw32
# mxe
#WCP=i686-pc-mingw32

w32: src/sdb_version.h
	cd src ; \
	${MAKE} OS=w32 WCP=${WCP} CC=${WCP}-gcc AR=${WCP}-ar RANLIB=${WCP}-ranlib sdb.exe

# ios toolchain
IOS_CC=$(shell xcrun --sdk iphoneos --find clang) -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch armv7 -arch arm64
IOS_AR=$(shell xcrun --sdk iphoneos --find ar)
IOS_RL=$(shell xcrun --sdk iphoneos --find ranlib)
ios: src/sdb_version.h
	${MAKE} OS=Darwin ARCH=arm CC="${IOS_CC}" AR="${IOS_AR}" RANLIB="${IOS_RL}" HAVE_VALA= all

.PHONY: all ${VALADIR} clean dist w32 ios
.PHONY: install-dirs install uninstall deinstall symstall
