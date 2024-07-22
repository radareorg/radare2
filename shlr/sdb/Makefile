include config.mk
VALADIR=bindings/vala

PWD=$(shell pwd)
PFX=${DESTDIR}${PREFIX}
HGFILES=`find sdb-${SDBVER} -type f | grep -v hg | grep -v swp`
ASANOPTS=address undefined signed-integer-overflow
LEAKOPTS=leak
CFLAGS_ASAN=$(addprefix -fsanitize=,$(ASANOPTS)) $(CFLAGS)
CFLAGS_LEAK=$(addprefix -fsanitize=,$(LEAKOPTS))
MKDIR=mkdir

all: pkgconfig include/sdb/version.h
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

include wasi.mk

x xxx cxx:
	# $(MAKE) CC="gcc -x c++ -Wall -fpermissive"
	$(MAKE) CC=g++ CFLAGS="-fPIC -x c++ -Wall -fpermissive -I../include -Werror"

o xo xoxo ox:
	g++ -o sdb $(filter-out src/ht.inc.c, src/*.c)  -I include/

wasi wasm: $(WASI_SDK)
	${MAKE} include/sdb/version.h
	CC=$(WASI_CC) CFLAGS="$(WASI_CFLAGS)" $(MAKE) CC=$(WASI_CC) -C src all WITHPIC=0
	mv src/sdb src/sdb.wasm
	file src/sdb.wasm

test:
	${MAKE} -C test

heap:
	CFLAGS=-DUSE_SDB_HEAP=1 $(MAKE) -C src all

asan:
	$(MAKE) include/sdb/version.h
	CC=gcc LDFLAGS="$(CFLAGS_ASAN)" CFLAGS="$(CFLAGS_ASAN)" ${MAKE} -C src all

asantest:
	export ASAN_OPTIONS=detect_leaks=0 ; \
	CC=gcc CFLAGS="$(CFLAGS_ASAN)" ${MAKE} -C test

leak:
	$(MAKE) include/sdb/version.h
	CC=gcc LDFLAGS="$(CFLAGS_LEAK)" CFLAGS="$(CFLAGS_LEAK)" $(MAKE) -C src all

leaktest:
	CC=gcc CFLAGS="$(CFLAGS_LEAK)" LDFLAGS="$(CFLAGS_LEAK)" $(MAKE) -C test

pkgconfig:
	[ -d pkgconfig ] && ${MAKE} -C pkgconfig || true

include/sdb/version.h:
	echo '#define SDB_VERSION "${SDBVER}"' > include/sdb/version.h

CFILES=cdb.c cdb_make.c ls.c ht.c sdb.c num.c base64.c text.c
CFILES+=json.c ns.c lock.c util.c disk.c query.c array.c fmt.c main.c
EMCCFLAGS=-O2 -s EXPORTED_FUNCTIONS="['_sdb_querys','_sdb_new0']"
#EMCCFLAGS+=--embed-file sdb.data

sdb.js: include/sdb/version.h
	cd src ; emcc ${EMCCFLAGS} -I../include -o ../sdb.js ${CFILES}

clean:
	rm -f include/sdb/version.h
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

INCFLS=sdb.h version.h cdb.h ht_uu.h ht_up.h ht_pp.h types.h heap.h
INCFLS+=ls.h cdb_make.h buffer.h config.h ht.h dict.h set.h ht_inc.h
INCFLS+=rangstr.h asserts.h cwisstable.h gcc_stdatomic.h msvc_stdatomic.h
INCFILES=$(addprefix include/sdb/,$(INCFLS))

install: pkgconfig install-dirs
	$(INSTALL_MAN) src/sdb.1 ${DESTDIR}${MANDIR}
	$(INSTALL_LIB) src/libsdb$(EXT_SO) ${DESTDIR}${LIBDIR}
	$(INSTALL_DATA) src/libsdb$(EXT_AR) ${DESTDIR}${LIBDIR}
	-if [ "$(EXT_SO)" != "$(SOVER)" ]; then \
	  cd ${DESTDIR}${LIBDIR} ; \
	  mv libsdb$(EXT_SO) libsdb$(SOVER) ; \
	  ln -s libsdb$(SOVER) libsdb$(EXT_SO) ; \
	  ln -s libsdb$(SOVER) libsdb$(EXT_SO).$(SOVERSION) ; \
	fi
	mkdir -p $(DESTDIR)/$(INCDIR)/sdb
	$(INSTALL_DATA) $(INCFILES) $(DESTDIR)$(INCDIR)/sdb
	$(INSTALL_PROGRAM) src/sdb $(DESTDIR)$(BINDIR)
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


PGOFLAG=-fprofile-instr-generate
# PGOFLAG=-fcs-profile-generate
# PGOFLAG=-fprofile-generate
# PROFDATA=/opt/homebrew/Cellar//llvm/16.0.4/bin/llvm-profdata
PROFDATA=xcrun llvm-profdata
pgo:
	$(MAKE) clean
	$(MAKE) CFLAGS="-O3 $(PGOFLAG)" LDFLAGS="$(PGOFLAG)"
	rm -f test/test-*.prof
	export LLVM_PROFILE_FILE="code-%p.prof" ; $(MAKE) -C test \
		CFLAGS="-O3 $(PGOFLAG)" LDFLAGS="$(PGOFLAG)"
	$(PROFDATA) merge -sparse -output=code.prof test/co*.prof
	rm -f test/test-*.prof
	$(MAKE) clean
	$(MAKE) CFLAGS="-O3 -fprofile-use=$(shell pwd)/code.prof"
	touch code.prof
# xcrun llvm-cov show src/sdb -instr-profile=$(shell pwd)/code.prof

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
	cd src && for a in libsdb.* ; do ln -fs ${PWD}/src/$$a ${DESTDIR}${LIBDIR}/$$a ; done
	ln -fs ${PWD}/src/sdb.1 ${DESTDIR}${MANDIR}/sdb.1
	ln -fs ${PWD}/src/sdb ${DESTDIR}${BINDIR}
	mkdir -p ${DESTDIR}${INCDIR}/sdb
	ln -fs ${PWD}/include/sdb/sdb.h ${DESTDIR}${INCDIR}/sdb
	ln -fs ${PWD}/include/sdb/version.h ${DESTDIR}${INCDIR}/sdb
	ln -fs ${PWD}/include/sdb/cdb.h ${DESTDIR}${INCDIR}/sdb
	ln -fs ${PWD}/include/sdb/ht_uu.h ${DESTDIR}${INCDIR}/sdb
	ln -fs ${PWD}/include/sdb/ht_up.h ${DESTDIR}${INCDIR}/sdb
	ln -fs ${PWD}/include/sdb/ht_pp.h ${DESTDIR}${INCDIR}/sdb
	ln -fs ${PWD}/include/sdb/types.h ${DESTDIR}${INCDIR}/sdb
	ln -fs ${PWD}/include/sdb/ls.h ${DESTDIR}${INCDIR}/sdb
	ln -fs ${PWD}/include/sdb/cdb_make.h ${DESTDIR}${INCDIR}/sdb
	ln -fs ${PWD}/include/sdb/buffer.h ${DESTDIR}${INCDIR}/sdb
	ln -fs ${PWD}/include/sdb/config.h ${DESTDIR}${INCDIR}/sdb
ifneq (${HAVE_VALA},)
	$(MKDIR) -p ${DESTDIR}$(VAPIDIR)
	ln -fs ${PWD}/bindings/vala/sdb.pc ${DESTDIR}${LIBDIR}/pkgconfig
	ln -fs ${PWD}/bindings/vala/mcsdb.pc ${DESTDIR}${LIBDIR}/pkgconfig
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

w32: include/sdb/version.h
	cd src ; \
	${MAKE} OS=w32 WCP=${WCP} CC=${WCP}-gcc AR=${WCP}-ar RANLIB=${WCP}-ranlib sdb.exe

# ios toolchain
IOS_CC=$(shell xcrun --sdk iphoneos --find clang) -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch armv7 -arch arm64
IOS_AR=$(shell xcrun --sdk iphoneos --find ar)
IOS_RL=$(shell xcrun --sdk iphoneos --find ranlib)

ios: include/sdb/version.h
	${MAKE} CFLAGS=-DUSE_DLSYSTEM=1 OS=Darwin ARCH=arm CC="${IOS_CC}" AR="${IOS_AR}" RANLIB="${IOS_RL}" HAVE_VALA= all

v version:
	@echo $(SDBVER)

.PHONY: all ${VALADIR} clean dist w32 ios v version
.PHONY: install-dirs install uninstall deinstall symstall
