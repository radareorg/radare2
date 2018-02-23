include ../global.mk
include ../config-user.mk
# for EXT_EXE
include ../libr/config.mk
include ../mk/platform.mk
_INCLUDE_MK_GCC_=
include ../mk/${COMPILER}.mk

# Build against last capstone release or next
CS_RELEASE=0

CAPSTONE_CFLAGS?=-g
# CAPSTONE_MAKEFLAGS?=CAPSTONE_ARCHS="arm aarch64"

GIT?=git
WGET?=wget

ifeq ($(CS_RELEASE),1)
CS_VER=3.0.4
CS_TAR=https://codeload.github.com/aquynh/capstone/tar.gz/$(CS_VER)
#CS_TAR=http://capstone-engine.org/download/$(CS_VER)/capstone-$(CS_VER).tgz
CS_PATCHES=0
else
CS_TAR=
CS_URL=$(GIT_PREFIX)github.com/aquynh/capstone.git
CS_UPD=20180106
CS_BRA=next
CS_TIP=bdbc57de63725a98732ddc34b48de96f8ada66f2
# REVERT THIS COMMIT BECAUSE ITS WRONG
CS_REV=
CS_PATCHES=1
endif

.PHONY: capstone-sync capstone-build all clean mrproper libgdbr libwindbg bochs

HOST_CC?=gcc
SHLR?=$(shell pwd)
AR?=ar
RANLIB?=ranlib
MODS=sdb zip udis86 java tcc
MODS+=gdb qnx ar
# lz4
ifneq ($(CC),cccl)
ifeq (1,$(WITH_GPL))
MODS+=grub
endif
endif
SDB_URL=git://github.com/radare/sdb
#SDB_URL=/Users/pancake/prg/sdb
SPP_URL=git://github.com/radare/spp
PWD=$(shell pwd)
SDB_CONFIG=${PWD}/sdb-config.mk

CFLAGS_SHARED=${PIC_CFLAGS}

ifeq (${EXT_SO},)
all:
	echo EXT_SO not defined
	exit 1
endif

preall: targets libwindbg capstone-build bochs
	@for MOD in ${MODS} ; do \
		echo $(MAKE) -C $$MOD ; \
		$(MAKE) -C $$MOD HAVE_VALA= ROOT="${PWD}/../" CC="${CC}" ; \
	done

SDBFILES=sdb/src/.sdb${EXT_EXE} sdb/sdb${EXT_EXE} sdb/src/.sdb sdb/sdb
PREMODS=capstone gdb windbg sdb bochs ar

clean mrproper:
	rm -f ${SDBFILES}
	@for MOD in ${PREMODS} ${MODS} ; do $(MAKE) -C $$MOD clean ; done

ifeq ($(BUILD_OS),windows)
BUILD_EXT_EXE=.exe
else
BUILD_EXT_EXE=
endif

SDB_TARGETS=$(SDBLIB)
ifneq (${EXT_EXE},)
SDB_TARGETS+=sdb/sdb${EXT_EXE}
else
SDB_TARGETS+=sdb/sdb
endif

PIC=
ifneq ($(CC),cccl)
PIC=-fPIC
ifeq ($(filter sdb/sdb${BUILD_EXT_EXE},$(SDB_TARGETS)),)
SDB_TARGETS+=sdb/sdb${BUILD_EXT_EXE}
endif
endif


targets:
	for TARGET in ${SDB_TARGETS} ; do ${MAKE} $$TARGET ; done

${SDB_TARGETS}:
	@echo
	@echo BUILD SUMARY
	@echo ============
	@echo COMPILER ${COMPILER}
	@echo CC ${CC}
	@echo HOST_CC ${HOST_CC}
	@echo HOST_OS ${HOST_OS}
	@echo BUILD_OS ${BUILD_OS}
	@echo ============
	@echo
	@echo ">>>>>>>>>>>>>>>>"
	@echo "NATIVE BUILD SDB"
	@echo ">>>>>>>>>>>>>>>>"
	@echo
	$(MAKE) -C sdb clean
	$(MAKE) -C sdb src/sdb_version.h
	$(MAKE) -C sdb/src CC=${HOST_CC} LDFLAGS='${HOST_LDFLAGS}' CPPFLAGS='' CFLAGS='${HOST_CFLAGS} ${PIC}' bin
	cp -f sdb/src/sdb${BUILD_EXT_EXE} sdb/src/.sdb${BUILD_EXT_EXE}
	@echo
	@echo ">>>>>>>>>>>>>>>>"
	@echo "TARGET BUILD SDB"
	@echo ">>>>>>>>>>>>>>>>"
	@echo
	$(MAKE) -C sdb clean
	cd sdb ; $(MAKE) src/sdb_version.h
	cd sdb/src ; $(MAKE) ARCH=xxx RANLIB="${RANLIB}" CFLAGS_SHARED="${CFLAGS_SHARED}" \
		CC="${CC}" AR="${AR}" CFLAGS='${CFLAGS}' LDFLAGS='${LDFLAGS}' libsdb.a
	${RANLIB} sdb/src/libsdb.a
ifneq (${EXT_AR},a)
	-cp -f sdb/src/libsdb.a sdb/src/libsdb.${EXT_AR}
endif
	rm -f $@
	cp -f sdb/src/.sdb${BUILD_EXT_EXE} $@

.PHONY: sdb-sync sync-sdb sdbclean
F=README.md config.mk src Makefile Jamroot meson.build msvc
SYNCFILES=$(addprefix sdb.vc/,${F})
I=../libr/include

libgdbr:
	$(MAKE) -C gdb all

libwindbg:
	$(MAKE) -C windbg all

bochs:
	$(MAKE) -C bochs all

sdb-clean clean-sdb:
	$(MAKE) -C sdb clean
	rm -f sdb/sdb.exe
	rm -f sdb/src/libsdb.${EXT_AR}

sdb-sync sync-sdb:
	rm -rf sdb sdb.vc
	git clone --depth 1 ${SDB_URL} sdb.vc
	mkdir -p sdb
	cp -rf ${SYNCFILES} sdb
	rm -rf sdb.vc $I/sdb
	mkdir -p $I/sdb
	rm -f src/sdb_version.h
	cd sdb ; $(MAKE) src/sdb_version.h
	cp -f sdb/src/*.h $I/sdb
	echo '#include <sdb/sdb.h>' > $I/sdb.h
	mkdir -p sdb/test sdb/memcache
	sed -e 's,HAVE_VALA=,HAVE_VALA=#,' sdb/config.mk > .t
	mv .t sdb/config.mk
	echo all clean mrproper: | tee sdb/test/Makefile > sdb/memcache/Makefile
	git add $I/sdb*
	git add sdb

$(TCCLIB) libr_tcc/libr_tcc.${EXT_AR}:
	cd libr_tcc ; $(MAKE)

udis-sync udis86-sync sync-udis sync-udis86:
	cd udis86 ; $(MAKE) sync

tcc-clean tccclean:
	cd libr_tcc ; $(MAKE) clean

CFILES=i386-asm.c i386-gen.c libtcc.c tccasm.c tccelf.c tccgen.c tccpp.c
HFILES=tcc.h i386-asm.h tcclib.h tcctok.h stab.h
HFILES+=elf.h config.h i386-tok.h

# TODO: use mob branch?

.PHONY: sdb-sync sync-sdb sdbclean
tcc-sync sync-tcc:
	rm -rf _
	$(GIT) clone --depth 1 git://repo.or.cz/tinycc.git _
	cd _ ; ./configure --prefix=${PREFIX}
	mkdir -p tcc
	for FILE in ${CFILES} ${HFILES} ; do cp -f _/$$FILE tcc ; done
	cp -f _/VERSION _/COPYING _/stab.def tcc
	$(GIT) add tcc
	rm -rf _

install: libr_shlr.${EXT_AR}
	mkdir -p ${DESTDIR}/${LIBDIR}
	cp -f libr_shlr.${EXT_AR} ${DESTDIR}/${LIBDIR}

install-symlink symstall:
	mkdir -p "${DESTDIR}${LIBDIR}"
	#cd tcc ; for FILE in libr_tcc* ; do \
	#	ln -fs `pwd`/$$FILE ${DESTDIR}${LIBDIR}/$$FILE ; done

uninstall deinstall:
	rm -f ${DESTDIR}${LIBDIR}/libr_shlr.${EXT_AR}

ifeq ($(USE_CAPSTONE),1)
# Do nothing here
capstone:

capstone-sync:

capstone-build:

else

ifeq ($(CS_RELEASE),1)
capstone-sync: capstone

capstone-clean:
	cd capstone ; $(MAKE) clean

capstone: capstone-$(CS_VER).tar.gz
	tar xzvf capstone-$(CS_VER).tar.gz
	rm -rf capstone
	mv capstone-$(CS_VER) capstone
ifeq ($(CS_PATCHES),1)
	#cd capstone ; for PATCH in ../capstone-patches/* ; do patch -tp1 < $$PATCH ; done
	cd capstone ; for PATCH in ../capstone-patches/* ; do patch -p1 < $$PATCH ; done
endif
	mkdir -p capstone/include/capstone
	cp -rf capstone/include/*.h capstone/include/capstone

capstone-$(CS_VER).tar.gz:
	$(WGET) --no-check-certificate -O capstone-$(CS_VER).tar.gz -c $(CS_TAR)
else

capstone: capstone-sync

capstone-sync:
ifeq ($(WITHOUT_PULL),1)
	@echo "Nothing to sync because of --without-pull"
else
	"$(SHELL)" capstone.sh "${CS_URL}" "${CS_BRA}" "${CS_TIP}" "${CS_REV}"
ifeq ($(CS_PATCHES),1)
	-cd capstone ; $(GIT) reset --hard
	#cd capstone ; for PATCH in ../capstone-patches/* ; do patch -tp1 < $$PATCH ; done
	cd capstone ; for PATCH in ../capstone-patches/* ; do patch -p1 < $$PATCH ; done
endif
endif

.PHONY: capstone
endif

ifeq (${EXT_AR},)
all:
	echo EXT_AR is not defined
	exit 1
endif

capstone-build: capstone
	cd capstone && CFLAGS="-Dmips=mips ${CAPSTONE_CFLAGS} $(CFLAGS)" LDFLAGS="$(LDFLAGS)" \
		$(MAKE) $(CAPSTONE_MAKEFLAGS) CC="$(CC)" AR_EXT=a IS_CYGWIN=0 CAPSTONE_STATIC=yes CAPSTONE_SHARED=no \
		RANLIB="$(RANLIB)" AR="$(AR)" IS_MINGW=0 libcapstone.a
ifneq (${EXT_AR},a)
	-cp -f capstone/libcapstone.a capstone/libcapstone.${EXT_AR}
endif
endif
../../radare2-webui:
	cd ../.. ; git clone --depth 1 https://github.com/radare/radare2-webui

../../radare2-webui/dist/m: ../../radare2-webui
ifeq ($(WITHOUT_PULL),1)
	cd ../../radare2-webui/www/m && npm i ; $(MAKE) release
else
	cd ../../radare2-webui/www/m && git pull ; npm i ; $(MAKE) release
endif

www-sync-m sync-www-m: ../../radare2-webui/dist/m
	cp -rf ../../radare2-webui/dist/m www/m.tmp
	rm -rf www/m
	mv www/m.tmp www/m
	git add www/m

www-sync-p sync-www-p:
	cp -rf ../../radare2-webui/dist/p www/p.tmp
	rm -rf www/p
	mv www/p.tmp www/p
	git add www/p

www-sync-t sync-www-t:
	cp -rf ../../radare2-webui/dist/t www/t.tmp
	rm -rf www/t
	mv www/t.tmp www/t
	git add www/p

sync-www www-sync: www-sync-m www-sync-p www-sync-t
	@echo webui sync done

spp-sync sync-spp:
	-git rm -r spp
	rm -rf spp
	git clone --depth 1 ${SPP_URL} spp
	rm -rf spp/.git*
	rm -rf spp/t
	git add spp

spp: spp-sync
	CFLAGS="-DHAVE_FORK=${HAVE_FORK} -fPIC" $(MAKE) -C spp

SHLRS+=ar/libr_ar.a
SHLRS+=bochs/lib/libbochs.a
SHLRS+=capstone/libcapstone.a
SHLRS+=gdb/lib/libgdbr.a
SHLRS+=grub/libgrubfs.a
SHLRS+=java/libr_java.a
SHLRS+=lz4/liblz4.a
SHLRS+=qnx/lib/libqnxr.a
#SHLRS+=sdb/src/libsdb.a
#SHLRS+=tcc/libr_tcc.a
SHLRS+=windbg/libr_windbg.a
SHLRS+=zip/librz.a

libr_shlr.${EXT_AR}:
	rm -rf .libr
	mkdir .libr
	for LIB in ${SHLRS} ; do \
		if [ -f "$${LIB}" ]; then ${PARTIALLD} -o .libr/$$(basename $${LIB} .a).o $${LIB} ; fi ; \
	done
	${AR} crs $@ .libr/*.o

.PHONY: spp
