include ../config-user.mk
include ../global.mk
include ../libr/config.mk
include ../mk/platform.mk
_INCLUDE_MK_GCC_=
include ../mk/${COMPILER}.mk
include ../mk/darwin.mk


# TODO: Delete this checks:
ifeq ($(shell test -f ../ChangeLog -a -d capstone -a ! -d capstone/.git && echo 1),1)
WITHOUT_PULL=1
CS_RELEASE=0
else
WITHOUT_PULL=0

# Build against last capstone release or next
# TODO: Delete this checks:
ifeq ($(shell test -e ../.git && echo 1),1)
CS_RELEASE=0
else
ifeq ($(shell test -d capstone/.git && echo 1),1)
CS_RELEASE=0
else
CS_RELEASE=1
endif
endif
endif

CAPSTONE_CFLAGS=
# CAPSTONE_MAKEFLAGS?=CAPSTONE_ARCHS="arm aarch64"

GIT?=git
ifeq ($(shell type wget 2> /dev/null && echo 1),1)
WGET?=wget -c --no-check-certificate -O
else
WGET?=curl -o
endif

ifeq ($(CS_RELEASE),1)
CS_PATCHES=0
else
ifeq ($(USE_CSNEXT),1)
CS_ROOT=../subprojects/capstone-next
else
ifeq ($(USE_CS4),1)
CS_ROOT=../subprojects/capstone-v4
else
CS_ROOT=../subprojects/capstone-v5
endif
endif

CS_PATCHES=1
endif

.PHONY: capstone-sync capstone-build all clean mrproper libgdbr libwinkd bochs sdbs

ifeq ($(shell gcc -v > /dev/null 2>&1 && echo works),works)
HOST_CC?=gcc
endif
SHLR?=$(shell pwd)
AR?=ar
RANLIB?=ranlib
MODS=zip java
MODS+=gdb qnx ar
# lz4
ifneq ($(CC),cccl)
ifeq (1,$(WITH_GPL))
MODS+=grub
endif
endif
SPP_URL=https://github.com/trufae/spp
PWD=$(shell pwd)

CFLAGS_SHARED=${PIC_CFLAGS}

ifeq (${EXT_SO},)
all:
	echo EXT_SO not defined
	exit 1
endif

preall: libwinkd capstone-build bochs sdbs sdbtool
	@for MOD in ${MODS} ; do \
		echo $(MAKE) -C $$MOD ; \
		$(MAKE) -C $$MOD HAVE_VALA= ROOT="${PWD}/../" CC="${CC}" ; \
	done

.PHONY: sdbtool
sdbtool:
	$(CC) -I ../libr/include -L ../libr/util -lr_util -o sdbtool sdbtool.c

ifeq ($(BUILD_OS),windows)
BUILD_EXT_EXE=.exe
else
BUILD_EXT_EXE=
endif

PIC=
ifneq ($(CC),cccl)
PIC=-fPIC
endif

SDB_ROOT=../subprojects/sdb
SDB_HOST=$(SDB_ROOT)/sdb$(BUILD_EXT_EXE)
SDB_LIBA=$(SDB_ROOT)/src/libsdb.$(EXT_AR)

SDBFILES=$(SDB_ROOT)/src/.sdb${EXT_EXE} $(SDB_ROOT)/sdb${EXT_EXE} $(SDB_ROOT)/src/.sdb $(SDB_ROOT)/sdb
PREMODS=capstone gdb winkd sdb bochs ar

clean mrproper:
	rm -f ${SDBFILES}
	@for MOD in ${PREMODS} ${MODS} ; do $(MAKE) -C $$MOD clean ; done

$(SDB_HOST): $(SDB_ROOT)
	$(MAKE) sdb-host HOST_CC=$(HOST_CC) CC=$(HOST_CC)

$(SDB_LIBA):
	$(MAKE) sdb-target RANLIB="$(RANLIB)"

sdbs: $(SDB_HOST)
	$(MAKE) $(SDB_LIBA) RANLIB="$(RANLIB)"

$(SDB_ROOT):
	$(MAKE) -C ../subprojects

sdb-host:
	@echo
	@echo ">>>>>>>>"
	@echo "HOST SDB"
	@echo ">>>>>>>>"
	@echo
	$(MAKE) -C $(SDB_ROOT) clean ; rm -f $(SDB_ROOT)/src/*.o $(SDB_ROOT)/include/sdb/version.h
	$(MAKE) -C $(SDB_ROOT)/src "CC=${HOST_CC}" LDFLAGS='${HOST_LDFLAGS}' CPPFLAGS='-I$(SDB_ROOT)/include' CFLAGS='${HOST_CFLAGS} ${PIC}' bin
	cp -f $(SDB_ROOT)/src/sdb${BUILD_EXT_EXE} $(SDB_ROOT)/src/.sdb${BUILD_EXT_EXE}
	cp -f $(SDB_ROOT)/src/sdb${BUILD_EXT_EXE} $(SDB_ROOT)/sdb$(BUILD_EXT_EXE)
	rm -f $(SDB_LIBA)
	-file $(SDB_ROOT)/sdb$(BUILD_EXT_EXE)

sdb-target:
	@echo
	@echo ">>>>>>>>>>"
	@echo "TARGET SDB"
	@echo ">>>>>>>>>>"
	@echo
	rm -f src/libsdb.$(EXT_AR)
	$(MAKE) -C $(SDB_ROOT) clean ; rm -f $(SDB_ROOT)/src/*.o ../include/sdb/version.h
	$(MAKE) -C $(SDB_ROOT)/src ../include/sdb/version.h
ifeq ($(EXT_EXE),.wasm)
	$(MAKE) -C $(SDB_ROOT)/src ARCH=xxx EXT_AR=.$(EXT_AR) RANLIB="${RANLIB}" CPPFLAGS=-I$(SDB_ROOT)/include \
		CFLAGS_SHARED="${CFLAGS_SHARED} -DHAVE_MMAN=0" \
		CC="${CC}" AR="${AR}" ARCH=undefined CFLAGS='${CFLAGS} -DHAVE_MMAN=0' LDFLAGS='${LDFLAGS}' libsdb.$(EXT_AR)
else
	$(MAKE) -C $(SDB_ROOT)/src ARCH=xxx EXT_AR=.$(EXT_AR) RANLIB="${RANLIB}" CPPFLAGS="-I$(SDB_ROOT)/include -DHAVE_SYSTEM=0" \
		CFLAGS_SHARED="${CFLAGS_SHARED}" \
		CC="${CC}" AR="${AR}" ARCH=undefined LDFLAGS='${LDFLAGS}' libsdb.$(EXT_AR)
endif
	$(RANLIB) $(SDB_ROOT)/src/libsdb.$(EXT_AR)

.PHONY: sdb-sync sync-sdb sdbclean sdb-native sdb-target
SDB_F=README.md config.mk src include Makefile meson.build wasi.mk wasi.sh
SDB_SYNCFILES=$(addprefix sdb.vc/,${SDB_F})
I=../libr/include

libgdbr:
	$(MAKE) -C gdb all

libwinkd:
	$(MAKE) -C winkd all

bochs:
	$(MAKE) -C bochs all

sdb-clean clean-sdb:
	$(MAKE) -C $(SDB_ROOT) clean
	rm -f $(SDB_ROOT)/sdb.exe
	rm -f $(SDB_ROOT)/src/libsdb.${EXT_AR}

ifeq ($(WITH_LIBR),1)
install: libr_shlr.${EXT_AR}
	mkdir -p ${DESTDIR}/${LIBDIR}
	cp -f libr_shlr.${EXT_AR} ${DESTDIR}/${LIBDIR}
else
install:
endif

install-symlink symstall:
	mkdir -p "${DESTDIR}${LIBDIR}"
	#cd tcc ; for FILE in libr_tcc* ; do \
	#	ln -fs `pwd`/$$FILE ${DESTDIR}${LIBDIR}/$$FILE ; done

uninstall deinstall:
	rm -f ${DESTDIR}${LIBDIR}/libr_shlr.${EXT_AR}

.PHONY: capstone capstone-sync capstone-build capstone-patch


ifeq ($(WANT_CAPSTONE),0)
capstone:

capstone-sync:

capstone-build:
else
ifeq ($(USE_CAPSTONE),1)
# Do nothing here
capstone:

capstone-sync:

capstone-build:

else

ifeq ($(CS_RELEASE),1)

capstone:
	$(MAKE) patch-capstone

# already implemented in capstone.sh
patch-capstone capstone-patch:
ifeq ($(CS_PATCHES),1)
	if [ -d $(CS_ROOT) -a -d $(CS_ROOT)/.git ]; then \
ifeq ($(USE_CS4),1)
		cd $(CS_ROOT) && for PATCH in ../capstone-patches/v4/* ; do patch -p1 < $$PATCH ; done ; \
else
		cd $(CS_ROOT) && for PATCH in ../capstone-patches/v5/* ; do patch -p1 < $$PATCH ; done ; \
endif
	fi
endif
	mkdir -p $(CS_ROOT)/include/capstone
	cp -rf $(CS_ROOT)/include/*.h $(CS_ROOT)/include/capstone

patch-capstone capstone-patch:

.PHONY: capstone capstone-sync
endif

ifeq (${EXT_AR},)
all:
	echo EXT_AR is not defined
	exit 1
endif

capstone-build: capstone
ifeq ($(CAPSTONE_LDFLAGS),)
	cd $(CS_ROOT) && CFLAGS="${CAPSTONE_CFLAGS} $(CFLAGS)" LDFLAGS="$(LDFLAGS)" \
		$(MAKE) $(CAPSTONE_MAKEFLAGS) CC="$(CC)" AR_EXT=a IS_CYGWIN=0 CAPSTONE_STATIC=yes CAPSTONE_SHARED=no \
		RANLIB="$(RANLIB)" LIBARCHS="" AR="$(AR)" IS_MINGW=0 libcapstone.a
ifneq (${EXT_AR},a)
	-cp -f $(CS_ROOT)/libcapstone.a $(CS_ROOT)/libcapstone.${EXT_AR}
endif
else
	echo "Using capstone from system"
endif

endif
endif

headsup:
	[ "`cd $(CS_ROOT) && git rev-parse HEAD`" = "$(CS_TIP)" ]

../../radare2-webui:
	cd ../.. ; git clone --depth 1 https://github.com/radareorg/radare2-webui

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
	export CFLAGS="-DUSE_R2=1 -I../../libr/include -DHAVE_FORK=${HAVE_FORK} -fPIC";  $(MAKE) -C spp r2lib

SHLRS+=ar/libr_ar.a
SHLRS+=bochs/lib/libbochs.a
SHLRS+=$(CS_ROOT)/libcapstone.a
SHLRS+=gdb/lib/libgdbr.a
SHLRS+=grub/libgrubfs.a
SHLRS+=java/libr_java.a
SHLRS+=qnx/lib/libqnxr.a
SHLRS+=winkd/libr_winkd.a
SHLRS+=zip/librz.a

libr_shlr.${EXT_AR}:
	rm -rf .libr
	mkdir .libr
	for LIB in ${SHLRS} ; do \
		if [ -f "$${LIB}" ]; then ${PARTIALLD} -o .libr/$$(basename $${LIB}.a).o $${LIB} ; fi ; \
	done
	${AR} rs $@ .libr/*.o
	$(RANLIB) $@

.PHONY: spp
