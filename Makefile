-include config-user.mk
include global.mk

PREVIOUS_RELEASE=`git log --tags --simplify-by-decoration --pretty='format:%d'|head -n1|cut -d ' ' -f3 |sed -e 's,),,'`

B=$(DESTDIR)$(BINDIR)
L=$(DESTDIR)$(LIBDIR)
MESON?=meson
PYTHON?=python
R2BINS=$(shell cd binr ; echo r*2 r2agent r2pm r2-indent r2r r2sdb)
ifdef SOURCE_DATE_EPOCH
BUILDSEC=$(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "+__%H:%M:%S" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "+__%H:%M:%S" 2>/dev/null || date -u "+__%H:%M:%S")
else
BUILDSEC=$(shell date "+__%H:%M:%S")
endif
DATADIRS=libr/cons/d libr/flag/d libr/bin/d libr/asm/d libr/syscall/d libr/magic/d libr/anal/d libr/util/d libr/arch/d
ZIPWINDIST=YES
ZIP=zip

R2VC=$(shell git rev-list --all --count 2>/dev/null)
ifeq ($(R2VC),)
# release
R2VC=0
endif

STRIP?=strip
ifneq ($(shell xz --help 2>/dev/null | grep improve),)
TAR=tar -cvf
TAREXT=tar.xz
CZ=xz -f
else
TAR=bsdtar cvf
TAREXT=tar.gz
CZ=gzip -f
endif
PWD=$(shell pwd)
JOBS?=

ifeq ($(BUILD_OS),windows)
ifeq ($(OSTYPE),mingw32)
ifneq (,$(findstring mingw32-make,$(MAKE)))
ifneq ($(APPVEYOR),True)
	LC_ALL=C
	export LC_ALL
endif
endif
endif
endif

all: plugins.cfg libr/include/r_version.h
	@libr/count.sh reset
	${MAKE} -C shlr sdbs
	${MAKE} -C shlr/zip
	${MAKE} -C libr/util
	${MAKE} -C libr/socket
	${MAKE} -C shlr
	${MAKE} -C libr
	${MAKE} -C binr

GIT_TAP=$(shell git describe --tags --match '[0-9]*' 2>/dev/null)
GIT_TIP=$(shell git rev-parse HEAD 2>/dev/null || echo $(R2_VERSION))
R2_VER=$(shell ./configure -qV)
ifeq ($(GIT_TAP),)
GIT_TAP=$(R2_VER)
endif
ifeq ($(GIT_TIP),)
GIT_TIP=$(R2_VER)
endif
ifdef SOURCE_DATE_EPOCH
GIT_NOW=$(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "+%Y-%m-%d" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "+%Y-%m-%d" 2>/dev/null || date -u "+%Y-%m-%d")
else
GIT_NOW=$(shell date "+%Y-%m-%d")
endif

tap tiptap tip:
	@echo tip $(GIT_TIP)
	@echo tap $(GIT_TAP)

libr/include/r_version.h:
	@echo Generating r_version.h file
	@echo '#ifndef R_VERSION_H' > $@.tmp
	@echo '#define R_VERSION_H 1' >> $@.tmp
	@echo '#define R2_VERSION_COMMIT $(R2VC)' >> $@.tmp
	@echo '#define R2_VERSION "$(R2_VERSION)"' >> $@.tmp
	@echo '#define R2_VERSION_MAJOR $(R2_VERSION_MAJOR)' >> $@.tmp
	@echo '#define R2_VERSION_MINOR $(R2_VERSION_MINOR)' >> $@.tmp
	@echo '#define R2_VERSION_PATCH $(R2_VERSION_PATCH)' >> $@.tmp
	@echo '#define R2_VERSION_NUMBER $(R2_VERSION_NUMBER)' >> $@.tmp
	@echo '#define R2_GITTAP $(ESC)"$(GIT_TAP)$(ESC)"' >> $@.tmp
	@echo '#define R2_GITTIP $(ESC)"$(GIT_TIP)$(ESC)"' >> $@.tmp
	@echo '#define R2_BIRTH $(ESC)"$(GIT_NOW)$(BUILDSEC)$(ESC)"' >> $@.tmp
	@echo '#endif' >> $@.tmp
	@mv -f $@.tmp $@
	@rm -f $@.tmp

plugins.cfg:
	@if [ ! -e config-user.mk ]; then echo ; \
	echo "  Please, run ./configure first" ; echo ; exit 1 ; fi
	$(SHELL) ./configure-plugins

w32:
	sys/mingw32.sh

depgraph.png:
	cd libr ; perl depgraph.pl dot | dot -Tpng -o../depgraph.png

android:
	@if [ -z "$(NDK_ARCH)" ]; then echo "Set NDK_ARCH=[arm|arm64|mips|x86]" ; false; fi
	sys/android-${NDK_ARCH}.sh

w32dist:
	${MAKE} windist WINBITS=w32

w64dist:
	${MAKE} windist WINBITS=w64

WINDIST=${WINBITS}dist
ZIPNAME?=radare2-${WINBITS}-${VERSION}.zip

C=$(shell printf "\033[32m")
R=$(shell printf "\033[0m")
windist:
	@echo "${C}[WINDIST] Installing binaries and libraries${R}"
	[ -n "${WINBITS}" ] || exit 1
	rm -rf "radare2-${WINBITS}-${VERSION}" "${WINDIST}"
	mkdir "${WINDIST}"
	for FILE in `find libr | grep -e dll$$`; do cp "$$FILE" "${WINDIST}" ; done
	for FILE in `find binr | grep -e exe$$`; do cp "$$FILE" "${WINDIST}" ; done
	rm -f "${WINDIST}/plugin.dll"
	@echo "${C}[WINDIST] Picking plugins from libraries${R}"
	mkdir -p "${WINDIST}/libs"
	mv "${WINDIST}/"lib*.dll "${WINDIST}/libs"
	mkdir -p "${WINDIST}/plugins"
	mv ${WINDIST}/*.dll "${WINDIST}/plugins"
	mv ${WINDIST}/libs/* "${WINDIST}"
	@echo "${C}[WINDIST] Do not include plugins for now${R}"
	rm -rf "${WINDIST}/libs"
	rm -rf ${WINDIST}/plugins/*
	@echo "${C}[WINDIST] Copying web interface${R}"
	mkdir -p "${WINDIST}/www"
	cp -rf shlr/www/* "${WINDIST}/www"
	mkdir -p "${WINDIST}/share/radare2/${VERSION}/magic"
	cp -f libr/magic/d/default/* "${WINDIST}/share/radare2/${VERSION}/magic"
	mkdir -p "${WINDIST}/share/radare2/${VERSION}/syscall"
	cp -f libr/syscall/d/*.sdb "${WINDIST}/share/radare2/${VERSION}/syscall"
	mkdir -p "${WINDIST}/share/radare2/${VERSION}/sysregs"
	cp -f libr/sysregs/d/*.sdb "${WINDIST}/share/radare2/${VERSION}/sysregs"
	mkdir -p "${WINDIST}/share/radare2/${VERSION}/fcnsign"
	cp -f libr/anal/d/*.sdb "${WINDIST}/share/radare2/${VERSION}/fcnsign"
	mkdir -p "${WINDIST}/share/radare2/${VERSION}/platform"
	cp -f libr/arch/d/*.r2 "${WINDIST}/share/radare2/${VERSION}/platform"
	mkdir -p "${WINDIST}/share/radare2/${VERSION}/opcodes"
	cp -f libr/asm/d/*.sdb "${WINDIST}/share/radare2/${VERSION}/opcodes"
	mkdir -p "${WINDIST}/share/radare2/${VERSION}/scripts"
	cp -f scripts/*.js scripts/*.py "${WINDIST}/share/radare2/${VERSION}/scripts"
	mkdir -p "${WINDIST}/share/radare2/${VERSION}/flag"
	cp -f libr/flag/d/*.r2 "${WINDIST}/share/radare2/${VERSION}/flag"
	mkdir -p "${WINDIST}/share/doc/radare2"
	mkdir -p "${WINDIST}/include/libr/sdb"
	mkdir -p "${WINDIST}/include/libr/r_util"
	mkdir -p "${WINDIST}/include/libr/r_anal"
	@echo "${C}[WINDIST] Copying development files${R}"
	cp -f subprojects/sdb/include/*.h "${WINDIST}/include/libr/sdb/"
	cp -f libr/include/r_util/*.h "${WINDIST}/include/libr/r_util/"
	cp -f libr/include/r_anal/*.h "${WINDIST}/include/libr/r_anal/"
	cp -f libr/include/*.h "${WINDIST}/include/libr"
	#mkdir -p "${WINDIST}/include/libr/sflib"
	@cp -f doc/fortunes.* "${WINDIST}/share/doc/radare2"
	@mkdir -p "${WINDIST}/share/radare2/${VERSION}/format/dll"
	@cp -f libr/bin/d/elf32 "${WINDIST}/share/radare2/${VERSION}/format"
	@cp -f libr/bin/d/elf64 "${WINDIST}/share/radare2/${VERSION}/format"
	@cp -f libr/bin/d/elf_enums "${WINDIST}/share/radare2/${VERSION}/format"
	@cp -f libr/bin/d/pe32 "${WINDIST}/share/radare2/${VERSION}/format"
	@cp -f libr/bin/d/trx "${WINDIST}/share/radare2/${VERSION}/format"
	@cp -f libr/bin/d/dll/*.sdb "${WINDIST}/share/radare2/${VERSION}/format/dll"
	@mkdir -p "${WINDIST}/share/radare2/${VERSION}/cons"
	@cp -PRpf libr/cons/d/* "${WINDIST}/share/radare2/${VERSION}/cons"
	@mkdir -p "${WINDIST}/share/radare2/${VERSION}/hud"
	@cp -f doc/hud "${WINDIST}/share/radare2/${VERSION}/hud/main"
	@mv "${WINDIST}" "radare2-${WINBITS}-${VERSION}"
	@rm -f "radare2-${WINBITS}-${VERSION}.zip"
ifneq ($(ZIPWINDIST),NO)
	$(ZIP) -r "${ZIPNAME}" "radare2-${WINBITS}-${VERSION}"
endif

clean:
	rm -f libr/libr.a libr/libr.dylib libr/include/r_version.h
	rm -rf libr/.libr
	-rm -f `find * | grep arm | grep dis.a$$`
	for DIR in shlr libr binr ; do $(MAKE) -C "$$DIR" clean ; done
	rm -f `find . -type f -name '*.d'` || for a in `find . -type f -name '*.d'` ; do rm -f "$$a" ; done
	rm -f `find . -type f -name '*.o'` || for a in `find . -type f -name '*.o'` ; do rm -f "$$a" ; done
	rm -f config-user.mk plugins.cfg libr/config.h
	rm -f libr/include/r_userconf.h libr/config.mk
	rm -f pkgcfg/*.pc

distclean mrproper: clean
	rm -rf libr/arch/p/arm/v35/arch-arm*
	rm -rf shlr/capstone
	$(MAKE) -C subprojects clean 

pkgcfg:
	cd libr && ${MAKE} pkgcfg

install-man:
	mkdir -p "${DESTDIR}${MANDIR}/man1"
	mkdir -p "${DESTDIR}${MANDIR}/man7"
	mkdir -p "${DESTDIR}${MANDIR}/man3"
	for FILE in man/*.1 ; do ${INSTALL_MAN} "$$FILE" "${DESTDIR}${MANDIR}/man1" ; done
	cd "${DESTDIR}${MANDIR}/man1" && ln -fs radare2.1 r2.1
	for FILE in man/*.7 ; do ${INSTALL_MAN} "$$FILE" "${DESTDIR}${MANDIR}/man7" ; done
	for FILE in man/3/*.3 ; do ${INSTALL_MAN} "$$FILE" "${DESTDIR}${MANDIR}/man3" ; done

install-man-symlink:
	mkdir -p "${DESTDIR}${MANDIR}/man1"
	mkdir -p "${DESTDIR}${MANDIR}/man7"
	mkdir -p "${DESTDIR}${MANDIR}/man3"
	for FILE in $(shell cd man && ls *.1) ; do \
		ln -fs "${PWD}/man/$$FILE" "${DESTDIR}${MANDIR}/man1/$$FILE" ; done
	cd "${DESTDIR}${MANDIR}/man1" && ln -fs radare2.1 r2.1
	for FILE in $(shell cd man && ls *.7) ; do \
		ln -fs "${PWD}/man/$$FILE" "${DESTDIR}${MANDIR}/man7/$$FILE" ; done
	for FILE in $(shell cd man/3 && ls *.3) ; do \
		ln -fs "${PWD}/man/3/$$FILE" "${DESTDIR}${MANDIR}/man3/$$FILE" ; done

install-doc:
	mkdir -p "${DESTDIR}${DOCDIR}"
	${INSTALL_DIR} "${DESTDIR}${DOCDIR}"
	@echo ${DOCDIR}
	for FILE in doc/* ; do \
		if [ -f $$FILE ]; then ${INSTALL_DATA} $$FILE "${DESTDIR}${DOCDIR}" || true ; fi; \
	done

install-doc-symlink:
	mkdir -p "${DESTDIR}${DOCDIR}"
	${INSTALL_DIR} "${DESTDIR}${DOCDIR}"
	for FILE in $(shell cd doc ; ls) ; do \
		ln -fs "$(PWD)/doc/$$FILE" "${DESTDIR}${DOCDIR}" ; done

install: install-doc install-man install-panels install-www install-pkgconfig
	$(MAKE) -C libr install
	$(MAKE) -C binr install
	$(MAKE) -C shlr install
	for DIR in ${DATADIRS} ; do $(MAKE) -C "$$DIR" install ; done
	cd "$(DESTDIR)$(LIBDIR)/radare2/" && rm -f last && ln -fs $(VERSION) last
	cd "$(DESTDIR)$(DATADIR)/radare2/" && rm -f last && ln -fs $(VERSION) last
	rm -rf "${DESTDIR}${DATADIR}/radare2/${VERSION}/scripts"
	mkdir -p "${DESTDIR}${DATADIR}/radare2/${VERSION}/scripts"
	cp -rf scripts/*.js scripts/*.py "${DESTDIR}${DATADIR}/radare2/${VERSION}/scripts"
	rm -rf "${DESTDIR}${DATADIR}/radare2/${VERSION}/hud"
	mkdir -p "${DESTDIR}${DATADIR}/radare2/${VERSION}/hud"
	mkdir -p "${DESTDIR}${BINDIR}"
	#${INSTALL_SCRIPT} "${PWD}/sys/indent.sh" "${DESTDIR}${BINDIR}/r2-indent"
	cp -f doc/hud "${DESTDIR}${DATADIR}/radare2/${VERSION}/hud/main"
	mkdir -p "${DESTDIR}${DATADIR}/radare2/${VERSION}/"
	$(SHELL) ./configure-plugins --rm-static $(DESTDIR)$(LIBDIR)/radare2/last/
	cp -f subprojects/sdb/sdb "${DESTDIR}${BINDIR}/r2sdb"

install-panels:
	rm -rf "${DESTDIR}${PANELS}"
	mkdir -p "${DESTDIR}${PANELS}"
	for FILE in $(shell cd shlr/panels ; ls | grep json) ; do \
		FILE2=$$(echo $$FILE | cut -d . -f 1); \
		cp -f "$(PWD)/shlr/panels/$$FILE" "$(DESTDIR)$(PANELS)/$$FILE2" ; done

symstall-panels:
	rm -rf "${DESTDIR}${PANELS}"
	mkdir -p "${DESTDIR}${PANELS}"
	for FILE in $(shell cd shlr/panels ; ls | grep json) ; do \
		FILE2=$$(echo $$FILE | cut -d . -f 1); \
		ln -fs "$(PWD)/shlr/panels/$$FILE" "$(DESTDIR)$(PANELS)/$$FILE2" ; done

install-www:
	rm -rf "${DESTDIR}${WWWROOT}"
	rm -rf "${DESTDIR}${LIBDIR}/radare2/${VERSION}/www" # old dir
	mkdir -p "${DESTDIR}${WWWROOT}"
	cp -rf shlr/www/* "${DESTDIR}${WWWROOT}"

symstall-www:
	rm -rf "${DESTDIR}${WWWROOT}"
	rm -rf "${DESTDIR}${LIBDIR}/radare2/${VERSION}/www" # old dir
	mkdir -p "${DESTDIR}${WWWROOT}"
	for FILE in $(shell cd shlr/www ; ls) ; do \
		ln -fs "$(PWD)/shlr/www/$$FILE" "$(DESTDIR)$(WWWROOT)" ; done

install-pkgconfig pkgconfig-install:
	@${INSTALL_DIR} "${DESTDIR}${LIBDIR}/pkgconfig"
	for FILE in $(shell cd pkgcfg ; ls *.pc) ; do \
		cp -f "$(PWD)/pkgcfg/$$FILE" "${DESTDIR}${LIBDIR}/pkgconfig/$$FILE" ; done

install-pkgconfig-symlink pkgconfig-symstall symstall-pkgconfig:
	mkdir -p "${DESTDIR}${LIBDIR}/pkgconfig"
	@${INSTALL_DIR} "${DESTDIR}${LIBDIR}/pkgconfig"
	for FILE in $(shell cd pkgcfg ; ls *.pc) ; do \
		ln -fs "$(PWD)/pkgcfg/$$FILE" "${DESTDIR}${LIBDIR}/pkgconfig/$$FILE" ; done

symstall-sdb:
	for DIR in ${DATADIRS} ; do (\
		cd "$$DIR" ; \
		echo "$$DIR" ; \
		${MAKE} install-symlink ); \
	done

symstall install-symlink: install-man-symlink install-doc-symlink install-pkgconfig-symlink symstall-www symstall-panels symstall-sdb
	cd libr && ${MAKE} install-symlink
	cd binr && ${MAKE} install-symlink
	cd shlr && ${MAKE} install-symlink
	mkdir -p "${DESTDIR}${BINDIR}"
	ln -fs "${PWD}/sys/indent.sh" "${DESTDIR}${BINDIR}/r2-indent"
	rm -rf "${DESTDIR}${DATADIR}/radare2/${VERSION}/scripts"
	ln -fs scripts "${DESTDIR}${DATADIR}/radare2/${VERSION}/scripts"
	mkdir -p "${DESTDIR}${DATADIR}/radare2/${VERSION}/hud"
	ln -fs "${PWD}/doc/hud" "${DESTDIR}${DATADIR}/radare2/${VERSION}/hud/main"
	#mkdir -p "${DESTDIR}${DATADIR}/radare2/${VERSION}/flag"
	#ln -fs $(PWD)/libr/flag/d/tags.r2 "${DESTDIR}${DATADIR}/radare2/${VERSION}/flag/tags.r2"
	cd "$(DESTDIR)$(LIBDIR)/radare2/" && rm -f last && ln -fs $(VERSION) last
	cd "$(DESTDIR)$(DATADIR)/radare2/" && rm -f last && ln -fs $(VERSION) last
	mkdir -p "${DESTDIR}${DATADIR}/radare2/${VERSION}/"
	$(SHELL) ./configure-plugins --rm-static $(DESTDIR)/$(LIBDIR)/radare2/last/

deinstall uninstall:
	rm -f $(DESTDIR)$(BINDIR)/r2-indent
	cd libr && ${MAKE} uninstall
	cd binr && ${MAKE} uninstall
	cd shlr && ${MAKE} uninstall
	cd libr/util/d && ${MAKE} uninstall
	cd libr/syscall/d && ${MAKE} uninstall
	cd libr/anal/d && ${MAKE} uninstall
	cd libr/arch/d && ${MAKE} uninstall
	@echo
	@echo "Run 'make purge' to also remove installed files from previous versions of r2"
	@echo

purge-doc:
	rm -rf "${DESTDIR}${DOCDIR}"
	cd man ; for FILE in *.1 ; do rm -f "${DESTDIR}${MANDIR}/man1/$$FILE" ; done
	cd man ; for FILE in *.7 ; do rm -f "${DESTDIR}${MANDIR}/man7/$$FILE" ; done
	cd man/3 ; for FILE in *.3 ; do rm -f "${DESTDIR}${MANDIR}/man3/$$FILE" ; done
	rm -f "${DESTDIR}${MANDIR}/man1/r2.1"

user-wrap=echo "\#!/bin/sh" > ~/bin/"$1" \
; echo "${PWD}/env.sh '${PREFIX}' '$1' \"\$$@\"" >> ~/bin/"$1" \
; chmod +x ~/bin/"$1" ;

purge-dev:
	rm -f "${DESTDIR}${LIBDIR}/libr_"*".${EXT_AR}"
	rm -f "${DESTDIR}${LIBDIR}/pkgconfig/r_"*.pc
	rm -rf "${DESTDIR}${INCLUDEDIR}/libr"
	rm -f "${DESTDIR}${LIBDIR}/radare2/${VERSION}/-"*

# required for EXT_SO
include libr/config.mk

strip:
	#-for FILE in ${R2BINS} ; do ${STRIP} -s "${DESTDIR}${BINDIR}/$$FILE" 2> /dev/null ; done
ifeq ($(HOST_OS),darwin)
	-${STRIP} -STxX "${DESTDIR}${LIBDIR}/libr_"*".${EXT_SO}"
else
	-${STRIP} -s "${DESTDIR}${LIBDIR}/libr_"*".${EXT_SO}"
endif

purge: purge-doc purge-dev uninstall
	for FILE in ${R2BINS} ; do rm -f "${DESTDIR}${BINDIR}/$$FILE" ; done
	rm -f "${DESTDIR}${BINDIR}/ragg2-cc"
	rm -f "${DESTDIR}${BINDIR}/r2"
	rm -f "${DESTDIR}${LIBDIR}/libr_"*
	rm -f "${DESTDIR}${LIBDIR}/libr2"*".${EXT_SO}"
	rm -rf "${DESTDIR}${LIBDIR}/radare2"
	rm -rf "${DESTDIR}${INCLUDEDIR}/libr"
	rm -rf "${DESTDIR}${DATADIR}/radare2"

system-purge: purge
	sys/purge.sh

user-purge:
	rm -rf $(HOME)/.local/share/radare2

dist:
	$(MAKE) -C dist/tarball
	cp -f dist/tarball/*.$(TAREXT) .
	cp -f dist/tarball/*.zip .

shot:
	$(MAKE) -C dist/tarball VERSION=`date '+%Y%m%d'`

tests test:
	$(MAKE) -j${JOBS} -C test

macos-sign:
	$(MAKE) -C binr/radare2 macos-sign

macos-sign-libs:
	$(MAKE) -C binr/radare2 macos-sign-libs

osx-pkg:
	sys/osx-pkg.sh $(VERSION)

quality:
	./sys/shellcheck.sh

ctags:
	@ctags **/*.c **/*.h > /dev/null

menu nconfig:
	./sys/menu.sh || true

include mk/meson.mk
include ${MKPLUGINS}

.PHONY: all clean install symstall uninstall deinstall strip
.PHONY: libr binr install-man w32dist tests dist shot pkgcfg depgraph.png love
.PHONY: purge system-purge
.PHONY: shlr/capstone
