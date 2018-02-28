-include config-user.mk
include global.mk

PREVIOUS_RELEASE=`git log --tags --simplify-by-decoration --pretty='format:%d'|head -n1|cut -d ' ' -f3 |sed -e 's,),,'`

MESON?=meson
PYTHON?=python
R2R=radare2-regressions
R2R_URL=$(shell doc/repo REGRESSIONS)
R2BINS=$(shell cd binr ; echo r*2 r2agent r2pm r2-indent)
BUILDSEC=$(shell date "+__%H:%M:%S")
DATADIRS=libr/cons/d libr/bin/d libr/asm/d libr/syscall/d libr/magic/d libr/anal/d
USE_ZIP=YES
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

# For echo without quotes
Q='
ESC=
ifeq ($(BUILD_OS),windows)
ifeq ($(OSTYPE),mingw32)
ifneq (,$(findstring mingw32-make,$(MAKE)))
ifneq ($(APPVEYOR),True)
	Q=
	ESC=^
	LC_ALL=C
	export LC_ALL
endif
endif
endif
endif

all: plugins.cfg libr/include/r_version.h
	${MAKE} -C shlr/zip
	${MAKE} -C libr/util
	${MAKE} -C libr/socket
	${MAKE} -C shlr
	${MAKE} -C libr
	${MAKE} -C binr

#.PHONY: libr/include/r_version.h
GIT_TAP=$(shell git describe --tags --match "[0-9]*" 2>/dev/null || echo $(VERSION))
GIT_TIP=$(shell git rev-parse HEAD 2>/dev/null || echo HEAD)
R2_VER=$(shell grep VERSION configure.acr | head -n1 | awk '{print $$2}')
ifndef SOURCE_DATE_EPOCH
GIT_NOW=$(shell date +%Y-%m-%d)
else
GIT_NOW=$(shell date --utc --date="@$$SOURCE_DATE_EPOCH" +%Y-%m-%d)
endif

libr/include/r_version.h:
	@echo Generating r_version.h file
	@echo $(Q)#ifndef R_VERSION_H$(Q) > $@.tmp
	@echo $(Q)#define R_VERSION_H 1$(Q) >> $@.tmp
	@echo $(Q)#define R2_VERSION_COMMIT $(R2VC)$(Q) >> $@.tmp
	@echo $(Q)#define R2_VERSION $(ESC)"$(R2_VER)$(ESC)"$(Q) >> $@.tmp
	@echo $(Q)#define R2_GITTAP $(ESC)"$(GIT_TAP)$(ESC)"$(Q) >> $@.tmp
	@echo $(Q)#define R2_GITTIP $(ESC)"$(GIT_TIP)$(ESC)"$(Q) >> $@.tmp
	@echo $(Q)#define R2_BIRTH $(ESC)"$(GIT_NOW)$(BUILDSEC)$(ESC)"$(Q) >> $@.tmp
	@echo $(Q)#endif$(Q) >> $@.tmp
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
	mkdir -p "${WINDIST}/share/radare2/${VERSION}/opcodes"
	cp -f libr/asm/d/*.sdb "${WINDIST}/share/radare2/${VERSION}/opcodes"
	mkdir -p "${WINDIST}/share/doc/radare2"
	mkdir -p "${WINDIST}/include/libr/sdb"
	mkdir -p "${WINDIST}/include/libr/r_util"
	@echo "${C}[WINDIST] Copying development files${R}"
	cp -f libr/include/sdb/*.h "${WINDIST}/include/libr/sdb/"
	cp -f libr/include/r_util/*.h "${WINDIST}/include/libr/r_util/"
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
	@cp -af libr/cons/d/* "${WINDIST}/share/radare2/${VERSION}/cons"
	@mkdir -p "${WINDIST}/share/radare2/${VERSION}/hud"
	@cp -f doc/hud "${WINDIST}/share/radare2/${VERSION}/hud/main"
	@mv "${WINDIST}" "radare2-${WINBITS}-${VERSION}"
	@rm -f "radare2-${WINBITS}-${VERSION}.zip"
ifneq ($(USE_ZIP),NO)
	$(ZIP) -r "${ZIPNAME}" "radare2-${WINBITS}-${VERSION}"
endif

clean: rmd
	rm -f libr/libr.a
	for DIR in shlr libr binr ; do (cd "$$DIR" ; ${MAKE} clean) ; done

distclean mrproper:
	-rm -f `find . -type f -name '*.d'`
	rm -f `find . -type f -name '*.o'`
	rm -f libr/libr.a
	for DIR in libr binr shlr ; do ( cd "$$DIR" ; ${MAKE} mrproper) ; done
	rm -f config-user.mk plugins.cfg libr/config.h
	rm -f libr/include/r_userconf.h libr/include/r_version.h libr/config.mk
	rm -f pkgcfg/*.pc

pkgcfg:
	cd libr && ${MAKE} pkgcfg

install-man:
	mkdir -p "${DESTDIR}${MANDIR}/man1"
	mkdir -p "${DESTDIR}${MANDIR}/man7"
	for FILE in man/*.1 ; do ${INSTALL_MAN} "$$FILE" "${DESTDIR}${MANDIR}/man1" ; done
	cd "${DESTDIR}${MANDIR}/man1" && ln -fs radare2.1 r2.1
	for FILE in man/*.7 ; do ${INSTALL_MAN} "$$FILE" "${DESTDIR}${MANDIR}/man7" ; done

install-man-symlink:
	mkdir -p "${DESTDIR}${MANDIR}/man1"
	mkdir -p "${DESTDIR}${MANDIR}/man7"
	for FILE in $(shell cd man && ls *.1) ; do \
		ln -fs "${PWD}/man/$$FILE" "${DESTDIR}${MANDIR}/man1/$$FILE" ; done
	cd "${DESTDIR}${MANDIR}/man1" && ln -fs radare2.1 r2.1
	for FILE in *.7 ; do \
		ln -fs "${PWD}/man/$$FILE" "${DESTDIR}${MANDIR}/man7/$$FILE" ; done

install-doc:
	${INSTALL_DIR} "${DESTDIR}${DOCDIR}"
	@echo ${DOCDIR}
	for FILE in doc/* ; do \
		if [ -f $$FILE ]; then ${INSTALL_DATA} $$FILE "${DESTDIR}${DOCDIR}" || true ; fi; \
	done

install-doc-symlink:
	${INSTALL_DIR} "${DESTDIR}${DOCDIR}"
	for FILE in $(shell cd doc ; ls) ; do \
		ln -fs "$(PWD)/doc/$$FILE" "${DESTDIR}${DOCDIR}" ; done

install love: install-doc install-man install-www
	cd libr && ${MAKE} install PARENT=1
	cd binr && ${MAKE} install
	cd shlr && ${MAKE} install
	for DIR in ${DATADIRS} ; do \
		(cd "$$DIR" ; ${MAKE} install ); \
	done
	cd "$(DESTDIR)$(LIBDIR)/radare2/" ;\
		rm -f last ; ln -fs $(VERSION) last
	cd "$(DESTDIR)$(DATADIR)/radare2/" ;\
		rm -f last ; ln -fs $(VERSION) last
	rm -rf "${DESTDIR}${DATADIR}/radare2/${VERSION}/hud"
	mkdir -p "${DESTDIR}${DATADIR}/radare2/${VERSION}/hud"
	mkdir -p "${DESTDIR}${BINDIR}"
	#${INSTALL_SCRIPT} "${PWD}/sys/indent.sh" "${DESTDIR}${BINDIR}/r2-indent"
	#${INSTALL_SCRIPT} "${PWD}/sys/r1-docker.sh" "${DESTDIR}${BINDIR}/r2-docker"
	cp -f doc/hud "${DESTDIR}${DATADIR}/radare2/${VERSION}/hud/main"
	mkdir -p "${DESTDIR}${DATADIR}/radare2/${VERSION}/"
	$(SHELL) sys/ldconfig.sh
	$(SHELL) ./configure-plugins --rm-static $(DESTDIR)$(LIBDIR)/radare2/last/

# Remove make .d files. fixes build when .c files are removed
rmd:
	rm -f `find . -type f -iname '*.d'`

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

install-pkgconfig-symlink:
	@${INSTALL_DIR} "${DESTDIR}${LIBDIR}/pkgconfig"
	for FILE in $(shell cd pkgcfg ; ls *.pc) ; do \
		ln -fs "$(PWD)/pkgcfg/$$FILE" "${DESTDIR}${LIBDIR}/pkgconfig/$$FILE" ; done

symstall-sdb:
	for DIR in ${DATADIRS} ; do (\
		cd "$$DIR" ; \
		echo "$$DIR" ; \
		${MAKE} install-symlink ); \
	done

symstall install-symlink: install-man-symlink install-doc-symlink install-pkgconfig-symlink symstall-www symstall-sdb
	cd libr && ${MAKE} install-symlink
	cd binr && ${MAKE} install-symlink
	cd shlr && ${MAKE} install-symlink
	mkdir -p "${DESTDIR}${BINDIR}"
	ln -fs "${PWD}/sys/indent.sh" "${DESTDIR}${BINDIR}/r2-indent"
	ln -fs "${PWD}/sys/r2-docker.sh" "${DESTDIR}${BINDIR}/r2-docker"
	mkdir -p "${DESTDIR}${DATADIR}/radare2/${VERSION}/hud"
	cd "$(DESTDIR)$(LIBDIR)/radare2/" ;\
		rm -f last ; ln -fs $(VERSION) last
	cd "$(DESTDIR)$(DATADIR)/radare2/" ;\
		rm -f last ; ln -fs $(VERSION) last
	ln -fs "${PWD}/doc/hud" "${DESTDIR}${DATADIR}/radare2/${VERSION}/hud/main"
	mkdir -p "${DESTDIR}${DATADIR}/radare2/${VERSION}/"
	$(SHELL) sys/ldconfig.sh
	$(SHELL) ./configure-plugins --rm-static $(DESTDIR)/$(LIBDIR)/radare2/last/

deinstall uninstall:
	rm -f $(DESTDIR)$(BINDIR)/r2-indent
	rm -f $(DESTDIR)$(BINDIR)/r2-docker
	cd libr && ${MAKE} uninstall PARENT=1
	cd binr && ${MAKE} uninstall PARENT=1
	cd shlr && ${MAKE} uninstall PARENT=1
	cd libr/syscall/d && ${MAKE} uninstall PARENT=1
	cd libr/anal/d && ${MAKE} uninstall PARENT=1
	@echo
	@echo "Run 'make purge' to also remove installed files from previous versions of r2"
	@echo

purge-doc:
	rm -rf "${DESTDIR}${DOCDIR}"
	cd man ; for FILE in *.1 ; do rm -f "${DESTDIR}${MANDIR}/man1/$$FILE" ; done
	rm -f "${DESTDIR}${MANDIR}/man1/r2.1"

user-wrap=echo "\#!/bin/sh" > ~/bin/"$1" \
; echo "${PWD}/env.sh '${PREFIX}' '$1' \"\$$@\"" >> ~/bin/"$1" \
; chmod +x ~/bin/"$1" ;

user-install:
	mkdir -p ~/bin
	$(foreach mod,$(R2BINS),$(call user-wrap,$(mod)))
	cd ~/bin ; ln -fs radare2 r2

user-uninstall:
	$(foreach mod,$(R2BINS),rm -f ~/bin/"$(mod)")
	rm -f ~/bin/r2
	-rmdir ~/bin

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

purge: purge-doc purge-dev user-uninstall
	for FILE in ${R2BINS} ; do rm -f "${DESTDIR}${BINDIR}/$$FILE" ; done
	rm -f "${DESTDIR}${BINDIR}/ragg2-cc"
	rm -f "${DESTDIR}${BINDIR}/r2"
	rm -f "${DESTDIR}${LIBDIR}/libr_"*
	rm -f "${DESTDIR}${LIBDIR}/libr2"*".${EXT_SO}"
	rm -rf "${DESTDIR}${LIBDIR}/radare2"
	rm -rf "${DESTDIR}${INCLUDEDIR}/libr"
	rm -rf "${DESTDIR}${DATADIR}/radare2"

purge2:
	$(MAKE) purge
ifneq ($(PREFIX),/usr)
	$(MAKE) purge PREFIX=/usr
endif
ifneq ($(PREFIX),/usr/local)
	$(MAKE) purge PREFIX=/usr/local
endif

purge3: purge2
	sys/purge.sh distro

R2V=radare2-${VERSION}

v ver version:
	@echo CURRENT=${VERSION}
	@echo PREVIOUS=${PREVIOUS_RELEASE}

dist:
	rm -rf $(R2V)
	git clone . $(R2V)
	-cd $(R2V) && [ ! -f config-user.mk -o configure -nt config-user.mk ] && ./configure "--prefix=${PREFIX}"
	cd $(R2V) ; git log $$(git show-ref | grep ${PREVIOUS_RELEASE} | awk '{print $$1}')..HEAD > ChangeLog
	$(MAKE) -C $(R2V)/shlr capstone-sync
	FILES=`cd $(R2V); git ls-files | sed -e "s,^,$(R2V)/,"` ; \
	CS_FILES=`cd $(R2V)/shlr/capstone ; git ls-files | grep -v pdf | grep -v xcode | grep -v msvc | grep -v suite | grep -v bindings | grep -v tests | sed -e "s,^,$(R2V)/shlr/capstone/,"` ; \
	${TAR} "radare2-${VERSION}.tar" $${FILES} $${CS_FILES} "$(R2V)/ChangeLog" ; \
	${CZ} "radare2-${VERSION}.tar"

olddist:
	-[ configure -nt config-user.mk ] && ./configure "--prefix=${PREFIX}"
	#git log $$(git show-ref `git tag |tail -n1`)..HEAD > ChangeLog
	git log $$(git show-ref | grep ${PREVIOUS_RELEASE} | awk '{print $$1}')..HEAD > ChangeLog
	cd shlr && ${MAKE} capstone-sync
	DIR=`basename "$$PWD"` ; \
	FILES=`git ls-files | sed -e "s,^,radare2-${VERSION}/,"` ; \
	CS_FILES=`cd shlr/capstone ; git ls-files | grep -v pdf | grep -v xcode | grep -v msvc | grep -v suite | grep -v bindings | grep -v tests | sed -e "s,^,radare2-${VERSION}/shlr/capstone/,"` ; \
	cd .. && mv "$${DIR}" "radare2-${VERSION}" && \
	${TAR} "radare2-${VERSION}.tar" $${FILES} $${CS_FILES} "radare2-${VERSION}/ChangeLog" ; \
	${CZ} "radare2-${VERSION}.tar" ; \
	mv "radare2-${VERSION}" "$${DIR}"

shot:
	DATE=`date '+%Y%m%d'` ; \
	FILES=`git ls-files | sed -e "s,^,radare2-${DATE}/,"` ; \
	cd .. && mv radare2 "radare2-$${DATE}" && \
	${TAR} "radare2-$${DATE}.tar" $${FILES} ;\
	${CZ} "radare2-$${DATE}.tar" ;\
	mv "radare2-$${DATE}" radare2 && \
	scp "radare2-$${DATE}.${TAREXT}" \
		radare.org:/srv/http/radareorg/get/shot

tests:
	@if [ -d $(R2R) ]; then \
		cd $(R2R) ; git clean -xdf ; git pull ; \
	else \
		git clone --depth 1 "${R2R_URL}" "$(R2R)"; \
	fi
	cd $(R2R) ; ${MAKE}

macos-sign:
	$(MAKE) -C binr/radare2 macos-sign

macos-sign-libs:
	$(MAKE) -C binr/radare2 macos-sign-libs

osx-pkg:
	sys/osx-pkg.sh $(VERSION)

quality:
	./sys/shellcheck.sh

menu nconfig:
	./sys/menu.sh || true

meson:
	@echo "[ Meson R2 Building ]"
	$(PYTHON) sys/meson.py --prefix="${PREFIX}" --shared

meson-install:
	DESTDIR="$(DESTDIR)" ninja -C build install

B=$(DESTDIR)$(BINDIR)
L=$(DESTDIR)$(LIBDIR)

meson-symstall: symstall-sdb
	@echo "[ Meson symstall (not stable) ]"
	ln -fs $(PWD)/binr/r2pm/r2pm  ${B}/r2pm
	ln -fs $(PWD)/build/binr/rasm2/rasm2 ${B}/rasm2
	ln -fs $(PWD)/build/binr/rarun2/rarun2 ${B}/rarun2
	ln -fs $(PWD)/build/binr/radare2/radare2 ${B}/radare2
	ln -fs $(PWD)/build/binr/rahash2/rahash2 ${B}/rahash2
	ln -fs $(PWD)/build/binr/rabin2/rabin2 ${B}/rabin2
	ln -fs $(PWD)/build/binr/radare2/radare2 ${B}/radare2
	ln -fs $(PWD)/build/binr/ragg2/ragg2 ${B}/ragg2
	cd $(B) && ln -fs radare2 r2
	ln -fs $(PWD)/build/libr/util/libr_util.$(EXT_SO) ${L}/libr_util.$(EXT_SO)
	ln -fs $(PWD)/build/libr/bp/libr_bp.$(EXT_SO) ${L}/libr_bp.$(EXT_SO)
	ln -fs $(PWD)/build/libr/syscall/libr_syscall.$(EXT_SO) ${L}/libr_syscall.$(EXT_SO)
	ln -fs $(PWD)/build/libr/cons/libr_cons.$(EXT_SO) ${L}/libr_cons.$(EXT_SO)
	ln -fs $(PWD)/build/libr/search/libr_search.$(EXT_SO) ${L}/libr_search.$(EXT_SO)
	ln -fs $(PWD)/build/libr/magic/libr_magic.$(EXT_SO) ${L}/libr_magic.$(EXT_SO)
	ln -fs $(PWD)/build/libr/flag/libr_flag.$(EXT_SO) ${L}/libr_flag.$(EXT_SO)
	ln -fs $(PWD)/build/libr/reg/libr_reg.$(EXT_SO) ${L}/libr_reg.$(EXT_SO)
	ln -fs $(PWD)/build/libr/bin/libr_bin.$(EXT_SO) ${L}/libr_bin.$(EXT_SO)
	ln -fs $(PWD)/build/libr/config/libr_config.$(EXT_SO) ${L}/libr_config.$(EXT_SO)
	ln -fs $(PWD)/build/libr/parse/libr_parse.$(EXT_SO) ${L}/libr_parse.$(EXT_SO)
	ln -fs $(PWD)/build/libr/lang/libr_lang.$(EXT_SO) ${L}/libr_lang.$(EXT_SO)
	ln -fs $(PWD)/build/libr/asm/libr_asm.$(EXT_SO) ${L}/libr_asm.$(EXT_SO)
	ln -fs $(PWD)/build/libr/anal/libr_anal.$(EXT_SO) ${L}/libr_anal.$(EXT_SO)
	ln -fs $(PWD)/build/libr/egg/libr_egg.$(EXT_SO) ${L}/libr_egg.$(EXT_SO)
	ln -fs $(PWD)/build/libr/fs/libr_fs.$(EXT_SO) ${L}/libr_fs.$(EXT_SO)
	ln -fs $(PWD)/build/libr/debug/libr_debug.$(EXT_SO) ${L}/libr_debug.$(EXT_SO)
	ln -fs $(PWD)/build/libr/core/libr_core.$(EXT_SO) ${L}/libr_core.$(EXT_SO)

meson-uninstall:
	ninja -C build uninstall
	$(MAKE) uninstall

meson-clean:
	rm -rf build
	rm -rf build_sdb

MESON_FILES=$(shell find build/libr build/binr -type f| grep -v @)
meson-symstall-experimental:
	for a in $(MESON_FILES) ; do echo ln -fs $(PWD)/$$a $(PWD)/$$(echo $$a|sed -e s,build/,,) ; done
	$(MAKE) symstall

.PHONY: meson meson-install

include ${MKPLUGINS}

.PHONY: all clean distclean mrproper install symstall uninstall deinstall strip
.PHONY: libr binr install-man w32dist tests dist shot pkgcfg depgraph.png love
.PHONY: purge purge2 purge3
