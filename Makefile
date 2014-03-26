-include config-user.mk
include global.mk

R2R=radare2-regressions
R2R_URL=$(shell doc/repo REGRESSIONS)
DLIBDIR=$(DESTDIR)/$(LIBDIR)
R2BINS=$(shell cd binr ; echo r*2)
DATADIRS=libr/cons/d libr/asm/d libr/syscall/d libr/magic/d
#binr/ragg2/d
STRIP?=strip
#ifneq ($(shell bsdtar -h 2>/dev/null|grep bsdtar),)
ifneq ($(shell xz --help 2>/dev/null|grep improve),)
TAR=tar -cvf
TAREXT=tar.xz
CZ=xz -f
else
TAR=bsdtar cvf
TAREXT=tar.gz
CZ=gzip -f
endif
PWD=$(shell pwd)
MAKE_JOBS?=1

all: plugins.cfg
	${MAKE} -C libr/util
	${MAKE} -j$(MAKE_JOBS) -C shlr
	${MAKE} -j$(MAKE_JOBS) -C libr
	${MAKE} -j$(MAKE_JOBS) -C binr

plugins.cfg:
	@if [ ! -e config-user.mk ]; then echo ; \
	echo "  Please, run ./configure first" ; echo ; exit 1 ; fi
	./configure-plugins

w32:
	sys/mingw32.sh

depgraph.png:
	cd libr ; perl depgraph.pl | dot -Tpng -odepgraph.png

android:
	@if [ -z "$(NDK_ARCH)" ]; then echo "Set NDK_ARCH=[arm|mips|x86]" ; false; fi
	sys/android-${NDK_ARCH}.sh

w32dist:
	rm -rf radare2-w32-${VERSION} w32dist
	mkdir w32dist
	for a in `find libr | grep -e dll$$`; do cp $$a w32dist ; done
	for a in `find binr | grep -e exe$$`; do cp $$a w32dist ; done
	rm -f w32dist/plugin.dll
	mkdir -p w32dist/radare2/${VERSION}/magic
	cp -f libr/magic/d/default/* w32dist/radare2/${VERSION}/magic
	mkdir -p w32dist/radare2/${VERSION}/syscall
	cp -f libr/syscall/d/*.sdb w32dist/radare2/${VERSION}/syscall
	mkdir -p w32dist/radare2/${VERSION}/opcodes
	cp -f libr/asm/d/*.sdb w32dist/radare2/${VERSION}/opcodes
	mkdir -p w32dist/share/doc/radare2
	mkdir -p w32dist/include/libr
	cp libr/include/*.h w32dist/include/libr
	#mkdir -p w32dist/include/libr/sflib
	cp -f doc/fortunes w32dist/share/doc/radare2
	mv w32dist radare2-w32-${VERSION}
	rm -f radare2-w32-${VERSION}.zip 
	zip -r radare2-w32-${VERSION}.zip radare2-w32-${VERSION}

clean:
	for a in shlr libr binr ; do (cd $$a ; ${MAKE} clean) ; done

distclean mrproper:
	for a in libr binr shlr ; do ( cd $$a ; ${MAKE} mrproper) ; done
	rm -f config-user.mk plugins.cfg libr/config.h
	rm -f libr/include/r_userconf.h libr/config.mk
	rm -f pkgcfg/*.pc

pkgcfg:
	cd libr && ${MAKE} pkgcfg

install-man:
	mkdir -p ${MDR}/man1
	for a in man/*.1 ; do ${INSTALL_MAN} $$a ${MDR}/man1 ; done
	cd ${MDR}/man1 && ln -fs radare2.1 r2.1

install-man-symlink:
	mkdir -p ${MDR}/man1
	cd man && for a in *.1 ; do ln -fs ${PWD}/man/$$a ${MDR}/man1/$$a ; done
	cd ${MDR}/man1 && ln -fs radare2.1 r2.1

install-doc:
	${INSTALL_DIR} ${PFX}/share/doc/radare2
	for a in doc/* ; do ${INSTALL_DATA} $$a ${PFX}/share/doc/radare2 ; done

install-doc-symlink:
	${INSTALL_DIR} ${PFX}/share/doc/radare2
	cd doc ; for a in * ; do \
		ln -fs ${PWD}/doc/$$a ${PFX}/share/doc/radare2 ; done

install: install-doc install-man install-www
	cd libr && ${MAKE} install PARENT=1 PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	cd binr && ${MAKE} install PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	cd shlr && ${MAKE} install PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	for a in ${DATADIRS} ; do \
	(cd $$a ; ${MAKE} install LIBDIR=${LIBDIR} PREFIX=${PREFIX} DESTDIR=${DESTDIR} ); \
	done
	mkdir -p ${DLIBDIR}/radare2/${VERSION}/hud
	cp -f doc/hud ${DLIBDIR}/radare2/${VERSION}/hud/main
	#cp ${PWD}/libr/lang/p/radare.lua ${DLIBDIR}/radare2/${VERSION}/radare.lua
	sys/ldconfig.sh

install-www:
	rm -rf ${DESTDIR}/${WWWROOT}
	rm -rf ${DLIBDIR}/radare2/${VERSION}/www # old dir
	mkdir -p ${DESTDIR}/${WWWROOT}
	cp -rf shlr/www/* ${DESTDIR}/${WWWROOT}

symstall-www:
	rm -rf ${DESTDIR}/${WWWROOT}
	rm -rf ${DLIBDIR}/radare2/${VERSION}/www # old dir
	mkdir -p ${DESTDIR}/${WWWROOT}
	cd ${DESTDIR}/${WWWROOT} ; for a in ${PWD}/shlr/www/* ; do \
		ln -fs $$a ${DESTDIR}/${DATADIR}/radare2/${VERSION}/www ; done

install-pkgconfig-symlink:
	@${INSTALL_DIR} ${DLIBDIR}/pkgconfig
	cd pkgcfg ; for a in *.pc ; do ln -fs $${PWD}/$$a ${DLIBDIR}/pkgconfig/$$a ; done

symstall install-symlink: install-man-symlink install-doc-symlink install-pkgconfig-symlink symstall-www
	cd libr && ${MAKE} install-symlink PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	cd binr && ${MAKE} install-symlink PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	cd shlr && ${MAKE} install-symlink PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	for a in ${DATADIRS} ; do (\
		cd $$a ; \
		echo $$a ; \
		${MAKE} install-symlink LIBDIR=${LIBDIR} PREFIX=${PREFIX} DESTDIR=${DESTDIR} ); \
	done
	mkdir -p ${DLIBDIR}/radare2/${VERSION}/hud
	cd $(DESTDIR)/$(PREFIX)/lib/radare2/ ; rm -f last ; ln -fs $(VERSION) last
	cd $(DESTDIR)/$(PREFIX)/share/radare2/ ; rm -f last ; ln -fs $(VERSION) last
	ln -fs ${PWD}/doc/hud ${DLIBDIR}/radare2/${VERSION}/hud/main
	ln -fs ${PWD}/libr/lang/p/radare.lua ${DLIBDIR}/radare2/${VERSION}/radare.lua
	sys/ldconfig.sh

deinstall uninstall:
	cd libr && ${MAKE} uninstall PARENT=1 PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	cd binr && ${MAKE} uninstall PARENT=1 PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	cd shlr && ${MAKE} uninstall PARENT=1 PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	cd libr/syscall/d && ${MAKE} uninstall PARENT=1 PREFIX=${PREFIX} DESTDIR=${DESTDIR} LIBDIR=${LIBDIR}
	@echo
	@echo "Run 'make purge' to also remove installed files from previous versions of r2"
	@echo

purge-doc:
	rm -rf ${DESTDIR}/${PREFIX}/share/doc/radare2
	cd man ; for a in *.1 ; do rm -f ${MDR}/man1/$$a ; done
	rm -f ${MDR}/man1/r2.1

purge-dev:
	rm -rf ${DESTDIR}/${LIBDIR}/libr_*.a
	rm -rf ${DESTDIR}/${LIBDIR}/pkgconfig/r_*.pc
	rm -rf ${DESTDIR}/${INCLUDEDIR}/libr
	rm -f ${DESTDIR}/${LIBDIR}/radare2/${VERSION}/-*
	# XXX: this must be in purge-sym ?
	-for a in ${R2BINS} ; do ${STRIP} -s ${DESTDIR}/${BINDIR}/$$a 2> /dev/null ; done
	-for a in ${DESTDIR}/${LIBDIR}/libr_*.so ; do ${STRIP} -s $$a ; done

purge: purge-doc purge-dev
	for a in ${R2BINS} ; do rm -f ${DESTDIR}/${BINDIR}/$$a ; done
	rm -f ${DESTDIR}/${BINDIR}/ragg2-cc
	rm -f ${DESTDIR}/${BINDIR}/r2
	rm -f ${DESTDIR}/${LIBDIR}/libr_*
	rm -rf ${DESTDIR}/${LIBDIR}/radare2
	rm -rf ${DESTDIR}/${INCLUDEDIR}/libr

dist:
	-[ configure -nt config-user.mk ] && ./configure --prefix=${PREFIX}
	git log $$(git show-ref `git tag |tail -n1`)..HEAD > ChangeLog
	DIR=`basename $$PWD` ; \
	FILES=`git ls-files | sed -e s,^,radare2-${VERSION}/,` ; \
	cd .. && mv $${DIR} radare2-${VERSION} && \
	${TAR} radare2-${VERSION}.tar $${FILES} radare2-${VERSION}/ChangeLog ;\
	${CZ} radare2-${VERSION}.tar ; \
	mv radare2-${VERSION} $${DIR}

shot:
	DATE=`date '+%Y%m%d'` ; \
	FILES=`git ls-files | sed -e s,^,radare2-${DATE}/,` ; \
	cd .. && mv radare2 radare2-$${DATE} && \
	${TAR} radare2-$${DATE}.tar $${FILES} ;\
	${CZ} radare2-$${DATE}.tar ;\
	mv radare2-$${DATE} radare2 && \
	scp radare2-$${DATE}.${TAREXT} \
		radare.org:/srv/http/radareorg/get/shot

tests:
	@if [ -d $(R2R) ]; then \
		cd $(R2R) ; git clean -xdf ; git pull ; \
	else \
		git clone ${R2R_URL} $(R2R); \
	fi
	cd $(R2R) ; ${MAKE}

include ${MKPLUGINS}

.PHONY: all clean distclean mrproper install symstall uninstall deinstall
.PHONY: libr binr install-man w32dist tests dist shot pkgcfg depgraph.png
