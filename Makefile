-include config-user.mk
include global.mk

STRIP?=strip
ifneq ($(shell bsdtar -h 2>/dev/null|grep bsdtar),)
TAR=bsdtar czvf
else
TAR=tar -czvf
endif
PWD=$(shell pwd)
REMOTE=radare.org:/srv/http/radareorg/get/beta

all: plugins.cfg
	${MAKE} libr
	${MAKE} binr

plugins.cfg:
	@if [ ! -e config-user.mk ]; then echo ; \
	echo "  Please, run ./configure first" ; echo ; exit 1 ; fi
	./configure-plugins

gitpush:
	sh mk/gitpush.sh

.PHONY: todo
todo:
	grep -re TODO:0.9.2 libr binr

libr:
	cd libr && ${MAKE} all

binr:
	cd binr && ${MAKE} all

R=$(shell hg tags|head -n2 | tail -n1|awk '{print $$2}' |cut -d : -f 1)
T=$(shell hg tip|grep changeset:|cut -d : -f 2)
.PHONY: chlog
chlog:
	@hg log -v -r tip:$R > chlog
	@echo "-=== release ${VERSION} ===-"
	@echo "hg tag -r $T ${VERSION}"
	@printf "last commit:   "
	@hg log -r tip | grep date: |cut -d : -f 2- |sed -e 's,^\ *,,g'
	@printf "oldest commit: "
	@hg log -r $R | grep date: |cut -d : -f 2- |sed -e 's,^\ *,,g'
	@printf "Commits:  "
	@grep changeset: chlog |wc -l
	@grep -v : chlog | grep -v '^$$'

w32:
	make clean
	# TODO: add support for debian
	./configure --without-ssl --without-gmp --with-compiler=i486-mingw32-gcc --with-ostype=windows --host=i486-unknown-windows
	make

w32dist:
	rm -rf radare2-w32-${VERSION} w32dist
	mkdir w32dist
	for a in `find libr | grep -e dll$$`; do cp $$a w32dist ; done
	for a in `find binr | grep -e exe$$`; do cp $$a w32dist ; done
	rm w32dist/plugin.dll
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

w32beta: w32dist
	scp radare2-w32-${VERSION}.zip ${REMOTE}
	cd r2-bindings ; $(MAKE) w32dist
	scp radare2-bindings-w32-${VERSION}.zip ${REMOTE}

clean:
	cd libr && ${MAKE} clean
	cd binr && ${MAKE} clean
	cd shrl && ${MAKE} clean

mrproper:
	cd libr && ${MAKE} mrproper
	cd binr && ${MAKE} mrproper
	rm -f config-user.mk plugins.cfg libr/config.h libr/include/r_userconf.h libr/config.mk
	rm -f pkgcfg/*.pc

mrpopper:
	@echo 8====================D

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
	cd doc ; for a in * ; do ln -fs ${PWD}/doc/$$a ${PFX}/share/doc/radare2 ; done

DATADIRS=libr/asm/d libr/syscall/d libr/magic/d
#binr/ragg2/d
install: install-doc install-man
	cd libr && ${MAKE} install PARENT=1 PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	cd binr && ${MAKE} install PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	for a in ${DATADIRS} ; do \
	(cd $$a ; ${MAKE} install LIBDIR=${LIBDIR} PREFIX=${PREFIX} DESTDIR=${DESTDIR} ); \
	done
	mkdir -p ${DESTDIR}/${LIBDIR}/radare2/${VERSION}/hud
	cp -f libr/core/hud/main ${DESTDIR}/${LIBDIR}/radare2/${VERSION}/hud/

install-pkgconfig-symlink:
	@${INSTALL_DIR} ${DESTDIR}/${LIBDIR}/pkgconfig
	cd pkgcfg ; for a in *.pc ; do ln -fs $${PWD}/$$a ${DESTDIR}/${LIBDIR}/pkgconfig/$$a ; done

symstall install-symlink: install-man-symlink install-doc-symlink install-pkgconfig-symlink
	cd libr && ${MAKE} install-symlink PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	cd binr && ${MAKE} install-symlink PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	for a in ${DATADIRS} ; do \
	(cd $$a ; echo $$a ; ${MAKE} install-symlink LIBDIR=${LIBDIR} PREFIX=${PREFIX} DESTDIR=${DESTDIR} ); \
	done
	mkdir -p ${DESTDIR}/${LIBDIR}/radare2/${VERSION}/hud
	ln -fs ${PWD}/libr/core/hud/main ${DESTDIR}/${LIBDIR}/radare2/${VERSION}/hud/main

deinstall uninstall:
	cd libr && ${MAKE} uninstall PARENT=1 PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	cd binr && ${MAKE} uninstall PARENT=1 PREFIX=${PREFIX} DESTDIR=${DESTDIR}
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
	for a in ${DESTDIR}/${BINDIR}/r*2 ; do ${STRIP} -s $$a ; done
	for a in ${DESTDIR}/${LIBDIR}/libr_*.so ; do ${STRIP} -s $$a ; done

# TODO strip syms!


purge: purge-doc purge-dev
	rm -f ${DESTDIR}/${BINDIR}/r2
	rm -f ${DESTDIR}/${BINDIR}/radare2
	rm -f ${DESTDIR}/${BINDIR}/rabin2
	rm -f ${DESTDIR}/${BINDIR}/rafind2
	rm -f ${DESTDIR}/${BINDIR}/ranal2
	rm -f ${DESTDIR}/${BINDIR}/rax2
	rm -f ${DESTDIR}/${BINDIR}/rsc2
	rm -f ${DESTDIR}/${BINDIR}/rasm2
	rm -f ${DESTDIR}/${BINDIR}/rarc2
	rm -f ${DESTDIR}/${BINDIR}/rahash2
	rm -f ${DESTDIR}/${BINDIR}/ragg2
	rm -f ${DESTDIR}/${BINDIR}/ragg2-cc
	rm -f ${DESTDIR}/${BINDIR}/rarun2
	rm -f ${DESTDIR}/${BINDIR}/rasc2
	rm -f ${DESTDIR}/${BINDIR}/radiff2
	rm -f ${DESTDIR}/${LIBDIR}/libr_*
	rm -rf ${DESTDIR}/${LIBDIR}/radare2
	rm -rf ${DESTDIR}/${INCLUDEDIR}/libr

beta: dist r2-bindings-dist
	scp ../radare2-${VERSION}.tar.gz ${REMOTE}
	scp r2-bindings-${VERSION}.tar.gz ${REMOTE}

version:
	@echo ${VERSION}

r2-bindings-dist:
	cd r2-bindings && ${MAKE} dist

dist:
	VERSION=${VERSION} ; \
	FILES=`hg manifest | grep -v r2-bindings | sed -e s,^,radare2-${VERSION}/,` ; \
	cd .. && mv radare2 radare2-${VERSION} && \
	${TAR} radare2-${VERSION}.tar.gz $${FILES} ;\
	mv radare2-${VERSION} radare2

pub:
	scp ../radare2-${VERSION}.tar.gz radare.org:/srv/http/radareorg/get

shot:
	DATE=`date '+%Y%m%d'` ; \
	FILES=`hg manifest | sed -e s,^,radare2-${DATE}/,` ; \
	cd .. && mv radare2 radare2-$${DATE} && \
	${TAR} radare2-$${DATE}.tar.gz $${FILES} ;\
	mv radare2-$${DATE} radare2 && \
	scp radare2-$${DATE}.tar.gz radare.org:/srv/http/radareorg/get/shot

# TODO: test/ must be removed
.PHONY: test tests
test tests:
	if [ -d r2-regressions ]; then \
		cd r2-regressions ; git pull ; \
	else \
		git clone git://github.com/vext01/r2-regressions.git ; \
	fi
	cd r2-regressions ; ${MAKE}

include ${MKPLUGINS}

.PHONY: all clean mrproper install symstall uninstall deinstall dist shot pkgcfg
.PHONY: r2-bindings r2-bindings-dist libr binr install-man version
