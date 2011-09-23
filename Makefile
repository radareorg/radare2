include config-user.mk
include global.mk

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

libr:
	cd libr && ${MAKE} all

binr:
	cd binr && ${MAKE} all

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
	mv w32dist radare2-w32-${VERSION}
	zip -r radare2-w32-${VERSION}.zip radare2-w32-${VERSION}

w32beta: w32dist
	scp radare2-w32-${VERSION}.zip ${REMOTE}
	cd r2-bindings ; $(MAKE) w32dist
	scp radare2-bindings-w32-${VERSION}.zip ${REMOTE}

clean:
	cd libr && ${MAKE} clean
	cd binr && ${MAKE} clean

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
	cd doc ; for a in * ; do ln -fs ${PWD}/$$a ${PFX}/share/doc/radare2 ; done

install: install-doc install-man
	cd libr && ${MAKE} install PARENT=1 PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	cd binr && ${MAKE} install PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	cd libr/syscall/d ; ${MAKE} install PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	cd libr/magic ; ${MAKE} install-data PREFIX=${PREFIX} DESTDIR=${DESTDIR}

install-pkgconfig-symlink:
	@${INSTALL_DIR} ${DESTDIR}/${LIBDIR}/pkgconfig
	cd pkgcfg ; for a in *.pc ; do ln -fs $${PWD}/$$a ${DESTDIR}/${LIBDIR}/pkgconfig/$$a ; done

symstall install-symlink: install-man-symlink install-doc-symlink install-pkgconfig-symlink
	cd libr && ${MAKE} install-symlink PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	cd binr && ${MAKE} install-symlink PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	cd libr/syscall/d ; ${MAKE} install-symlink PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	cd libr/magic ; ${MAKE} install-symlink-data PREFIX=${PREFIX} DESTDIR=${DESTDIR}

deinstall uninstall:
	cd libr && ${MAKE} uninstall PARENT=1 PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	cd binr && ${MAKE} uninstall PARENT=1 PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	cd libr/syscall/d && ${MAKE} uninstall PARENT=1 PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	@echo
	@echo "Run 'make purge' to also remove installed files from previous versions of r2"
	@echo

purge:
	rm -rf ${DESTDIR}/${LIBDIR}/libr_*
	rm -rf ${DESTDIR}/${LIBDIR}/radare2
	rm -rf ${DESTDIR}/${INCLUDEDIR}/libr
	cd man ; for a in *.1 ; do rm -f ${MDR}/man1/$$a ; done
	rm -f ${MDR}/man1/r2.1

beta: dist r2-bindings-dist
	scp ../radare2-${VERSION}.tar.gz ${REMOTE}
	scp r2-bindings-${VERSION}.tar.gz ${REMOTE}

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

include ${MKPLUGINS}

.PHONY: all clean mrproper install symstall uninstall deinstall dist shot pkgcfg r2-bindings r2-bindings-dist libr binr install-man
