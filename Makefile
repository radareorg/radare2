include config-user.mk
include global.mk

PWD=$(shell pwd)
REMOTE=radare.org:/srv/http/radareorg/get/beta

all: plugins.cfg
	${MAKE} libr
	${MAKE} binr

plugins.cfg:
	@if [ ! -e config-user.mk ]; then echo ; \
	echo "  Please, run ./configure first" ; echo ; exit 1 ; fi
	./configure-plugins

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
	for a in `find binr libr | grep -e exe$$ -e dll$$`; do cp $$a w32dist ; done
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
	mkdir -p ${PFX}/share/man/man1
	for a in man/*.1 ; do ${INSTALL_MAN} $$a ${PFX}/share/man/man1 ; done
	cd ${PFX}/share/man/man1 && ln -fs radare2.1 r2.1

install-man-symlink:
	mkdir -p ${PFX}/share/man/man1
	cd man && for a in *.1 ; do ln -fs ${PWD}/$$a ${PFX}/share/man/man1/$$a ; done
	cd ${PFX}/share/man/man1 && ln -fs radare2.1 r2.1

install-doc:
	${INSTALL_DIR} ${PFX}/share/doc/radare2
	for a in doc/* ; do ${INSTALL_DATA} $$a ${PFX}/share/doc/radare2 ; done

install-doc-symlink:
	${INSTALL_DIR} ${PFX}/share/doc/radare2
	cd doc ; for a in * ; do ln -fs ${PWD}/$$a ${PFX}/share/doc/radare2 ; done

install: install-doc install-man
	cd libr && ${MAKE} install PARENT=1 PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	cd binr && ${MAKE} install PREFIX=${PREFIX} DESTDIR=${DESTDIR}

install-pkgconfig-symlink:
	@${INSTALL_DIR} ${PFX}/lib/pkgconfig
	cd pkgcfg ; for a in *.pc ; do ln -fs $${PWD}/$$a ${PFX}/lib/pkgconfig/$$a ; done

symstall install-symlink: install-man-symlink install-doc-symlink install-pkgconfig-symlink
	cd libr && ${MAKE} install-symlink PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	cd binr && ${MAKE} install-symlink PREFIX=${PREFIX} DESTDIR=${DESTDIR}

deinstall uninstall:
	cd libr && ${MAKE} uninstall PARENT=1 PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	cd binr && ${MAKE} uninstall PARENT=1 PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	@echo
	@echo "Run 'make purge' to also remove installed files from previous versions of r2"
	@echo

purge:
	rm -rf ${DESTDIR}/${PREFIX}/lib/libr_*
	rm -rf ${DESTDIR}/${PREFIX}/lib/radare2
	rm -rf ${DESTDIR}/${PREFIX}/include/libr

beta: dist r2-bindings-dist
	scp ../radare2-${VERSION}.tar.gz ${REMOTE}
	scp radare2-bindings-${VERSION}.tar.gz ${REMOTE}

r2-bindings-dist:
	cd r2-bindings && ${MAKE} dist

dist:
	VERSION=${VERSION} ; \
	FILES=`hg st -mc .| cut -c 3-|sed -e s,^,radare2-${VERSION}/, | grep -v r2-bindings | grep -v '/\.'` ; \
	cd .. && mv radare2 radare2-${VERSION} && \
	tar czvf radare2-${VERSION}.tar.gz $${FILES} ;\
	mv radare2-${VERSION} radare2

pub:
	scp ../radare2-${VERSION}.tar.gz radare.org:/srv/http/radareorg/get

shot:
	DATE=`date '+%Y%m%d'` ; \
	FILES=`hg status -mc|cut -c 3-|sed -e s,^,radare2-$${DATE}/,`; \
	cd .. && mv radare2 radare2-$${DATE} && \
	tar czvf radare2-$${DATE}.tar.gz $${FILES} ;\
	mv radare2-$${DATE} radare2 && \
	scp radare2-$${DATE}.tar.gz radare.org:/srv/http/radareorg/get/shot

include ${MKPLUGINS}

.PHONY: all clean mrproper install symstall uninstall deinstall dist shot pkgcfg r2-bindings r2-bindings-dist libr binr install-man
