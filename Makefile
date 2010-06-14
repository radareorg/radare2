include config-user.mk
include global.mk

all: plugins.cfg libr binr r2rc

plugins.cfg:
	./configure-plugins

libr:
	cd libr && ${MAKE} all

binr:
	cd binr && ${MAKE} all

r2rc:
	cd r2rc && ${MAKE} all

w32dist:
	rm -rf radare2-w32-${VERSION} w32dist
	mkdir w32dist
	for a in `find * | grep -e exe$$ -e dll$$`; do cp $$a w32dist ; done
	mv w32dist radare2-w32-${VERSION}
	zip -r radare2-w32-${VERSION}.zip radare2-w32-${VERSION}

clean:
	cd libr && ${MAKE} clean

mrproper:
	cd libr && ${MAKE} mrproper
	rm -f plugins.cfg libr/config.h libr/config.mk

pkgcfg:
	cd libr && ${MAKE} pkgcfg

install-man:
	mkdir -p ${DESTDIR}/${PREFIX}/share/man/man1
	for a in man/*.1 ; do ${INSTALL_MAN} $$a ${DESTDIR}/${PREFIX}/share/man/man1 ; done

install: install-man
	${INSTALL_DIR} ${DESTDIR}${PREFIX}/share/doc/radare2
	for a in doc/* ; do ${INSTALL_DATA} $$a ${DESTDIR}/${PREFIX}/share/doc/radare2 ; done
	cd libr && ${MAKE} install PARENT=1 PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	cd binr && ${MAKE} install PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	cd r2rc && ${MAKE} install PREFIX=${PREFIX} DESTDIR=${DESTDIR}

symstall install-symlink:
	cd libr && ${MAKE} install-symlink PREFIX=${PREFIX} DESTDIR=${DESTDIR}

uninstall:
	rm -rf prefix

deinstall: uninstall
	cd libr && ${MAKE} uninstall PARENT=1 PREFIX=${PREFIX} DESTDIR=${DESTDIR}
	rm -rf ${DESTDIR}${PREFIX}/include/libr
	rm -rf ${DESTDIR}${PREFIX}/lib/libr_*.so
	rm -rf ${DESTDIR}${PREFIX}/lib/libr_*.a
	rm -rf ${DESTDIR}${PREFIX}/lib/libr.so
	rm -rf ${DESTDIR}${PREFIX}/lib/libr.a
	rm -rf ${DESTDIR}${PREFIX}/share/doc/radare2

swig-dist:
	cd swig && ${MAKE} dist

dist:
	VERSION=${VERSION} ; \
	FILES=`hg st -mc .| cut -c 3-|sed -e s,^,radare2-${VERSION}/,` ; \
	cd .. && mv radare2 radare2-${VERSION} && \
	tar czvf radare2-${VERSION}.tar.gz $${FILES} ;\
	mv radare2-${VERSION} radare2
	if [ ${RELEASE} = 1 ]; then \
	scp ../radare2-${VERSION}.tar.gz radare.org:/srv/http/radareorg/get ; fi

shot:
	DATE=`date '+%Y%m%d'` ; \
	FILES=`hg status -mc|cut -c 3-|sed -e s,^,radare2-$${DATE}/,`; \
	cd .. && mv radare2 radare2-$${DATE} && \
	tar czvf radare2-$${DATE}.tar.gz $${FILES} ;\
	mv radare2-$${DATE} radare2 && \
	scp radare2-$${DATE}.tar.gz radare.org:/srv/http/radareorg/get/shot

include ${MKPLUGINS}

.PHONY: all clean mrproper install symstall uninstall deinstall dist shot pkgcfg vdoc swig libr binr r2rc install-man
