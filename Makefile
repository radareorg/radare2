include config-user.mk

all:
	cd libr && make

clean:
	cd libr && make clean

install:
	${INSTALL_DIR} ${DESTDIR}${PREFIX}/share/doc/radare2
	for a in doc/* ; do ${INSTALL_DATA} $$a ${DESTDIR}/${PREFIX}/share/doc/radare2 ; done
	cd libr && make install PARENT=1 PREFIX=${DESTDIR}${PREFIX}

uninstall:
	rm -rf prefix

deinstall: uninstall
	cd libr && make uninstall PARENT=1 PREFIX=${DESTDIR}${PREFIX}
	rm -rf ${DESTDIR}${PREFIX}/share/doc/radare2

dist:
	FILES=`hg st -mc .| cut -c 3-|sed -e s,^,radare2-${VERSION}/,` ; \
	cd .. && mv radare2 radare2-${VERSION} && \
	tar czvf radare2-${VERSION}.tar.gz $${FILES} ;\
	mv radare2-${VERSION} radare2
	if [ ${RELEASE} = 1 ]; then \
	scp radare2-$${DATE}.tar.gz news.nopcode.org:/home/www/radarenopcode/get/shot ; fi

.PHONY: all clean install uninstall deinstall dist
