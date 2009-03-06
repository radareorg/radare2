VERSION=0.1
PREFIX=${PWD}/prefix
DESTDIR=

all:
	cd libr && make

clean:
	cd libr && make clean

install:
	mkdir -p ${DESTDIR}${PREFIX}
	cd libr && make install PREFIX=${DESTDIR}${PREFIX}

uninstall:
	rm -rf prefix

deinstall: uninstall
	cd libr && make uninstall PREFIX=${DESTDIR}${PREFIX}

dist:
	FILES=`hg st -mc .| cut -c 3-|sed -e s,^,radare2-${VERSION}/,` ; \
	cd .. && mv radare2 radare2-${VERSION} && \
	tar czvf radare2-${VERSION}.tar.gz $${FILES} ;\
	mv radare2-${VERSION} radare2

shot:
	DATE=`date '+%Y%m%d'` ; \
	FILES=`hg status -mc|cut -c 3-|sed -e s,^,radare2-$${DATE}/,`; \
	cd .. && mv radare2 radare2-$${DATE} && \
	tar czvf radare2-$${DATE}.tar.gz $${FILES} ;\
	mv radare2-$${DATE} radare && \
	scp radare2-$${DATE}.tar.gz news.nopcode.org:/home/www/radarenopcode/get/shot
