VERSION=0.1
RELEASE=1
DESTDIR=
ifeq (${RELEASE},1)
PREFIX=/usr/local
else
PREFIX=${PWD}/prefix
VERSION=`date '+%Y%m%d'`
endif

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
	if [ ${RELEASE} = 1 ]; then \
	scp radare2-$${DATE}.tar.gz news.nopcode.org:/home/www/radarenopcode/get/shot ; fi

.PHONY: all clean install uninstall deinstall dist
