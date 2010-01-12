include config-user.mk
include config.mk

all: libr swig

libr:
	cd libr && ${MAKE} all

swig:
ifeq (${HAVE_VALASWIG},1)
	cd swig && ${MAKE} all
endif

clean:
	cd libr && make clean

vdoc:
	rm -rf vdoc
	cat libr/vapi/*.vapi > /tmp/libr.vapi
	valadoc -o vdoc /tmp/libr.vapi
	# rsync -avz vdoc/* pancake@radare.org:/srv/http/radareorg/vdoc/

vdoc_pkg:
	rm -rf vdoc
	valadoc -o vdoc libr/vapi/*.vapi
	# rsync -avz vdoc/* pancake@radare.org:/srv/http/radareorg/vdoc/

mrproper:
	cd libr && make mrproper

pkgcfg:
	cd libr && make pkgcfg

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

.PHONY: all clean mrproper install uninstall deinstall dist shot pkgcfg vdoc swig libr
