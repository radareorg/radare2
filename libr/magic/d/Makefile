include ../../config.mk

install: ${F_SDB}
	mkdir -p ${DESTDIR}${LIBDIR}/radare2/${VERSION}/magic
	cp -f default/* ${DESTDIR}${LIBDIR}/radare2/${VERSION}/magic

CWD=$(shell pwd)
symstall install-symlink: ${F_SDB}
	mkdir -p ${DESTDIR}${PREFIX}/lib/radare2/${VERSION}/magic
	cd default ; for a in * ; do ln -fs ${CWD}/default/d/$$a \
		${DESTDIR}${PREFIX}/lib/radare2/${VERSION}/magic/$$a ; done

.PHONY: install symstall
