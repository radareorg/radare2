FILES=x86 arm ppc
F_SDB=$(addsuffix .sdb,${FILES})
SDB=../../../shlr/sdb/sdb
include ../../../config-user.mk

all: ${F_SDB}

%.sdb:%
	${SDB} $<.sdb = < $<

clean:
	rm -f *.sdb

.PHONY: all clean install install-symlink symstall

install: ${F_SDB}
	mkdir -p ${DESTDIR}${LIBDIR}/radare2/${VERSION}/opcodes
	cp -f *.sdb ${DESTDIR}${LIBDIR}/radare2/${VERSION}/opcodes

CWD=$(shell pwd)
symstall install-symlink: ${F_SDB}
	mkdir -p ${DESTDIR}${LIBDIR}/radare2/${VERSION}/opcodes
	for a in *.sdb ; do ln -fs ${CWD}/$$a ${DESTDIR}${LIBDIR}/radare2/${VERSION}/opcodes/$$a ; done

uninstall:
	rm -rf ${DESTDIR}${LIBDIR}/radare2/opcodes
