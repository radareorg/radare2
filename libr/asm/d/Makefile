FILES=x86 arm ppc z80
F_SDB=$(addsuffix .sdb,${FILES})
SDB=../../../shlr/sdb/sdb
include ../../../config-user.mk

all: ${F_SDB}

%.sdb:%
	${SDB} $<.sdb = < $<

clean:
	rm -f *.sdb

.PHONY: all clean install install-symlink symstall

# XXX rmdblslash not defined, but doesnt warns about it
#OPDIR=$(call rmdblslash,${DESTDIR}${LIBDIR}/radare2/${VERSION}/opcodes)
OPDIR=${DESTDIR}${LIBDIR}/radare2/${VERSION}/opcodes

install: ${F_SDB}
	mkdir -p "${OPDIR}"
	cp -f *.sdb "${OPDIR}"

#that sed is a workaround for mingw's pwd
CWD=$(shell pwd)
symstall install-symlink: ${F_SDB}
	mkdir -p "${OPDIR}"
	for a in *.sdb ; do ln -fs "${CWD}/$$a" "${OPDIR}/$$a" ; done

uninstall:
	rm -rf "${DESTDIR}${LIBDIR}/radare2/opcodes"
