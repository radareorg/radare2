FILES=6502 8051 m68k x86 arc arm avr lh5801 java ppc z80 mips sparc sh
F_SDB=$(addsuffix .sdb,${FILES})
SDB=../../../shlr/sdb/sdb
include ../../../config-user.mk

all: ${F_SDB}

%.sdb:%
	${SDB} $<.sdb = < $<
	test -f $<.sdb

clean:
	rm -f *.sdb

.PHONY: all clean install install-symlink symstall uninstall

# XXX rmdblslash not defined, but doesnt warns about it
OPDIR=${DESTDIR}${LIBDIR}/radare2/${VERSION}/opcodes

install: ${F_SDB}
	-rm -rf "${OPDIR}"
	mkdir -p "${OPDIR}"
	cp -f *.sdb "${OPDIR}"

#that sed is a workaround for mingw's pwd
CWD=$(shell pwd)
symstall install-symlink: ${F_SDB}
	mkdir -p "${OPDIR}"
	for FILE in *.sdb ; do ln -fs "${CWD}/$$FILE" "${OPDIR}/$$FILE" ; done

uninstall:
	rm -rf "${DESTDIR}${LIBDIR}/radare2/opcodes"
