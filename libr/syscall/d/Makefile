F=
F+= linux-x86-32
F+= linux-x86-64
F+= linux-arm-32
F+= linux-mips-32
F+= linux-sparc-32
F+= darwin-x86-32
F+= darwin-x86-64
F+= netbsd-x86-32
F+= freebsd-x86-32
F+= openbsd-x86-32
F+= openbsd-x86-64
F+= windows-x86-32
F+= windows-x86-64

include ../../../config-user.mk

F_SDB=$(addsuffix .sdb,$F)

SDB=../../db/sdb/src/sdb

all: ${SDB}
	@${MAKE} compile

compile: ${F_SDB}

linux-x86-32.sdb: linux-x86-32

%.sdb:%
	@echo "  SDB $<"
	@sh gen.sh < $< | ${SDB} $<.sdb =

clean:
	rm -f *.sdb

${SDB}:
	cd ../../db/sdb/src && ${MAKE}

.PHONY: all clean install install-symlink symstall

install: ${F_SDB}
	mkdir -p ${DESTDIR}${PREFIX}/lib/radare2/${VERSION}/syscall
	cp -f *.sdb ${DESTDIR}${PREFIX}/lib/radare2/${VERSION}/syscall

CWD=$(shell pwd)
symstall install-symlink: ${F_SDB}
	mkdir -p ${DESTDIR}${PREFIX}/lib/radare2/${VERSION}/syscall
	for a in *.sdb ; do ln -fs ${CWD}/$$a ${DESTDIR}${PREFIX}/lib/radare2/${VERSION}/syscall/$$a ; done

uninstall:
	rm -rf ${PREFIX}/lib/radare2/syscall
