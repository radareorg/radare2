F=
F+= linux-x86-32
F+= linux-x86-64
F+= linux-arm-32
F+= linux-mips-32
F+= linux-sparc-32
F+= darwin-x86-32
F+= netbsd-x86-32
F+= freebsd-x86-32
F+= openbsd-x86-32
F+= windows-x86-32

# XXX: use config.mk
PREFIX?=/usr
DESTDIR?=

SDB=../../db/sdb/src/sdb

all: ${SDB}
	@for a in ${F} ; do \
		echo " SDB $$a.sdb" ; \
		sh gen.sh < $$a | ${SDB} $$a.sdb = ; \
	done

clean:
	rm -f *.sdb

${SDB}:
	cd ../../db/sdb/src && ${MAKE}

.PHONY: all clean install install-symlink symstall

linux-x86-32.sdb:
	${MAKE}

install: linux-x86-32.sdb
	mkdir -p ${PREFIX}/lib/radare2/syscall
	cp -f *.sdb ${PREFIX}/lib/radare2/syscall

CWD=$(shell pwd)
symstall install-symlink: linux-x86-32.sdb
	mkdir -p ${PREFIX}/lib/radare2/syscall
	for a in *.sdb ; do ln -fs ${CWD}/$$a ${PREFIX}/lib/radare2/syscall/$$a ; done

uninstall:
	rm -rf ${PREFIX}/lib/radare2/syscall
