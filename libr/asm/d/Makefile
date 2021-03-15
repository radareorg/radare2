FILES=6502 8051 m68k x86 arc arm avr LH5801 ppc z80 mips sparc sh malbolge xtensa
FILES+=i8080 java i4004 dalvik msp430 lm32 sysz tms320 riscv propeller v810 v850
FILES+=pic18c chip8 tricore
F_SDB=$(addsuffix .sdb,${FILES})
SDB=../../../shlr/sdb/sdb

CFLAGS+=-fvisibility=hidden
LDFLAGS+=-fvisibility=hidden
include ../../../config-user.mk

all: ${F_SDB}

%.sdb:%.sdb.txt
	${SDB} $@ = < $<
	test -f $@

clean:
	rm -f *.sdb

.PHONY: all clean install install-symlink symstall uninstall

# XXX rmdblslash not defined, but doesnt warns about it
OPDIR=${DESTDIR}${DATADIR}/radare2/${VERSION}/opcodes

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
	rm -rf "${OPDIR}"
