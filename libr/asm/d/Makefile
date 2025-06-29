FILES=6502 8051 m68k x86 arc arm avr bpf LH5801 ppc z80 mips sparc sh xtensa
FILES+=i8080 java i4004 dalvik msp430 lm32 s390 tms320 propeller v810 v850
FILES+=pic18c chip8 tricore bf pickle riscv evm sm5xx gb stm8 cosmac
F_SDB=$(addsuffix .sdb,${FILES})

CFLAGS+=-fvisibility=hidden
LDFLAGS+=-fvisibility=hidden
include ../../../config-user.mk
include ../../../global.mk

ifeq ($(USE_SDBTOOL),1)
all:
	$(SDBTOOL) $(shell pwd)
else
all: ${F_SDB}

%.sdb: %.sdb.txt
	$(SDB) -r .

old_%.sdb:%.sdb.txt
	${SDB} $@ = < $<
	test -f $@
	${SDB} -t -C $@
endif

clean:
	rm -f *.sdb *.c *.h *.gperf a.out

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
