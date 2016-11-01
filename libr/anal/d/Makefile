include ../../../global.mk
F=
F+= types
F+= types-16
F+= types-32
F+= types-64
F+= types-windows
F+= types-x86-windows-32
F+= types-x86-windows-64
F+= types-linux
F+= types-x86-osx-64
F+= cc-x86-64
F+= cc-x86-32
F+= cc-mips-32
F+= cc-m68k-32
F+= cc-sparc-32
F+= cc-arm-64
F+= cc-arm-32
F+= cc-avr-8
F+= cc-powerpc-32
F+= cc-powerpc-64
F+= cc-xtensa-32
F+= cc-riscv-64

include $(TOP)/config-user.mk
HOST_CC?=gcc

F_SDB=$(addsuffix .sdb,$F)

SDBPATH=$(LTOP)/../shlr/sdb/
ifeq ($(BUILD_OS),windows)
BUILD_EXT_EXE=.exe
else
BUILD_EXT_EXE=
endif
SDB=$(SDBPATH)/sdb${BUILD_EXT_EXE}

all: ${SDB}
	@$(MAKE) compile

compile: ${F_SDB}

linux-x86-32.sdb: linux-x86-32

%.sdb:%
ifneq ($(SILENT),)
	@echo SDB $<
	@rm -f $<.sdb
	@cat $< | ${SDB} $<.sdb =
	@test -f $<.sdb
else
	rm -f $<.sdb
	cat $< | ${SDB} $<.sdb =
	test -f $<.sdb
endif

clean:
	rm -f *.sdb

${SDB}:
	@echo "Cannot find ${SDB}"
	@false

.PHONY: all clean install install-symlink symstall

install: ${F_SDB}
	-rm -rf "${DESTDIR}${LIBDIR}/radare2/${VERSION}/fcnsign"
	mkdir -p "${DESTDIR}${LIBDIR}/radare2/${VERSION}/fcnsign"
	cp -f *.sdb "${DESTDIR}${LIBDIR}/radare2/${VERSION}/fcnsign"

CWD=$(shell pwd)
symstall install-symlink: ${F_SDB}
	mkdir -p "${DESTDIR}${LIBDIR}/radare2/${VERSION}/fcnsign"
	for FILE in *.sdb ; do ln -fs "${CWD}/$$FILE" "${DESTDIR}${LIBDIR}/radare2/${VERSION}/fcnsign/$$FILE" ; done

uninstall:
	rm -rf "${DESTDIR}${LIBDIR}/radare2/fcnsign"
