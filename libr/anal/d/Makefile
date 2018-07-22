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
F+= types-x86-macos-64
F+= types-arm-ios-16
F+= types-arm-ios-32
F+= types-arm-ios-64
F+= spec
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

FCNSIGNPATH=$(DESTDIR)$(DATADIR)/radare2/$(VERSION)/fcnsign

all: ${SDB}
	@$(MAKE) compile

compile: ${F_SDB}

linux-x86-32.sdb: linux-x86-32

%.sdb:%.sdb.txt
ifneq ($(SILENT),)
	@echo SDB $@
	@rm -f $@
	@cat $< | ${SDB} $@ =
	@test -f $@
else
	rm -f $@
	cat $< | ${SDB} $@ =
	test -f $@
endif

clean:
	rm -f *.sdb

${SDB}:
	@echo "Cannot find ${SDB}"
	@false

.PHONY: all clean install install-symlink symstall

install: ${F_SDB}
	rm -rf "${FCNSIGNPATH}"
	mkdir -p "${FCNSIGNPATH}"
	cp -f *.sdb "${FCNSIGNPATH}"

CWD=$(shell pwd)
symstall install-symlink: ${F_SDB}
	cd ../../.. && mkdir -p "${FCNSIGNPATH}" && \
	for FILE in $(shell cd $(TOP)/libr/anal/d ; ls *.sdb); do \
		ln -fs "$(CWD)/$$FILE" "$(FCNSIGNPATH)/$$FILE" ; \
	done

uninstall:
	rm -rf "${FCNSIGNPATH}"
