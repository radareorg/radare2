include ../../../global.mk
F=
F+= types
F+= types-16
F+= types-32
F+= types-64
F+= types-android
F+= types-darwin
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
F+= cc-x86-16
F+= cc-mips-32
F+= cc-mips-64
F+= cc-m68k-32
F+= cc-sparc-32
F+= cc-arm-64
F+= cc-arm-32
F+= cc-arm-16
F+= cc-avr-8
F+= cc-ppc-32
F+= cc-ppc-64
F+= cc-xtensa-32
F+= cc-riscv-64
F+= cc-hexagon-32
F+= cc-sysz-64

WIN_TYPES=
WIN_TYPES+= bcrypt
WIN_TYPES+= cfgmgr32
WIN_TYPES+= combaseapi
WIN_TYPES+= commctrl
WIN_TYPES+= consoleapi2
WIN_TYPES+= dbghelp
WIN_TYPES+= evntrace
WIN_TYPES+= fileapi
WIN_TYPES+= libloaderapi
WIN_TYPES+= memoryapi
WIN_TYPES+= ncrypt
WIN_TYPES+= objbase
WIN_TYPES+= oleauto
WIN_TYPES+= processthreadsapi
WIN_TYPES+= psapi
WIN_TYPES+= securitybaseapi
WIN_TYPES+= shellapi
WIN_TYPES+= shlwapi
WIN_TYPES+= synchapi
WIN_TYPES+= sysinfoapi
WIN_TYPES+= threadpoolapiset
WIN_TYPES+= userenv
WIN_TYPES+= winbase
WIN_TYPES+= wincred
WIN_TYPES+= wincrypt
WIN_TYPES+= winhttp
WIN_TYPES+= winldap
WIN_TYPES+= winnls
WIN_TYPES+= winreg
WIN_TYPES+= winsock2
WIN_TYPES+= winsvc
WIN_TYPES+= winuser
WIN_TYPES+= ws2spi

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

types-windows.sdb: EXTRA_FILES = $(addsuffix .sdb.txt,$(addprefix types-windows_,$(WIN_TYPES)))

%.sdb:%.sdb.txt $(EXTRA_FILES)
ifneq ($(SILENT),)
	@echo SDB $@
	@rm -f $@
	@cat $< $(EXTRA_FILES) | ${SDB} $@ =
	@test -f $@
else
	rm -f $@
	cat $< $(EXTRA_FILES) | ${SDB} $@ =
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
