include ../../../global.mk
F=
F+= dos-x86-16
F+= ios-x86-32
F+= ios-arm-32
F+= ios-arm-64
F+= linux-x86-32
F+= linux-x86-64
F+= linux-arm-32
F+= linux-arm-64
F+= linux-mips-32
F+= linux-sparc-32
F+= darwin-x86-32
F+= darwin-x86-64
F+= darwin-arm-32
F+= darwin-arm-64
F+= netbsd-x86-32
F+= freebsd-x86-32
F+= openbsd-x86-32
F+= openbsd-x86-64
F+= windows-x86-32
F+= windows-x86-64

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
	@echo "SDB $<"
	@rm -f $<.sdb
	@"${SHELL}" gen.sh < $< | ${SDB} $<.sdb =
	@test -f $<.sdb
else
	rm -f $<.sdb
	"${SHELL}" gen.sh < $< | ${SDB} $<.sdb =
	test -f $<.sdb
endif

clean:
	rm -f *.sdb

${SDB}:
	@echo "Cannot find ${SDB}"
	@false

#	cp -rf "$(SDBPATH)/src" "$(SDBPATH)/src-native"
#	cd "$(SDBPATH)/src-native" && CFLAGS="-w ${CPPFLAGS}" \
#		$(MAKE) -j 1 ARCH=xxx CC=${HOST_CC} clean sdb
#	cp -f "$(SDBPATH)/src-native/sdb" "$(SDBPATH)/sdb"
#	rm -rf "$(SDBPATH)/src-native"

.PHONY: all clean install install-symlink symstall

SYSCALLPATH=${DESTDIR}${DATADIR}/radare2/${VERSION}/syscall

install: ${F_SDB}
	-rm -rf "${SYSCALLPATH}"
	mkdir -p "${SYSCALLPATH}"
	cp -f *.sdb "${SYSCALLPATH}"

CWD=$(shell pwd)
symstall install-symlink: ${F_SDB}
	mkdir -p "${SYSCALLPATH}"
	for FILE in *.sdb ; do ln -fs "${CWD}/$$FILE" "${SYSCALLPATH}/$$FILE" ; done

uninstall:
	rm -rf "${SYSCALLPATH}"
