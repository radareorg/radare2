include ../../../global.mk
F=
F+= dos-x86-16
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

include $(TOP)/config-user.mk
HOST_CC?=gcc

F_SDB=$(addsuffix .sdb,$F)

SDBPATH=$(call rmdblslash,$(LTOP)/../shlr/sdb/)
SDB=$(call rmdblslash,$(SDBPATH)/sdb)

all: ${SDB}
	@$(MAKE) compile

compile: ${F_SDB}

linux-x86-32.sdb: linux-x86-32

%.sdb:%
ifneq ($(SILENT),)
	@echo "SDB $<"
	@rm -f $<.sdb
	@${SHELL} gen.sh < $< | ${SDB} $<.sdb =
	@test -f $<.sdb
else
	rm -f $<.sdb
	${SHELL} gen.sh < $< | ${SDB} $<.sdb =
	test -f $<.sdb
endif

clean:
	rm -f *.sdb

${SDB}:
	cp -rf "$(SDBPATH)/src" "$(SDBPATH)/src-native"
	cd "$(SDBPATH)/src-native" && CFLAGS="-w ${CPPFLAGS}" \
		$(MAKE) -j 1 ARCH=xxx CC=${HOST_CC} clean sdb
	cp -f "$(SDBPATH)/src-native/sdb" "$(SDBPATH)/sdb"
	rm -rf "$(SDBPATH)/src-native"

.PHONY: all clean install install-symlink symstall

install: ${F_SDB}
	mkdir -p "${DESTDIR}${LIBDIR}/radare2/${VERSION}/syscall"
	cp -f *.sdb "${DESTDIR}${LIBDIR}/radare2/${VERSION}/syscall"

CWD=$(shell pwd)
symstall install-symlink: ${F_SDB}
	mkdir -p "${DESTDIR}${LIBDIR}/radare2/${VERSION}/syscall"
	for a in *.sdb ; do ln -fs "${CWD}/$$a" "${DESTDIR}${LIBDIR}/radare2/${VERSION}/syscall/$$a" ; done

uninstall:
	rm -rf "${DESTDIR}${LIBDIR}/radare2/syscall"
