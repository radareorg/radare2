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
F+= s110-arm-16
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

ifeq (0,1)
#$(USE_SDBTOOL),1)
all: ${SDB}
	@$(MAKE) compile

compile: ${F_SDB}

%.sdb:%.sdb.txt
ifneq ($(SILENT),)
	@echo "SDB $<"
	@rm -f $@
	@"${SHELL}" gen.sh < $< | ${SDB} $@ =
else
	rm -f $@
	"${SHELL}" gen.sh < $< | ${SDB} $@ =
endif
	test -f $@
	${SDB} -t -C $@
	$(CC) $(CFLAGS) $(PIC_CFLAGS) -c `echo $@ | sed -e s,sdb,c,`

${SDB}:
	@echo "Cannot find ${SDB}"
	@false
else
all:
	$(SDBTOOL) $(shell pwd)
endif

clean:
	rm -f *.sdb *.tmp *.d *.o *.c

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
