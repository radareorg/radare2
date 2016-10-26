PREFIX?=/usr
DESTDIR?=/

BINS=rabin2 rarun2 rasm2 ragg2 rahash2 rax2 rafind2 radiff2
BINS2=radare2 ${BINS}
include ../../config-user.mk

ifneq ($(OSTYPE),windows)
CFLAGS+=-pie -fPIC -fPIE
LDFLAGS+=-pie
endif
SHLR=../../shlr

include ../../config-user.mk
include ../../shlr/zip/deps.mk
include ../../shlr/bochs/deps.mk
include ../../shlr/qnx/deps.mk

ifneq (${ANDROID},1)
ifneq (${OSTYPE},linux)
LDFLAGS+=-lpthread
LDFLAGS+=-ldl
endif
endif

CFLAGS=-I../../libr/include/

#ifeq ($(STATIC_BUILD),1)
ifeq ($(WITHNONPIC),1)
LDFLAGS+=../../libr/io/libr_io.a
LDFLAGS+=../../libr/asm/libr_asm.a
LDFLAGS+=../../libr/egg/libr_egg.a
LDFLAGS+=../../libr/core/libr_core.a
LDFLAGS+=../../libr/crypto/libr_crypto.a
LDFLAGS+=../../libr/parse/libr_parse.a
LDFLAGS+=../../libr/anal/libr_anal.a
LDFLAGS+=../../libr/fs/libr_fs.a
LDFLAGS+=../../libr/magic/libr_magic.a
LDFLAGS+=../../libr/cons/libr_cons.a
LDFLAGS+=../../libr/syscall/libr_syscall.a
LDFLAGS+=../../libr/flag/libr_flag.a
LDFLAGS+=../../libr/reg/libr_reg.a
LDFLAGS+=../../libr/debug/libr_debug.a
LDFLAGS+=../../libr/search/libr_search.a
LDFLAGS+=../../libr/config/libr_config.a
LDFLAGS+=../../libr/lang/libr_lang.a
LDFLAGS+=../../libr/bp/libr_bp.a
LDFLAGS+=../../libr/hash/libr_hash.a
LDFLAGS+=../../libr/bin/libr_bin.a
LDFLAGS+=../../libr/util/libr_util.a
LDFLAGS+=../../libr/socket/libr_socket.a
# extra libs #
LDFLAGS+=../../shlr/grub/libgrubfs.a
LDFLAGS+=../../shlr/capstone/libcapstone.a
LDFLAGS+=../../shlr/sdb/src/libsdb.a
LDFLAGS+=../../shlr/gdb/lib/libgdbr.a
LDFLAGS+=../../shlr/wind/libr_wind.a
LDFLAGS+=../../shlr/java/libr_java.a
LDFLAGS+=-lm
else
LDFLAGS+=-L../../libr/io -lr_io
LDFLAGS+=-L../../libr/bp -lr_bp
LDFLAGS+=-L../../libr/socket -lr_socket
LDFLAGS+=-L../../libr/bin -lr_bin
LDFLAGS+=-L../../libr/reg -lr_reg
LDFLAGS+=-L../../libr/asm -lr_asm
LDFLAGS+=-L../../libr/egg -lr_egg
LDFLAGS+=-L../../libr/core -lr_core
LDFLAGS+=-L../../libr/anal -lr_anal
LDFLAGS+=-L../../libr/crypto -lr_crypto
LDFLAGS+=-L../../libr/flag -lr_flag
LDFLAGS+=-L../../libr/parse -lr_parse
LDFLAGS+=-L../../libr/fs -lr_fs
LDFLAGS+=-L../../libr/magic -lr_magic
LDFLAGS+=-L../../libr/syscall -lr_syscall
LDFLAGS+=-L../../libr/util -lr_util
LDFLAGS+=-L../../libr/cons -lr_cons
LDFLAGS+=-L../../libr/hash -lr_hash
LDFLAGS+=-L../../libr/debug -lr_debug
LDFLAGS+=-L../../libr/search -lr_search
LDFLAGS+=-L../../libr/config -lr_config
endif
LDFLAGS+=${LINK}

all: symlinks

symlinks: build
	for FILE in r2 ${BINS} ; do \
		ln -fs radare2 $$FILE ; \
	done

clean:
	mv main.c main.k
	mv version.c version.k
	rm -f *.[ch]
	mv main.k main.c
	mv version.k version.c
	rm -f ${BINS2} r2

SOURCES= main.c rabin2.c radare2.c radiff2.c rafind2.c
SOURCES+=rahash2.c rarun2.c rasm2.c rax2.c ragg2.c

build:
	mv main.c main.k
	mv version.c version.k
	rm -f *.[ch]
	mv main.k main.c
	mv version.k version.c
	for FILE in ${BINS2} ; do cp ../$$FILE/*.[ch] . ; done
	rm -f rwx.c xorhex.c rsc2.c
	for FILE in ${BINS2} ; do \
		mv $${FILE}.c _$${FILE}.c ;\
		sed -e "s,^int main,int $${FILE}_main,g" _$${FILE}.c > $${FILE}.c ; \
		rm -f _$${FILE} ; \
	done
	rm -f _*
	${CC} -o radare2 ${SOURCES} ${CFLAGS} ${LDFLAGS}
	mv main.c main.k
	mv version.c version.k
	rm -f *.[ch]
	mv main.k main.c
	mv version.k version.c

install:
	mkdir -p "${DESTDIR}${BINDIR}"
	for FILE in r2 ${BINS2} ; do \
		rm -f "${DESTDIR}${BINDIR}/$$FILE" ; \
		cp -af "$$FILE" "${DESTDIR}${BINDIR}/$$FILE" ; \
	done

