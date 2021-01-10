PREFIX?=/usr
DESTDIR?=/

BINS=rabin2 rarun2 rasm2 ragg2 rahash2 rax2 rafind2 radiff2
BINS2=radare2 ${BINS}

SOURCES= main.c rabin2.c radare2.c radiff2.c rafind2.c
SOURCES+=rahash2.c rarun2.c rasm2.c rax2.c ragg2.c

include ../../config-user.mk

SHLR=../../shlr

ifeq (${ANDROID},1)
LDFLAGS+=-lm
else
ifneq (${OSTYPE},linux)
LDFLAGS+=-lpthread
LDFLAGS+=-ldl
endif
endif
ifeq ($(USE_LTO),1)
LDFLAGS+=-flto
endif

CFLAGS+=-I../../libr/include/
CFLAGS+=-I$(SHLR)/spp

LDFLAGS+=-L../../libr/main -lr_main
LDFLAGS+=-L../../libr/io -lr_io
LDFLAGS+=-L../../libr/bp -lr_bp
LDFLAGS+=-L../../libr/socket -lr_socket
LDFLAGS+=-L../../libr/bin -lr_bin
LDFLAGS+=-L../../libr/reg -lr_reg
LDFLAGS+=-L../../libr/asm -lr_asm
LDFLAGS+=-L../../libr/lang -lr_lang
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
LDFLAGS+=${LINK}

include ../../libr/config.mk
include ../../libr/socket/deps.mk
include ../../libr/magic/deps.mk
include ../../libr/main/deps.mk
include ../../shlr/sdb.mk
include ../../shlr/zip/deps.mk
include ../../shlr/gdb/deps.mk
include ../../shlr/java/deps.mk
include ../../shlr/bochs/deps.mk
include ../../shlr/grub/deps.mk
include ../../shlr/qnx/deps.mk
include ../../shlr/ar/deps.mk
include ../../shlr/sdb.mk
include ../../shlr/capstone.mk
include ../../shlr/radare2-shell-parser-deps.mk
LINK+=$(SHLR)/tcc/libr_tcc.a

all: symlinks

symlinks: build
	for FILE in r2 ${BINS} ; do \
		ln -fs radare2 $$FILE ; \
	done

clean:
	mv main.c main.k
	rm -f *.[ch]
	mv main.k main.c
	rm -f ${BINS2} r2

build:
	mv main.c main.k
	rm -f *.[ch]
	mv main.k main.c
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
	rm -f *.[ch]
	mv main.k main.c

install:
	mkdir -p "${DESTDIR}${BINDIR}"
	for FILE in r2 ${BINS2} ; do \
		rm -f "${DESTDIR}${BINDIR}/$$FILE" ; \
		cp -PRpf "$$FILE" "${DESTDIR}${BINDIR}/$$FILE" ; \
	done

