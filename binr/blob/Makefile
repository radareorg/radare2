PREFIX?=/usr
DESTDIR?=/

BINS=rabin2 rarun2 rasm2 ragg2 rahash2 rax2 rafind2 radiff2
BINS2=radare2 ${BINS}

include ../../config-user.mk

CFLAGS=-I ../../libr/include/
CFLAGS+=-DLIBDIR="\"${LIBDIR}\""
CFLAGS+=-DR2_BIRTH=\"`date +%Y-%m-%d`\"
CFLAGS+=-DR2_GITTIP=\"$(GIT_TIP)\"

#ifeq ($(STATIC_BUILD),1)
ifeq ($(WITHNONPIC),1)
LDFLAGS+=../../libr/th/libr_th.a
LDFLAGS+=../../libr/io/libr_io.a
LDFLAGS+=../../libr/asm/libr_asm.a
LDFLAGS+=../../libr/db/libr_db.a
LDFLAGS+=../../libr/parse/libr_parse.a
LDFLAGS+=../../libr/lib/libr_lib.a
LDFLAGS+=../../libr/egg/libr_egg.a
LDFLAGS+=../../libr/core/libr_core.a
LDFLAGS+=../../libr/anal/libr_anal.a
LDFLAGS+=../../libr/cmd/libr_cmd.a
LDFLAGS+=../../libr/fs/libr_fs.a
LDFLAGS+=../../libr/sign/libr_sign.a
LDFLAGS+=../../libr/magic/libr_magic.a
LDFLAGS+=../../libr/line/libr_line.a
LDFLAGS+=../../libr/cons/libr_cons.a
LDFLAGS+=../../libr/diff/libr_diff.a
LDFLAGS+=../../libr/syscall/libr_syscall.a
LDFLAGS+=../../libr/flags/libr_flags.a
LDFLAGS+=../../libr/print/libr_print.a
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
LDFLAGS+=../../libr/fs/p/grub/libgrubfs.a
LDFLAGS+=../../libr/db/sdb/src/libsdb.a
LDFLAGS+=-lm
else
LDFLAGS+=-L../../libr/th -lr_th
LDFLAGS+=-L../../libr/io -lr_io
LDFLAGS+=-L../../libr/bp -lr_bp
LDFLAGS+=-L../../libr/socket -lr_socket
LDFLAGS+=-L../../libr/bin -lr_bin
LDFLAGS+=-L../../libr/reg -lr_reg
LDFLAGS+=-L../../libr/asm -lr_asm
LDFLAGS+=-L../../libr/cmd -lr_cmd
LDFLAGS+=-L../../libr/lib -lr_lib
LDFLAGS+=-L../../libr/egg -lr_egg
LDFLAGS+=-L../../libr/core -lr_core
LDFLAGS+=-L../../libr/anal -lr_anal
LDFLAGS+=-L../../libr/diff -lr_diff
LDFLAGS+=-L../../libr/util -lr_util
LDFLAGS+=-L../../libr/cons -lr_cons
LDFLAGS+=-L../../libr/hash -lr_hash
LDFLAGS+=-L../../libr/print -lr_print
LDFLAGS+=-L../../libr/debug -lr_debug
LDFLAGS+=-L../../libr/search -lr_search
LDFLAGS+=-L../../libr/config -lr_config
endif

all: symlinks

symlinks: build
	for a in r2 ${BINS} ; do \
		ln -fs radare2 $$a ; \
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
	for a in ${BINS2} ; do cp ../$$a/*.[ch] . ; done
	rm -f rwx.c xorhex.c rsc2.c
	for a in ${BINS2} ; do \
		mv $$a.c _$$a.c ;\
		sed -e "s,^int main,int $${a}_main,g" _$$a.c > $$a.c ; \
		rm -f _$$a ; \
	done
	rm -f _*
	${CC} -o radare2 *.c ${CFLAGS} ${LDFLAGS}
	mv main.c main.k
	rm -f *.[ch]
	mv main.k main.c

install:
	mkdir -p ${DESTDIR}/${PREFIX}/bin
	for a in r2 ${BINS2} ; do \
		rm -f ${DESTDIR}/${PREFIX}/bin/$$a ; \
		cp -af $$a ${DESTDIR}/${PREFIX}/bin/$$a ; \
	done
