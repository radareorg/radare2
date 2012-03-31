PREFIX?=/usr
DESTDIR?=/
BINS=rabin2 rarun2 rasm2 ragg2 rahash2 rax2 rafind2
BINS2=radare2 ${BINS}
CFLAGS=-I ../../libr/include/ -DLIBDIR="\"/usr/lib/\"" -DR2_BIRTH="\"123\""
LDFLAGS+=-L../../libr/th -lr_th
LDFLAGS+=-L../../libr/io -lr_io
LDFLAGS+=-L../../libr/bin -lr_bin
LDFLAGS+=-L../../libr/search -lr_search
LDFLAGS+=-L../../libr/asm -lr_asm
LDFLAGS+=-L../../libr/lib -lr_lib
LDFLAGS+=-L../../libr/egg -lr_egg
LDFLAGS+=-L../../libr/core -lr_core
LDFLAGS+=-L../../libr/util -lr_util
LDFLAGS+=-L../../libr/cons -lr_cons
LDFLAGS+=-L../../libr/hash -lr_hash
LDFLAGS+=-L../../libr/print -lr_print
LDFLAGS+=-L../../libr/debug -lr_debug
LDFLAGS+=-L../../libr/config -lr_config

all: symlinks

symlinks: build
	for a in ${BINS} ; do \
		ln -fs radare2 $$a ; \
	done

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
	cp ${BINS2} ${DESTDIR}/${PREFIX}/bin
