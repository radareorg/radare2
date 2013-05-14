NAME=r_fs
DEPS=r_lib r_util r_io
CFLAGS+=-DCORELIB -Iarch/include -Iarch

CFLAGS+=-Ip/grub/include
LDFLAGS+=p/grub/libgrubfs.a

include ../config.mk

EXTRA_TARGETS=plugins
foo:
	for a in pre plugins ${LIBSO} ${LIBAR} ; do ${MAKE} $$a ; done

include ${STATIC_FS_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst fs_,p/fs_,$(STATIC_OBJ)))
OBJS=${STATIC_OBJS} fs.o file.o 
#p/grub/main.o

p/grub/libgrubfs.a:
	cd p/grub && ${MAKE} libgrubfs.a CC="${CC}"

pre: 
	cd d && ${MAKE}
#	@if [ ! -e libr_fs.${EXT_SO} ]; then if [ ! -e libr_fs.${EXT_AR} ]; then rm -f ${STATIC_OBJS} ; fi ; fi

re:
	rm -f fs.o libr_fs.so
	${MAKE}
	rm -f t/fastcall.o
	sudo ${MAKE} install
	cd t && ${MAKE}

test:
	#valgrind r2 -i test.rsc /tmp/test.fs.img
	gdb --args r2 -i test.rsc /tmp/test.fs.img

plugins:
	cd p/grub && ${MAKE} libgrubfs.a CC="${CC}"
	cd p && ${MAKE} all

include ../rules.mk
