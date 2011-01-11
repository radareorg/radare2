NAME=r_fs
DEPS=r_lib r_util r_io
CFLAGS+=-DCORELIB -Iarch/include -Iarch

include ../config.mk

foo: pre ${LIBSO} ${LIBAR} plugins

include ${STATIC_FS_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst fs_,p/fs_,$(STATIC_OBJ)))
OBJ=${STATIC_OBJS} fs.o file.o

pre:
	@if [ ! -e libr_fs.${EXT_SO} ]; then if [ ! -e libr_fs.${EXT_AR} ]; then rm -f ${STATIC_OBJS} ; fi ; fi

re:
	rm -f fs.o libr_fs.so
	${MAKE}
	rm -f t/fastcall.o
	sudo ${MAKE} install
	cd t && ${MAKE}

plugins:
	cd p && ${MAKE} all

include ../rules.mk
