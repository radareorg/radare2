NAME=r_fs
R2DEPS=r_util r_io r_socket r_hash r_cons r_crypto
CFLAGS:=-DR2_PLUGIN_INCORE -Iarch/include -Iarch $(CFLAGS)

SHLR=../../shlr/

include ../config.mk
CFLAGS:=-I$(SHLR)/grub/include $(CFLAGS)
ifeq ($(WITH_GPL),1)
LDFLAGS+=$(SHLR)/grub/libgrubfs.a
endif

EXTRA_TARGETS=plugins
foo:
	for TARGET in pre plugins ${LIBSO} ${LIBAR} ; do ${MAKE} $$TARGET ; done

include ${STATIC_FS_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst fs_,p/fs_,$(STATIC_OBJ)))
OBJS=${STATIC_OBJS} fs.o fs_file.o fs_shell.o

pre:
	cd d && ${MAKE}

re:
	rm -f fs.o libr_fs.so
	${MAKE}
	rm -f t/fastcall.o
	sudo ${MAKE} install
	cd t && ${MAKE}

plugins:
	cd p && ${MAKE} all

include ../rules.mk
