NAME=r_fs
R2DEPS=r_util r_io r_socket r_cons r_muta
CFLAGS:=-DR2_PLUGIN_INCORE -Iarch/include -Iarch $(CFLAGS)

include ../config.mk

OBJS=fs.o fs_file.o fs_shell.o
include p/grub/deps.mk

ifeq ($(R2_USE_SQSH),1)
CFLAGS+=$(SQSH_CFLAGS)
LDFLAGS+=$(SQSH_LDFLAGS)
endif

EXTRA_TARGETS=plugins

foo:
	for TARGET in pre plugins ${LIBSO} ${LIBAR} ; do ${MAKE} $$TARGET ; done

include ${STATIC_FS_PLUGINS}
OBJS+=$(subst ..,p/..,$(subst fs_,p/fs_,$(STATIC_OBJ)))

pre:
	$(MAKE) -C d

re:
	rm -f fs.o libr_fs.so
	$(MAKE)
	rm -f t/fastcall.o
	sudo $(MAKE) install
	$(MAKE) -C t

plugins:
	$(MAKE) -C p all

include ../rules.mk

# Ensure zip library is linked when building shared library
include $(SHLR)/zip/deps.mk
LINK+=$(OTEZIP_LIBA)
