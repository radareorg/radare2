NAME=r_fs
R2DEPS=r_util r_io r_socket r_cons r_muta
CFLAGS:=-DR2_PLUGIN_INCORE -Iarch/include -Iarch $(CFLAGS)

include ../config.mk
CFLAGS:=-Ip/grub/include $(CFLAGS)
ifeq ($(WITH_GPL),1)
# grub sources are now compiled directly into libr_fs
endif
ifeq ($(R2_USE_SQSH),1)
CFLAGS+=$(SQSH_CFLAGS)
LDFLAGS+=$(SQSH_LDFLAGS)
endif

EXTRA_TARGETS=plugins

foo:
	for TARGET in pre plugins ${LIBSO} ${LIBAR} ; do ${MAKE} $$TARGET ; done

include ${STATIC_FS_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst fs_,p/fs_,$(STATIC_OBJ)))
OBJS=${STATIC_OBJS} fs.o fs_file.o fs_shell.o
ifeq (1,$(WITH_GPL))
OBJS+=p/grub/grubfs.o
OBJS+=p/grub/kern/device.o
OBJS+=p/grub/kern/file.o
OBJS+=p/grub/kern/env.o
OBJS+=p/grub/kern/err.o
OBJS+=p/grub/kern/time.o
OBJS+=p/grub/kern/fs.o
OBJS+=p/grub/kern/partition.o
OBJS+=p/grub/kern/disk.o
OBJS+=p/grub/kern/misc.o
OBJS+=p/grub/kern/term.o
OBJS+=p/grub/kern/mm.o
OBJS+=p/grub/partmap/sunpc.o
OBJS+=p/grub/partmap/sun.o
OBJS+=p/grub/partmap/amiga.o
OBJS+=p/grub/partmap/apple.o
OBJS+=p/grub/partmap/msdos.o
OBJS+=p/grub/partmap/gpt.o
OBJS+=p/grub/partmap/bsdlabel.o
# OBJS+=p/grub/partmap/acorn.o
OBJS+=p/grub/fs/udf.o
OBJS+=p/grub/fs/ufs.o
OBJS+=p/grub/fs/sfs.o
OBJS+=p/grub/fs/hfsplus.o
OBJS+=p/grub/fs/iso9660.o
OBJS+=p/grub/fs/ntfs.o
OBJS+=p/grub/fs/fshelp.o
OBJS+=p/grub/fs/reiserfs.o
OBJS+=p/grub/fs/tar.o
OBJS+=p/grub/fs/xfs.o
OBJS+=p/grub/fs/fb.o
OBJS+=p/grub/fs/befs_be.o
OBJS+=p/grub/fs/hfs.o
# OBJS+=p/grub/fs/affs.o
OBJS+=p/grub/fs/jfs.o
OBJS+=p/grub/fs/fat.o
OBJS+=p/grub/fs/ext2.o
OBJS+=p/grub/fs/ntfscomp.o
OBJS+=p/grub/fs/minix.o
OBJS+=p/grub/fs/cpio.o
endif


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
