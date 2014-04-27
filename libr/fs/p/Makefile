include ../../config.mk

CFLAGS+=-I$(LIBR)/include -Wall -shared -fPIC ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}..
GRUB=$(LIBR)../shlr/grub/libgrub.a
#CFLAGS+=-I../../include
LDFLAGS+=${LINK}

foo: all

#FILESYSTEMS=hfs.mk iso9660.mk jfs.mk
#FILESYSTEMS=hfsplus.mk
FILESYSTEMS=ext2.mk fat.mk ntfs.mk reiserfs.mk tar.mk udf.mk ufs2.mk ufs.mk xfs.mk hfs.mk

include $(FILESYSTEMS)

all:

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d ../arch/*/*/*.d

.PHONY: all clean foo mrproper
