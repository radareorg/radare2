include ../../config.mk
include ../../../mk/platform.mk

CFLAGS+=-I$(LIBR)/include -Wall -shared ${PIC_CFLAGS} ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}..
GRUB=$(LIBR)../shlr/grub/libgrub.a
#CFLAGS+=-I../../include
LDFLAGS+=${LINK}

ifeq ($(WITHPIC),1)
all:

#FILESYSTEMS=hfs.mk iso9660.mk jfs.mk
#FILESYSTEMS=hfsplus.mk
FILESYSTEMS=ext2.mk fat.mk ntfs.mk reiserfs.mk tar.mk udf.mk ufs2.mk ufs.mk xfs.mk hfs.mk
include $(FILESYSTEMS)

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d ../arch/*/*/*.d

.PHONY: all clean mrproper
else
all clean mrproper:

.PHONY: all clean mrproper
endif
