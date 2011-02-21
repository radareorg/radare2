include ../../config.mk

CFLAGS+=-I../../include -Wall -shared -fPIC ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}..
#CFLAGS+=-I../../include
LDFLAGS+=${LINK}

foo: all

#FILESYSTEMS=hfs.mk iso9660.mk jfs.mk
#FILESYSTEMS=hfsplus.mk
FILESYSTEMS=ext2.mk fat.mk ntfs.mk reiserfs.mk tar.mk udf.mk ufs2.mk ufs.mk xfs.mk hfs.mk

include $(FILESYSTEMS)

all:
	cd grub && ${MAKE} lib

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}
	cd grub && ${MAKE} clean

mrproper: clean
	-rm -f *.d ../arch/*/*/*.d

.PHONY: all clean foo mrproper
