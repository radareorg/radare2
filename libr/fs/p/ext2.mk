OBJ_EXT2=fs_ext2.o
CFLAGS+=-I$(TOP)/shlr/grub/include

STATIC_OBJ+=${OBJ_EXT2}
TARGET_EXT2=fs_ext2.${EXT_SO}

ALL_TARGETS+=${TARGET_EXT2}

${TARGET_EXT2}: ${OBJ_EXT2}
	${CC} $(call libname,fs_ext2) ${LDFLAGS} ${CFLAGS} -o ${TARGET_EXT2} ${OBJ_EXT2}
