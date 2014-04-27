OBJ_FAT=fs_fat.o
EXTRA=$(GRUB)
CFLAGS+=-Igrub/include

STATIC_OBJ+=${OBJ_FAT}
#STATIC_OBJ+=${EXTRA}
TARGET_FAT=fs_fat.${EXT_SO}

ALL_TARGETS+=${TARGET_FAT}

${TARGET_FAT}: ${OBJ_FAT}
	${CC} $(call libname,fs_fat) ${LDFLAGS} ${CFLAGS} -o ${TARGET_FAT} ${OBJ_FAT} ${EXTRA}
