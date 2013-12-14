OBJ_JFS=fs_jfs.o
EXTRA=$(GRUB)
CFLAGS+=-Igrub/include

STATIC_OBJ+=${OBJ_JFS}
#STATIC_OBJ+=${EXTRA}
TARGET_JFS=fs_jfs.${EXT_SO}

ALL_TARGETS+=${TARGET_JFS}

${TARGET_JFS}: ${OBJ_JFS}
	${CC} $(call libname,fs_jfs) ${LDFLAGS} ${CFLAGS} -o ${TARGET_JFS} ${OBJ_JFS} ${EXTRA}
