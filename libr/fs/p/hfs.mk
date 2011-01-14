OBJ_HFS=fs_hfs.o
EXTRA=../p/grub/libgrubfs.a
CFLAGS+=-Igrub/include

STATIC_OBJ+=${OBJ_HFS}
#STATIC_OBJ+=${EXTRA}
TARGET_HFS=fs_hfs.${EXT_SO}

ALL_TARGETS+=${TARGET_HFS}

${TARGET_HFS}: ${OBJ_HFS}
	${CC} ${LDFLAGS} ${CFLAGS} -o ${TARGET_HFS} ${OBJ_HFS} ${EXTRA}
