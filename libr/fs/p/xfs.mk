OBJ_XFS=fs_xfs.o
EXTRA=../p/grub/libgrubfs.a
CFLAGS+=-Igrub/include

STATIC_OBJ+=${OBJ_XFS}
#STATIC_OBJ+=${EXTRA}
TARGET_XFS=fs_xfs.${EXT_SO}

ALL_TARGETS+=${TARGET_XFS}

${TARGET_XFS}: ${OBJ_XFS}
	${CC} ${LDFLAGS} ${CFLAGS} -o ${TARGET_XFS} ${OBJ_XFS} ${EXTRA}
