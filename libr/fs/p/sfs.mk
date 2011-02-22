OBJ_SFS=fs_sfs.o
EXTRA=../p/grub/libgrubfs.a
CFLAGS+=-Igrub/include

STATIC_OBJ+=${OBJ_SFS}
#STATIC_OBJ+=${EXTRA}
TARGET_SFS=fs_sfs.${EXT_SO}

ALL_TARGETS+=${TARGET_SFS}

${TARGET_SFS}: ${OBJ_SFS}
	${CC} ${LDFLAGS} ${CFLAGS} -o ${TARGET_SFS} ${OBJ_SFS} ${EXTRA}
