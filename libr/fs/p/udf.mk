OBJ_UDF=fs_udf.o
EXTRA=../p/grub/libgrubfs.a
CFLAGS+=-Igrub/include

STATIC_OBJ+=${OBJ_UDF}
#STATIC_OBJ+=${EXTRA}
TARGET_UDF=fs_udf.${EXT_SO}

ALL_TARGETS+=${TARGET_UDF}

${TARGET_UDF}: ${OBJ_UDF}
	${CC} ${LDFLAGS} ${CFLAGS} -o ${TARGET_UDF} ${OBJ_UDF} ${EXTRA}
