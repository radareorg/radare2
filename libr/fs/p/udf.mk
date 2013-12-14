OBJ_UDF=fs_udf.o
EXTRA=$(GRUB)
CFLAGS+=-Igrub/include

STATIC_OBJ+=${OBJ_UDF}
#STATIC_OBJ+=${EXTRA}
TARGET_UDF=fs_udf.${EXT_SO}

ALL_TARGETS+=${TARGET_UDF}

${TARGET_UDF}: ${OBJ_UDF}
	${CC} $(call libname,fs_udf) ${LDFLAGS} ${CFLAGS} -o ${TARGET_UDF} ${OBJ_UDF} ${EXTRA}
