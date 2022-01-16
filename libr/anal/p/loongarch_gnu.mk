OBJ_LOONGARCH=anal_loongarch_gnu.o
OBJ_LOONGARCH += ../arch/loongarch/gnu/loongarch-dis.o
OBJ_LOONGARCH += ../arch/loongarch/gnu/loongarch-opc.o
OBJ_LOONGARCH += ../arch/loongarch/gnu/loongarch-coder.o

STATIC_OBJ+=${OBJ_LOONGARCH}
TARGET_LOONGARCH=$(N).${EXT_SO}

ALL_TARGETS+=${TARGET_LOONGARCH}

${TARGET_LOONGARCH}: ${OBJ_LOONGARCH}
	${CC} $(call libname,$(N)) ${CFLAGS} ${CS_CFLAGS} \
		-o $(TARGET_LOONGARCH) ${OBJ_LOONGARCH} ${CS_LDFLAGS}
