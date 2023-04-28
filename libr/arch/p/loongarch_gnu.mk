N=loongarch_gnu
OBJ_LOONGARCH=p/loongarch/plugin.o
OBJ_LOONGARCH+=p/loongarch/loongarch-dis.o
OBJ_LOONGARCH+=p/loongarch/loongarch-opc.o
OBJ_LOONGARCH+=p/loongarch/loongarch-coder.o

STATIC_OBJ+=${OBJ_LOONGARCH}
TARGET_LOONGARCH=$(N).${EXT_SO}

ALL_TARGETS+=${TARGET_LOONGARCH}

${TARGET_LOONGARCH}: ${OBJ_LOONGARCH}
	${CC} $(call libname,$(N)) ${CFLAGS} ${CS_CFLAGS} \
		-o $(TARGET_LOONGARCH) ${OBJ_LOONGARCH} ${CS_LDFLAGS}
