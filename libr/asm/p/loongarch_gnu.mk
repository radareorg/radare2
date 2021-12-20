OBJ_LOONGARCH=asm_loongarch_gnu.o
# gnu loongarch-dis
OBJ_LOONGARCH+=../arch/loongarch/gnu/loongarch-dis.o
OBJ_LOONGARCH+=../arch/loongarch/gnu/loongarch-opc.o
OBJ_LOONGARCH+=../arch/loongarch/gnu/loongarch-coder.o

TARGET_LOONGARCH=asm_loongarch_gnu.${EXT_SO}
STATIC_OBJ+=${OBJ_LOONGARCH}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_LOONGARCH}
${TARGET_LOONGARCH}: ${OBJ_LOONGARCH}
	${CC} $(call libname,asm_loongarch) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_LOONGARCH} ${OBJ_LOONGARCH}
endif
