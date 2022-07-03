OBJ_CR16=anal_cr16.o

STATIC_OBJ+=${OBJ_CR16}
OBJ_CR16+=../arch/cr16/cr16_disas.o
TARGET_CR16=anal_cr16.${EXT_SO}

ALL_TARGETS+=${TARGET_CR16}

${TARGET_CR16}: ${OBJ_CR16} ${SHARED_OBJ}
	${CC} $(call libname,anal_cr16) ${CFLAGS} \
		-o ${TARGET_CR16} ${OBJ_CR16}
