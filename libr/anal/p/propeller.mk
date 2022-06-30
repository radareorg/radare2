OBJ_propeller=anal_propeller.o
CFLAGS+=-Iarch

STATIC_OBJ+=${OBJ_propeller}
OBJ_propeller+=../arch/propeller/propeller_disas.o
TARGET_propeller=anal_propeller.${EXT_SO}

ALL_TARGETS+=${TARGET_propeller}

${TARGET_propeller}: ${OBJ_propeller} ${SHARED_OBJ}
	${CC} $(call libname,anal_propeller) ${CFLAGS} \
		-o ${TARGET_propeller} ${OBJ_propeller}
