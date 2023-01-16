OBJ_propeller=p/propeller/plugin.o
CFLAGS+=-Iarch

STATIC_OBJ+=${OBJ_propeller}
OBJ_propeller+=p/propeller/propeller_disas.o
TARGET_propeller=arch_propeller.${EXT_SO}

ALL_TARGETS+=${TARGET_propeller}

${TARGET_propeller}: ${OBJ_propeller} ${SHARED_OBJ}
	${CC} $(call libname,arch_propeller) ${CFLAGS} \
		-o ${TARGET_propeller} ${OBJ_propeller}
