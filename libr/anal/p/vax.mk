OBJ_VAX=anal_vax.o

STATIC_OBJ+=${OBJ_VAX}
TARGET_VAX=anal_vax.${EXT_SO}

ALL_TARGETS+=${TARGET_VAX}

${TARGET_VAX}: ${OBJ_VAX}
	${CC} $(call libname,anal_vax) ${CFLAGS} -o anal_vax.${EXT_SO} ${OBJ_VAX}
