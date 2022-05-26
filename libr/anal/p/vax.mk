OBJ_VAX=anal_vax.o
OBJ_VAX+=../arch/vax/vax-dis.o

STATIC_OBJ+=${OBJ_VAX}
TARGET_VAX=anal_vax.${EXT_SO}

ALL_TARGETS+=${TARGET_VAX}

${TARGET_VAX}: ${OBJ_VAX}
	${CC} $(call libname,anal_vax) ${CFLAGS} -o anal_vax.${EXT_SO} ${LDFLAGS} \
		-I../arch/vax ${CFLAGS} -o anal_vax.${EXT_SO} ${OBJ_VAX}
