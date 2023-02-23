OBJ_VAX=p/vax/vax.o
OBJ_VAX+=p/vax/vax-dis.o

STATIC_OBJ+=${OBJ_VAX}
TARGET_VAX=vax.${EXT_SO}

ALL_TARGETS+=${TARGET_VAX}

${TARGET_VAX}: ${OBJ_VAX}
	${CC} $(call libname,vax) ${CFLAGS} -o vax.${EXT_SO} ${LDFLAGS} \
		-Ip/vax ${CFLAGS} -o anal_vax.${EXT_SO} ${OBJ_VAX}
