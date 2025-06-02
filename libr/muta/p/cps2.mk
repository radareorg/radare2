OBJ_CPS2=muta_cps2.o

STATIC_OBJ+=${OBJ_CPS2}
TARGET_CPS2=muta_cps2.${EXT_SO}

ALL_TARGETS+=${TARGET_CPS2}

${TARGET_CPS2}: ${OBJ_CPS2}
	${CC} $(call libname,muta_cps2) ${LDFLAGS} ${CFLAGS} -o ${TARGET_CPS2} ${OBJ_CPS2}
