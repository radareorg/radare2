OBJ_MREPLACE+=parse_mreplace.o parse_mreplace/mreplace.o parse_mreplace/mmemory.o

TARGET_MREPLACE=parse_mreplace.${EXT_SO}
ALL_TARGETS+=${TARGET_MREPLACE}
STATIC_OBJ+=${OBJ_MREPLACE}

${TARGET_MREPLACE}: ${OBJ_MREPLACE}
	${CC} $(call libname,parse_mreplace) ${CFLAGS} -o ${TARGET_MREPLACE} ${OBJ_MREPLACE}
