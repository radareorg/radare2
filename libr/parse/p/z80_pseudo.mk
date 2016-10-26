OBJ_z80PSEUDO+=parse_z80_pseudo.o

TARGET_z80PSEUDO=parse_z80_pseudo.${EXT_SO}
ALL_TARGETS+=${TARGET_z80PSEUDO}
STATIC_OBJ+=${OBJ_z80PSEUDO}
LIBDEPS=-L../../util -lr_util
LIBDEPS+=-L../../flag -lr_flag

${TARGET_z80PSEUDO}: ${OBJ_z80PSEUDO}
	${CC} $(call libname,parse_z80_pseudo) ${LIBDEPS} $(LDFLAGS_SHARED) \
		${CFLAGS} -o ${TARGET_z80PSEUDO} ${OBJ_z80PSEUDO}
