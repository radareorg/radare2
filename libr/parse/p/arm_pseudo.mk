OBJ_ARMPSEUDO+=parse_arm_pseudo.o

TARGET_ARMPSEUDO=parse_arm_pseudo.${EXT_SO}
ALL_TARGETS+=${TARGET_ARMPSEUDO}
STATIC_OBJ+=${OBJ_ARMPSEUDO}
LIBDEPS=-L../../util -lr_util
LIBDEPS+=-L../../flags -lr_flags

${TARGET_ARMPSEUDO}: ${OBJ_ARMPSEUDO}
	${CC} $(call libname,parse_arm_pseudo) ${LIBDEPS} $(LDFLAGS) \
		-shared ${CFLAGS} -o ${TARGET_ARMPSEUDO} ${OBJ_ARMPSEUDO}
