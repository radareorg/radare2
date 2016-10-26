OBJ_ARMPSEUDO+=parse_arm_pseudo.o

TARGET_ARMPSEUDO=parse_arm_pseudo.${EXT_SO}
STATIC_OBJ+=${OBJ_ARMPSEUDO}
LIBDEPS=-L../../util -lr_util
LIBDEPS+=-L../../flag -lr_flag

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_ARMPSEUDO}
${TARGET_ARMPSEUDO}: ${OBJ_ARMPSEUDO}
	${CC} $(call libname,parse_arm_pseudo) ${LIBDEPS} $(LDFLAGS) \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_ARMPSEUDO} ${OBJ_ARMPSEUDO}
endif
