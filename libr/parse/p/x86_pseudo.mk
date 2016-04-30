OBJ_X86PSEUDO+=parse_x86_pseudo.o

TARGET_X86PSEUDO=parse_x86_pseudo.${EXT_SO}
STATIC_OBJ+=${OBJ_X86PSEUDO}
LIBDEPS=-L../../util -lr_util
LIBDEPS+=-L../../flags -lr_flags

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_X86PSEUDO}
${TARGET_X86PSEUDO}: ${OBJ_X86PSEUDO}
	${CC} $(call libname,parse_x86_pseudo) ${LIBDEPS} $(LDFLAGS) \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_X86PSEUDO} ${OBJ_X86PSEUDO}
endif
