OBJ_X86PSEUDO+=parse_x86_pseudo.o

TARGET_X86PSEUDO=parse_x86_pseudo.${EXT_SO}
STATIC_OBJ+=${OBJ_X86PSEUDO}
ifeq ($(CC),cccl)
LIBDEPS=-L../../util -llibr_util
LIBDEPS+=-L../../flag -llibr_flag
LDFLAGS+=-L../../reg -llibr_reg
LDFLAGS+=-L../../cons -llibr_cons
else
LIBDEPS=-L../../util -lr_util
LIBDEPS+=-L../../flag -lr_flag
LDFLAGS+=-L../../reg -lr_reg
LDFLAGS+=-L../../cons -lr_cons
endif

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_X86PSEUDO}
${TARGET_X86PSEUDO}: ${OBJ_X86PSEUDO}
	${CC} $(call libname,parse_x86_pseudo) ${LIBDEPS} $(LDFLAGS) \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_X86PSEUDO} ${OBJ_X86PSEUDO}
endif
