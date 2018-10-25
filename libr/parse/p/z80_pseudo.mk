OBJ_Z80PSEUDO+=parse_z80_pseudo.o

TARGET_Z80PSEUDO=parse_z80_pseudo.${EXT_SO}
STATIC_OBJ+=${OBJ_Z80PSEUDO}
ifeq ($(CC),cccl)
LIBDEPS=-L../../util -llibr_util
LIBDEPS+=-L../../flag -llibr_flag
else
LIBDEPS=-L../../util -lr_util
LIBDEPS+=-L../../flag -lr_flag
endif

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_Z80PSEUDO}
${TARGET_Z80PSEUDO}: ${OBJ_Z80PSEUDO}
	${CC} $(call libname,parse_z80_pseudo) ${LIBDEPS} $(LDFLAGS) \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_Z80PSEUDO} ${OBJ_Z80PSEUDO}
endif
