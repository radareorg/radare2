OBJ_6502PSEUDO+=$(LIBR)/arch/p/pseudo/6502_pseudo.o

TARGET_6502PSEUDO=parse_6502_pseudo.${EXT_SO}
STATIC_OBJ+=${OBJ_6502PSEUDO}
ifeq ($(CC),cccl)
LIBDEPS=-L../../util -llibr_util
LIBDEPS+=-L../../flag -llibr_flag
else
LIBDEPS=-L../../util -lr_util
LIBDEPS+=-L../../flag -lr_flag
endif

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_6502PSEUDO}
${TARGET_6502PSEUDO}: ${OBJ_6502PSEUDO}
	${CC} $(call libname,parse_6502_pseudo) ${LIBDEPS} $(LDFLAGS) \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_6502PSEUDO} ${OBJ_6502PSEUDO}
endif
