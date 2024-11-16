OBJ_GB_PSEUDO+=$(LIBR)/arch/p/gb/pseudo.o

TARGET_GB_PSEUDO=parse_gb_pseudo.${EXT_SO}
STATIC_OBJ+=${OBJ_GB_PSEUDO}
ifeq ($(CC),cccl)
LIBDEPS=-L../../util -llibr_util
LIBDEPS+=-L../../flag -llibr_flag
else
LIBDEPS=-L../../util -lr_util
LIBDEPS+=-L../../flag -lr_flag
endif

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_GB_PSEUDO}
${TARGET_GB_PSEUDO}: ${OBJ_GB_PSEUDO}
	${CC} $(call libname,parse_gb_pseudo) ${LIBDEPS} $(LDFLAGS) \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_GB_PSEUDO} ${OBJ_GB_PSEUDO}
endif
