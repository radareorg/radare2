OBJ_S1C88PSEUDO+=$(LIBR)/arch/p/s1c88/pseudo.o

TARGET_S1C88PSEUDO=parse_s1c88_pseudo.${EXT_SO}
ALL_TARGETS+=${TARGET_S1C88PSEUDO}
STATIC_OBJ+=${OBJ_S1C88PSEUDO}

${TARGET_S1C88PSEUDO}: ${OBJ_S1C88PSEUDO}
ifeq ($(CC),cccl)
	${CC} $(call libname,parse_s1c88_pseudo) -L../../util -llibr_util \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_S1C88PSEUDO} ${OBJ_S1C88PSEUDO}
else
	${CC} $(call libname,parse_s1c88_pseudo) -L../../util -lr_util \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_S1C88PSEUDO} ${OBJ_S1C88PSEUDO} $(LINK)
endif
