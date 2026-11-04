OBJ_E0C62PSEUDO+=$(LIBR)/arch/p/e0c62/pseudo.o

TARGET_E0C62PSEUDO=parse_e0c62_pseudo.${EXT_SO}
ALL_TARGETS+=${TARGET_E0C62PSEUDO}
STATIC_OBJ+=${OBJ_E0C62PSEUDO}

${TARGET_E0C62PSEUDO}: ${OBJ_E0C62PSEUDO}
ifeq ($(CC),cccl)
	${CC} $(call libname,parse_e0c62_pseudo) -L../../util -llibr_util \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_E0C62PSEUDO} ${OBJ_E0C62PSEUDO}
else
	${CC} $(call libname,parse_e0c62_pseudo) -L../../util -lr_util \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_E0C62PSEUDO} ${OBJ_E0C62PSEUDO} $(LINK)
endif
