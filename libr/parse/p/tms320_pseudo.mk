OBJ_TMS320PSEUDO+=parse_tms320_pseudo.o

TARGET_TMS320PSEUDO=parse_tms320_pseudo.${EXT_SO}
ALL_TARGETS+=${TARGET_TMS320PSEUDO}
STATIC_OBJ+=${OBJ_TMS320PSEUDO}

${TARGET_TMS320PSEUDO}: ${OBJ_TMS320PSEUDO}
ifeq ($(CC),cccl)
	${CC} $(call libname,parse_tms320_pseudo) -L../../util -llibr_util \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_TMS320PSEUDO} ${OBJ_TMS320PSEUDO}
else
	${CC} $(call libname,parse_tms320_pseudo) -L../../util -lr_util \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_TMS320PSEUDO} ${OBJ_TMS320PSEUDO} $(LINK)
endif
