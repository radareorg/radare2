OBJ_H8300PSEUDO+=$(LIBR)/arch/p/h8300/pseudo.o

TARGET_H8300PSEUDO=parse_h8300_pseudo.${EXT_SO}
ALL_TARGETS+=${TARGET_H8300PSEUDO}
STATIC_OBJ+=${OBJ_H8300PSEUDO}

${TARGET_H8300PSEUDO}: ${OBJ_H8300PSEUDO}
ifeq ($(CC),cccl)
	${CC} $(call libname,parse_h8300_pseudo) -L../../util -llibr_util \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_H8300PSEUDO} ${OBJ_H8300PSEUDO}
else
	${CC} $(call libname,parse_h8300_pseudo) -L../../util -lr_util \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_H8300PSEUDO} ${OBJ_H8300PSEUDO}
endif
