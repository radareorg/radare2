OBJ_BA2=asm_ba2.o
CFLAGS+=-I./arch/ba2/

STATIC_OBJ+=${OBJ_BA2}
TARGET_BA2=asm_ba2.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_BA2}

${TARGET_BA2}: ${OBJ_BA2}
	${CC} $(call libname,asm_ba2) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_BA2} ${OBJ_BA2}
endif

