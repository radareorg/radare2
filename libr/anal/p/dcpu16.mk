OBJ_DCPU16=anal_dcpu16.o
#OBJ_DCPU16+=../arch/dcpu16/asm.o
#OBJ_DCPU16+=../arch/dcpu16/dis.o

STATIC_OBJ+=${OBJ_DCPU16}
TARGET_DCPU16=anal_dcpu16.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_DCPU16}

${TARGET_DCPU16}: ${OBJ_DCPU16}
	${CC} $(call libname,anal_dcpu16) ${LDFLAGS} ${CFLAGS} -o anal_dcpu16.${EXT_SO} ${OBJ_DCPU16}
endif
