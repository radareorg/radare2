OBJ_8051=anal_8051.o
CFLAGS+=-I../asm/arch/8051

STATIC_OBJ+=${OBJ_8051}
TARGET_8051=anal_8051.${EXT_SO}

ifeq ($(WITHPIC),1)
OBJ_8051+=$(LIBR)/asm/arch/8051/8051.o
endif

ALL_TARGETS+=${TARGET_8051}

${TARGET_8051}: ${OBJ_8051}
	${CC} $(call libname,anal_z80) ${LDFLAGS} ${CFLAGS} -o anal_8051.${EXT_SO} ${OBJ_8051}
