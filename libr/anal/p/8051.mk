OBJ_8051=anal_8051.o

STATIC_OBJ+=${OBJ_8051}
TARGET_8051=anal_8051.${EXT_SO}

ALL_TARGETS+=${TARGET_8051}
#LDFLAGS+=-L../../lib -lr_lib
#LDFLAGS+=-L../../syscall -lr_syscall
#LDFLAGS+=-L../../diff -lr_diff

${TARGET_8051}: ${OBJ_8051}
	${CC} $(call libname,anal_z80) ${LDFLAGS} ${CFLAGS} -o anal_8051.${EXT_SO} ${OBJ_8051}
