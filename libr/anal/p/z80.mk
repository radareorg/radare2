OBJ_Z80=anal_z80.o

STATIC_OBJ+=${OBJ_Z80}
TARGET_Z80=anal_z80.${EXT_SO}

ALL_TARGETS+=${TARGET_Z80}
LDFLAGS+=-L../../lib -lr_lib
LDFLAGS+=-L../../syscall -lr_syscall
LDFLAGS+=-L../../diff -lr_diff

${TARGET_Z80}: ${OBJ_Z80}
	${CC} $(call libname,anal_z80) ${LDFLAGS} ${CFLAGS} -o anal_z80.${EXT_SO} ${OBJ_Z80}
