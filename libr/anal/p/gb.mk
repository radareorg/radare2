OBJ_GB=anal_gb.o

STATIC_OBJ+=${OBJ_GB}
TARGET_GB=anal_gb.${EXT_SO}

ALL_TARGETS+=${TARGET_GB}
#LDFLAGS+=-L../../lib -lr_lib
#LDFLAGS+=-L../../syscall -lr_syscall
#LDFLAGS+=-L../../diff -lr_diff

${TARGET_GB}: ${OBJ_GB}
	${CC} $(call libname,anal_gb) ${LDFLAGS} ${CFLAGS} -o anal_gb.${EXT_SO} ${OBJ_GB}
