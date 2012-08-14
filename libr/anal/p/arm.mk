OBJ_ARM=anal_arm.o $(TOP)/libr/asm/arch/arm/winedbg/be_arm.o

STATIC_OBJ+=${OBJ_ARM}
TARGET_ARM=anal_arm.${EXT_SO}

ALL_TARGETS+=${TARGET_ARM}
LDFLAGS+=-L$(TOP)/libr/lib -lr_lib
LDFLAGS+=-L$(TOP)/libr/syscall -lr_syscall
LDFLAGS+=-L$(TOP)/libr/diff -lr_diff

${TARGET_ARM}: ${OBJ_ARM}
	${CC} $(call libname,anal_arm) ${LDFLAGS} ${CFLAGS} -o anal_arm.${EXT_SO} ${OBJ_ARM}
