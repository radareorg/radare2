OBJ_PIC=asm_pic.o
OBJ_PIC+=../arch/pic/pic_baseline.o \
    ../arch/pic/pic_pic18.o \
    ../arch/pic/pic_midrange.o

STATIC_OBJ+=${OBJ_PIC}
TARGET_PIC=asm_pic.${EXT_SO}

ALL_TARGETS+=${TARGET_PIC}

${TARGET_PIC}: ${OBJ_PIC}
	${CC} $(call libname,asm_pic) ${LDFLAGS} ${CFLAGS} -o asm_pic.${EXT_SO} ${OBJ_PIC}
