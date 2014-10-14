OBJ_H8300=anal_h8300.o
CFLAGS+=-I../asm/arch/h8300/

STATIC_OBJ+=${OBJ_H8300}
#OBJ_H8300+=../../../../../../../../../../../../../../../../../../../../${LTOP}/asm/arch/h8300/h8300_disas.o
OBJ_H8300+=../../asm/arch/h8300/h8300_disas.o
TARGET_H8300=anal_h8300.${EXT_SO}

ALL_TARGETS+=${TARGET_H8300}

${TARGET_H8300}: ${OBJ_H8300} ${SHARED_OBJ}
	$(call pwd)
	${CC} $(call libname,anal_h8300) ${CFLAGS} \
		-o ${TARGET_H8300} ${OBJ_H8300}
