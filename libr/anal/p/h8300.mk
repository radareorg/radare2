OBJ_H8300=anal_h8300.o
CFLAGS+=-I$(LIBR)/asm/arch/h8300/

STATIC_OBJ+=${OBJ_H8300}
TARGET_H8300=anal_h8300.${EXT_SO}

ifeq ($(WITHPIC),1)
OBJ_H8300+=$(LIBR)/asm/arch/h8300/h8300_disas.o
endif

ALL_TARGETS+=${TARGET_H8300}

${TARGET_H8300}: ${OBJ_H8300} ${SHARED_OBJ}
	$(call pwd)
	${CC} $(call libname,anal_h8300) ${CFLAGS} \
		-o ${TARGET_H8300} ${OBJ_H8300}
