OBJ_CR16=anal_cr16.o
CFLAGS+=-I$(LIBR)/asm/arch/cr16/

STATIC_OBJ+=${OBJ_CR16}
TARGET_CR16=anal_cr16.${EXT_SO}

ifeq ($(WITHPIC),1)
OBJ_CR16+=$(LIBR)/asm/arch/cr16/cr16_disas.o
endif

ALL_TARGETS+=${TARGET_CR16}

${TARGET_CR16}: ${OBJ_CR16} ${SHARED_OBJ}
	$(call pwd)
	${CC} $(call libname,anal_cr16) ${CFLAGS} \
		-o ${TARGET_CR16} ${OBJ_CR16}
