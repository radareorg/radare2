OBJ_V850=anal_v850.o

STATIC_OBJ+=${OBJ_V850}
TARGET_V850=anal_v850.${EXT_SO}

CFLAGS+=-I$(LIBR)/asm/arch/v850/

ifeq ($(WITHPIC),1)
OBJ_V850+=$(LIBR)/asm/arch/v850/v850_disas.o
endif

ALL_TARGETS+=${TARGET_V850}

${TARGET_V850}: ${OBJ_V850} ${SHARED_OBJ}
	$(call pwd)
	${CC} $(call libname,anal_v850) ${CFLAGS} \
		-I../../asm/arch/v850/ -o ${TARGET_V850} ${OBJ_V850}
