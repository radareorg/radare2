# capstone-m68k

OBJ_M68KCS=asm_m68k_cs.o

include p/capstone.mk

STATIC_OBJ+=${OBJ_M68KCS}
SHARED_OBJ+=${SHARED_M68KCS}
TARGET_M68KCS=asm_m68k_cs.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_M68KCS}

${TARGET_M68KCS}: ${OBJ_M68KCS}
	${CC} $(call libname,asm_m68k_cs) ${LDFLAGS} ${CFLAGS} ${CS_CFLAGS} \
		-o ${TARGET_M68KCS} ${OBJ_M68KCS} ${CS_LDFLAGS}
endif
