OBJ_Z80_CR=asm_z80_cr.o

STATIC_OBJ+=${OBJ_Z80_CR}
TARGET_Z80_CR=asm_z80_cr.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_Z80_CR}

${TARGET_Z80_CR}: ${OBJ_Z80_CR}
	${CC} $(call libname,asm_z80-cr) ${LDFLAGS} ${CFLAGS} -o ${TARGET_Z80_CR} ${OBJ_Z80_CR}
endif
