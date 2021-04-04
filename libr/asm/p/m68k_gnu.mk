OBJ_M68KGNU=asm_m68k_gnu.o
OBJ_M68KGNU+=../arch/m68k/gnu/m68k-dis.o
OBJ_M68KGNU+=../arch/m68k/gnu/m68k-opc.o

STATIC_OBJ+=${OBJ_M68KGNU}
TARGET_M68KGNU=asm_m68k_gnu.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_M68KGNU}

${TARGET_M68KGNU}: ${OBJ_M68KGNU}
	${CC} $(call libname,asm_m68k_gnu) ${LDFLAGS} ${CFLAGS} \
		-o asm_m68k_gnu.${EXT_SO} ${OBJ_M68KGNU}
endif
