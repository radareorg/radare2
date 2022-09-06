OBJ_M68K_GNU=anal_m68k_gnu.o
OBJ_M68K_GNU+=../../asm/arch/m68k/gnu/m68k-dis.o
OBJ_M68K_GNU+=../../asm/arch/m68k/gnu/m68k-opc.o

STATIC_OBJ+=${OBJ_M68K_GNU}
TARGET_M68K_GNU=anal_m68k_gnu.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_M68K_GNU}

${TARGET_M68K_GNU}: ${OBJ_M68K_GNU}
	${CC} $(call libname,anal_m68k) ${LDFLAGS} ${CFLAGS} \
		-o anal_m68k_gnu.${EXT_SO} ${OBJ_M68K_GNU}
endif
