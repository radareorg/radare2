OBJ_M68K_GNU=p/m68k_gnu/plugin.o
OBJ_M68K_GNU+=p/m68k_gnu/m68k-dis.o
OBJ_M68K_GNU+=p/m68k_gnu/m68k-opc.o
OBJ_M68K_GNU+=p/arm/gnu/floatformat.o

STATIC_OBJ+=${OBJ_M68K_GNU}
TARGET_M68K_GNU=m68k_gnu.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_M68K_GNU}

${TARGET_M68K_GNU}: ${OBJ_M68K_GNU}
	${CC} $(call libname,arch_m68k) ${LDFLAGS} ${CFLAGS} \
		-o m68k_gnu.${EXT_SO} ${OBJ_M68K_GNU}
endif
