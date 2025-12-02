OBJ_Z80=p/z80/plugin.o
OBJ_Z80+=p/z80/z80asm.o
OBJ_Z80+=p/z80/z80dis.o

STATIC_OBJ+=${OBJ_Z80}
TARGET_Z80=arch_z80.${EXT_SO}

ALL_TARGETS+=${TARGET_Z80}

${TARGET_Z80}: ${OBJ_Z80}
	${CC} $(call libname,arch_z80) ${LDFLAGS} ${CFLAGS} \
		-o arch_z80.${EXT_SO} ${OBJ_Z80}
