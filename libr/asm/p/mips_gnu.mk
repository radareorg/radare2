OBJ_MIPS=asm_mips_gnu.o
# gnu mips-dis
OBJ_MIPS+=../arch/mips/gnu/mips-dis.o
OBJ_MIPS+=../arch/mips/gnu/mips16-opc.o
OBJ_MIPS+=../arch/mips/gnu/micromips-opc.o
OBJ_MIPS+=../arch/mips/gnu/mips-opc.o

ifeq ($(WANT_CAPSTONE),0)
OBJ_MIPS+=../arch/mips/mipsasm.o
endif

TARGET_MIPS=asm_mips_gnu.${EXT_SO}
STATIC_OBJ+=${OBJ_MIPS}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_MIPS}
${TARGET_MIPS}: ${OBJ_MIPS}
	${CC} $(call libname,asm_mips) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_MIPS} ${OBJ_MIPS}
endif
