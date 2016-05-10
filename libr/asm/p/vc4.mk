OBJ_VC4=asm_vc4.o
OBJ_VC4+=../arch/vc4/vc4-dis.o
OBJ_VC4+=../arch/vc4/vc4-asm.o
OBJ_VC4+=../arch/vc4/vc4-desc.o
OBJ_VC4+=../arch/vc4/vc4-ibld.o
OBJ_VC4+=../arch/vc4/vc4-opc.o
OBJ_VC4+=../arch/vc4/cgen-bitset.o
OBJ_VC4+=../arch/vc4/cgen-dis.o
OBJ_VC4+=../arch/vc4/cgen-asm.o
OBJ_VC4+=../arch/vc4/cgen-opc.o
OBJ_VC4+=../arch/vc4/libvc4/eval.o
OBJ_VC4+=../arch/vc4/libvc4/decode.o
OBJ_VC4+=../arch/vc4/libvc4/vc4_decode.o
OBJ_VC4+=../arch/vc4/libvc4/vc4_arch.o
OBJ_VC4+=../arch/vc4/libvc4/vc4_util.o

CFLAGS+=-Iarch/vc4/libvc4/ -Iarch/include/
STATIC_OBJ+=${OBJ_VC4}
TARGET_VC4=asm_vc4.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_VC4}

${TARGET_VC4}: ${OBJ_VC4}
	${CC} $(call libname,asm_ppc) ${LDFLAGS} ${CFLAGS} -o asm_vc4.${EXT_SO} ${OBJ_VC4}
endif
