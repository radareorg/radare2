CFLAGS=-I../../include -I../arch/ -I../arch/include -Wall
# XXX
CFLAGS+=-DLIL_ENDIAN=1

## X86
OBJ_X86=asm_x86.o
# udis86
OBJ_X86+=../arch/x86/udis86/syn.o
OBJ_X86+=../arch/x86/udis86/input.o
OBJ_X86+=../arch/x86/udis86/udis86.o
OBJ_X86+=../arch/x86/udis86/decode.o
OBJ_X86+=../arch/x86/udis86/itab.o
OBJ_X86+=../arch/x86/udis86/syn-intel.o
OBJ_X86+=../arch/x86/udis86/syn-att.o
# olly
OBJ_X86+=../arch/x86/ollyasm/disasm.o
OBJ_X86+=../arch/x86/ollyasm/asmserv.o
OBJ_X86+=../arch/x86/ollyasm/assembl.o
## ARM
OBJ_ARM=asm_arm.o
# gnu arm-dis
OBJ_ARM+=../arch/arm/gnu/arm-dis.o
## MIPS
OBJ_MIPS=asm_mips.o
# gnu mips-dis
OBJ_MIPS+=../arch/mips/gnu/mips-dis.o
OBJ_MIPS+=../arch/mips/gnu/mips16-opc.o
OBJ_MIPS+=../arch/mips/gnu/mips-opc.o
## SPARC
OBJ_SPARC=asm_sparc.o
# gnu sparc-dis
OBJ_SPARC+=../arch/sparc/gnu/sparc-dis.o
OBJ_SPARC+=../arch/sparc/gnu/sparc-opc.o
## PPC
OBJ_PPC=asm_ppc.o
# ppc-disasm
OBJ_PPC+=../arch/ppc/ppc_disasm/ppc_disasm.o
## BF
OBJ_BF=asm_bf.o
## CSR
OBJ_CSR=asm_csr.o
# csr-disasm
OBJ_CSR+=../arch/csr/csr_disasm/dis.o
## M68K
OBJ_M68K=asm_m68k.o
# mk8k-disasm
OBJ_M68K+=../arch/m68k/m68k_disasm/m68k_disasm.o

all: asm_dummy.so asm_x86.so asm_arm.so \
		asm_mips.so asm_sparc.so asm_ppc.so \
		asm_bf.so asm_csr.so asm_m68k.so
	@true

asm_dummy.so: asm_dummy.o
	${CC} ${CFLAGS} -fPIC -shared -o asm_dummy.so asm_dummy.o -Wl,-R..
	@#strip -s asm_dummy.so

asm_x86.so: ${OBJ_X86}
	${CC} ${CFLAGS} -fPIC -shared -o asm_x86.so ${OBJ_X86} -Wl,-R..
	@#strip -s asm_x86.so

asm_arm.so: ${OBJ_ARM}
	${CC} ${CFLAGS} -fPIC -shared -o asm_arm.so ${OBJ_ARM} -Wl,-R..
	@#strip -s asm_x86.so

asm_mips.so: ${OBJ_MIPS}
	${CC} ${CFLAGS} -fPIC -shared -o asm_mips.so ${OBJ_MIPS} -Wl,-R..
	@#strip -s asm_x86.so

asm_sparc.so: ${OBJ_SPARC}
	${CC} ${CFLAGS} -fPIC -shared -o asm_sparc.so ${OBJ_SPARC} -Wl,-R..
	@#strip -s asm_x86.so

asm_ppc.so: ${OBJ_PPC}
	${CC} ${CFLAGS} -fPIC -shared -o asm_ppc.so ${OBJ_PPC} -Wl,-R..
	@#strip -s asm_x86.so

asm_bf.so: ${OBJ_BF}
	${CC} ${CFLAGS} -fPIC -shared -o asm_bf.so ${OBJ_BF} -Wl,-R..
	@#strip -s asm_x86.so

asm_csr.so: ${OBJ_CSR}
	${CC} ${CFLAGS} -fPIC -shared -o asm_csr.so ${OBJ_CSR} -Wl,-R..
	@#strip -s asm_x86.so

asm_m68k.so: ${OBJ_M68K}
	${CC} ${CFLAGS} -fPIC -shared -o asm_m68k.so ${OBJ_M68K} -Wl,-R..
	@#strip -s asm_x86.so

clean:
	-rm -f *.so *.o \
		${OBJ_X86} ${OBJ_ARM} ${OBJ_MIPS} \
		${OBJ_SPARC} ${OBJ_PPC} ${OBJ_BF} \
		${OBJ_CSR} ${OBJ_M68K}
