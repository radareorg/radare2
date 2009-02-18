CFLAGS=-I../../include -I../arch/ -Wall
BINDEPS=
# XXX
CFLAGS+=-DLIL_ENDIAN=1

# X86
# udis86
OBJ_X86+=asm_x86.o
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

all: asm_dummy.so asm_x86.so
	@true

asm_dummy.so: asm_dummy.o
	${CC} ${CFLAGS} -fPIC -shared -o asm_dummy.so asm_dummy.o -Wl,-R..
	@#strip -s asm_dummy.so

asm_x86.so: ${OBJ_X86}
	${CC} ${CFLAGS} -fPIC -shared -o asm_x86.so ${OBJ_X86} -Wl,-R..
	@#strip -s asm_x86.so

clean:
	-rm -f *.so *.o

#NAME=r_asm
#OBJ=asm.o
#DEPS=r_util
#
#CFLAGS+=-Iarch/include
#
#
## ARM
#OBJ+=arch/arm/asm.o
## gnu arm-dis
#OBJ+=arch/arm/gnu/arm-dis.o
#
## MIPS
#OBJ+=arch/mips/asm.o
## gnu mips-dis
#OBJ+=arch/mips/gnu/mips-dis.o
#OBJ+=arch/mips/gnu/mips16-opc.o
#OBJ+=arch/mips/gnu/mips-opc.o
#
## SPARC
#OBJ+=arch/sparc/asm.o
## gnu sparc-dis
#OBJ+=arch/sparc/gnu/sparc-dis.o
#OBJ+=arch/sparc/gnu/sparc-opc.o
#
## PPC
#OBJ+=arch/ppc/asm.o
## ppc-disasm
#OBJ+=arch/ppc/ppc_disasm/ppc_disasm.o
#
## BF
#OBJ+=arch/bf/asm.o
#
## CSR
#OBJ+=arch/csr/asm.o
## ppc-disasm
#OBJ+=arch/csr/csr_disasm/dis.o
#
## M68K
#OBJ+=arch/m68k/asm.o
## mk8k-disasm
#OBJ+=arch/m68k/m68k_disasm/m68k_disasm.o
#
#include ../rules.mk
