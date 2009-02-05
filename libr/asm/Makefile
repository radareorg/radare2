NAME=r_asm
OBJ=asm.o
CFLAGS+=-Iarch/include
# XXX
CFLAGS+=-DLIL_ENDIAN=1

# X86
OBJ+=arch/x86/asm.o
OBJ+=arch/x86/pseudo.o
OBJ+=arch/x86/realloc.o
# udis86
OBJ+=arch/x86/udis86/syn.o
OBJ+=arch/x86/udis86/input.o
OBJ+=arch/x86/udis86/udis86.o
OBJ+=arch/x86/udis86/decode.o
OBJ+=arch/x86/udis86/itab.o
OBJ+=arch/x86/udis86/syn-intel.o
OBJ+=arch/x86/udis86/syn-att.o
# olly
OBJ+=arch/x86/ollyasm/disasm.o
OBJ+=arch/x86/ollyasm/asmserv.o
OBJ+=arch/x86/ollyasm/assembl.o

# ARM
OBJ+=arch/arm/asm.o
# gnu arm-dis
OBJ+=arch/arm/gnu/arm-dis.o

# MIPS
OBJ+=arch/mips/asm.o
# gnu mips-dis
OBJ+=arch/mips/gnu/mips-dis.o
OBJ+=arch/mips/gnu/mips16-opc.o
OBJ+=arch/mips/gnu/mips-opc.o

# SPARC
OBJ+=arch/sparc/asm.o
# gnu sparc-dis
OBJ+=arch/sparc/gnu/sparc-dis.o
OBJ+=arch/sparc/gnu/sparc-opc.o

# PPC
OBJ+=arch/ppc/asm.o
# ppc-disasm
OBJ+=arch/ppc/ppc_disasm/ppc_disasm.o

# BF
OBJ+=arch/bf/asm.o

include ../rules.mk
