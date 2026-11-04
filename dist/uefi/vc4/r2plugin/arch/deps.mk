VC4_ROOT=$(LIBR)/xps/p/vc4/libr/asm
VC4_ARCH=$(VC4_ROOT)/arch/vc4
VC4_SOURCES=$(VC4_ROOT)/p/arch_vc4.c
VC4_SOURCES+=$(addprefix $(VC4_ARCH)/,vc4-dis.c vc4-asm.c vc4-desc.c vc4-ibld.c vc4-opc.c)
VC4_SOURCES+=$(addprefix $(VC4_ARCH)/,cgen-bitset.c cgen-dis.c cgen-asm.c cgen-opc.c)
VC4_OBJS=$(VC4_SOURCES:.c=.o)

$(VC4_OBJS): CFLAGS+=-I$(VC4_ARCH) -I$(VC4_ARCH)/include -I$(VC4_ARCH)/include/opcode
$(VC4_OBJS): CFLAGS+=-I$(LIBR)/arch/include
$(VC4_OBJS): CFLAGS+=-I$(LIBR)/xps/p/vc4/r2plugin/arch
$(VC4_ROOT)/p/arch_vc4.o: CFLAGS+=-include $(LIBR)/xps/p/vc4/r2plugin/arch/disasm.h
EXTERNAL_STATIC_OBJS+=$(VC4_OBJS)
