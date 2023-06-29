
V35ARM64_SRCDIR=$(V35ARM64_HOME)/arch-arm64/disassembler/

V35ARM64_CFLAGS=-I$(V35ARM64_SRCDIR)
# V35ARM64_OBJS+=arm64dis.o
# V35ARM64_OBJS+=encodings.o
# V35ARM64_OBJS+=test.o
V35ARM64_OBJS+=decode.o
V35ARM64_OBJS+=decode0.o
V35ARM64_OBJS+=decode1.o
V35ARM64_OBJS+=decode2.o
V35ARM64_OBJS+=decode_fields32.o
V35ARM64_OBJS+=decode_scratchpad.o
V35ARM64_OBJS+=encodings_dec.o
V35ARM64_OBJS+=encodings_fmt.o
V35ARM64_OBJS+=format.o
V35ARM64_OBJS+=gofer.o
V35ARM64_OBJS+=operations.o
V35ARM64_OBJS+=pcode.o
V35ARM64_OBJS+=regs.o
V35ARM64_OBJS+=sysregs.o
V35ARM64_LINK=$(addprefix $(V35ARM64_SRCDIR),$(V35ARM64_OBJS))
V35ARM64_LIBS=$(V35ARM64_HOME)/arm64dis.a

${V35ARM64_LINK}: $(V35ARM64_SRCDIR)
$(V35ARM64_SRCDIR):

#	$(MAKE) -C $(V35ARM64_HOME) arch-arm64
#	$(MAKE) $(V35ARM64_HOME)/arm64dis.a
#	$(MAKE) git-clone-arm64v35

git-clone-arm64v35: # $(V35ARM64_HOME)/arm64dis.a:
	$(MAKE) -C $(V35ARM64_HOME) arch-arm64

.PHONY: git-clone-arm64v35
