
# V35ARMV7_ARCH?=arch-armv7
# V35ARMV7_SRCDIR=$(V35ARM64_HOME)/$(V35ARMV7_ARCH)/armv7_disasm/
V35ARMV7_SRCDIR=$(TOP)/subprojects/binaryninja/arch/armv7/armv7_disasm/
# subprojects/binaryninja/arch/armv7/armv7_disasm

V35ARMV7_CFLAGS=-I$(V35ARMV7_SRCDIR)
V35ARMV7_CFLAGS=-DUNUSED=R_UNUSED

V35ARMV7_OBJS+=armv7.o
V35ARMV7_LINK=$(addprefix $(V35ARMV7_SRCDIR),$(V35ARMV7_OBJS))
V35ARMV7_LIBS=$(V35ARM64_HOME)/armv7dis.a

${V35ARMV7_LINK}: $(V35ARMV7_SRCDIR)

$(V35ARMV7_SRCDIR):
	$(MAKE) $(V35ARM64_HOME)/armv7dis.a

git-clone-armv7v35 $(V35ARM64_HOME)/armv7dis.a:
	$(MAKE) -C $(V35ARM64_HOME) arch-armv7

.PHONY: git-clone-armv7v35
