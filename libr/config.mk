CFLAGS_APPEND=
GNULINUX=1
BSD=0
SOLARIS=0
WINDOWS=0
OSX=0
USE_RIO=1

# static plugins
STATIC_DEBUG=0
RUNTIME_DEBUG=1
STATIC_ASM_PLUGINS=p/x86olly.mk p/x86nasm.mk p/mips.mk p/java.mk
STATIC_BIN_PLUGINS=p/elf.mk p/elf64.mk p/pe.mk p/pe64.mk p/java.mk p/dummy.mk
STATIC_BP_PLUGINS=p/x86.mk
STATIC_BININFO_PLUGINS=p/addr2line.mk

ifneq (${BINDEPS},)
include ../../../config-user.mk
include ../../../config.mk
include ../../../mk/${COMPILER}.mk
else
include ../../config-user.mk
include ../../config.mk
include ../../mk/${COMPILER}.mk
endif
