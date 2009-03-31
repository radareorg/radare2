CFLAGS_APPEND=
GNULINUX=1
BSD=0
SOLARIS=0
WINDOWS=0
OSX=0
USE_RIO=1

# static plugins
STATIC_ASM_PLUGINS=p/x86olly.mk p/mips.mk p/java.mk
STATIC_BIN_PLUGINS=p/elf.mk
STATIC_BININFO_PLUGINS=p/addr2line.mk

ifneq (${BINDEPS},)
include ../../../config.mk
include ../../../mk/${COMPILER}.mk
else
include ../../config.mk
include ../../mk/${COMPILER}.mk
endif
