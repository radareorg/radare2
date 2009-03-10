CFLAGS_APPEND=
GNULINUX=1
BSD=0
SOLARIS=0
WINDOWS=0
OSX=0
USE_RIO=1

# static plugins
STATIC_ASM_PLUGINS=p/x86olly.mk p/mips.mk p/java.mk
STATIC_BIN_PLUGINS=

ifneq (${BINDEPS},)
include ../../../config.mk
else
include ../../config.mk
endif
