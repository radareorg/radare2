BIN=r2r
BINDEPS=r_util r_cons
OBJ=load.o run.o
#CFLAGS+=-DALLINC=1

include ../rules.mk
include ../../libr/util/deps.mk

LDFLAGS+=${DL_LIBS}
LDFLAGS+=$(CLOCK_LDFLAGS)

# required for the static builds
include ../../libr/socket/deps.mk
include ../../libr/main/deps.mk
include ../../shlr/zip/deps.mk
include ../../shlr/gdb/deps.mk
include ../../shlr/java/deps.mk
include ../../shlr/grub/deps.mk
include ../../shlr/bochs/deps.mk
include ../../shlr/qnx/deps.mk
include ../../shlr/ar/deps.mk
include ../../shlr/capstone.mk
LDFLAGS+=$(LINK)
