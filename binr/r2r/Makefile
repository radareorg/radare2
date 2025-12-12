BIN=r2r
BINDEPS=r_util r_cons
OBJ=load.o run.o
#CFLAGS+=-DALLINC=1

include ../rules.mk
include ../../libr/util/deps.mk

LDFLAGS+=${DL_LIBS}
LDFLAGS+=$(CLOCK_LDFLAGS)

include ../shlr.mk
