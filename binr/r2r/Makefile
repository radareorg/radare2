BIN=r2r
BINDEPS=r_util
OBJ=load.o run.o

include ../rules.mk
include ../../libr/util/deps.mk

LDFLAGS+=${DL_LIBS}
LDFLAGS+=$(CLOCK_LDFLAGS)
LDFLAGS+=$(LINK)
