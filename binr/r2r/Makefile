BIN=r2r
BINDEPS=r_util
OBJ=load.o run.o

# LDFLAGS+=-static -ldl -lpthread -lm

include ../rules.mk
include ../../libr/util/deps.mk

LDFLAGS+=$(CLOCK_LDFLAGS)
LDFLAGS+=$(LINK)
