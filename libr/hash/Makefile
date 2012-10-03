include ../config.mk

NAME=r_hash
# HACK
ifneq ($(OSTYPE),darwin)
LDFLAGS+=-lm
LINK=-lm
endif

OBJS=state.o md5c.o crc16.o crc32.o sha1.o hash.o hamdist.o entropy.o sha2.o calc.o

include ../rules.mk
