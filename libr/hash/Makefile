include ../config.mk

NAME=r_hash
# HACK
ifneq ($(OSTYPE),darwin)
LDFLAGS+=-lm
LINK=-lm
endif

OBJS=state.o md5c.o crc16.o crc32.o sha1.o hash.o
OBJS+=hamdist.o entropy.o sha2.o calc.o xxhash.o

include ../rules.mk
