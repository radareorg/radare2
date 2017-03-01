include ../config.mk

NAME=r_hash
# HACK
ifneq ($(OSTYPE),darwin)
ifneq ($(OSTYPE),haiku)
LDFLAGS+=-lm
LINK=-lm
endif
endif

OBJS=state.o md5.o crc16.o crc32.o sha1.o hash.o md4.o
OBJS+=hamdist.o entropy.o sha2.o calc.o xxhash.o adler32.o luhn.o
# OBJS+=crca.o

include ../rules.mk
