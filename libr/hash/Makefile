include ../config.mk

NAME=r_hash
# HACK
ifneq ($(OSTYPE),darwin)
ifneq ($(OSTYPE),haiku)
LDFLAGS+=-lm
LINK=-lm
endif
endif

OBJS=state.o md5.o sha1.o hash.o md4.o hamdist.o crca.o
OBJS+=entropy.o sha2.o calc.o xxhash.o adler32.o luhn.o

include ../rules.mk
