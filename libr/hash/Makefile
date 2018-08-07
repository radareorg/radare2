include ../config.mk

NAME=r_hash
PCLIBS=@LIBXXHASH@
# HACK
ifneq ($(OSTYPE),darwin)
ifneq ($(OSTYPE),haiku)
LDFLAGS+=-lm
LINK=-lm
endif
endif

DEPS=r_util
OBJS=state.o md5.o sha1.o hash.o md4.o hamdist.o crca.o
OBJS+=entropy.o sha2.o calc.o adler32.o luhn.o

ifeq ($(USE_LIB_XXHASH),1)
LDFLAGS+=${LIB_XXHASH}
LINK+=${LIBXXHASH}
else
OBJS+=xxhash.o
endif

include ../rules.mk
