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

R2DEPS=r_util
OBJS=state.o hash.o hamdist.o crca.o fletcher.o
OBJS+=entropy.o hcalc.o adler32.o luhn.o ssdeep.o

ifeq ($(HAVE_LIB_SSL),1)
CFLAGS+=${SSL_CFLAGS}
LDFLAGS+=${SSL_LDFLAGS}
LINK+=${SSL_LDFLAGS}
else
OBJS+=md4.o md5.o sha1.o sha2.o
endif

ifeq ($(USE_LIB_XXHASH),1)
LDFLAGS+=${LIB_XXHASH}
LINK+=${LIBXXHASH}
else
OBJS+=xxhash.o
endif

include ../rules.mk
