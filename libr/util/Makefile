include ../config.mk

NAME=r_util
DEPS=

OBJS=mem.o pool.o num.o str.o hex.o file.o range.o
OBJS+=prof.o cache.o sys.o buf.o w32-sys.o base64.o base85.o
OBJS+=list.o flist.o ht.o ht64.o mixed.o btree.o chmod.o graph.o
OBJS+=regex/regcomp.o regex/regerror.o regex/regexec.o uleb128.o
OBJS+=sandbox.o calc.o thread.o thread_lock.o thread_msg.o
OBJS+=strpool.o bitmap.o strht.o p_date.o p_format.o print.o
OBJS+=p_seven.o slist.o randomart.o log.o zip.o debruijn.o
OBJS+=utf8.o strbuf.o lib.o name.o

# DO NOT BUILD r_big api (not yet used and its buggy)
ifeq (1,0)
ifeq (${HAVE_LIB_GMP},1)
  OBJS+=big-gmp.o
else
  ifeq (${HAVE_LIB_SSL},1)
    OBJS+=big-ssl.o
  else
    OBJS+=big.o
  endif
endif
endif

ifeq ($(USE_LIB_ZIP),1)
  LINK+=$(LIBZIP)
else
  LINK+=$(SHLR)/zip/librz.a
endif
CFLAGS+=-I$(SHLR)/zip/include

LDFLAGS+=${BN_LIBS}
LDFLAGS+=${TH_LIBS}
LDFLAGS+=${DL_LIBS}

# NetBSD 7.0 ships with backtrace(3) in -lexecinfo
ifeq (${BUILD_OS},netbsd)
ifneq ($(shell expr "`uname -r`" : '[0-6]\.'), 2)
  LDFLAGS+=-lexecinfo
endif
endif

include ../rules.mk
