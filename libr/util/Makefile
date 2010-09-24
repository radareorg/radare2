include ../config.mk

NAME=r_util
OBJ=mem.o pool.o num.o str.o re.o hex.o file.o alloca.o range.o log.o
OBJ+=prof.o cache.o sys.o btree.o buf.o list.o flist.o w32-sys.o
ifeq (${HAVE_LIB_GMP},1)
  OBJ+=big-gmp.o
else
  ifeq (${HAVE_LIB_OPENSSL},1)
    OBJ+=big-ssl.o
  else
    OBJ+=big.o
  endif
endif

LDFLAGS+=${BN_LIBS}

include ../rules.mk
