include ../config.mk

NAME=r_util
DEPS=

OBJS=mem.o pool.o num.o str.o hex.o file.o alloca.o range.o log.o
OBJS+=prof.o cache.o sys.o buf.o w32-sys.o base64.o base85.o name.o
OBJS+=list.o flist.o ht.o ht64.o mixed.o btree.o chmod.o graph.o
OBJS+=regex/regcomp.o regex/regerror.o regex/regexec.o uleb128.o
OBJS+=sandbox.o calc.o thread.o lock.o

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

LDFLAGS+=${BN_LIBS}
LDFLAGS=${TH_LIBS}

include ../rules.mk

ht64:
	cat ht.c | sed -e s,hashtable,hashtable64,g -e s,HashTable,HashTable64,g -e s,ut32,ut64,g > ht64.c
	#cat ht.c ht64.c | sed -e 's,) {,);,'
m:
	${CC} mixed.c -I ../include/ -DTEST=1 -lr_util -g

h:
	${CC} ht.c -I ../include/ -DTEST=1 -lr_util -g
