include ../config.mk

NAME=r_util
OBJ=mem.o pool.o num.o str.o hex.o file.o alloca.o range.o log.o
OBJ+=prof.o cache.o sys.o buf.o w32-sys.o base64.o name.o
OBJ+=list.o flist.o ht.o ht64.o mixed.o btree.o chmod.o graph.o

OBJ+=regex/regcomp.o regex/regerror.o regex/regexec.o

# DO NOT BUILD r_big api (not yet used and its buggy)
ifeq (1,0)
ifeq (${HAVE_LIB_GMP},1)
  OBJ+=big-gmp.o
else
  ifeq (${HAVE_LIB_SSL},1)
    OBJ+=big-ssl.o
  else
    OBJ+=big.o
  endif
endif
endif

LDFLAGS+=${BN_LIBS}

include ../rules.mk

ht64:
	cat ht.c | sed -e s,hashtable,hashtable64,g -e s,HashTable,HashTable64,g -e s,ut32,ut64,g > ht64.c
	#cat ht.c ht64.c | sed -e 's,) {,);,'
m:
	gcc mixed.c -I ../include/ -DTEST=1 -lr_util -g
	#valgrind ./a.out

h:
	gcc ht.c -I ../include/ -DTEST=1 -lr_util -g
	#valgrind ./a.out
