include ../config.mk

NAME=r_reg
R2DEPS=r_util
OBJS=reg.o arena.o rvalue.o rcond.o double.o profile.o

include ../rules.mk

fast:
	rm -f sasa.c && cat *.c > sasa.c
	$(CC_LIB) $(LIBNAME) $(CFLAGS) sasa.c $(SHARED_OBJ) $(LINK) $(LDFLAGS)
	rm -f sasa.c

