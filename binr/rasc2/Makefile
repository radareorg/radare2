BIN=rasc2
BINDEPS=r_util
MYCLEAN=myclean
OBJS=shellcodes.o test.o

preall: shellcodes.c
	${MAKE} all

xorhex:
	gcc xorhex.c -o xorhex

shellcodes.c: xorhex
	./xorhex < shellcodes.c.src > shellcodes.c
	./xorhex decode < shellcodes.c > shellcodes.c.new
	diff -ru shellcodes.c.src shellcodes.c.new

myclean:
	rm -f shellcodes.c xorhex.o

include ../binr.mk
