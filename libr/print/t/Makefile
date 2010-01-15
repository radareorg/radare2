all: hex fmt

BIN=hex
OBJ=hex.o
BINDEPS=r_cons r_util r_line r_print

ftm: fmt.o
	${CC} -I../../include fmt.o -L../../util -lr_util ../*.o -o fmt

myclean:
	rm -f fmt fmt.o

include ../../rules.mk
