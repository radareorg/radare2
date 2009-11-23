OBJ=rahash2.o
BIN=rahash2
BINDEPS=r_io r_hash r_util
LIBS=-lm

all: ${BIN} hello

hello: hello.o
	${CC} -I../../include hello.o -Wl,-R.. -L.. -L../../io -L../../util -L../../lib -lr_util -lr_lib -lr_hash -lr_io -o hello

myclean:
	rm -f hello hello.o

include ../../rules.mk
