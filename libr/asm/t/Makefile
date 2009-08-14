OBJ=rasm2.o
BIN=rasm2
BINDEPS=r_util r_lib r_asm r_print r_cons
LIBS+=-ldl

include ../../rules.mk

all: ${BIN} fastcall

fastcall: fastcall.o
	${CC} -I../../include fastcall.o -Wl,-R.. -L.. -lr_asm -o fastcall

myclean:
	rm -f fastcall fastcall.o

include ../../rules.mk
