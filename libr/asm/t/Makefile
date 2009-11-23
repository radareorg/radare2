OBJ=rasm2.o
BIN=rasm2
BINDEPS=r_util r_lib r_asm r_print r_cons
LIBS+=-ldl

LDPATH=-L.. -L../../util -L../../lib
LDPATH+=-lr_util -lr_lib
CFLAGS+=-DVERSION=\"${VERSION}\"

all: ${BIN} fastcall

fastcall: fastcall.o
	${CC} fastcall.o ${LDPATH} -Wl,-R.. -L.. -lr_asm -o fastcall

myclean:
	rm -f fastcall fastcall.o

include ../../rules.mk
