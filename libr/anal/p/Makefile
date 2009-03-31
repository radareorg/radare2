CFLAGS=-I../../include -I../../asm/arch/ -I../arch/ -Wall -fPIC -shared -Wl,-R..
CFLAGS+=-DR_DEBUG=1

ANAL_X86_OBJ=../arch/x86/dislen.o

all: anal_dummy.so anal_x86.so anal_x86_bea.so
	@true

anal_dummy.so: anal_dummy.o
	${CC} ${CFLAGS} -o anal_dummy.so anal_dummy.o
	@#strip -s anal_dummy.so

anal_x86.so: anal_x86.o ${ANAL_X86_OBJ}
	${CC} ${CFLAGS} -o anal_x86.so anal_x86.o ${ANAL_X86_OBJ}
	@#strip -s anal_x86.so

anal_x86_bea.so: anal_x86_bea.o
	${CC} ${CFLAGS} -o anal_x86_bea.so anal_x86_bea.o
	@#strip -s anal_x86_bea.so

clean:
	-rm -f *.so *.o ${ANAL_X86_OBJ}
