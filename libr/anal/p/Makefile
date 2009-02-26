CFLAGS=-I../../include -I../../asm/arch/ -I../arch/include -Wall -fPIC -shared -Wl,-R..

all: anal_dummy.so anal_x86.so anal_x86_bea.so
	@true

anal_dummy.so: anal_dummy.o
	${CC} ${CFLAGS} -o anal_dummy.so anal_dummy.o
	@#strip -s anal_dummy.so

anal_x86.so: anal_x86.o
	${CC} ${CFLAGS} -o anal_x86.so anal_x86.o
	@#strip -s anal_x86.so

anal_x86_bea.so: anal_x86_bea.o
	${CC} ${CFLAGS} -o anal_x86_bea.so anal_x86_bea.o
	@#strip -s anal_x86_bea.so

clean:
	-rm -f *.so *.o
