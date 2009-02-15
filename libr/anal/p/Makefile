CFLAGS=-I../../include -Wall
BINDEPS=

all: anal_dummy.so anal_x86.so
	@true

anal_dummy.so: anal_dummy.o
	${CC} ${CFLAGS} -fPIC -shared -o anal_dummy.so anal_dummy.c -Wl,-R..
	@#strip -s anal_dummy.so

anal_x86.so: anal_x86.o
	${CC} ${CFLAGS} -fPIC -shared -o anal_x86.so anal_x86.c -Wl,-R..
	@#strip -s anal_x86.so

clean:
	-rm -f *.so *.o
