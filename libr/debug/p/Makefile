CFLAGS=-I../../include -Wall
BINDEPS=

all: dbg-ptrace.so
	@true

dbg-ptrace.so: dbg-ptrace.o
	${CC} ${CFLAGS} -fPIC -shared -o dbg-ptrace.so dbg-ptrace.c
	#strip -s ptrace.so

clean:
	-rm -f *.so *.o
