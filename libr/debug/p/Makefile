CFLAGS=-I../../include -Wall
BINDEPS=

all: dbg_ptrace.so
	@true

dbg_ptrace.so: dbg_ptrace.o
	${CC} ${CFLAGS} -fPIC -shared -o dbg_ptrace.so dbg_ptrace.c
	#strip -s ptrace.so

clean:
	-rm -f *.so *.o
