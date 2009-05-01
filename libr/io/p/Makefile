CFLAGS=-I../../include -Wall -DWORDSIZE=64
BINDEPS=

all: io_ptrace.so io_dbg.so io_malloc.so io_shm.so
	@true

io_malloc.so: malloc.o
	${CC} ${CFLAGS} -fPIC -shared -o io_malloc.so malloc.c

io_ptrace.so: ptrace.o
	${CC} ${CFLAGS} -fPIC -shared -o io_ptrace.so ptrace.c

io_dbg.so: dbg.o
	${CC} ${CFLAGS} -fPIC -shared -o io_dbg.so dbg.c -lr_io -L../../io -Wl,-R..

io_shm.so: shm.o
	${CC} ${CFLAGS} -fPIC -shared -o io_shm.so shm.c -lr_io -L../../io -Wl,-R..

io_ewf.so: ewf.o
	${CC} ${CFLAGS} -fPIC -shared -o io_ewf.so ewf.c -lr_io -L../../io -Wl,-R..

clean:
	-rm -f *.so *.o
