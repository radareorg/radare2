CFLAGS=-I../../include -Wall
BINDEPS=

all: lua.so dummy.so ruby.so
	@true

lua.so: lua.o
	${CC} ${CFLAGS} -fPIC -shared -o lua.so lua.c -Wl,-R..
	@#strip -s lua.so

ruby.so:
	-ruby mkruby.rb

dummy.so: dummy.o
	${CC} ${CFLAGS} -fPIC -shared -o dummy.so dummy.c -Wl,-R..
	@#strip -s lua.so
clean:
	-rm -f *.so *.o
