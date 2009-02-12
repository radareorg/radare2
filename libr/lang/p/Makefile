CFLAGS=-I../../include -Wall
BINDEPS=

all: lua.so dummy.so ruby.so python.so
	@true

python.so:
	-${CC} ${CFLAGS} -I/usr/include/python2.5 \
	-fPIC -shared -o python.so python.c -lpython >/dev/null 2>&1

lua.so: lua.o
	-${CC} ${CFLAGS} -fPIC -shared -o lua.so lua.c -Wl,-R..
	@#strip -s lua.so

ruby.so:
	-ruby mkruby.rb

dummy.so: dummy.o
	${CC} ${CFLAGS} -fPIC -shared -o dummy.so dummy.c -Wl,-R..
	@#strip -s lua.so
clean:
	-rm -f *.so *.o
