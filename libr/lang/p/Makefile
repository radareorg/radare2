CFLAGS=-I../../include -Wall
BINDEPS=

all: lua.so dummy.so ruby.so python.so perl.so
	@true

python.so:
	-gcc -lpython >/dev/null 2>&1 ; \
		if [ $$? = 0 ]; then \
		${CC} ${CFLAGS} -I/usr/include/python2.5 \
		-fPIC -shared -o python.so python.c -lpython ; \
		else \
		${CC} ${CFLAGS} -I/usr/include/python2.5 \
		-fPIC -shared -o python.so python.c \
		-I/usr/include/python2.6/ -lpython2.6 ; \
		fi

lua.so: lua.o
	-${CC} ${CFLAGS} -fPIC -shared -o lua.so lua.c -Wl,-R..
	@#strip -s lua.so

ruby.so:
	-ruby mkruby.rb

perl.so:
	-${CC} ${CFLAGS} -I/usr/lib/perl/5.10/CORE/ \
		-fPIC -shared -o perl.so perl.c -Wl,-R.. \
		`perl -MExtUtils::Embed -e ccopts` \
		`perl -MExtUtils::Embed -e ldopts` -lncurses

dummy.so: dummy.o
	${CC} ${CFLAGS} -fPIC -shared -o dummy.so dummy.c -Wl,-R..
	@#strip -s lua.so
clean:
	-rm -f *.so *.o
