include ../../../config-user.mk

CFLAGS=-I../../include -Wall -DPREFIX=\"${PREFIX}\"
BINDEPS=

LANGS=lang_lua.so lang_dummy.so lang_python.so lang_perl.so
#LANGS+=lang_ruby.so
ifeq ($(HAVE_LIB_TCC),1)
LANGS+=lang_tcc.so
endif

all: ${LANGS}
	@true

lang_python.so:
	-gcc -lpython >/dev/null 2>&1 ; \
		if [ $$? = 0 ]; then \
		${CC} ${CFLAGS} -I/usr/include/python2.5 \
		-fPIC -shared -o lang_python.so python.c -lpython ; \
		else \
		${CC} ${CFLAGS} -I/usr/include/python2.5 \
		-fPIC -shared -o lang_python.so python.c \
		-I/usr/include/python2.6/ -lpython2.6 ; \
		fi

ifeq ($(HAVE_LIB_TCC),1)
lang_tcc.so: tcc.o
	-${CC} ${CFLAGS} -fPIC -shared -o lang_tcc.so tcc.c -Wl,-R.. -ldl -ltcc
endif

lang_lua.so: lua.o
	-${CC} ${CFLAGS} -fPIC -shared -o lang_lua.so lua.c -Wl,-R..
	@#strip -s lua.so

lang_ruby.so:
	-env CFLAGS="${CFLAGS}" ruby mkruby.rb

lang_perl.so:
	-${CC} ${CFLAGS} -I/usr/lib/perl/5.10/CORE/ \
		-fPIC -shared -o lang_perl.so perl.c -Wl,-R.. \
		`perl -MExtUtils::Embed -e ccopts` \
		`perl -MExtUtils::Embed -e ldopts` -lncurses

lang_dummy.so: dummy.o
	${CC} ${CFLAGS} -fPIC -shared -o lang_dummy.so dummy.c -Wl,-R..
	@#strip -s lua.so

clean:
	-rm -f *.so *.o
