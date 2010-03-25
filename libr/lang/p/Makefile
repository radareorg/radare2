BINDEPS=foo
#include ../../../config-user.mk
include ../../config.mk

CFLAGS=-I../../include -Wall -DPREFIX=\"${PREFIX}\"
BINDEPS=

LANGS=lang_dummy.${EXT_SO} lang_python.${EXT_SO} lang_perl.${EXT_SO}
#LANGS+=lang_ruby.so
ifeq ($(HAVE_LIB_TCC),1)
LANGS+=lang_tcc.${EXT_SO}
endif

ifeq ($(HAVE_LIB_LUA5_1),1)
LANGS+=lang_lua.${EXT_SO}
endif

all: ${LANGS}
	@true

lang_python.${EXT_SO}:
	-gcc -lpython >/dev/null 2>&1 ; \
	if [ $$? = 0 ]; then \
		${CC} ${CFLAGS} -I/usr/include/python2.5 \
		-fPIC ${LDFLAGS_LIB} -o lang_python.${EXT_SO} python.c -lpython ; \
	else \
		${CC} ${CFLAGS} -I/usr/include/python2.5 \
		-fPIC ${LDFLAGS_LIB} -o lang_python.${EXT_SO} python.c \
		-I/usr/include/python2.6/ -lpython2.6 ; \
	fi

ifeq ($(HAVE_LIB_TCC),1)
lang_tcc.${EXT_SO}: tcc.o
	-${CC} ${CFLAGS} -fPIC ${LDFLAGS_LIB} -o lang_tcc.${EXT_SO} tcc.c ${LDFLAGS_LINKPATH}.. -ldl -ltcc
endif

ifeq ($(HAVE_LIB_LUA5_1),1)
lang_lua.${EXT_SO}: lua.o
	-${CC} ${CFLAGS} -fPIC ${LDFLAGS_LIB} -o lang_lua.${EXT_SO} lua.c ${LDFLAGS_LINKPATH}.. -llua5.1
endif

lang_ruby.${EXT_SO}:
	-env CFLAGS="${CFLAGS}" ruby mkruby.rb

lang_perl.${EXT_SO}:
	-${CC} ${CFLAGS} -I/usr/lib/perl/5.10/CORE/ \
		-fPIC ${LDFLAGS_LIB} -o lang_perl.${EXT_SO} perl.c ${LDFLAGS_LINKPATH}.. \
		`perl -MExtUtils::Embed -e ccopts` \
		`perl -MExtUtils::Embed -e ldopts` -lncurses

lang_dummy.${EXT_SO}: dummy.o
	${CC} ${CFLAGS} -shared -fPIC ${LDFLAGS_LIB} -o lang_dummy.${EXT_SO} dummy.c ${LDFLAGS_LINKPATH}.. -L..
	@#strip -s lua.so

clean:
	-rm -f *.${EXT_SO} *.${EXT_AR} *.o
