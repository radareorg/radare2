BINDEPS=foo
#include ../../../config-user.mk
include ../../config.mk

CFLAGS+=-I../../include -Wall -DPREFIX=\"${PREFIX}\"
ifeq ($(OSTYPE),darwin)
CFLAGS+=-undefined dynamic_lookup
endif

BINDEPS=

LANGS=$(shell ./getlangs.sh ${EXT_SO})
#LANGS=lang_python.${EXT_SO} lang_perl.${EXT_SO}

#LANGS+=lang_ruby.so
ifeq ($(HAVE_LIB_TCC),1)
LANGS+=lang_tcc.${EXT_SO}
endif
ifeq ($(HAVE_LIB_LUA5_1),1)
LANGS+=lang_lua.${EXT_SO}
endif

all: ${LANGS}
	@echo "LANG ${LANGS}"

ifeq ($(OSTYPE),windows)
lang_python.${EXT_SO}:
	${CC} ${CFLAGS} -I${HOME}/.wine/drive_c/Python27/include \
	-L${HOME}/.wine/drive_c/Python27/libs -L../../core/ -lr_core \
	${LDFLAGS_LIB} -shared -o lang_python.${EXT_SO} python.c -lpython27
else
PYCFG=../../../r2-bindings/python-config-wrapper
PYCFLAGS=$(shell ${PYCFG} --cflags)
PYLDFLAGS=$(shell ${PYCFG} --libs) -L$(shell ${PYCFG} --prefix)/lib

lang_python.${EXT_SO}:
	${CC} ${CFLAGS} ${PYCFLAGS} ${PYLDFLAGS} \
	${LDFLAGS} ${LDFLAGS_LIB} -fPIC -o lang_python.${EXT_SO} python.c
endif

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
		`perl -MExtUtils::Embed -e ccopts | sed -e 's/-arch [^\s]* //g'` \
		`perl -MExtUtils::Embed -e ldopts | sed -e 's/-arch [^\s]* //g'` -lncurses

mrproper clean:
	-rm -f *.${EXT_SO} *.${EXT_AR} *.o
	-rm -rf *.dSYM
