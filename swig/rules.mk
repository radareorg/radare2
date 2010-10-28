include ../config.mk

LIBS=r_util.so r_bp.so r_asm.so r_diff.so r_core.so r_bin.so r_cons.so r_anal.so r_cmd.so
LIBS+=r_debug.so r_config.so r_io.so r_syscall.so r_search.so r_lib.so libr.so r_flags.so
LIBS+=r_parse.so

.SUFFIXES: .so

all: ${LIBS}

w32:
	# TODO: add support for debian
	CC=i486-mingw32-gcc \
	CXX=i486-mingw32-g++ \
	LDFLAGS="-L${W32PY}/libs ${LDFLAGS}" \
	CFLAGS="-Wl,--enable-auto-import -L../../radare2-w32-${VERSION} ${CFLAGS}" \
	export CC CXX CFLAGS LDFLAGS ; \
	${MAKE}

%.so:
	@-test ../../libr/vapi/`echo $@|sed -e s,.so,.vapi,` -nt ${LIBS_PFX}$@ ; \
	if [ ! $$? = 0 ]; then \
	  if [ ! -e ${LIBS_PFX}$@ ]; then \
            true ; \
          else \
            false ; \
          fi ; \
	fi ; \
	if [ $$? = 0 ]; then \
	  (cd .. && sh do-swig.sh ${LANG} `echo $@ | sed -e s,.so,,`) ; \
	fi

test:
	-${LANG} test-r_bp.${LANG_EXT}
	-${LANG} test-r_asm.${LANG_EXT}
	-${LANG} test-r_hash.${LANG_EXT}

clean:
	rm -f *.so r_* libr*

.PHONY: all test clean
