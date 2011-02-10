include ../config.mk

LIBS=r_util.${SOEXT} r_bp.${SOEXT} r_asm.${SOEXT} r_diff.${SOEXT}
LIBS+=r_bin.${SOEXT} r_cons.${SOEXT} r_anal.${SOEXT} r_cmd.${SOEXT}
LIBS+=r_debug.${SOEXT} r_config.${SOEXT} r_io.${SOEXT} r_syscall.${SOEXT}
LIBS+=r_search.${SOEXT} r_lib.${SOEXT} libr.${SOEXT} r_flags.${SOEXT}
LIBS+=r_parse.${SOEXT} r_lang.${SOEXT} r_core.${SOEXT}

.SUFFIXES: .$(SOEXT)

all: ${LIBS}

w32:
	# TODO: add support for debian
	CC=i486-mingw32-gcc \
	CXX=i486-mingw32-g++ \
	LDFLAGS="-L${W32PY}/libs ${LDFLAGS}" \
	CFLAGS="-Wl,--enable-auto-import -L../../radare2-w32-${VERSION} ${CFLAGS}" \
	export CC CXX CFLAGS LDFLAGS ; \
	${MAKE}

%.${SOEXT}:
	@-test ../../libr/vapi/`echo $@|sed -e s,.${SOEXT},.vapi,` -nt ${LIBS_PFX}$@ ; \
	if [ ! $$? = 0 ]; then \
	  if [ ! -e ${LIBS_PFX}$@ ]; then \
            true ; \
          else \
            false ; \
          fi ; \
	fi ; \
	[ $$? = 0 ] && \
	  (cd .. && sh RELEASE=$(RELEASE) ; \
		do-swig.sh ${LANG} `echo $@ | sed -e s,.${SOEXT},,`)

test:
	-${LANG} test-r_bp.${LANG_EXT}
	-${LANG} test-r_asm.${LANG_EXT}
	-${LANG} test-r_hash.${LANG_EXT}

clean:
	rm -f *.so r_* libr*

.PHONY: all test clean
