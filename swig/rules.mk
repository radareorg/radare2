include ../config.mk

LIBS=r_util.${SOEXT} r_bp.${SOEXT} r_asm.${SOEXT} r_diff.${SOEXT}
LIBS+=r_bin.${SOEXT} r_cons.${SOEXT} r_anal.${SOEXT} r_cmd.${SOEXT}
LIBS+=r_debug.${SOEXT} r_config.${SOEXT} r_io.${SOEXT} r_syscall.${SOEXT}
LIBS+=r_search.${SOEXT} r_lib.${SOEXT} r_flags.${SOEXT}
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

ifeq ($(DEVEL_MODE),1)
%.${SOEXT}:
	@-test ../vapi/`echo $@|sed -e s,.${SOEXT},.vapi,` -nt ${LIBS_PFX}$@ ; \
	if [ ! $$? = 0 ]; then \
	  if [ ! -e ${LIBS_PFX}$@ ]; then \
            true ; \
          else \
            false ; \
          fi ; \
	fi ; \
	[ $$? = 0 ] && \
	  (cd .. && RELEASE=$(RELEASE) \
		sh do-swig.sh ${LANG} `echo $@ | sed -e s,.${SOEXT},,`) ; true

clean:
	rm -f *.${SOEXT} r_*
else
%.${SOEXT}:
	@VAPI=`echo $@|sed -e s,.${SOEXT},.vapi,` ; \
	test ../vapi/$${VAPI} -nt ${LIBS_PFX}$@ -o ! -e ${LIBS_PFX}$@ ; \
	if [ $$? = 0 ]; then echo " - ${LANG} $@" ; \
	LIB=`echo $@ | sed -e s,.${SOEXT},,` ; \
	${CXX} -fPIC -shared $${LIB}_wrap.cxx `../python-config-wrapper --cflags --libs` \
		`pkg-config --cflags --libs $${LIB}` ${CFLAGS} ${LDFLAGS} -o ${LIBS_PFX}$@ ; \
	fi ; true

clean:
	rm -f *.${SOEXT}
endif

test:
	-${LANG} test-r_bp.${LANG_EXT}
	-${LANG} test-r_asm.${LANG_EXT}
	-${LANG} test-r_hash.${LANG_EXT}

.PHONY: all test clean w32
