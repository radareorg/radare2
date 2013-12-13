include ../config.mk
include ../libs.mk

ifneq ($(MY_SOEXT),)
SOEXT=${MY_SOEXT}
endif

.SUFFIXES: .$(SOEXT)

all: ${LIBS}

w32:
	# TODO: add support for debian
	LDFLAGS="-L${W32PY}/libs ${LDFLAGS}" \
	CFLAGS="-Wl,--enable-auto-import -L../../radare2-w32-${VERSION} ${CFLAGS}" \
	export CC CXX CFLAGS LDFLAGS ; \
	${MAKE} CC=${CC} CXX=${CXX}

%.${SOEXT}: ../vapi/%.vapi
ifeq (${LANG},cxx)
	mod=`echo $@ | sed -e s,.${SOEXT},,` ; \
	echo "MOD=$$mod" ; \
	valabind --cxx -N Radare -m $$mod --vapidir=../vapi $$mod && \
	${CXX} -shared -fPIC -o $@ $${mod}.cxx `pkg-config --cflags --libs $$mod`
else
ifeq (${LANG},dlang)
	mod=`echo $@ | sed -e s,.${SOEXT},,` ; \
	echo "MOD=$$mod" ; \
	valabind --dlang -N Radare -m $$mod --vapidir=../vapi $$mod
else
ifeq (${LANG},java)
	mkdir -p ${R2_JAVA_DIR}
endif
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
		sh do-swig.sh ${LANG} `echo $@ | sed -e s,.${SOEXT},,`) || exit 0 ; \
		[ "${LANG}`uname`" = pythonDarwin ] && cp _${LIBPFX}$@ _`echo $@|sed -e s,.${SOEXT},.so,` ; \
		true
	@echo ... $@
endif
endif

install:
	cd .. ; ${MAKE} install-${LANG}

clean:
ifeq (${LANG},java)
	rm -rf radare2.jar
	rm -rf ${R2_JAVA_DIR}
endif
ifneq ($(SAVED),)
	mkdir -p .skip
	cp $(SAVED) .skip
endif
	rm -f r_*.${SOEXT} _r_*.$(SOEXT)
ifneq ($(SAVED),)
	cd .skip ; cp * ..
	rm -rf .skip
endif

mrproper: clean

test:
	-${LANG} test-r_bp.${LANG_EXT}
	-${LANG} test-r_asm.${LANG_EXT}
	-${LANG} test-r_hash.${LANG_EXT}

.PHONY: all test clean w32
