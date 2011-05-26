include ../config.mk
SOEXT=gir
include ../libs.mk

all: ${LIBS}

${LIBS}:
ifeq ($(HAVE_VALABIND),1)
	@PKG=`echo $@|sed -e s,.gir,,` ; \
	VAPI=`echo $@|sed -e s,.gir,.vapi,` ; \
	DEPS="$$(cat ../vapi/$${PKG}.deps 2>/dev/null | awk '{print "--pkg "$$1}')" ; \
	echo "valabind --module $${PKG} $$(echo $$DEPS) --gir ../vapi/$@" ; \
	valabind --module $${PKG} $${DEPS} --gir ../vapi/$${VAPI} && \
	g-ir-compiler $${PKG}.gir > $${PKG}.typelib
endif

install:
	rm -f /usr/lib/girepository-1.0/RAsm-1.0.*
	rm -f /usr/lib/girepository-1.0/r_asm-1.0.*
	rm -f /usr/share/gir-1.0/RAsm-1.0.*
	rm -f /usr/share/gir-1.0/r_asm-1.0.*
	cp r_asm.typelib /usr/lib/girepository-1.0/r_asm-1.0.typelib
	cp r_asm.gir /usr/share/gir-1.0/r_asm-1.0.gir
	gjs test.js

clean:
	@rm -f *.gir *.typelib
