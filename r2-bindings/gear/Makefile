include ../config.mk
SOEXT=gear
include ../libs.mk

all: ${LIBS}

${LIBS}:
ifeq ($(HAVE_VALABIND),1)
	@PKG=`echo $@|sed -e s,.gear,,` ; \
	VAPI=`echo $@|sed -e s,.gear,.vapi,` ; \
	DEPS="$$(cat ../vapi/$${PKG}.deps 2>/dev/null | awk '{print "--pkg "$$1}')" ; \
	echo "valabind --module $${PKG} $$(echo $$DEPS) --gear ../vapi/$@" ; \
	valabind --module $${PKG} $${DEPS} --gear ../vapi/$${VAPI}
endif

clean:
	@rm -f *.gear
