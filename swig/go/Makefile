LANG=go
LANG_EXT=go
LIBS_PFX=

include ../rules.mk

%.so:
	@-test ../../libr/vapi/`echo $@|sed -e s,.so,.vapi,` -nt ${LIBS_PFX}$@ ; \
	if [ ! $$? = 0 ]; then \
	  if [ ! -e ${LIBS_PFX}$@ ]; then \
            true ; \
          else \
            false ; \
          fi ; \
	fi ; \
	if [ "${GOARCH}" = "amd64" ]; then \
		GO_FLAGS=-D_64BIT ; \
		GO_N=6 ; \
	else \
	if [ "${GOARCH}" = "386" ]; then \
		GO_N=8 ; \
	else \
		GO_N=5 ; \
	fi ; fi ; \
	if [ $$? = 0 ]; then \
	  (cd .. && sh do-swig.sh ${LANG} `echo $@ | sed -e s,.so,,`) ; \
	  ./fixgoswig.sh `echo $@ | sed -e s,.so,.go,` ; \
	  $${GO_N}g `echo $@ | sed -e s,.so,.go,` ; \
	  $${GO_N}c $${GO_FLAGS} -I ${GOROOT}/pkg/${GOOS}_${GOARCH} `echo $@ | sed -e s,.so,_gc.c,` ; \
	  gopack grc `echo $@ | sed -e s,.so,.a,` `echo $@ | sed -e s,.so,.$${GO_N},` `echo $@ | sed -e s,.so,_gc.$${GO_N},` ; \
	fi

rbintest:
	6g test-r_bin.go
	6l test-r_bin.6
	./6.out /bin/ls
