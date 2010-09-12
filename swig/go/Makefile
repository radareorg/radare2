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
		FLAGS_6c=-D_64BIT ; \
	fi ; \
	if [ $$? = 0 ]; then \
	  (cd .. && sh do-swig.sh ${LANG} `echo $@ | sed -e s,.so,,`) ; \
	  sed -i 's,^\(const UT.*\) int,\1 uint,' `echo $@ | sed -e s,.so,.go,` ; \
	  6g `echo $@ | sed -e s,.so,.go,` ; \
	  6c $${FLAGS_6c} -I ${GOROOT}/pkg/${GOOS}_${GOARCH} `echo $@ | sed -e s,.so,_gc.c,` ; \
	  gopack grc `echo $@ | sed -e s,.so,.a,` `echo $@ | sed -e s,.so,.6,` `echo $@ | sed -e s,.so,_gc.6,` ; \
	fi
