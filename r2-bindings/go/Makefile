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
	. ./goenv.sh ; \
	if [ $$? = 0 ]; then \
	  (cd .. && sh do-swig.sh ${LANG} `echo $@ | sed -e s,.so,,`) ; \
	  ./fixgoswig.sh `echo $@ | sed -e s,.so,.go,` ; \
	  echo $${GOC} `echo $@ | sed -e s,.so,.go,` ; \
	  $${GOC} `echo $@ | sed -e s,.so,.go,` ; \
	  echo $${GOCC} $${GO_FLAGS} -I ${GOROOT}/pkg/$${GOOS}_$${GOARCH} `echo $@ | sed -e s,.so,_gc.c,` ; \
	  $${GOCC} $${GO_FLAGS} -I ${GOROOT}/pkg/$${GOOS}_$${GOARCH} `echo $@ | sed -e s,.so,_gc.c,` ; \
	  gopack grc `echo $@ | sed -e s,.so,.a,` `echo $@ | sed -e s,.so,.$${GO_N},` `echo $@ | sed -e s,.so,_gc.$${GO_N},` ; \
	fi

rbintest:
	. ./goenv.sh ; \
	$${GOC} -I. test-r_bin.go ; \
	$${GOL} -L. test-r_bin.$${GO_N} ; \
	LD_LIBRARY_PATH=. ./$${GO_N}.out /bin/ls

ibintest:
	. ./goenv.sh ; \
	$${GOC} test-r_bin.go ; \
	$${GOL} test-r_bin.$${GO_N} ; \
	./$${GO_N}.out /bin/ls
