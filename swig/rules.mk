LIBS=r_util.so r_bp.so r_asm.so r_diff.so r_core.so r_bin.so r_cons.so 
LIBS+=r_debug.so r_config.so r_io.so r_syscall.so r_search.so r_lib.so libr.so

.SUFFIXES: .so

all: ${LIBS}

%.so:
	@echo ignore $@
	#@if test ../../libr/vapi/`echo $@|sed -e s,.so,.vapi,` -nt ${LIBS_PFX}$@ ; then
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
