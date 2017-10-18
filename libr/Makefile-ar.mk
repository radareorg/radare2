# Adds the libr.$(EXT_AR) make target

ARTYPE?=default
EXT_AR?=a

ifeq (${ARTYPE},default)
libr.${EXT_AR}:
	rm -rf .libr
	mkdir .libr
	for FILE in */libr_*.${EXT_AR} ../shlr/*/*.${EXT_AR} ; do \
		F=${B}basename $$FILE${B} ; \
		Q=${B}dirname $$FILE${B} ; \
		D=${B}basename $$Q${B} ; \
		mkdir -p .libr/$$D ; \
		cp -f $$FILE .libr/$$D/$$F ; \
		ls -l .libr/$$D/$$F ; \
		(cd .libr/$$D && ${AR} x $$F || true ) ; \
	done
ifeq ($(IOSVER),)
	cd .libr ; ${AR} qv libr.${EXT_AR} `find * -iname *.${EXT_AR} 2> /dev/null`
	mv .libr/libr.${EXT_AR} libr.${EXT_AR}
	${RANLIB} libr.${EXT_AR}
else
	libtool -static -o libr.${EXT_AR} `find * -iname *.${EXT_AR} 2> /dev/null`
endif
endif

ifeq ($(ARTYPE),gnu)
libr.${EXT_AR}: $(shell ls */libr_*.${EXT_AR} 2>/dev/null)
	rm -f libr.
	echo CREATE libr.${EXT_AR} > libr.m
	for FILE in */libr_*.${EXT_AR} ; do echo ADDLIB $$FILE >> libr.m ; done
	echo SAVE >> libr.m
	# ar -M is a gnu-ism .. try to find a proper portable way to do that
	$(C_AR) -M < libr.m
	rm -f libr.m
endif

ifeq ($(ARTYPE),ios)
__AR=xcrun --sdk iphoneos ar
__RANLIB=xcrun --sdk iphoneos ranlib
libr.$(EXT_AR):
	rm -rf .libr
	mkdir .libr
	for FILE in */libr_*.${EXT_AR} ; do \
		mkdir -p .libr/$$FILE ; \
		cp -f $$FILE .libr/$$FILE ; \
		(cd .libr/$$FILE ; ${__AR} x *.${EXT_AR} ; rm -f *.${EXT_AR} ) ; \
		done
	cd .libr ; ${__AR} qv libr.${EXT_AR} `find * -iname *.o`
	mv .libr/libr.${EXT_AR} libr.${EXT_AR}
	${__RANLIB} libr.${EXT_AR}
	lipo -info libr.${EXT_AR}
	rm -rf .libr
endif
