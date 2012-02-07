-include config.mk
PYTHON2_CONFIG=python2.7-config
PYTHON3_CONFIG=python3.2-config

ifneq ($(shell bsdtar -h 2>/dev/null|grep bsdtar),)
TAR=bsdtar czvf
else
TAR=tar -czvf
endif

W32PY="${HOME}/.wine/drive_c/Python27/"
INSTALL_TARGETS=install-vapi

LANGS=
# Experimental:
# LANGS+=gear
# LANGS+=gir
ALANGS=gir gear python ruby perl lua go java guile php5
.PHONY: ${ALANGS}

define ADD_lang
ifneq ($(shell grep $(1) supported.langs),)
LANGS+=$(1)
INSTALL_TARGETS+=install-$(1)
endif
endef

ifneq ($(shell grep python supported.langs),)
INSTALL_EXAMPLE_TARGETS+=install-python-examples
endif

$(foreach p,${ALANGS},$(eval $(call ADD_lang,$(p))))

.PHONY: ${INSTALL_TARGETS} ${INSTALL_EXAMPLE_TARGETS} ${LANG}

ifeq ($(DEVEL_MODE),1)
all: supported.langs ruby perl python lua go gear gir
supported.langs:
	CC=${CC} CXX=${CXX} sh check-langs.sh
else
# compile more
all: supported.langs python lua gear gir
supported.langs:
	CC=${CC} CXX=${CXX} sh check-langs.sh force-all
endif

chect:
	rm -f supported.langs
	${MAKE} supported.langs

check-w32:
	if [ ! -d "${W32PY}/libs" ]; then \
		wget http://www.python.org/ftp/python/2.7/python-2.7.msi ; \
		msiexec /i python-2.7.msi ; \
	fi

w32:
	cd python && ${MAKE} w32

DSTNAME=radare2-bindings-w32-$(VERSION)
DST=../$(DSTNAME)/Python27/Lib/site-packages/r2
SJLJ=/usr/i486-mingw32/bin/libgcc_s_sjlj-1.dll
STDC=/usr/i486-mingw32/bin/libstdc++-6.dll

w32dist:
	rm -rf ../${DSTNAME}
	mkdir -p ${DST}
	cp -f python/*.dll ${DST}
	cp -f python/r_*.py ${DST}
	:> ${DST}/__init__.py
	cd ${DST} ; for a in *.dll ; do mv $$a `echo $$a | sed -e s,dll,pyd,g` ; done
	# Copy missing libraries
	-cp -f ${SJLJ} ${DST}
	-cp -f ${STDC} ${DST}
	cd .. ; zip -r $(DSTNAME).zip $(DSTNAME)

.PHONY: w32dist dist w32 check check-w32 vdoc vdoc_pkg

dist:
	PKG=r2-bindings-${VERSION} ; \
	FILES=`cd .. ; hg st -mac . | grep r2-bindings | grep -v '/\.' | sed -e "s,r2-bindings/,$${PKG}/," | cut -c 3-` ; \
	CXXFILES=`cd .. ; find r2-bindings | grep -e cxx$$ -e py$$ | sed -e "s,r2-bindings/,$${PKG}/,"` ; \
	cd .. && mv r2-bindings $${PKG} && \
	echo $$FILES ; \
	${TAR} $${PKG}.tar.gz $${FILES} $${CXXFILES} ; \
	mv $${PKG} r2-bindings

# TODO: valadoc
vdoc:
	-rm -rf vdoc
	cat vapi/r_*.vapi > libr.vapi
	valadoc --package-version=${VERSION} --package-name=libr --driver 0.13.x -o vdoc libr.vapi
	-rm -f libr.vapi
	# rsync -avz vdoc/* pancake@radare.org:/srv/http/radareorg/vdoc/

vdoc_pkg:
	rm -rf vdoc
	valadoc -o vdoc vapi/*.vapi
	# rsync -avz vdoc/* pancake@radare.org:/srv/http/radareorg/vdoc/

# TODO: unspaguetti this targets
.PHONY: python2 python3
python2:
	@-[ "`grep python supported.langs`" ] && ( cd python && ${MAKE} PYTHON_CONFIG=${PYTHON2_CONFIG}) || true

python3:
	@-[ "`grep python supported.langs`" ] && ( cd python && ${MAKE} PYTHON_CONFIG=${PYTHON3_CONFIG}) || true

${ALANG}::
	cd $@ && ${MAKE}

go::
	@-[ -x "${GOBIN}/5g" -o -x "${GOBIN}/6g" -o -x "${GOBIN}/8g" ]

test:
	cd perl && ${MAKE} test
	cd python && ${MAKE} test
	cd ruby && ${MAKE} test
	cd lua && ${MAKE} test
	cd guile && ${MAKE} test
	cd go && ${MAKE} test
	cd java && ${MAKE} test

PYTHON?=python
PYTHON_VERSION?=`${PYTHON} --version 2>&1 | cut -d ' ' -f 2 | cut -d . -f 1,2`
PYTHON_PKGDIR=$(shell ${PYTHON} mp.py)
PYTHON_INSTALL_DIR=${DESTDIR}/${PYTHON_PKGDIR}/r2

.PHONY: purge purge-python install-cxx

purge: purge-python

install-cxx:
	@echo TODO: install-cxx

purge-python:
	[ -n "${PYTHON_PKGDIR}" ] && \
	rm -rf ${DESTDIR}/${LIBDIR}/python${PYTHON_VERSION}/*-packages/r2
	rm -rf ${PYTHON_INSTALL_DIR}

install-python:
	E=${SOEXT} ; [ `uname` = Darwin ] && E=so ; \
	echo "Installing python${PYTHON_VERSION} r2 modules in ${PYTHON_INSTALL_DIR}" ; \
	mkdir -p ${PYTHON_INSTALL_DIR} ; \
	: > ${PYTHON_INSTALL_DIR}/__init__.py ; \
	cp -rf python/r_*.py python/*.$$E ${PYTHON_INSTALL_DIR}

install-lua:
	for a in 5.1 ; do \
		mkdir -p ${DESTDIR}${PREFIX}/lib/lua/$$a ; \
		echo "Installing lua$$a r2 modules..." ; \
		cp -rf lua/*.${SOEXT} ${DESTDIR}${PREFIX}/lib/lua/$$a ; \
	done

install-go:
	@. ./go/goenv.sh ; \
	if [ -n "$${GOROOT}" -a -n "$${GOOS}" -a -n "$${GOARCH}" ]; then \
		echo "Installing r2 modules in $${GOROOT}/pkg/$${GOOS}_$${GOARCH}" ; \
		cp -f go/*.a go/*.${SOEXT} $${GOROOT}/pkg/$${GOOS}_$${GOARCH} ; \
	else \
		echo "You have to set the following vars: GOROOT, GOOS and GOARCH" ; \
	fi

install-java:
	@echo "TODO: install-java"

install-ruby:
	for a in 1.8 1.9.1; do \
		mkdir -p ${DESTDIR}${PREFIX}/lib/ruby/$$a/r2 ; \
		echo "Installing ruby$$a r2 modules..." ; \
		cp -rf ruby/* ${DESTDIR}${PREFIX}/lib/ruby/$$a/r2 ; \
	done

install-perl:
	# hack for slpm
	if [ -n "`echo ${PREFIX}${DESTDIR}|grep home`" ]; then \
		target=${PREFIX}${DESTDIR}`perl -e 'for (@INC) { print "$$_\n" if /lib(64)?\/perl5/ && !/local/; }'|head -n 1` ; \
	else \
		target=${DESTDIR}`perl -e 'for (@INC) { print "$$_\n" if /lib(64)?\/perl5/ && !/local/; }'|head -n 1` ; \
	fi ; \
	mkdir -p $$target/r2 ; \
	echo "Installing perl r2 modules..." ; \
	cp -rf perl/*.so $$target/r2 ; \
	cp -rf perl/*.pm $$target/r2

install-vapi:
	mkdir -p ${DESTDIR}${PREFIX}/share/vala/vapi
	${INSTALL_DATA} vapi/*.vapi vapi/*.deps ${DESTDIR}${PREFIX}/share/vala/vapi

install-gir:
	cd gir && ${MAKE} install

install-php5 install-guile:
	@echo TODO install-$@

EXAMPLEDIR=${DESTDIR}${PREFIX}/share/radare2-swig

install-examples: ${INSTALL_EXAMPLE_TARGETS}
	mkdir -p ${EXAMPLEDIR}/vala
	cp -rf vapi/t/*.vala vapi/t/*.gs ${EXAMPLEDIR}/vala

install-python-examples:
	mkdir -p ${EXAMPLEDIR}/python
	cp -rf python/test-*.py ${EXAMPLEDIR}/python

install: ${INSTALL_TARGETS}

deinstall uninstall:
	cd vapi/ ; for a in *.vapi *.deps ; do rm -f ${DESTDIR}${PREFIX}/share/vala/vapi/$$a ; done
	rm -rf ${EXAMPLEDIR}

oldtest:
	sh do-swig.sh r_bp
	python test.py

clean:
	@for a in $(LANGS); do \
		echo "Cleaning $$a " ; \
		cd $$a ; ${MAKE} clean ; cd .. ; \
	done

mrproper:
	for a in $(LANGS); do cd $$a ; ${MAKE} mrproper; cd .. ; done

version:
	@echo ${VERSION}

.PHONY: $(LANGS) $(ALANGS) 
.PHONY: clean mrproper all vdoc 
.PHONY: oldtest test 
.PHONY: w32 w32dist check check-w32 
.PHONY: deinstall uninstall install version
